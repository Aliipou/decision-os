//! Decision OS model gateway (port of the oracle `gateway/llm_proxy.py`).
//!
//! The pure core finds every tool call a client would execute in an upstream model
//! response (OpenAI chat completions, OpenAI Responses, Anthropic Messages; JSON bodies
//! and SSE streams), gates each one through a [`Gate`], and rewrites the response so a
//! refused call is removed and replaced by the oracle's note. When nothing is refused or
//! rewritten the upstream bytes pass through unchanged. Unknown content encodings,
//! unparseable or ambiguous bodies and malformed streams are refused ([`Refusal`]).
//!
//! [`server`] is a minimal std-only HTTP forwarder on top (plain HTTP upstreams only).
//! Design: `design/llm.md`.
#![forbid(unsafe_code)]

mod body;
mod gate;
mod json;
mod sse;
mod stream;
mod stream_anthropic;
mod stream_chat;
mod stream_responses;

// pub mod engine_gate;
// pub mod server;

pub use gate::{Gate, Outcome};
pub use json::{dumps_py, parse_strict};
pub use stream::{MAX_BUFFERED_BYTES, StreamRewriter, rewrite_stream};

/// The API shape of a gated route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// OpenAI chat completions (`.../chat/completions`).
    Chat,
    /// OpenAI Responses (`.../responses`).
    Responses,
    /// Anthropic Messages (`.../messages`).
    Anthropic,
}

impl Shape {
    /// The shape of a request path, as the oracle's `detect_shape` decides it.
    pub fn detect(path: &str) -> Option<Shape> {
        let p = path.split('?').next().unwrap_or(path).trim_end_matches('/');
        if p.ends_with("/chat/completions") {
            Some(Shape::Chat)
        } else if p.ends_with("/responses") {
            Some(Shape::Responses)
        } else if p.ends_with("/messages") {
            Some(Shape::Anthropic)
        } else {
            None
        }
    }

    /// `chat`, `responses` or `anthropic` (the vector spelling).
    pub fn parse(s: &str) -> Option<Shape> {
        match s {
            "chat" => Some(Shape::Chat),
            "responses" => Some(Shape::Responses),
            "anthropic" => Some(Shape::Anthropic),
            _ => None,
        }
    }
}

/// Why a response was not delivered. Nothing of a refused JSON body reaches the client;
/// a refused stream stops at the refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A `Content-Encoding` the gateway cannot inspect (anything but identity).
    UnsupportedEncoding(String),
    /// A JSON body that does not parse, is ambiguous, or has the wrong shape.
    UnparseableBody(String),
    /// An SSE stream that is not well formed, ambiguous or inconsistent.
    MalformedStream(String),
    /// A body or buffered stream larger than the gateway will hold.
    TooLarge(usize),
}

impl Refusal {
    /// The conformance error code.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::UnsupportedEncoding(_) => "unsupported_encoding",
            Refusal::UnparseableBody(_) => "unparseable_body",
            Refusal::MalformedStream(_) => "malformed_stream",
            Refusal::TooLarge(_) => "too_large",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::UnsupportedEncoding(e) => {
                write!(f, "Decision OS cannot inspect a {e}-encoded model response")
            }
            Refusal::UnparseableBody(why) => write!(
                f,
                "Decision OS could not parse the model response, so it was not delivered \
                 (tool calls in it could not be checked): {why}"
            ),
            Refusal::MalformedStream(why) => write!(
                f,
                "Decision OS stopped a malformed model stream (tool calls in it could not be \
                 checked): {why}"
            ),
            Refusal::TooLarge(n) => write!(
                f,
                "Decision OS refused a model response larger than {n} bytes (it could not be checked)"
            ),
        }
    }
}

/// Largest JSON body the gateway will parse and gate.
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Accepts only an absent, empty or `identity` `Content-Encoding`.
pub fn check_encoding(encoding: Option<&str>) -> Result<(), Refusal> {
    let e = encoding.unwrap_or("").trim().to_ascii_lowercase();
    if e.is_empty() || e == "identity" {
        Ok(())
    } else {
        Err(Refusal::UnsupportedEncoding(e))
    }
}

/// Gates a complete JSON response body. Returns the bytes for the client: the input
/// itself when nothing was refused or rewritten, else the rewritten body.
pub fn rewrite_body(shape: Shape, raw: &[u8], gate: &mut dyn Gate) -> Result<Vec<u8>, Refusal> {
    if raw.len() > MAX_BODY_BYTES {
        return Err(Refusal::TooLarge(MAX_BODY_BYTES));
    }
    let before = parse_strict(raw).map_err(Refusal::UnparseableBody)?;
    let mut after = before.clone();
    match shape {
        Shape::Chat => body::gate_chat_completion(&mut after, gate)?,
        Shape::Anthropic => body::gate_anthropic_message(&mut after, gate)?,
        Shape::Responses => body::gate_responses_body(&mut after, gate)?,
    }
    if after == before {
        Ok(raw.to_vec())
    } else {
        Ok(dumps_py(&after).into_bytes())
    }
}
