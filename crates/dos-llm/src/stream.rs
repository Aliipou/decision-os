//! The incremental stream rewriter. Its output does not depend on how the input is
//! chunked: events are only acted on once complete.

use crate::sse::{Event, Splitter};
use crate::stream_anthropic::AnthropicStream;
use crate::stream_chat::ChatStream;
use crate::stream_responses::ResponsesStream;
use crate::{Gate, Refusal, Shape};

/// Most bytes a stream may hold back (an event in progress plus everything buffered
/// after the first tool call). Past this the stream is refused.
pub const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;

/// One shape's rewrite over complete events.
pub(crate) trait Shaper {
    /// Handle one event, appending client bytes to `out`. `Ok(true)`: the message is
    /// over and the rest of the input is ignored (the oracle stops reading there).
    fn event(&mut self, ev: Event, gate: &mut dyn Gate, out: &mut Vec<u8>)
    -> Result<bool, Refusal>;
    /// End of the message.
    fn finish(&mut self, gate: &mut dyn Gate, out: &mut Vec<u8>) -> Result<(), Refusal>;
    /// Bytes held back so far.
    fn held(&self) -> usize;
}

enum State {
    Open,
    Stopped,
    Finished,
    Failed(Refusal),
}

/// Feed upstream bytes with [`StreamRewriter::push`], then call
/// [`StreamRewriter::finish`] once at end of input. Each call returns the bytes to send
/// to the client now. After a refusal every call returns the same refusal.
pub struct StreamRewriter {
    splitter: Splitter,
    shaper: Box<dyn Shaper>,
    state: State,
}

impl StreamRewriter {
    pub fn new(shape: Shape) -> Self {
        let shaper: Box<dyn Shaper> = match shape {
            Shape::Chat => Box::new(ChatStream::default()),
            Shape::Anthropic => Box::new(AnthropicStream::default()),
            Shape::Responses => Box::new(ResponsesStream::default()),
        };
        StreamRewriter {
            splitter: Splitter::new(),
            shaper,
            state: State::Open,
        }
    }

    fn fail(&mut self, r: Refusal) -> Refusal {
        self.state = State::Failed(r.clone());
        r
    }

    pub fn push(&mut self, bytes: &[u8], gate: &mut dyn Gate) -> Result<Vec<u8>, Refusal> {
        match &self.state {
            State::Failed(r) => return Err(r.clone()),
            State::Stopped => return Ok(Vec::new()),
            State::Finished => {
                return Err(self.fail(Refusal::MalformedStream("input after the end".into())));
            }
            State::Open => {}
        }
        let mut out = Vec::new();
        let events = match self.splitter.push(bytes) {
            Ok(e) => e,
            Err(r) => return Err(self.fail(r)),
        };
        for ev in events {
            match self.shaper.event(ev, gate, &mut out) {
                Ok(false) => {}
                Ok(true) => {
                    self.state = State::Stopped;
                    break;
                }
                Err(r) => return Err(self.fail(r)),
            }
        }
        if matches!(self.state, State::Open)
            && self.splitter.held() + self.shaper.held() > MAX_BUFFERED_BYTES
        {
            return Err(self.fail(Refusal::TooLarge(MAX_BUFFERED_BYTES)));
        }
        Ok(out)
    }

    pub fn finish(&mut self, gate: &mut dyn Gate) -> Result<Vec<u8>, Refusal> {
        let mut out = Vec::new();
        match &self.state {
            State::Failed(r) => return Err(r.clone()),
            State::Finished => return Ok(out),
            State::Open => {
                let last = match self.splitter.finish() {
                    Ok(e) => e,
                    Err(r) => return Err(self.fail(r)),
                };
                if let Some(ev) = last
                    && let Err(r) = self.shaper.event(ev, gate, &mut out)
                {
                    return Err(self.fail(r));
                }
            }
            State::Stopped => {}
        }
        if let Err(r) = self.shaper.finish(gate, &mut out) {
            return Err(self.fail(r));
        }
        self.state = State::Finished;
        Ok(out)
    }
}

/// The whole stream at once: the same bytes as any chunked feed.
pub fn rewrite_stream(shape: Shape, raw: &[u8], gate: &mut dyn Gate) -> Result<Vec<u8>, Refusal> {
    let mut r = StreamRewriter::new(shape);
    let mut out = r.push(raw, gate)?;
    out.extend(r.finish(gate)?);
    Ok(out)
}
