//! Server-sent events: an incremental splitter that reads exactly what the oracle's
//! `sse_events` reads, and refuses input a client could read differently.

use crate::Refusal;
use crate::json::{dumps_py, parse_strict};
use serde_json::Value;

/// One event: its raw bytes, `event:` name and joined `data:` lines.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Event {
    pub raw: Vec<u8>,
    pub name: Option<String>,
    pub data: Option<String>,
}

impl Event {
    /// The data parsed as a JSON object; `None` for no data and `[DONE]`. Anything else
    /// that is not a JSON object refuses the stream.
    pub(crate) fn json(&self) -> Result<Option<Value>, Refusal> {
        let Some(d) = &self.data else {
            return Ok(None);
        };
        if d.trim() == "[DONE]" {
            return Ok(None);
        }
        let v = parse_strict(d.as_bytes())
            .map_err(|e| Refusal::MalformedStream(format!("event data: {e}")))?;
        if v.is_object() {
            Ok(Some(v))
        } else {
            Err(Refusal::MalformedStream(
                "event data is not a JSON object".into(),
            ))
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.data.as_deref().is_some_and(|d| d.trim() == "[DONE]")
    }
}

fn malformed(why: &str) -> Refusal {
    Refusal::MalformedStream(why.to_owned())
}

/// Splits a byte stream into events at blank lines (`\n` or `\r\n`).
#[derive(Default)]
pub(crate) struct Splitter {
    partial: Vec<u8>,
    lines: Vec<Vec<u8>>,
    pending: usize,
    first_line: bool,
}

impl Splitter {
    pub(crate) fn new() -> Self {
        Splitter {
            first_line: true,
            ..Default::default()
        }
    }

    /// Bytes held for the event in progress.
    pub(crate) fn held(&self) -> usize {
        self.pending + self.partial.len()
    }

    fn check_line(&mut self, line: &[u8], at_eof: bool) -> Result<(), Refusal> {
        if self.first_line && line.starts_with(b"\xef\xbb\xbf") {
            return Err(malformed("byte-order mark at the start of the stream"));
        }
        self.first_line = false;
        let body = if at_eof {
            line
        } else {
            let l = line.strip_suffix(b"\n").unwrap_or(line);
            l.strip_suffix(b"\r").unwrap_or(l)
        };
        if body.contains(&b'\r') {
            return Err(malformed("a bare carriage return in the stream"));
        }
        std::str::from_utf8(line).map_err(|_| malformed("the stream is not UTF-8"))?;
        Ok(())
    }

    /// Feeds bytes; returns the events they complete.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<Vec<Event>, Refusal> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while let Some(pos) = rest.iter().position(|b| *b == b'\n') {
            let (head, tail) = rest.split_at(pos + 1);
            rest = tail;
            let mut line = std::mem::take(&mut self.partial);
            line.extend_from_slice(head);
            self.check_line(&line, false)?;
            let blank = line == b"\n" || line == b"\r\n";
            self.pending += line.len();
            self.lines.push(line);
            if blank {
                let lines = std::mem::take(&mut self.lines);
                self.pending = 0;
                out.push(parse(lines, false));
            }
        }
        self.partial.extend_from_slice(rest);
        Ok(out)
    }

    /// End of input: the unterminated last event, if any.
    pub(crate) fn finish(&mut self) -> Result<Option<Event>, Refusal> {
        let partial = std::mem::take(&mut self.partial);
        if !partial.is_empty() {
            self.check_line(&partial, true)?;
            self.lines.push(partial);
        }
        let lines = std::mem::take(&mut self.lines);
        self.pending = 0;
        Ok(if lines.is_empty() {
            None
        } else {
            Some(parse(lines, true))
        })
    }
}

fn parse(lines: Vec<Vec<u8>>, at_eof: bool) -> Event {
    let mut name = None;
    let mut data: Vec<String> = Vec::new();
    for line in &lines {
        let text = String::from_utf8_lossy(line);
        let text = text.trim_end_matches(['\r', '\n']);
        if let Some(rest) = text.strip_prefix("event:") {
            name = Some(rest.trim().to_owned());
        } else if let Some(rest) = text.strip_prefix("data:") {
            data.push(rest.strip_prefix(' ').unwrap_or(rest).to_owned());
        }
    }
    let mut raw: Vec<u8> = lines.concat();
    if at_eof && !(raw.ends_with(b"\n\n") || raw.ends_with(b"\r\n\r\n")) {
        while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            raw.pop();
        }
        raw.extend_from_slice(b"\n\n");
    }
    Event {
        raw,
        name,
        data: if data.is_empty() {
            None
        } else {
            Some(data.join("\n"))
        },
    }
}

/// `sse(data, event)`: one event as the oracle writes it.
pub(crate) fn sse(data: &Value, event: Option<&str>) -> Vec<u8> {
    let mut s = String::new();
    if let Some(e) = event.filter(|e| !e.is_empty()) {
        s.push_str("event: ");
        s.push_str(e);
        s.push('\n');
    }
    s.push_str("data: ");
    s.push_str(&dumps_py(data));
    s.push_str("\n\n");
    s.into_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn splits_like_the_oracle() {
        let mut s = Splitter::new();
        let evs = s
            .push(b"event: a\ndata: {\"x\":1}\n\n: c\r\n\r\ndata: 1\ndata: 2\n\ndata: tail")
            .unwrap();
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].name.as_deref(), Some("a"));
        assert_eq!(evs[0].data.as_deref(), Some("{\"x\":1}"));
        assert_eq!(evs[1].data, None);
        assert_eq!(evs[1].raw, b": c\r\n\r\n");
        assert_eq!(evs[2].data.as_deref(), Some("1\n2"));
        let last = s.finish().unwrap().unwrap();
        assert_eq!(last.raw, b"data: tail\n\n");
        assert!(s.finish().unwrap().is_none());
    }

    #[test]
    fn refuses_bare_cr_bom_and_bad_utf8() {
        assert!(Splitter::new().push(b"data: {}\rdata: {}\n\n").is_err());
        assert!(Splitter::new().push(b"\xef\xbb\xbfdata: {}\n\n").is_err());
        assert!(Splitter::new().push(b"data: \xff\n\n").is_err());
        let mut s = Splitter::new();
        s.push(b"data: {}\r").unwrap();
        assert!(s.finish().is_err());
        // a CR split from its LF across chunks is fine
        let mut s = Splitter::new();
        assert!(s.push(b"data: {}\r").unwrap().is_empty());
        assert_eq!(s.push(b"\n\r").unwrap().len(), 0);
        assert_eq!(s.push(b"\n").unwrap().len(), 1);
    }
}
