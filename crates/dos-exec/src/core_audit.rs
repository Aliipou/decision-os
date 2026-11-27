//! Bridge from the executor's [`AuditSink`] to `dos_core::store::AuditSink` (the signed,
//! hash-chained log in `dos-audit`). The entry has the oracle's `HashLog` fields, so the
//! Python tooling reads the log: `ts`, `actor`, `tool`, `verdict`, `reason`, `executed`,
//! `payload_digest`. Any failure to write is an error, and the proxy then refuses the call.

use std::time::{SystemTime, UNIX_EPOCH};

use dos_core::canon::{self, Value};
use dos_core::store::AuditSink as CoreSink;

use crate::decision::{AuditEvent, AuditSink};

/// Writes every executor [`AuditEvent`] to a core audit sink.
pub struct CoreAudit<S> {
    sink: S,
    actor: String,
}

impl<S: CoreSink + Send + Sync> CoreAudit<S> {
    pub fn new(sink: S) -> Self {
        CoreAudit {
            sink,
            actor: "dos-exec".into(),
        }
    }

    /// The actor name written to every entry (default `dos-exec`).
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }
}

/// Free text from a tool or a server must not stop the audit write: the characters the
/// log refuses (they would break Python's `splitlines`) become spaces.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{2028}' | '\u{2029}' | '\u{85}' => ' ',
            c => c,
        })
        .collect()
}

/// `YYYY-MM-DDTHH:MM:SS.ffffff+00:00` (Python's `datetime.isoformat()` for UTC).
fn iso_utc(unix_micros: u128) -> String {
    let secs = (unix_micros / 1_000_000) as i64;
    let micros = (unix_micros % 1_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}+00:00",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn now_iso() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    iso_utc(micros)
}

impl<S: CoreSink + Send + Sync> AuditSink for CoreAudit<S> {
    fn record(&self, ev: &AuditEvent) -> Result<(), String> {
        let s = |v: &str| Value::String(clean(v));
        let entry = Value::Object(vec![
            ("ts".into(), Value::String(now_iso())),
            ("actor".into(), s(&self.actor)),
            ("tool".into(), s(&ev.tool)),
            ("verdict".into(), s(ev.verdict)),
            ("reason".into(), s(&ev.reason)),
            ("executed".into(), Value::Bool(ev.executed)),
            ("payload_digest".into(), Value::Null),
        ]);
        let bytes = canon::to_jcs(&entry).map_err(|e| format!("audit entry: {e}"))?;
        self.sink
            .append(&bytes)
            .map(|_| ())
            .map_err(|e| format!("audit append: {}", e.code()))
    }
}

#[cfg(test)]
mod tests {
    use super::iso_utc;

    #[test]
    fn iso_matches_python_isoformat() {
        // datetime.fromtimestamp(0, UTC).isoformat() and a leap-day case.
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00.000000+00:00");
        assert_eq!(
            iso_utc(1_709_210_096_123_456),
            "2024-02-29T12:34:56.123456+00:00"
        );
        assert_eq!(
            iso_utc(951_782_400_000_001),
            "2000-02-29T00:00:00.000001+00:00"
        );
    }
}
