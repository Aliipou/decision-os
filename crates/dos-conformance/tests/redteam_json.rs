//! Red team (conformance-runner): the comparator and the request writer.
//!
//! Each test states a hypothesis "the runner treats as equal two documents the spec says
//! differ" (or the converse), or "the request it sends is not the vector's input".
//! Tests that pass here are recorded as negative results in findings/conformance-runner.md.

use dos_conformance::json::{self, ErrorKind, Json};
use dos_conformance::protocol::{self, Output};

fn p(s: &str) -> Json {
    let r = json::parse(s);
    assert!(r.is_ok(), "parse {s:?}: {:?}", r.as_ref().err());
    r.unwrap_or(Json::Null)
}

fn kind(s: &str) -> Option<ErrorKind> {
    json::parse(s).err().map(|e| e.kind)
}

// H4: numbers -------------------------------------------------------------------------

#[test]
fn rt_numbers_equal_forms() {
    let equal = [
        ("1", "1.0"),
        ("1", "1e0"),
        ("1", "10E-1"),
        ("1", "0.1e1"),
        ("1", "100e-2"),
        ("1", "1.000000000000000000000000000000000000"),
        ("0", "-0"),
        ("0", "-0.0e-999999999999999"),
        ("0", "0e999999999999999"),
        ("10", "1e0000000000000000000000001"), // leading zeros in the exponent
        ("1e999999999999999", "10e999999999999998"),
        ("1e-999999999999999", "0.1e-999999999999998"),
        ("-1.5", "-15e-1"),
        (
            "123456789012345678901234567890",
            "1.2345678901234567890123456789e29",
        ),
    ];
    for (a, b) in equal {
        assert_eq!(p(a), p(b), "{a} == {b}");
    }
}

#[test]
fn rt_numbers_different_values() {
    let differ = [
        ("1", "-1"),
        ("1e999999999999999", "1e999999999999998"),
        ("1e-999999999999999", "1e-999999999999998"),
        ("9007199254740993", "9007199254740992"),
        ("0.1", "0.10000000000000001"),
        ("1", "1.0000000000000000000000000000000000001"),
        ("100", "10"),
        ("1e2", "1e-2"),
        ("0.01", "0.1"),
        ("12", "21"),
        ("1.2e1", "12.1"),
        ("-0.0000001", "0"),
    ];
    for (a, b) in differ {
        assert_ne!(p(a), p(b), "{a} != {b}");
    }
}

#[test]
fn rt_number_limits() {
    // Written exponent magnitude >= 10^15 refused, whatever its spelling.
    for bad in [
        "1e1000000000000000",
        "1e-1000000000000000",
        "1E+1000000000000000",
        "1e00001000000000000000",
        "1e99999999999999999999999999",
    ] {
        assert_eq!(kind(bad), Some(ErrorKind::NumberRange), "{bad}");
    }
    for bad in [
        "01",
        "-",
        "1.",
        ".1",
        "+1",
        "1e",
        "1e+",
        "--1",
        "0x10",
        "1_0",
        "NaN",
        "Infinity",
        "-Infinity",
    ] {
        assert!(json::parse(bad).is_err(), "{bad}");
    }
}

// H5: strings and keys ----------------------------------------------------------------

#[test]
fn rt_strings() {
    assert_eq!(p(r#""😀""#), p("\"\u{1F600}\""));
    assert_eq!(p(r#""é""#), p("\"é\""));
    assert_eq!(p(r#""\/""#), p(r#""/""#));
    // NFC vs NFD are different code point sequences.
    assert_ne!(p("\"\u{e9}\""), p("\"e\u{301}\""));
    // Lone surrogates are their own code points.
    assert_ne!(p(r#""\ud83d""#), p(r#""\ude00""#));
    assert_ne!(p(r#""😀""#), p(r#""\ude00\ud83d""#));
    assert_ne!(p(r#""\ud800""#), p("\"\u{fffd}\""));
    // Case of hex digits does not matter.
    assert_eq!(p(r#""\uD800""#), p(r#""\ud800""#));
}

#[test]
fn rt_duplicate_keys_via_escapes_refused_at_depth() {
    for doc in [
        r#"{"a":1,"a":2}"#,
        r#"{"x":[{"k":1,"k":1}]}"#,
        r#"{"x":{"y":{"z":{"😀":1,"😀":2}}}}"#,
        r#"{"x":{"\ud800":1,"\uD800":1}}"#,
    ] {
        assert_eq!(kind(doc), Some(ErrorKind::DuplicateKey), "{doc}");
    }
    // Different lone surrogates are distinct keys (no lossy folding).
    assert!(json::parse(r#"{"\ud800":1,"\ud801":1}"#).is_ok());
}

#[test]
fn rt_key_order_and_lossy_keys() {
    assert_eq!(
        p(r#"{"a":1,"b":[1,{"c":2,"d":3}]}"#),
        p(r#"{"b":[1,{"d":3,"c":2}],"a":1}"#)
    );
    // Two objects whose keys differ only by lone surrogates must not compare equal.
    assert_ne!(p(r#"{"\ud800":1}"#), p(r#"{"\ud801":1}"#));
    // A response whose key is a lone surrogate must not satisfy exact_keys.
    assert!(protocol::parse_response(r#"{"name":"a","\ud800output":{"ok":1}}"#).is_err());
    assert!(protocol::parse_response(r#"{"name\ud800":"a","output":{"ok":1}}"#).is_err());
}

#[test]
fn rt_types_never_cross() {
    for (a, b) in [
        ("1", "true"),
        ("0", "false"),
        ("null", "0"),
        ("\"1\"", "1"),
        ("[]", "{}"),
        ("[1]", "1"),
        ("\"\"", "null"),
    ] {
        assert_ne!(p(a), p(b), "{a} != {b}");
    }
}

// H6: request writer round trip --------------------------------------------------------

#[test]
fn rt_write_round_trip() {
    let docs = [
        r#"{"op":"echo","value":"a\ud800b  \u007f\u0000\u001f\"\\"}"#,
        r#"{"v":[1e999999999999999,-0,0.10000000000000001,18446744073709551617]}"#,
        r#"{"z":1,"a":2,"é":3,"é":4}"#,
        r#"{"s":"😀\ude00\ud83d"}"#,
        "{\"raw\":\"\u{10FFFF}\u{FEFF}\"}",
    ];
    for d in docs {
        let v = p(d);
        let w = json::write(&v);
        assert!(!w.contains('\n') && !w.contains('\r'), "{w}");
        let v2 = p(&w);
        assert_eq!(v, v2, "{d} -> {w}");
        assert_eq!(w, json::write(&v2), "writer not idempotent on {d}");
        // Member order is kept for requests.
        assert_eq!(v.keys(), v2.keys());
    }
    // The request line carries exactly area, name, input.
    let line = protocol::request_line("a", "n", &p(r#"{"x":1.50}"#));
    assert_eq!(line, r#"{"area":"a","name":"n","input":{"x":1.50}}"#);
}

#[test]
fn rt_output_error_codes_compare_by_code_points() {
    let a = Output::from_json(&p(r#"{"error":"bad"}"#), false);
    let b = Output::from_json(&p(r#"{"error":"bad"}"#), false);
    assert_eq!(a, b);
    // A lone-surrogate error code is refused, not folded to U+FFFD.
    assert!(Output::from_json(&p(r#"{"error":"\ud800"}"#), false).is_err());
}

#[test]
fn rt_depth_bound() {
    let ok = format!("{}{}", "[".repeat(128), "]".repeat(128));
    assert!(json::parse(&ok).is_ok());
    let bad = format!("{}{}", "[".repeat(129), "]".repeat(129));
    assert_eq!(kind(&bad), Some(ErrorKind::TooDeep));
    let deep_obj = format!("{}1{}", "{\"a\":".repeat(129), "}".repeat(129));
    assert_eq!(kind(&deep_obj), Some(ErrorKind::TooDeep));
    // Unclosed deep input must not overflow the stack.
    assert!(json::parse(&"[".repeat(1_000_000)).is_err());
}
