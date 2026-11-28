//! Every `conformance/vectors/llm` case, whole and split at every byte offset.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::Scripted;
use dos_llm::{Refusal, Shape, StreamRewriter, check_encoding, rewrite_body, rewrite_stream};
use serde_json::{Value, json};
use std::path::PathBuf;

fn b64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64"),
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|c| *c != b'=').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c) << (18 - 6 * i);
        }
        let take = chunk.len() - 1;
        for i in 0..take {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

fn vectors() -> Vec<(PathBuf, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/llm");
    let mut out: Vec<(PathBuf, Value)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let v = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            (p, v)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

struct Case {
    shape: Shape,
    stream: bool,
    encoding: Option<String>,
    body: Vec<u8>,
    decisions: Value,
}

fn case(v: &Value) -> Case {
    let i = &v["input"];
    let body = match (i.get("body"), i.get("body_b64")) {
        (Some(b), _) => b.as_str().unwrap().as_bytes().to_vec(),
        (None, Some(b)) => b64(b.as_str().unwrap()),
        _ => panic!("no body"),
    };
    Case {
        shape: Shape::parse(i["shape"].as_str().unwrap()).unwrap(),
        stream: i["stream"].as_bool().unwrap(),
        encoding: i
            .get("content_encoding")
            .and_then(Value::as_str)
            .map(str::to_owned),
        body,
        decisions: i["decisions"].clone(),
    }
}

/// The adapter output for one case: `{"ok": {"body", "calls"}}` or `{"error": code}`.
fn run(c: &Case) -> Value {
    let mut gate = Scripted::new(c.decisions.clone());
    let res: Result<Vec<u8>, Refusal> = check_encoding(c.encoding.as_deref()).and_then(|()| {
        if c.stream {
            rewrite_stream(c.shape, &c.body, &mut gate)
        } else {
            rewrite_body(c.shape, &c.body, &mut gate)
        }
    });
    match res {
        Ok(out) => json!({"ok": {"body": String::from_utf8(out).unwrap(), "calls": gate.calls}}),
        Err(r) => json!({"error": r.code()}),
    }
}

fn run_chunked(c: &Case, cuts: &[usize]) -> Value {
    let mut gate = Scripted::new(c.decisions.clone());
    let mut r = StreamRewriter::new(c.shape);
    let mut out = Vec::new();
    let mut start = 0;
    let mut err = None;
    for &end in cuts.iter().chain(std::iter::once(&c.body.len())) {
        match r.push(&c.body[start..end], &mut gate) {
            Ok(b) => out.extend(b),
            Err(e) => {
                err = Some(e);
                break;
            }
        }
        start = end;
    }
    if err.is_none() {
        match r.finish(&mut gate) {
            Ok(b) => out.extend(b),
            Err(e) => err = Some(e),
        }
    }
    match err {
        Some(r) => json!({"error": r.code()}),
        None => json!({"ok": {"body": String::from_utf8(out).unwrap(), "calls": gate.calls}}),
    }
}

#[test]
fn llm_vectors_pass() {
    let all = vectors();
    assert!(all.len() >= 25, "only {} llm vectors", all.len());
    let mut failed = Vec::new();
    for (path, v) in &all {
        let got = run(&case(v));
        if got != v["expected"] {
            failed.push(format!(
                "{}\n  expected {}\n  got      {}",
                path.display(),
                v["expected"],
                got
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "{} failed:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

#[test]
fn stream_vectors_do_not_depend_on_chunking() {
    for (path, v) in vectors() {
        let c = case(&v);
        if !c.stream || c.encoding.is_some() {
            continue;
        }
        let whole = run(&c);
        for cut in 0..=c.body.len() {
            assert_eq!(
                run_chunked(&c, &[cut]),
                whole,
                "{} split at {cut}",
                path.display()
            );
        }
        let bytes: Vec<usize> = (1..c.body.len()).collect();
        assert_eq!(
            run_chunked(&c, &bytes),
            whole,
            "{} byte by byte",
            path.display()
        );
    }
}

#[test]
fn passthrough_vectors_are_byte_identical() {
    let mut n = 0;
    for (path, v) in vectors() {
        let c = case(&v);
        if let Some(ok) = v["expected"].get("ok")
            && ok["body"].as_str().unwrap().as_bytes() == c.body.as_slice()
        {
            n += 1;
            assert_eq!(
                run(&c)["ok"]["body"].as_str().unwrap().as_bytes(),
                c.body.as_slice(),
                "{}",
                path.display()
            );
        }
    }
    assert!(n >= 6, "only {n} passthrough vectors");
}
