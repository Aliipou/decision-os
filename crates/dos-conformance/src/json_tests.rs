use super::*;

fn p(t: &str) -> Result<Json, String> {
    parse(t).map_err(|e| format!("{t:?}: {e:?}"))
}

fn eq(a: &str, b: &str) -> Result<bool, String> {
    Ok(p(a)? == p(b)?)
}

#[test]
fn accepts_rfc8259_documents() -> Result<(), String> {
    for t in [
        "null",
        "true",
        "false",
        "0",
        "-0",
        "1",
        "-1",
        "1.5",
        "1e5",
        "1E+5",
        "1e-5",
        "-0.0e0",
        "123456789012345678901234567890",
        "\"\"",
        "\"a\\\"b\\\\c\\/d\\b\\f\\n\\r\\t\"",
        "\"\\u00e9\\u00E9\"",
        "\"\\ud83d\\ude00\"",
        "\"é😀\"",
        "[]",
        "{}",
        " [ 1 , 2 ] ",
        "{\"a\":{\"b\":[{}]}}",
        "\t\r\n null \t\r\n",
    ] {
        p(t)?;
    }
    Ok(())
}

#[test]
fn rejects_non_json() -> Result<(), String> {
    for t in [
        "",
        " ",
        "nul",
        "True",
        "NaN",
        "Infinity",
        "-Infinity",
        "01",
        "-01",
        "1.",
        ".5",
        "-",
        "+1",
        "1e",
        "1e+",
        "0x10",
        "1_000",
        "\"",
        "\"\\x\"",
        "\"\\U0041\"",
        "\"\\u12\"",
        "\"\\u12G4\"",
        "\"a\nb\"",
        "\"\u{1}\"",
        "[1,]",
        "[,1]",
        "{\"a\":1,}",
        "{\"a\" 1}",
        "{a:1}",
        "{'a':1}",
        "[1 2]",
        "1 2",
        "{}{}",
        "[]]",
        "\u{feff}null",
        "null\u{0}",
        "// c\nnull",
        "\u{a0}null",
        "{\"a\":1,\"a\":2}",
        "{\"a\":{\"b\":1,\"b\":1}}",
        "[{\"x\":1,\"y\":2,\"x\":3}]",
        "{\"\\u0061\":1,\"a\":2}",
        "1e1000000000000000000",
        "1e-99999999999999999",
    ] {
        if parse(t).is_ok() {
            return Err(format!("accepted {t:?}"));
        }
    }
    Ok(())
}

#[test]
fn depth_is_bounded() -> Result<(), String> {
    let ok = format!("{}{}", "[".repeat(128), "]".repeat(128));
    p(&ok)?;
    let deep = format!("{}{}", "[".repeat(129), "]".repeat(129));
    if parse(&deep).is_ok() {
        return Err("accepted depth 129".into());
    }
    let very_deep = "[".repeat(1_000_000);
    if parse(&very_deep).is_ok() {
        return Err("accepted unterminated deep array".into());
    }
    Ok(())
}

#[test]
fn object_key_order_is_ignored() -> Result<(), String> {
    if !eq(
        "{\"a\":1,\"b\":[1,{\"c\":2,\"d\":3}]}",
        "{\"b\":[1,{\"d\":3,\"c\":2}],\"a\":1}",
    )? {
        return Err("reordered objects differ".into());
    }
    if eq("{\"a\":1}", "{\"a\":1,\"b\":2}")? || eq("{\"a\":1,\"b\":2}", "{\"a\":1}")? {
        return Err("subset object compared equal".into());
    }
    if eq("[1,2]", "[2,1]")? || eq("[1]", "[1,1]")? {
        return Err("array order ignored".into());
    }
    Ok(())
}

#[test]
fn numbers_compare_by_exact_value() -> Result<(), String> {
    let same = [
        ("1", "1.0"),
        ("1", "1e0"),
        ("100", "1E2"),
        ("100", "1.00e+2"),
        ("0.1", "1e-1"),
        ("0", "-0"),
        ("0", "0.000e99"),
        ("-0.0", "0"),
        ("12.50", "1.25e1"),
        (
            "123456789012345678901234567890",
            "1.2345678901234567890123456789e29",
        ),
    ];
    for (a, b) in same {
        if !eq(a, b)? {
            return Err(format!("{a} != {b}"));
        }
    }
    let differ = [
        ("9007199254740993", "9007199254740992"),
        ("0.1", "0.10000000000000001"),
        ("18446744073709551617", "18446744073709551616"),
        ("1", "-1"),
        ("1e400", "1e401"),
        ("1", "\"1\""),
        ("0", "false"),
        ("0", "null"),
        ("1", "true"),
        ("10", "1"),
        ("1e-400", "0"),
    ];
    for (a, b) in differ {
        if eq(a, b)? {
            return Err(format!("{a} == {b}"));
        }
    }
    Ok(())
}

#[test]
fn strings_compare_by_code_points() -> Result<(), String> {
    if !eq("\"\\u00e9\"", "\"é\"")?
        || !eq("\"\\ud83d\\ude00\"", "\"😀\"")?
        || !eq("\"\\/\"", "\"/\"")?
    {
        return Err("escaped and raw forms differ".into());
    }
    // NFC vs NFD: different code points, different strings.
    if eq("\"\\u00e9\"", "\"e\\u0301\"")? {
        return Err("normalization applied".into());
    }
    // Lone surrogates are kept as themselves.
    if !eq("\"\\ud800\"", "\"\\uD800\"")?
        || eq("\"\\ud800\"", "\"\\udc00\"")?
        || eq("\"\\ud800\"", "\"\"")?
    {
        return Err("lone surrogates mishandled".into());
    }
    if eq("\"\\ud83d\\ude00\"", "\"\\ude00\\ud83d\"")? {
        return Err("swapped surrogates equal".into());
    }
    Ok(())
}

#[test]
fn serde_magic_key_is_just_an_object() -> Result<(), String> {
    if eq("{\"$serde_json::private::Number\":\"5\"}", "5")? {
        return Err("magic key parsed as a number".into());
    }
    Ok(())
}

#[test]
fn write_round_trips_and_keeps_lexemes_and_order() -> Result<(), String> {
    let t = "{\"z\":1.50E+2,\"a\":[true,false,null,\"\\ud800\\\"\\u0001é😀\"],\"m\":{}}";
    let j = p(t)?;
    let w = write(&j);
    if w != "{\"z\":1.50E+2,\"a\":[true,false,null,\"\\ud800\\\"\\u0001é😀\"],\"m\":{}}" {
        return Err(format!("written as {w}"));
    }
    if p(&w)? != j {
        return Err("round trip changed value".into());
    }
    // Control characters and line separators are escaped, so a written value is one line.
    let w = write(&p("\"\\n\\r\\t\\u2028\\u007f\"")?);
    if w.contains('\n') || w.contains('\r') || w.contains('\t') || w.contains('\u{2028}') {
        return Err(format!("unescaped control in {w:?}"));
    }
    Ok(())
}

/// Differential test: the strict parser and serde_json must agree on accept/reject
/// for every document, except for the deliberate differences (duplicate keys and
/// out-of-range exponents refused here; lone surrogates and numbers beyond f64
/// accepted here).
#[test]
fn agrees_with_serde_json() -> Result<(), String> {
    let seeds = [
        "{\"a\":[1,2.5,-3e2,{\"b\":null}],\"c\":\"x\\u0041\\n\",\"d\":true}",
        "[\"\\ud83d\\ude00\",0,-0.0,1E+2,{},[]]",
        "{\"k\":{\"k2\":{\"k3\":[false,\"\\\\\"]}}}",
        "\"plain\"",
        "123.456e-7",
    ];
    let alphabet: &[u8] = b"{}[]\":,.-+0123456789eEtrufalsn\\u \n\tA";
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut checked = 0usize;
    for seed in seeds {
        for _ in 0..4000 {
            let mut bytes = seed.as_bytes().to_vec();
            for _ in 0..(1 + next() % 3) {
                let len = bytes.len() as u64;
                let pos = usize::try_from(next() % (len + 1)).map_err(|e| e.to_string())?;
                let ch = alphabet
                    .get(
                        usize::try_from(next() % alphabet.len() as u64)
                            .map_err(|e| e.to_string())?,
                    )
                    .copied()
                    .unwrap_or(b' ');
                match next() % 3 {
                    0 => bytes.insert(pos, ch),
                    1 if pos < bytes.len() => {
                        bytes.remove(pos);
                    }
                    _ if pos < bytes.len() => {
                        if let Some(b) = bytes.get_mut(pos) {
                            *b = ch;
                        }
                    }
                    _ => bytes.push(ch),
                }
            }
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            let mine = parse(&text);
            let theirs = serde_json::from_str::<serde_json::Value>(&text);
            match (&mine, &theirs) {
                (Ok(_), Ok(_)) | (Err(_), Err(_)) => {}
                (Err(e), Ok(_))
                    if e.kind == ErrorKind::DuplicateKey || e.kind == ErrorKind::NumberRange => {}
                (Ok(v), Err(_)) if has_lone_surrogate(v) => {}
                (Ok(_), Err(e)) if e.to_string().contains("out of range") => {}
                _ => {
                    return Err(format!(
                        "disagree on {text:?}: mine {mine:?}, serde {theirs:?}"
                    ));
                }
            }
            checked += 1;
        }
    }
    if checked < 10_000 {
        return Err(format!("only {checked} documents checked"));
    }
    Ok(())
}

fn has_lone_surrogate(j: &Json) -> bool {
    let lone = |s: &JStr| char::decode_utf16(s.units().iter().copied()).any(|r| r.is_err());
    match j {
        Json::String(s) => lone(s),
        Json::Array(a) => a.iter().any(has_lone_surrogate),
        Json::Object(m) => m.iter().any(|(k, v)| lone(k) || has_lone_surrogate(v)),
        _ => false,
    }
}

#[test]
fn agrees_with_serde_json_on_values() -> Result<(), String> {
    for t in [
        "{\"a\":[1,2,{\"b\":null}],\"c\":\"x\\u0041\\n\\ud83d\\ude00\",\"d\":true,\"e\":-7}",
        "[[],{},\"\",0,false]",
    ] {
        let theirs: serde_json::Value = serde_json::from_str(t).map_err(|e| e.to_string())?;
        if p(&theirs.to_string())? != p(t)? {
            return Err(format!("value differs for {t}"));
        }
    }
    Ok(())
}
