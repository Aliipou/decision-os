//! RFC 8785 / I-JSON behavior of `dos_core::canon`. Spec: spec/canon.md.

use dos_core::canon::{self, CanonError, MAX_DEPTH, Number, Value};
use proptest::prelude::*;

fn jcs_bytes(input: &[u8]) -> Result<String, &'static str> {
    match canon::canonicalize(input) {
        Ok(out) => String::from_utf8(out).map_err(|_| "output is not utf-8"),
        Err(e) => Err(e.code()),
    }
}

fn jcs(input: &str) -> Result<String, &'static str> {
    jcs_bytes(input.as_bytes())
}

fn ok(input: &str, expected: &str) {
    assert_eq!(jcs(input), Ok(expected.to_string()), "input {input:?}");
}

fn err(input: &str, code: &str) {
    assert_eq!(jcs(input), Err(code), "input {input:?}");
}

fn value_jcs(v: &Value) -> Result<String, &'static str> {
    match canon::to_jcs(v) {
        Ok(out) => String::from_utf8(out).map_err(|_| "output is not utf-8"),
        Err(e) => Err(e.code()),
    }
}

fn num(f: f64) -> Result<String, &'static str> {
    let n = Number::new(f).map_err(CanonError::code)?;
    value_jcs(&Value::Number(n))
}

// ---- RFC 8785 examples ----

const RFC_3_2_2_INPUT: &str = r#"{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}"#;

const RFC_3_2_3_OUTPUT: &str = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";

#[test]
fn rfc8785_3_2_3_sample_output() {
    ok(RFC_3_2_2_INPUT, RFC_3_2_3_OUTPUT);
}

#[test]
fn rfc8785_3_2_4_utf8_bytes() {
    let hex = "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72 \
               75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a \
               5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31 \
               65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37 \
               5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30 \
               30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d";
    let expected: Vec<u8> = hex
        .split_whitespace()
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();
    assert_eq!(expected.len(), 118);
    assert_eq!(
        canon::canonicalize(RFC_3_2_2_INPUT.as_bytes()),
        Ok(expected)
    );
}

#[test]
fn rfc8785_3_2_3_sort_example() {
    let input = r#"{
       "\u20ac": "Euro Sign",
       "\r": "Carriage Return",
       "\ufb33": "Hebrew Letter Dalet With Dagesh",
       "1": "One",
       "\ud83d\ude00": "Emoji: Grinning Face",
       "\u0080": "Control",
       "\u00f6": "Latin Small Letter O With Diaeresis"
     }"#;
    let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
                    \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\
                    \"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
    ok(input, expected);
}

#[test]
fn rfc8785_3_2_3_sort_order_strings() {
    ok(
        r#"{"ab":0,"aa":0,"a":0,"":0}"#,
        r#"{"":0,"a":0,"aa":0,"ab":0}"#,
    );
}

/// RFC 8785 Appendix B, every row.
const APPENDIX_B: &[(u64, &str)] = &[
    (0x0000000000000000, "0"),
    (0x8000000000000000, "0"),
    (0x0000000000000001, "5e-324"),
    (0x8000000000000001, "-5e-324"),
    (0x7fefffffffffffff, "1.7976931348623157e+308"),
    (0xffefffffffffffff, "-1.7976931348623157e+308"),
    (0x4340000000000000, "9007199254740992"),
    (0xc340000000000000, "-9007199254740992"),
    (0x4430000000000000, "295147905179352830000"),
    (0x44b52d02c7e14af5, "9.999999999999997e+22"),
    (0x44b52d02c7e14af6, "1e+23"),
    (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
    (0x444b1ae4d6e2ef4e, "999999999999999700000"),
    (0x444b1ae4d6e2ef4f, "999999999999999900000"),
    (0x444b1ae4d6e2ef50, "1e+21"),
    (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
    (0x3eb0c6f7a0b5ed8d, "0.000001"),
    (0x41b3de4355555553, "333333333.3333332"),
    (0x41b3de4355555554, "333333333.33333325"),
    (0x41b3de4355555555, "333333333.3333333"),
    (0x41b3de4355555556, "333333333.3333334"),
    (0x41b3de4355555557, "333333333.33333343"),
    (0xbecbf647612f3696, "-0.0000033333333333333333"),
    (0x43143ff3c1cb0959, "1424953923781206.2"),
];

#[test]
fn rfc8785_appendix_b_serialize() {
    for &(bits, text) in APPENDIX_B {
        assert_eq!(
            num(f64::from_bits(bits)),
            Ok(text.to_string()),
            "bits {bits:016x}"
        );
    }
}

#[test]
fn rfc8785_appendix_b_parse_back() -> Result<(), String> {
    for &(bits, text) in APPENDIX_B {
        let v =
            canon::parse_strict(text.as_bytes()).map_err(|e| format!("{text}: {}", e.code()))?;
        let Value::Number(n) = v else {
            return Err(format!("{text}: not a number"));
        };
        let want = f64::from_bits(bits);
        // "0" parses to +0 for the minus-zero row; the value is equal, the sign is not kept.
        assert!(
            n.get() == want && (want != 0.0 || n.get().to_bits() == 0),
            "{text}"
        );
        assert_eq!(jcs(text), Ok(text.to_string()));
    }
    Ok(())
}

#[test]
fn rfc8785_appendix_b_nan_and_infinity_refused() {
    for bits in [
        0x7fffffffffffffff_u64,
        0x7ff0000000000000,
        0xfff0000000000000,
        0x7ff8000000000000,
    ] {
        assert_eq!(
            Number::new(f64::from_bits(bits)),
            Err(CanonError::NonFiniteNumber)
        );
    }
}

// ---- numbers ----

#[test]
fn minus_zero_is_zero() {
    ok("-0", "0");
    ok("-0.0", "0");
    ok("-0e10", "0");
    ok("0e-999999999999999999999", "0");
    assert_eq!(num(-0.0), Ok("0".to_string()));
}

#[test]
fn exponent_boundaries() {
    ok("1e20", "100000000000000000000");
    ok("1e21", "1e+21");
    ok("1.23456789012345678901e20", "123456789012345680000");
    err("123456789012345678901", "unsafe_integer");
    ok("1e-6", "0.000001");
    ok("1e-7", "1e-7");
    ok("1.5e-7", "1.5e-7");
    ok("0.0000015", "0.0000015");
    ok("12345e-3", "12.345");
    ok("1E+2", "100");
    ok("4.50", "4.5");
    ok("2e-3", "0.002");
    ok("1E30", "1e+30");
    ok("1e16", "10000000000000000");
    ok("1.0", "1");
}

#[test]
fn smallest_and_rounding() {
    ok("5e-324", "5e-324");
    ok("4e-324", "5e-324");
    ok("2e-324", "0");
    ok("1e-400", "0");
    ok("1.7976931348623157e308", "1.7976931348623157e+308");
    ok(
        "0.1000000000000000055511151231257827021181583404541015625",
        "0.1",
    );
    ok("333333333.33333329", "333333333.3333333");
    ok("1424953923781206.25", "1424953923781206.2");
}

#[test]
fn exact_ties_round_to_even() {
    // ECMA-262 Note 2. Found by numbers_match_ryu_js: core's shortest digits give ...492.3.
    assert_eq!(
        num(f64::from_bits(4832322511278445154)),
        Ok("1120913795580492.2".to_string())
    );
    assert_eq!(
        num(f64::from_bits(0x43143ff3c1cb0959)),
        Ok("1424953923781206.2".to_string())
    );
    assert_eq!(
        num(f64::from_bits(0xc3143ff3c1cb0959)),
        Ok("-1424953923781206.2".to_string())
    );
    // Exactly representable halves with an even neighbour above: keep rounding up.
    assert_eq!(num(0.5), Ok("0.5".to_string()));
    assert_eq!(num(2.5), Ok("2.5".to_string()));
}

#[test]
fn non_finite_refused() {
    err("NaN", "non_finite_number");
    err("Infinity", "non_finite_number");
    err("-Infinity", "non_finite_number");
    err("[1,NaN]", "non_finite_number");
    err("1e400", "non_finite_number");
    err("-1e400", "non_finite_number");
    err("1.8e308", "non_finite_number");
    let big = format!("1{}", "0".repeat(400));
    err(&big, "non_finite_number");
    err("nan", "syntax");
    err("inf", "syntax");
    err("-inf", "syntax");
    err("Inf", "syntax");
}

#[test]
fn integer_literals_must_survive_as_text() {
    ok("9007199254740991", "9007199254740991");
    ok("-9007199254740991", "-9007199254740991");
    // Exactly the JCS text of a double: accepted (RFC 8785 Appendix B rows).
    ok("9007199254740992", "9007199254740992");
    ok("-9007199254740992", "-9007199254740992");
    ok("295147905179352830000", "295147905179352830000");
    // Would be rounded: refused.
    err("9007199254740993", "unsafe_integer");
    err("-9007199254740993", "unsafe_integer");
    err("9223372036854775807", "unsafe_integer");
    err("18446744073709551615", "unsafe_integer");
    err("295147905179352825856", "unsafe_integer");
    err(r#"{"amount":9007199254740993}"#, "unsafe_integer");
    // Fraction or exponent form: a double by RFC 8785 3.2.2, rounded.
    ok("9007199254740993.0", "9007199254740992");
    ok("9.007199254740993e15", "9007199254740992");
}

#[test]
fn number_syntax() {
    for bad in [
        "01", "-01", "00", "+1", "1.", ".5", "-", "1e", "1e+", "1E-", "0x10", "1_000", "- 1",
        "1.e5", "--1",
    ] {
        err(bad, "syntax");
    }
    ok("1e+0001", "10");
    ok("-1E-0001", "-0.1");
}

// ---- strings ----

#[test]
fn escapes_minimal() {
    ok(r#""\u001f""#, r#""\u001f""#);
    ok(r#""\u007f""#, "\"\u{7f}\"");
    ok(r#""\u0000""#, r#""\u0000""#);
    ok(r#""\u0008\u0009\u000a\u000c\u000d""#, r#""\b\t\n\f\r""#);
    ok(r#""\b\f\n\r\t""#, r#""\b\f\n\r\t""#);
    ok(r#""\/""#, r#""/""#);
    ok(r#""\u00e9\u20AC""#, "\"\u{e9}\u{20ac}\"");
    ok(r#""\u2028\u2029""#, "\"\u{2028}\u{2029}\"");
    ok("\"\u{e9}\"", "\"\u{e9}\"");
    ok(r#""\"\\""#, r#""\"\\""#);
    ok(r#""\u000B""#, r#""\u000b""#);
}

#[test]
fn invalid_escapes() {
    for bad in [
        r#""\x41""#,
        r#""\u12G4""#,
        r#""\U0041""#,
        r#""\u004""#,
        r#""\'""#,
        r#""\a""#,
        r#""\0""#,
        r#""\u""#,
    ] {
        err(bad, "invalid_escape");
    }
}

#[test]
fn surrogates() {
    ok(r#""\ud83d\ude00""#, "\"\u{1f600}\"");
    ok(r#""\uD83D\uDE00""#, "\"\u{1f600}\"");
    // U+10FFFD is the last scalar that is not a noncharacter (U+10FFFF is one).
    ok(r#""\udbff\udffd""#, "\"\u{10fffd}\"");
    err(r#""\ud83d""#, "lone_surrogate");
    err(r#""\ude00""#, "lone_surrogate");
    err(r#""\ude00\ud83d""#, "lone_surrogate");
    err(r#""\ud83d\u0041""#, "lone_surrogate");
    err(r#""\ud83dx""#, "lone_surrogate");
    err(r#""\ud83d\ud83d""#, "lone_surrogate");
    err(r#""\ud83d\n""#, "lone_surrogate");
    err(r#"{"\udead":1}"#, "lone_surrogate");
    err(r#""\ud83d\u12G4""#, "invalid_escape");
}

#[test]
fn surrogate_bytes_are_invalid_utf8() {
    // CESU-8 / WTF-8 encoding of U+D83D U+DE00.
    assert_eq!(
        jcs_bytes(b"\"\xed\xa0\xbd\xed\xb8\x80\""),
        Err("invalid_utf8")
    );
    assert_eq!(jcs_bytes(b"\"\xed\xa0\x80\""), Err("invalid_utf8"));
}

#[test]
fn invalid_utf8() {
    for bad in [
        &b"\"\xff\""[..],
        b"\"\xc0\xaf\"",
        b"\"\xe2\x82\"",
        b"\"\xf4\x90\x80\x80\"",
        b"[1]\xff",
        b"\xfe\xff",
        b"\x80",
    ] {
        assert_eq!(jcs_bytes(bad), Err("invalid_utf8"), "{bad:?}");
    }
}

#[test]
fn noncharacters_refused() {
    for bad in [
        r#""\ufdd0""#,
        r#""\ufdef""#,
        r#""\ufffe""#,
        r#""\uffff""#,
        r#""\ud83f\udffe""#,
        r#""\udbff\udfff""#,
    ] {
        err(bad, "noncharacter");
    }
    err("\"\u{fdd0}\"", "noncharacter");
    err("\"\u{10fffe}\"", "noncharacter");
    err("{\"\u{ffff}\":1}", "noncharacter");
    // Neighbours are ordinary characters.
    ok(r#""\ufdcf\ufdf0\ufffd""#, "\"\u{fdcf}\u{fdf0}\u{fffd}\"");
    ok("\"\u{feff}\"", "\"\u{feff}\"");
}

#[test]
fn control_characters_must_be_escaped_in_input() {
    err("\"a\u{1}b\"", "syntax");
    err("\"a\nb\"", "syntax");
    err("\"a\u{1f}\"", "syntax");
    ok("\"a\u{7f}\"", "\"a\u{7f}\"");
}

// ---- objects ----

#[test]
fn utf16_order_differs_from_utf8_order() {
    // UTF-8 order would be U+20AC, U+FB33, U+1F600. UTF-16: 20AC < D83D < FB33.
    ok(
        r#"{"\ufb33":3,"\ud83d\ude00":2,"\u20ac":1}"#,
        "{\"\u{20ac}\":1,\"\u{1f600}\":2,\"\u{fb33}\":3}",
    );
    // U+FF61 sorts after U+10000 (D800 DC00) in UTF-16 and before it in UTF-8.
    ok(
        r#"{"\uff61":1,"\ud800\udc00":2}"#,
        "{\"\u{10000}\":2,\"\u{ff61}\":1}",
    );
}

#[test]
fn duplicate_keys_refused() {
    err(r#"{"a":1,"a":2}"#, "duplicate_key");
    err(r#"{"a":1,"\u0061":2}"#, "duplicate_key");
    err(r#"{"a":1,"b":{"c":1,"c":1}}"#, "duplicate_key");
    err(r#"[{"x":1,"y":2,"x":3}]"#, "duplicate_key");
    err("{\"\\ud83d\\ude00\":1,\"\u{1f600}\":2}", "duplicate_key");
    ok(r#"{"a":1,"A":2}"#, r#"{"A":2,"a":1}"#);
    ok(r#"{"a":{"a":1}}"#, r#"{"a":{"a":1}}"#);
}

#[test]
fn programmatic_values_checked() {
    let dup = Value::Object(vec![
        ("k".into(), Value::Null),
        ("k".into(), Value::Bool(true)),
    ]);
    assert_eq!(value_jcs(&dup), Err("duplicate_key"));
    let nonchar = Value::String("\u{fffe}".into());
    assert_eq!(value_jcs(&nonchar), Err("noncharacter"));
    let nonchar_key = Value::Object(vec![("\u{fdd0}".into(), Value::Null)]);
    assert_eq!(value_jcs(&nonchar_key), Err("noncharacter"));
    let fine = Value::Object(vec![
        ("b".into(), Value::Null),
        ("a".into(), Value::Array(vec![])),
    ]);
    assert_eq!(value_jcs(&fine), Ok(r#"{"a":[],"b":null}"#.to_string()));
}

// ---- structure ----

fn nested_arrays(n: usize) -> String {
    format!("{}{}", "[".repeat(n), "]".repeat(n))
}

fn nested_objects(n: usize) -> String {
    format!("{}0{}", "{\"a\":".repeat(n), "}".repeat(n))
}

#[test]
fn depth_limit() {
    assert_eq!(MAX_DEPTH, 128);
    let a128 = nested_arrays(128);
    ok(&a128, &a128);
    err(&nested_arrays(129), "depth_exceeded");
    let o128 = nested_objects(128);
    ok(&o128, &o128);
    err(&nested_objects(129), "depth_exceeded");
    // Far deeper than any stack, closed or not: refused, no overflow.
    err(&"[".repeat(1_000_000), "depth_exceeded");
    err(&nested_arrays(200_000), "depth_exceeded");
}

#[test]
fn programmatic_depth_limit() {
    let mut v = Value::Null;
    for _ in 0..128 {
        v = Value::Array(vec![v]);
    }
    assert!(value_jcs(&v).is_ok());
    let deeper = Value::Object(vec![("a".into(), v)]);
    assert_eq!(value_jcs(&deeper), Err("depth_exceeded"));
}

#[test]
fn syntax_errors() {
    for bad in [
        "",
        " ",
        "\n",
        "[",
        "]",
        "{",
        "}",
        "[1,]",
        "[,1]",
        r#"{"a":1,}"#,
        r#"{"a"}"#,
        r#"{"a":}"#,
        r#"{a:1}"#,
        "{'a':1}",
        "tru",
        "nul",
        "fals",
        "True",
        "[1 2]",
        r#""abc"#,
        r#"{"a" 1}"#,
        r#"{1:1}"#,
        "[\"a\"\"b\"]",
        "\u{c}1",
        "\u{a0}1",
        "/*c*/1",
        "//c\n1",
    ] {
        err(bad, "syntax");
    }
}

#[test]
fn trailing_data() {
    err("1 2", "trailing_data");
    err("{} x", "trailing_data");
    err("[]]", "trailing_data");
    err("null\u{0}", "trailing_data");
    err("\"a\"\"b\"", "trailing_data");
    err("{}{}", "trailing_data");
    ok(" \t\r\n1 \t\r\n", "1");
}

#[test]
fn leading_bom() {
    err("\u{feff}1", "leading_bom");
    err("\u{feff}", "leading_bom");
    assert_eq!(jcs_bytes(b"\xef\xbb\xbf{}"), Err("leading_bom"));
    err(" \u{feff}1", "syntax");
}

#[test]
fn literals_and_empties() {
    ok("null", "null");
    ok("true", "true");
    ok("false", "false");
    ok("[ ]", "[]");
    ok("{ }", "{}");
    ok(
        r#"[ null , true , false , "" , [ ] , { } ]"#,
        r#"[null,true,false,"",[],{}]"#,
    );
}

#[test]
fn error_codes_are_stable_and_distinct() {
    let all = [
        (CanonError::LeadingBom, "leading_bom"),
        (CanonError::InvalidUtf8, "invalid_utf8"),
        (CanonError::Syntax, "syntax"),
        (CanonError::TrailingData, "trailing_data"),
        (CanonError::InvalidEscape, "invalid_escape"),
        (CanonError::LoneSurrogate, "lone_surrogate"),
        (CanonError::Noncharacter, "noncharacter"),
        (CanonError::DuplicateKey, "duplicate_key"),
        (CanonError::DepthExceeded, "depth_exceeded"),
        (CanonError::NonFiniteNumber, "non_finite_number"),
        (CanonError::UnsafeInteger, "unsafe_integer"),
    ];
    for (e, code) in all {
        assert_eq!(e.code(), code);
    }
}

#[test]
fn parse_keeps_member_order() -> Result<(), CanonError> {
    let v = canon::parse_strict(br#"{"b":1,"a":[true]}"#);
    let expected = Value::Object(vec![
        ("b".into(), Value::Number(Number::new(1.0)?)),
        ("a".into(), Value::Array(vec![Value::Bool(true)])),
    ]);
    assert_eq!(v, Ok(expected));
    Ok(())
}

// ---- properties ----

fn key_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-c]{0,2}",
        any::<String>(),
        "[\u{80}-\u{ffff}\u{10000}-\u{10ffff}]{1,3}",
    ]
}

fn number_strategy() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<u64>().prop_map(f64::from_bits),
        any::<i32>().prop_map(f64::from),
        (-1e25f64..1e25f64),
        (-1e-5f64..1e-5f64),
    ]
    .prop_filter("finite", |f| f.is_finite())
}

fn value_strategy() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        number_strategy().prop_filter_map("finite", |f| Number::new(f).ok().map(Value::Number)),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(6, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map(key_strategy(), inner, 0..8)
                .prop_map(|m| Value::Object(m.into_iter().rev().collect())),
        ]
    })
}

fn is_noncharacter(c: char) -> bool {
    let u = u32::from(c);
    (0xfdd0..=0xfdef).contains(&u) || (u & 0xfffe) == 0xfffe
}

fn has_noncharacter(v: &Value) -> bool {
    match v {
        Value::String(s) => s.chars().any(is_noncharacter),
        Value::Array(a) => a.iter().any(has_noncharacter),
        Value::Object(o) => o
            .iter()
            .any(|(k, v)| k.chars().any(is_noncharacter) || has_noncharacter(v)),
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    #[test]
    fn idempotent(v in value_strategy()) {
        match canon::to_jcs(&v) {
            Ok(first) => {
                prop_assert!(!has_noncharacter(&v));
                prop_assert_eq!(canon::canonicalize(&first), Ok(first.clone()));
                let reparsed = canon::parse_strict(&first);
                prop_assert!(reparsed.is_ok());
                if let Ok(r) = reparsed {
                    prop_assert_eq!(canon::to_jcs(&r), Ok(first));
                }
            }
            Err(e) => {
                prop_assert_eq!(e, CanonError::Noncharacter);
                prop_assert!(has_noncharacter(&v));
            }
        }
    }

    #[test]
    fn parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = canon::canonicalize(&bytes);
    }

    #[test]
    fn parse_never_panics_on_json_like(s in r#"[\[\]{}",:0-9eE.+\-a-z\\ ]{0,64}"#) {
        if let Ok(out) = canon::canonicalize(s.as_bytes()) {
            prop_assert_eq!(canon::canonicalize(&out), Ok(out.clone()));
        }
    }

    #[test]
    fn mutated_canonical_never_panics(v in value_strategy(), at in any::<usize>(), byte in any::<u8>()) {
        if let Ok(mut out) = canon::to_jcs(&v) {
            let len = out.len();
            if let Some(b) = out.get_mut(at % len.max(1)) {
                *b = byte;
            }
            if let Ok(again) = canon::canonicalize(&out) {
                prop_assert_eq!(canon::canonicalize(&again), Ok(again.clone()));
            }
        }
    }

    #[test]
    fn integers_in_safe_range_round_trip(i in -9_007_199_254_740_991_i64..=9_007_199_254_740_991_i64) {
        let text = i.to_string();
        prop_assert_eq!(jcs(&text), Ok(text.clone()));
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 200_000, ..ProptestConfig::default() })]

    #[test]
    fn numbers_match_ryu_js(bits in any::<u64>()) {
        let f = f64::from_bits(bits);
        if f.is_finite() && f != 0.0 {
            let mut buf = ryu_js::Buffer::new();
            let reference = buf.format_finite(f).to_string();
            prop_assert_eq!(num(f), Ok(reference.clone()));
            // The text parses back to the same double.
            let back = canon::parse_strict(reference.as_bytes());
            prop_assert!(matches!(back, Ok(Value::Number(n)) if n.get().to_bits() == bits));
        }
    }

    /// Doubles with short exact expansions near 17 significant digits, where exact ties
    /// between two shortest candidates (Note 2) actually occur.
    #[test]
    fn tie_prone_numbers_match_ryu_js(m in 1u64..(1u64 << 53), e in -8i32..80, neg in any::<bool>()) {
        let f = (m as f64) * 2f64.powi(e) * if neg { -1.0 } else { 1.0 };
        if f.is_finite() {
            let mut buf = ryu_js::Buffer::new();
            prop_assert_eq!(num(f), Ok(buf.format_finite(f).to_string()));
        }
    }
}
