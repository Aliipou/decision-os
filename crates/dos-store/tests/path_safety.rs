//! Token ids are never paths: hostile ids create nothing outside the store directory,
//! the marker name is a pure function of the id, and distinct ids never share a marker.
mod common;
use common::*;
use dos_store::{FileSpentStore, MAX_TOKEN_ID_BYTES, Spend, SpentStore};
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::path::Path;

fn names(dir: &Path) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let mut out = BTreeSet::new();
    for e in std::fs::read_dir(dir)? {
        out.insert(e?.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}

fn is_marker_name(n: &str) -> bool {
    n.len() == 64 && n.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Spend `id` in a fresh store under a sandbox; check the sandbox and the store dir.
fn check_id(id: &str) -> TestResult {
    let sandbox = tempfile::tempdir()?;
    let dir = sandbox.path().join("store");
    let store = FileSpentStore::open(&dir).map_err(se)?;
    assert_eq!(store.try_spend(id, 1_000), Ok(Spend::First), "{id:?}");
    assert_eq!(store.try_spend(id, 1_000), Ok(Spend::AlreadySpent), "{id:?}");
    let marker = FileSpentStore::marker_file_name(id).map_err(se)?;
    assert!(is_marker_name(&marker), "{marker}");
    assert_eq!(FileSpentStore::marker_file_name(id).map_err(se)?, marker);
    assert_eq!(
        names(sandbox.path())?,
        BTreeSet::from(["store".to_string()]),
        "something escaped the store dir for {id:?}"
    );
    let inside = names(&dir)?;
    let expected = BTreeSet::from([FileSpentStore::LOCK_FILE_NAME.to_string(), marker]);
    assert_eq!(inside, expected, "{id:?}");
    Ok(())
}

#[test]
fn hostile_ids_stay_inside() -> TestResult {
    let long = "../".repeat(MAX_TOKEN_ID_BYTES / 3);
    for id in [
        "../../x",
        "../../../../../../../../etc/passwd",
        "a/b",
        "/abs",
        "C:\\x",
        "C:x",
        "\\\\?\\C:\\x",
        "..",
        ".",
        ".dos-spent.lock",
        "NUL",
        "con",
        "a\0b",
        "\0",
        "tok\n",
        "日本語/トークン",
        "\u{202e}gpj.exe",
        long.as_str(),
    ] {
        check_id(id)?;
    }
    Ok(())
}

#[test]
fn marker_name_is_domain_tagged_not_plain_sha256() -> TestResult {
    // sha256("tok-1"), the oracle's marker name: Rust must not reuse it (domain tag).
    let plain = "c6b6a5d5c4b2e7d5f2b8b5c0b2c5e0f1d3a8b6c7e9f0a1b2c3d4e5f6a7b8c9d0";
    let ours = FileSpentStore::marker_file_name("tok-1").map_err(se)?;
    assert!(is_marker_name(&ours));
    assert_ne!(ours, plain);
    assert_eq!(
        FileSpentStore::marker_file_name(""),
        Err(dos_store::StoreError::InvalidInput)
    );
    Ok(())
}

fn id_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 1..80)
        .prop_map(|v| v.into_iter().collect::<String>())
        .prop_filter("within byte limit", |s| s.len() <= MAX_TOKEN_ID_BYTES)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_ids_stay_inside(id in id_strategy()) {
        prop_assert!(check_id(&id).is_ok(), "{:?}", check_id(&id));
    }

    #[test]
    fn distinct_ids_never_collide(a in id_strategy(), b in id_strategy()) {
        let ma = FileSpentStore::marker_file_name(&a);
        let mb = FileSpentStore::marker_file_name(&b);
        prop_assert!(ma.is_ok() && mb.is_ok());
        prop_assert_eq!(a == b, ma == mb);
    }
}

#[test]
fn many_distinct_ids_all_first_in_one_store() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = FileSpentStore::open(tmp.path().join("s")).map_err(se)?;
    // Ids the oracle's old sanitizer collapsed (`a:b` vs `a_b`), plus near neighbours.
    let ids = ["ipc:bot:a:b", "ipc:bot:a_b", "ipc/bot/a/b", "ipc\\bot\\a\\b", "A", "a", "a ", " a"];
    for id in ids {
        assert_eq!(store.try_spend(id, 1), Ok(Spend::First), "{id:?}");
    }
    let markers: BTreeSet<_> = ids
        .iter()
        .map(|id| FileSpentStore::marker_file_name(id))
        .collect::<Result<_, _>>()
        .map_err(se)?;
    assert_eq!(markers.len(), ids.len());
    Ok(())
}
