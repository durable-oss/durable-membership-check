//! Verifies the registry works through the public API, in an external crate.
//!
//! These tests live outside the library so they exercise `dmc` the way a real
//! consumer does. That matters for `inventory`: registration happens through
//! link-time sections, so a filter reachable in a unit test is not proof it is
//! reachable from a separately linked binary.

use dmc::{Params, build, decode, resolve_alias};

#[test]
fn registered_filters_are_visible_from_an_external_crate() {
    let ids = dmc::filter_ids();
    assert!(
        ids.contains(&"bloom_001"),
        "bloom_001 missing from an externally linked binary: {ids:?}"
    );
}

#[test]
fn family_alias_resolves_across_the_crate_boundary() {
    assert_eq!(resolve_alias("bloom"), Some("bloom_001"));
}

#[test]
fn build_and_query_through_the_public_api() {
    let owned: Vec<Vec<u8>> = (0..1_000)
        .map(|i| format!("user-{i}").into_bytes())
        .collect();
    let keys: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

    let filter = build("bloom", &keys, &Params::new(1_000, 0.01)).unwrap();

    for key in &owned {
        assert!(filter.contains(key), "false negative for {key:?}");
    }
}

#[test]
fn encode_decode_round_trips_through_the_registry() {
    let owned: Vec<Vec<u8>> = (0..100).map(|i| format!("k{i}").into_bytes()).collect();
    let keys: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

    let filter = build("bloom", &keys, &Params::new(100, 0.01)).unwrap();
    let mut bytes = Vec::new();
    filter.encode(&mut bytes).unwrap();

    let restored = decode(&bytes).unwrap();

    assert_eq!(restored.id(), filter.id());
    assert_eq!(restored.len(), filter.len());
    for key in &owned {
        assert!(restored.contains(key));
    }
}

#[test]
fn filters_are_shareable_across_threads() {
    // The Filter trait promises Send + Sync; hold it to that.
    let owned: Vec<Vec<u8>> = (0..100).map(|i| format!("k{i}").into_bytes()).collect();
    let keys: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    let filter = build("bloom", &keys, &Params::new(100, 0.01)).unwrap();

    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for key in &owned {
                    assert!(filter.contains(key));
                }
            });
        }
    });
}
