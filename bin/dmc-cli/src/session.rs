//! Command dispatch and the table of retained filters.
//!
//! A [`Session`] owns every filter built during its lifetime, keyed by handle.
//! In `serve` mode one session spans the whole process, so a client builds once
//! and queries a million times without rebuilding. In one-shot mode a session
//! lives for a single command.
//!
//! Dispatch is the same either way: [`Session::handle`] takes a
//! [`Request`](crate::wire::Request) and returns a
//! [`Response`](crate::wire::Response). Every failure becomes a response, never
//! a panic and never a process exit, because the correctness suite drives the
//! error paths deliberately and needs to read the result back.

use std::collections::BTreeMap;

use dmc_core::Filter;

use crate::hex;
use crate::wire::{BuiltInfo, CapabilitiesInfo, FilterInfo, Payload, Request, Response};

/// Filters retained across commands, plus the handle counter.
#[derive(Default)]
pub struct Session {
    /// Live filters by handle.
    filters: BTreeMap<u64, Box<dyn Filter>>,

    /// Next handle to hand out.
    ///
    /// Monotonic and never reused, so a client holding a stale handle after a
    /// `drop` gets a clean "unknown handle" rather than someone else's filter.
    next_handle: u64,
}

impl Session {
    /// Creates an empty session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
            next_handle: 1,
        }
    }

    /// Executes one command.
    ///
    /// Returns `None` for `quit`, which is the only command that ends a serve
    /// loop. Every other outcome, including every error, is a `Some(response)`.
    pub fn handle(&mut self, request: Request) -> Option<Response> {
        Some(match request {
            Request::List => Self::list(),
            Request::Describe { name } => Self::describe(&name),
            Request::Build {
                name,
                keys_hex,
                params,
            } => {
                let key_count = keys_hex.len();
                match hex::decode_all(&keys_hex) {
                    Ok(owned) => {
                        let borrowed: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                        let resolved = params.resolve(key_count);

                        match dmc_core::build(&name, &borrowed, &resolved) {
                            Ok(filter) => self.retain(filter),
                            Err(err) => Response::from_error(&err),
                        }
                    }
                    Err(why) => Response::client_error("bad_hex", why),
                }
            }
            Request::Contains { handle, keys_hex } => match hex::decode_all(&keys_hex) {
                Ok(probes) => match self.filters.get(&handle) {
                    Some(filter) => Response::Ok(Payload::Answers {
                        ok: true,
                        answers: probes.iter().map(|k| filter.contains(k)).collect(),
                    }),
                    None => Self::unknown_handle(handle),
                },
                Err(why) => Response::client_error("bad_hex", why),
            },
            Request::Info { handle } => match self.filters.get(&handle) {
                Some(filter) => Response::Ok(Payload::Info {
                    ok: true,
                    info: BuiltInfo::of(filter.as_ref()),
                }),
                None => Self::unknown_handle(handle),
            },
            Request::Encode { handle } => match self.filters.get(&handle) {
                Some(filter) => {
                    let mut bytes = Vec::new();
                    match filter.encode(&mut bytes) {
                        Ok(()) => Response::Ok(Payload::Encoded {
                            ok: true,
                            bytes_hex: hex::encode(&bytes),
                        }),
                        Err(err) => Response::from_error(&err),
                    }
                }
                None => Self::unknown_handle(handle),
            },
            Request::Decode { bytes_hex } => match hex::decode(&bytes_hex) {
                Ok(bytes) => match dmc_core::decode(&bytes) {
                    Ok(filter) => self.retain(filter),
                    Err(err) => Response::from_error(&err),
                },
                Err(why) => Response::client_error("bad_hex", why),
            },
            Request::Union { left, right } => self.combine(left, right, Combine::Union),
            Request::Intersect { left, right } => self.combine(left, right, Combine::Intersect),
            Request::EstimatedLen { handle } => match self.concrete(handle) {
                Ok(filter) => Response::Ok(Payload::Estimate {
                    ok: true,
                    estimated_len: filter.estimated_len(),
                }),
                Err(response) => response,
            },
            Request::Similarity { left, right } => self.similarity(left, right),
            Request::Drop { handle } => {
                if self.filters.remove(&handle).is_some() {
                    Response::Ok(Payload::Done { ok: true })
                } else {
                    Self::unknown_handle(handle)
                }
            }
            Request::Quit => return None,
        })
    }

    /// Recovers the concrete filter type behind a handle.
    ///
    /// The set operations live on `Bloom001` rather than on the `Filter` trait,
    /// which is object-safe and deliberately narrow. With no `Any` supertrait
    /// there is no downcast available, so the round trip through the encoded
    /// form is how a boxed filter becomes a concrete one.
    ///
    /// That is not merely a workaround: encode-then-decode is exactly what a
    /// caller sharding filters across processes does, so routing the set
    /// operations through it exercises the path a real deployment uses.
    ///
    /// Returns the error response directly, since every caller forwards it.
    // The `Err` is a `Response`, which clippy flags as a large error type. It
    // is the same value every command in this file returns by value already,
    // and boxing it here would only make each caller unbox before returning.
    #[allow(clippy::result_large_err)]
    fn concrete(&self, handle: u64) -> core::result::Result<dmc_bloom::Bloom001, Response> {
        let filter = self
            .filters
            .get(&handle)
            .ok_or_else(|| Self::unknown_handle(handle))?;

        // Set operations are implemented for Bloom filters only. Another
        // family reaching here is a client error, not a filter error, and the
        // message points at the capability that would have said so.
        if filter.id() != "bloom_001" {
            return Err(Response::client_error(
                "unsupported_operation",
                format!(
                    "set operations are implemented for bloom_001; handle {handle} holds {}. \
                     Check `supports_union` in `describe`",
                    filter.id()
                ),
            ));
        }

        let mut bytes = Vec::new();
        filter
            .encode(&mut bytes)
            .map_err(|err| Response::from_error(&err))?;

        dmc_bloom::Bloom001::decode(&bytes).map_err(|err| Response::from_error(&err))
    }

    /// Reports both similarity measures for a pair of retained filters.
    ///
    /// Jaccard and both containment directions come back in one reply. All
    /// three read the same pair of bit arrays, so computing them together costs
    /// barely more than computing one, and a client comparing two sets almost
    /// always wants the asymmetric pair alongside the symmetric score.
    fn similarity(&self, left: u64, right: u64) -> Response {
        let a = match self.concrete(left) {
            Ok(filter) => filter,
            Err(response) => return response,
        };
        let b = match self.concrete(right) {
            Ok(filter) => filter,
            Err(response) => return response,
        };

        // All three come from the same pair, so one incompatibility fails the
        // whole reply rather than half of it.
        match (
            a.jaccard_similarity(&b),
            a.containment_in(&b),
            b.containment_in(&a),
        ) {
            (Ok(jaccard), Ok(left_in_right), Ok(right_in_left)) => {
                Response::Ok(Payload::Similarity {
                    ok: true,
                    jaccard,
                    containment_left_in_right: left_in_right,
                    containment_right_in_left: right_in_left,
                })
            }
            (Err(err), _, _) | (_, Err(err), _) | (_, _, Err(err)) => Response::from_error(&err),
        }
    }

    /// Applies a set operation to two retained filters and retains the result.
    fn combine(&mut self, left: u64, right: u64, how: Combine) -> Response {
        let a = match self.concrete(left) {
            Ok(filter) => filter,
            Err(response) => return response,
        };
        let b = match self.concrete(right) {
            Ok(filter) => filter,
            Err(response) => return response,
        };

        let combined = match how {
            Combine::Union => a.union(&b),
            Combine::Intersect => a.intersect(&b),
        };

        match combined {
            Ok(filter) => self.retain(Box::new(filter)),
            Err(err) => Response::from_error(&err),
        }
    }

    /// Stores a freshly built filter and reports its handle and accounting.
    fn retain(&mut self, filter: Box<dyn Filter>) -> Response {
        let handle = self.next_handle;
        self.next_handle += 1;

        let info = BuiltInfo::of(filter.as_ref());
        self.filters.insert(handle, filter);

        Response::Ok(Payload::Built {
            ok: true,
            handle,
            info,
        })
    }

    /// Reports a handle that names no live filter.
    fn unknown_handle(handle: u64) -> Response {
        Response::client_error("unknown_handle", format!("no filter with handle {handle}"))
    }

    /// Lists every linked implementation, sorted by id.
    fn list() -> Response {
        Response::Ok(Payload::List {
            ok: true,
            filters: dmc_core::registrations()
                .map(describe_registration)
                .collect(),
        })
    }

    /// Reports one implementation, resolved by exact id or family alias.
    fn describe(name: &str) -> Response {
        match dmc_core::find(name) {
            Some(reg) => Response::Ok(Payload::Describe {
                ok: true,
                filter: describe_registration(reg),
            }),
            None => Response::from_error(&dmc_core::Error::UnknownFilter {
                requested: name.to_string(),
            }),
        }
    }
}

/// Which set operation [`Session::combine`] should apply.
#[derive(Debug, Clone, Copy)]
enum Combine {
    /// Keys held by either operand.
    Union,

    /// Keys held by both operands.
    Intersect,
}

/// Flattens a registration into its wire form.
fn describe_registration(reg: &'static dmc_core::registry::Registration) -> FilterInfo {
    FilterInfo {
        id: reg.id.to_string(),
        family: reg.family.to_string(),
        version: reg.version,
        description: reg.description.to_string(),
        family_resolves_to: dmc_core::resolve_alias(reg.family).map(ToString::to_string),
        capabilities: CapabilitiesInfo::from(&reg.capabilities),
    }
}

#[cfg(test)]
// Every `other => panic!(...)` below is a test assertion: the match names the
// one variant the call should produce, and anything else is a failure. Clippy
// reads that as a wildcard over a single variant and suggests naming it, which
// would make each assertion silently pass a future variant instead of failing.
#[allow(clippy::match_wildcard_for_single_variants)]
mod tests {
    use super::*;
    use crate::wire::ParamsSpec;

    /// Builds a filter over the given hex keys and returns its handle.
    fn build(session: &mut Session, keys_hex: Vec<String>) -> u64 {
        let response = session
            .handle(Request::Build {
                name: "bloom".to_string(),
                keys_hex,
                params: ParamsSpec::default(),
            })
            .expect("build is not quit");

        match response {
            Response::Ok(Payload::Built { handle, .. }) => handle,
            other => panic!("expected a built filter, got {other:?}"),
        }
    }

    #[test]
    fn build_then_query_finds_every_member() {
        let mut session = Session::new();
        let keys = vec![hex::encode(b"alice"), hex::encode(b"bob")];
        let handle = build(&mut session, keys.clone());

        let response = session
            .handle(Request::Contains {
                handle,
                keys_hex: keys,
            })
            .unwrap();

        match response {
            Response::Ok(Payload::Answers { answers, .. }) => {
                assert_eq!(answers, vec![true, true]);
            }
            other => panic!("expected answers, got {other:?}"),
        }
    }

    #[test]
    fn handles_are_not_reused_after_a_drop() {
        // A stale handle must report itself rather than aliasing a later
        // filter, or a client bug becomes a silently wrong test result.
        let mut session = Session::new();
        let first = build(&mut session, vec![hex::encode(b"a")]);

        session.handle(Request::Drop { handle: first }).unwrap();
        let second = build(&mut session, vec![hex::encode(b"b")]);

        assert_ne!(first, second, "handle was reused");

        let response = session.handle(Request::Info { handle: first }).unwrap();
        assert!(matches!(response, Response::Err { .. }));
    }

    #[test]
    fn unknown_handle_is_an_error_not_a_panic() {
        let mut session = Session::new();
        let response = session.handle(Request::Info { handle: 999 }).unwrap();

        match response {
            Response::Err { kind, .. } => assert_eq!(kind, "unknown_handle"),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_hex_is_reported_as_a_client_error() {
        let mut session = Session::new();
        let response = session
            .handle(Request::Build {
                name: "bloom".to_string(),
                keys_hex: vec!["nothex".to_string()],
                params: ParamsSpec::default(),
            })
            .unwrap();

        match response {
            Response::Err { kind, .. } => assert_eq!(kind, "bad_hex"),
            other => panic!("expected a hex error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_filter_name_reports_the_library_error() {
        let mut session = Session::new();
        let response = session
            .handle(Request::Build {
                name: "no-such-filter".to_string(),
                keys_hex: vec![],
                params: ParamsSpec::default(),
            })
            .unwrap();

        match response {
            Response::Err { kind, .. } => assert_eq!(kind, "unknown_filter"),
            other => panic!("expected unknown_filter, got {other:?}"),
        }
    }

    #[test]
    fn invalid_params_reach_the_client_as_invalid_parameter() {
        let mut session = Session::new();
        let response = session
            .handle(Request::Build {
                name: "bloom".to_string(),
                keys_hex: vec![hex::encode(b"a")],
                params: ParamsSpec {
                    expected_items: Some(1),
                    false_positive_rate: Some(1.5),
                    seed: None,
                },
            })
            .unwrap();

        match response {
            Response::Err { kind, .. } => assert_eq!(kind, "invalid_parameter"),
            other => panic!("expected invalid_parameter, got {other:?}"),
        }
    }

    #[test]
    fn encode_then_decode_yields_an_equivalent_filter() {
        let mut session = Session::new();
        let keys = vec![hex::encode(b"alice"), hex::encode(b"bob")];
        let handle = build(&mut session, keys.clone());

        let encoded = match session.handle(Request::Encode { handle }).unwrap() {
            Response::Ok(Payload::Encoded { bytes_hex, .. }) => bytes_hex,
            other => panic!("expected an encoding, got {other:?}"),
        };

        let restored = match session
            .handle(Request::Decode { bytes_hex: encoded })
            .unwrap()
        {
            Response::Ok(Payload::Built { handle, .. }) => handle,
            other => panic!("expected a decoded filter, got {other:?}"),
        };

        let response = session
            .handle(Request::Contains {
                handle: restored,
                keys_hex: keys,
            })
            .unwrap();

        match response {
            Response::Ok(Payload::Answers { answers, .. }) => {
                assert!(
                    answers.iter().all(|&a| a),
                    "member lost across a round trip"
                );
            }
            other => panic!("expected answers, got {other:?}"),
        }
    }

    #[test]
    fn describe_reports_declared_capabilities() {
        let mut session = Session::new();
        let response = session
            .handle(Request::Describe {
                name: "bloom".to_string(),
            })
            .unwrap();

        match response {
            Response::Ok(Payload::Describe { filter, .. }) => {
                assert_eq!(filter.id, "bloom_001");
                assert_eq!(filter.family, "bloom");
                assert!(filter.capabilities.tolerates_duplicate_keys);
                assert!(!filter.capabilities.supports_deletion);
                assert_eq!(filter.family_resolves_to.as_deref(), Some("bloom_001"));
            }
            other => panic!("expected a description, got {other:?}"),
        }
    }

    #[test]
    fn describe_rejects_an_unknown_name() {
        let mut session = Session::new();
        let response = session
            .handle(Request::Describe {
                name: "nope".to_string(),
            })
            .unwrap();

        match response {
            Response::Err { kind, .. } => assert_eq!(kind, "unknown_filter"),
            other => panic!("expected unknown_filter, got {other:?}"),
        }
    }

    #[test]
    fn quit_ends_the_session() {
        let mut session = Session::new();
        assert!(session.handle(Request::Quit).is_none());
    }

    #[test]
    fn decoding_garbage_is_an_error_not_a_panic() {
        let mut session = Session::new();

        for bytes_hex in ["", "00", "6e6f2d6e756c"] {
            let response = session
                .handle(Request::Decode {
                    bytes_hex: bytes_hex.to_string(),
                })
                .unwrap();

            assert!(
                matches!(response, Response::Err { .. }),
                "decoding {bytes_hex:?} should have failed"
            );
        }
    }
}
