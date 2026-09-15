//! `constraints::memory`, `docs/spec/memory.md` §2, §3.3 and §8: the three
//! memory artifacts validate and keep the construction-time rules at two
//! heights, their layouts, obligations and read sets are the document's, the
//! committed fixtures are the constructors' bytes, and `check_memory` refuses
//! each thing §8 names. S14 acceptance 9 is here; acceptance 12's negative
//! control is the unit test in `src/memory.rs`, which reaches the private
//! construction.

use constants::{address_space, challenge_slot, lookup_channel};
use constraints::memory::{
    check_memory, frame, frame_artifact, image_window_artifact, zero_window_artifact, CYCLE,
    FIELD_MASK, FIELD_READ_TS, FRAME_DELTA, FRAME_NAMES, FRAME_SPACE,
};
use constraints::{
    CachedEntry, CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, LookupExpr, Padding,
    PolyAddress, ProducingEntry, Relation, ScratchSlot, VirtualKind,
    COEFFICIENT_ENCODING_CANONICAL_LE, FORMAT_VERSION,
};
use field::Fr;
use test_support::{sha256, to_hex};

const FRAME_SHA256: &str = "a18112c678db49eed95654e2b38c8d0e78f60be5b8c543e91ac897952f205df5";
const IMAGE_WINDOW_SHA256: &str =
    "39a8655d430ed5c031e4f27075662fe92a9a1274cd23dc300ae5e2e82df67ecc";
const ZERO_WINDOW_SHA256: &str = "f08dde677a70c8a15cc7b67b35806e6ee5d9afff9cb703586f21426baa51ec1c";

type Constructor = fn(u32) -> CircuitArtifact;

const CONSTRUCTORS: [(&str, Constructor); 3] = [
    ("frame", frame_artifact),
    ("image window", image_window_artifact),
    ("zero window", zero_window_artifact),
];

/// Each committed fixture is pinned, then held to its constructor's bytes at
/// `trace_vars` 22. The constructors are the only definition; the pin is what
/// makes a changed circuit a deliberate refresh.
#[test]
fn the_fixtures_are_the_constructors_bytes() {
    let fixtures: [(&str, &str, Constructor); 3] = [
        ("memory_frame.bin", FRAME_SHA256, frame_artifact),
        (
            "image_window.bin",
            IMAGE_WINDOW_SHA256,
            image_window_artifact,
        ),
        ("zero_window.bin", ZERO_WINDOW_SHA256, zero_window_artifact),
    ];
    for (name, digest, construct) in fixtures {
        let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        assert_eq!(
            to_hex(&sha256(&bytes)),
            digest,
            "{name} changed. Regenerate it with `cargo run -p kat-gen -- memory`, review the \
             diff, then update the pinned digest deliberately."
        );
        assert_eq!(bytes, construct(22).to_bytes(), "{name}");
        assert_eq!(
            CircuitArtifact::from_bytes(&bytes),
            Ok(construct(22)),
            "{name}"
        );
    }
}

#[test]
fn every_constructor_validates_and_keeps_the_memory_rules_at_12_and_22() {
    for (label, construct) in CONSTRUCTORS {
        for trace_vars in [12, 22] {
            let a = construct(trace_vars);
            assert_eq!(a.validate(), Ok(()), "{label} at {trace_vars}");
            assert_eq!(check_memory(&a), Ok(()), "{label} at {trace_vars}");
            assert_eq!(a.trace_vars, trace_vars, "{label}");
        }
    }
}

fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

/// The shape both sides share: two output roots at the top, named, and a
/// padding row of zeros whose zero row is valid.
#[test]
fn every_artifact_has_two_named_roots_and_an_all_zero_padding_row() {
    for (label, construct) in CONSTRUCTORS {
        let a = construct(12);
        let n = a.depth() as u32;
        assert_eq!(a.outputs, vec![inner(n, 0), inner(n, 1)], "{label}");
        let names: Vec<&str> = a.scratch[a.scratch.len() - 2..]
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, ["read_root", "write_root"], "{label}");
        assert_eq!(
            a.padding.row,
            vec![Fr::ZERO; a.committed().len()],
            "{label}"
        );
        assert!(a.padding.zero_row_valid, "{label}");
        // Halving from the first layer of width 2 down to one row.
        let halving = a.layers.iter().filter(|l| l.halving).count() as u32;
        assert_eq!(halving, 12, "{label}");
        assert!(a.layers.iter().all(|l| l.cached.is_empty()), "{label}");
    }
}

/// §2.1 and §2.4: the 41 memory columns, the 11 witness columns, 16 leaves in
/// the order `R_0..R_7, W_0..W_7`, three row-wise lists `16 → 8 → 4 → 2`, and
/// the enforcing gates by name. The AS and Δ tables are written here again.
#[test]
fn the_frame_layout_is_the_documents() {
    let a = frame_artifact(12);
    let mut memory = vec!["cycle".to_string()];
    for q in ["pc", "rs1", "rs2", "arg1", "arg2", "load", "ram", "rd"] {
        for f in ["mask", "addr", "read_ts", "read_value", "write_value"] {
            memory.push(format!("{q}_{f}"));
        }
    }
    assert_eq!(a.memory, memory);
    let witness = [
        "pc_gap_hi",
        "rs1_gap_hi",
        "rs2_gap_hi",
        "arg1_gap_hi",
        "arg2_gap_hi",
        "load_gap_hi",
        "ram_gap_hi",
        "rd_gap_hi",
        "rd_inv",
        "rd_is_zero",
        "rd_selected",
    ];
    assert_eq!(a.witness, witness);
    assert!(a.setup.is_empty() && a.virtuals.is_empty());
    assert_eq!(frame(0, FIELD_MASK), PolyAddress::Memory(1));
    assert_eq!(frame(7, 4), PolyAddress::Memory(40));
    assert_eq!(CYCLE, PolyAddress::Memory(0));
    assert_eq!(FRAME_DELTA, [0, 1, 2, 2, 2, 2, 3, 3]);
    let (pc, reg, ram) = (address_space::PC, address_space::REG, address_space::RAM);
    assert_eq!(FRAME_SPACE, [pc, reg, reg, reg, reg, ram, ram, reg]);

    let leaves: Vec<&str> = a.scratch[..16].iter().map(|s| s.name.as_str()).collect();
    let mut expected: Vec<String> = FRAME_NAMES.iter().map(|q| format!("read_{q}")).collect();
    expected.extend(FRAME_NAMES.iter().map(|q| format!("write_{q}")));
    assert_eq!(leaves, expected);
    let widths: Vec<u32> = a.layers[..4].iter().map(|l| l.width).collect();
    assert_eq!(widths, [16, 8, 4, 2]);
    assert_eq!(a.depth(), 4 + 12);

    let enforcing: Vec<&str> = a.layers[0]
        .enforcing
        .iter()
        .map(|e| a.relations[e.relation as usize].name.as_str())
        .collect();
    assert_eq!(
        enforcing,
        [
            "pc_mask_boolean",
            "rs1_mask_boolean",
            "rs2_mask_boolean",
            "arg1_mask_boolean",
            "arg2_mask_boolean",
            "load_mask_boolean",
            "ram_mask_boolean",
            "rd_mask_boolean",
            "rs1_writes_back",
            "rs2_writes_back",
            "arg1_writes_back",
            "arg2_writes_back",
            "load_writes_back",
            "rd_is_zero_inverse",
            "rd_is_zero_at_nonzero",
            "rd_is_zero_boolean",
            "rd_write_masked",
        ]
    );
}

/// §2.4: 16 obligations, two per query in query order, `gap_hi_<q>` then
/// `gap_lo_<q>`, on the timestamp channel under the query's mask; the high
/// chunk reads `W[q]`, and the low chunk's constant is `Δ − 1` — `−1` for the
/// pc query.
#[test]
fn the_frame_carries_two_gap_obligations_per_query() {
    let a = frame_artifact(12);
    assert_eq!(a.lookups.len(), 16);
    let minus = |v: u64| Coeff::Literal(-Fr::from_u64(v));
    let lit = |v: u64| Coeff::Literal(Fr::from_u64(v));
    for (q, name) in FRAME_NAMES.iter().enumerate() {
        let hi = PolyAddress::Witness(q as u32);
        let selector = frame(q, FIELD_MASK);
        let expected = [
            LookupExpr {
                name: format!("gap_hi_{name}"),
                channel: lookup_channel::TIMESTAMP,
                selector,
                tuple: vec![GateDef::Linear {
                    terms: vec![(lit(1), hi)],
                    constant: lit(0),
                }],
            },
            LookupExpr {
                name: format!("gap_lo_{name}"),
                channel: lookup_channel::TIMESTAMP,
                selector,
                tuple: vec![GateDef::Linear {
                    terms: vec![
                        (lit(4), CYCLE),
                        (minus(1), frame(q, FIELD_READ_TS)),
                        (minus(1 << 19), hi),
                    ],
                    constant: Coeff::Literal(Fr::from_u64(FRAME_DELTA[q]) - Fr::ONE),
                }],
            },
        ];
        assert_eq!(a.lookups[2 * q..2 * q + 2], expected, "{name}");
    }
    let GateDef::Linear { constant, .. } = &a.lookups[1].tuple[0] else {
        panic!("gap_lo_pc is Linear");
    };
    assert_eq!(*constant, minus(1), "gap_lo_pc's constant is −1");
}

/// Every base address a gate or an obligation of the artifact reads, once each,
/// ascending.
fn read_set(a: &CircuitArtifact) -> Vec<PolyAddress> {
    let list = &a.layers[0];
    let mut read: Vec<PolyAddress> = Vec::new();
    for gate in list.producing.iter().map(|e| &e.gate) {
        read.extend(gate.operands());
    }
    for gate in list.enforcing.iter().map(|e| &e.gate) {
        read.extend(gate.operands());
    }
    for l in &a.lookups {
        read.push(l.selector);
        read.extend(l.tuple.iter().flat_map(|g| g.operands()));
    }
    read.sort();
    read.dedup();
    read
}

/// §8's pinned read sets: `ZERO_WINDOWS` reads exactly `M[0]`, `M[1]`,
/// `V[row]`; `INIT_TEARDOWN` those and `S[0]`, `V[ram_live]`; the frame reads
/// no `S` and no `V`.
#[test]
fn the_read_sets_are_pinned() {
    let (m0, m1, s0) = (
        PolyAddress::Memory(0),
        PolyAddress::Memory(1),
        PolyAddress::Setup(0),
    );
    let row = PolyAddress::Virtual(VirtualKind::RowIndex);
    let live = PolyAddress::Virtual(VirtualKind::RamLive);
    for trace_vars in [12, 22] {
        assert_eq!(
            read_set(&zero_window_artifact(trace_vars)),
            [m0, m1, row],
            "{trace_vars}"
        );
        assert_eq!(
            read_set(&image_window_artifact(trace_vars)),
            [m0, m1, s0, row, live],
            "{trace_vars}"
        );
        let frame = read_set(&frame_artifact(trace_vars));
        assert!(
            frame
                .iter()
                .all(|op| matches!(op, PolyAddress::Memory(_) | PolyAddress::Witness(_))),
            "{frame:?}"
        );
    }
    let zero = zero_window_artifact(12);
    assert_eq!(zero.memory, ["teardown_ts", "teardown_value"]);
    assert!(zero.witness.is_empty() && zero.setup.is_empty() && zero.lookups.is_empty());
    let image = image_window_artifact(12);
    assert_eq!(image.memory, ["teardown_ts", "teardown_value"]);
    assert_eq!(image.setup, ["init_value"]);
    assert!(image.witness.is_empty() && image.lookups.is_empty());
    for a in [&zero, &image] {
        assert!(a.layers[0].enforcing.is_empty());
        let leaves: Vec<&str> = a.scratch[..2].iter().map(|s| s.name.as_str()).collect();
        assert_eq!(leaves, ["teardown", "init"]);
    }
}

/// `gate` with every `from` operand replaced by `to`.
fn swap(gate: &GateDef, from: PolyAddress, to: PolyAddress) -> GateDef {
    let at = |x: PolyAddress| if x == from { to } else { x };
    let GateDef::Quadratic {
        constant,
        linear,
        products,
    } = gate
    else {
        panic!("a leaf is a Quadratic");
    };
    GateDef::Quadratic {
        constant: *constant,
        linear: linear.iter().map(|(c, x)| (*c, at(*x))).collect(),
        products: products
            .iter()
            .map(|(c, y, z)| (*c, at(*y), at(*z)))
            .collect(),
    }
}

/// S14 acceptance 9: the `rs1` read leaf's address fed from `W[0]` instead of
/// `M[7]`, in its gate and its relation alike. The artifact is still a lawful
/// circuit — `validate` accepts it — and `check_memory` refuses it by
/// provenance, naming the leaf.
///
/// Kills a provenance check that ignores `W` operands or list 0.
#[test]
fn a_tuple_fed_from_a_witness_column_is_refused() {
    let mut a = frame_artifact(12);
    let (from, to) = (frame(1, 1), PolyAddress::Witness(0));
    let entry = &mut a.layers[0].producing[1];
    entry.gate = swap(&entry.gate, from, to);
    let r = entry.relation as usize;
    a.relations[r].gate = swap(&a.relations[r].gate, from, to);
    assert_eq!(a.relations[r].name, "define_read_rs1");
    assert_eq!(a.validate(), Ok(()));
    let e = check_memory(&a).unwrap_err();
    assert!(
        e.starts_with("memory provenance: `define_read_rs1` in gate list 0"),
        "{e}"
    );
}

/// §8's forward-provenance counterexample, built whole:
///
/// ```text
/// base    M[0] a   W[0] w                      2 rows
/// list 0  L{1}[0] tuple = α_addr·a + γ_M        names a slot, reads no W
///         L{1}[1] copy  = w                     reads W, names no slot
/// list 1  L{2}[0] mixed = tuple·copy            both, through its operands only
/// ```
///
/// No gate of list 0 is refused; the product in layer 2 is. Then the same
/// product as an enforcing gate of list 1, `mixed = 0`, beside a lawful
/// producing `squared = tuple·tuple`: refused too, and there rule 1 is the only
/// rule that can see it — its coefficient is a literal. The controls copy `a`
/// instead of `w` and pass. Kills a provenance check that reads a gate's own
/// coefficients and base operands without carrying flags up, or that skips
/// enforcing gates.
#[test]
fn a_product_of_a_tuple_and_a_witness_copy_two_layers_up_is_refused() {
    let circuit = |copied: PolyAddress, enforced: bool| {
        let (a, lit1) = (PolyAddress::Memory(0), Coeff::Literal(Fr::ONE));
        let tuple = GateDef::Linear {
            terms: vec![(Coeff::Challenge(challenge_slot::MEM_ALPHA_ADDR), a)],
            constant: Coeff::Challenge(challenge_slot::MEM_GAMMA),
        };
        let copy = GateDef::Linear {
            terms: vec![(lit1, copied)],
            constant: Coeff::Literal(Fr::ZERO),
        };
        let product = |left, right| GateDef::Product {
            coeff: lit1,
            left,
            right,
        };
        let relation = |name: &str, output, gate| Relation {
            name: name.into(),
            output,
            gate,
        };
        let entry = |relation, output, gate| ProducingEntry {
            relation,
            output,
            gate,
        };
        let slot = |name: &str, address| ScratchSlot {
            name: name.into(),
            address,
        };
        let (s0, s1) = (PolyAddress::Scratch(0), PolyAddress::Scratch(1));
        let mut relations = vec![
            relation("define_tuple", Some(0), tuple.clone()),
            relation("define_copy", Some(1), copy.clone()),
        ];
        let mut scratch = vec![slot("tuple", inner(1, 0)), slot("copy", inner(1, 1))];
        let mut list1 = LayerSpec {
            halving: false,
            num_vars: 1,
            width: 1,
            cached: vec![],
            producing: vec![],
            enforcing: vec![],
        };
        if enforced {
            list1.producing = vec![entry(2, inner(2, 0), product(inner(1, 0), inner(1, 0)))];
            list1.enforcing = vec![EnforcingEntry {
                relation: 3,
                gate: product(inner(1, 0), inner(1, 1)),
            }];
            relations.push(relation("define_squared", Some(2), product(s0, s0)));
            relations.push(relation("mixed", None, product(s0, s1)));
            scratch.push(slot("squared", inner(2, 0)));
        } else {
            list1.producing = vec![entry(2, inner(2, 0), product(inner(1, 0), inner(1, 1)))];
            relations.push(relation("define_mixed", Some(2), product(s0, s1)));
            scratch.push(slot("mixed", inner(2, 0)));
        }
        let artifact = CircuitArtifact {
            format_version: FORMAT_VERSION,
            coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
            trace_vars: 1,
            memory: vec!["a".into()],
            witness: vec!["w".into()],
            setup: vec![],
            virtuals: vec![],
            layers: vec![
                LayerSpec {
                    halving: false,
                    num_vars: 1,
                    width: 2,
                    cached: vec![],
                    producing: vec![
                        entry(0, inner(1, 0), tuple.clone()),
                        entry(1, inner(1, 1), copy.clone()),
                    ],
                    enforcing: vec![],
                },
                list1,
            ],
            relations,
            lookups: vec![],
            scratch,
            outputs: vec![inner(2, 0)],
            padding: Padding {
                row: vec![Fr::ZERO; 2],
                zero_row_valid: true,
            },
        };
        assert_eq!(artifact.validate(), Ok(()));
        artifact
    };
    for (enforced, name) in [(false, "define_mixed"), (true, "mixed")] {
        assert_eq!(
            check_memory(&circuit(PolyAddress::Witness(0), enforced)),
            Err(format!(
                "memory provenance: `{name}` in gate list 1 names a global memory slot and reads a \
                 W column"
            ))
        );
        assert_eq!(
            check_memory(&circuit(PolyAddress::Memory(0), enforced)),
            Ok(())
        );
    }
}

/// One gate list over `M[0] a` and `W[0] w`, 2 rows: `cached`, then one
/// producing gate `gate` writing the top column `out`, whose relation is
/// `flat`, the same polynomial with the cached entries substituted.
fn cached_circuit(cached: Vec<(&str, GateDef)>, gate: GateDef, flat: GateDef) -> CircuitArtifact {
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars: 1,
        memory: vec!["a".into()],
        witness: vec!["w".into()],
        setup: vec![],
        virtuals: vec![],
        layers: vec![LayerSpec {
            halving: false,
            num_vars: 1,
            width: 1,
            cached: cached
                .into_iter()
                .enumerate()
                .map(|(j, (name, gate))| CachedEntry {
                    name: name.into(),
                    address: PolyAddress::Cached {
                        layer: 0,
                        offset: j as u32,
                    },
                    gate,
                })
                .collect(),
            producing: vec![ProducingEntry {
                relation: 0,
                output: inner(1, 0),
                gate,
            }],
            enforcing: vec![],
        }],
        relations: vec![Relation {
            name: "define_out".into(),
            output: Some(0),
            gate: flat,
        }],
        lookups: vec![],
        scratch: vec![ScratchSlot {
            name: "out".into(),
            address: inner(1, 0),
        }],
        outputs: vec![inner(1, 0)],
        padding: Padding {
            row: vec![Fr::ZERO; 2],
            zero_row_valid: true,
        },
    };
    assert_eq!(artifact.validate(), Ok(()));
    artifact
}

/// Cached entries under §8, substituted as `validate` substitutes them, each
/// circuit lawful:
///
/// ```text
/// C[0] tuple = γ_M + α_addr·a,  C[1] copy = w,  out = tuple·copy
///     refused at `out`: the slot and the W column meet only through the cache
/// C[0] slot_over_w = α_addr·w,  out = slot_over_w
///     refused at the cached entry itself, which is checked before `out`
/// C[0] copy_a = a,  out = γ_M·copy_a
///     refused by the slot rule: a slot over a cached entry
/// ```
///
/// Kills a check that gives a cached operand no flags or drops its W flag, that
/// does not check cached entries themselves, or that admits a slot over one.
#[test]
fn cached_entries_are_held_to_the_memory_rules() {
    let (a, w) = (PolyAddress::Memory(0), PolyAddress::Witness(0));
    let c = |offset| PolyAddress::Cached { layer: 0, offset };
    let (gamma, alpha) = (
        Coeff::Challenge(challenge_slot::MEM_GAMMA),
        Coeff::Challenge(challenge_slot::MEM_ALPHA_ADDR),
    );
    let (one, zero) = (Coeff::Literal(Fr::ONE), Coeff::Literal(Fr::ZERO));
    let linear = |terms, constant| GateDef::Linear { terms, constant };

    let through_the_cache = cached_circuit(
        vec![
            ("tuple", linear(vec![(alpha, a)], gamma)),
            ("copy", linear(vec![(one, w)], zero)),
        ],
        GateDef::Product {
            coeff: one,
            left: c(0),
            right: c(1),
        },
        GateDef::Quadratic {
            constant: zero,
            linear: vec![(gamma, w)],
            products: vec![(alpha, a, w)],
        },
    );
    assert_eq!(
        check_memory(&through_the_cache),
        Err(
            "memory provenance: `define_out` in gate list 0 names a global memory slot and reads \
             a W column"
                .to_string()
        )
    );

    let bad_entry = cached_circuit(
        vec![("slot_over_w", linear(vec![(alpha, w)], zero))],
        linear(vec![(one, c(0))], zero),
        linear(vec![(alpha, w)], zero),
    );
    assert_eq!(
        check_memory(&bad_entry),
        Err(
            "memory provenance: `slot_over_w` in gate list 0 names a global memory slot and reads \
             a W column"
                .to_string()
        )
    );

    let slot_over_cache = cached_circuit(
        vec![("copy_a", linear(vec![(one, a)], zero))],
        linear(vec![(gamma, c(0))], zero),
        linear(vec![(gamma, a)], zero),
    );
    assert_eq!(
        check_memory(&slot_over_cache),
        Err(
            "memory slot operands: `define_out` in gate list 0 carries a global memory slot and \
             reads C{0}[0]; only M, S and V columns may be weighted by one"
                .to_string()
        )
    );
}

/// The frame with one query's booleanity gate removed — its enforcing entry
/// and its relation, every later relation index shifted down — is still a
/// lawful circuit, and `check_memory` refuses that query's leaves' mask as
/// unconstrained. Tried on `pc_mask_boolean`, whose mask no other gate reads,
/// and on `rd_mask_boolean`, whose mask `rd_is_zero_inverse` still reads.
/// Kills a mask rule that is not checked, or that accepts any enforcing gate
/// on the mask.
#[test]
fn a_frame_missing_a_booleanity_gate_is_refused() {
    for (query, mask) in [("pc", "M[1]"), ("rd", "M[36]")] {
        let mut a = frame_artifact(12);
        let r = a
            .relations
            .iter()
            .position(|rel| rel.name == format!("{query}_mask_boolean"))
            .expect("the frame names it") as u32;
        a.layers[0].enforcing.retain(|e| e.relation != r);
        a.relations.remove(r as usize);
        for list in a.layers.iter_mut() {
            for e in list.producing.iter_mut() {
                e.relation -= (e.relation > r) as u32;
            }
            for e in list.enforcing.iter_mut() {
                e.relation -= (e.relation > r) as u32;
            }
        }
        assert_eq!(a.validate(), Ok(()), "{query}");
        assert_eq!(
            check_memory(&a),
            Err(format!(
                "unconstrained mask: leaf `define_read_{query}` masks with {mask}, and gate list \
                 0 has no enforcing gate {mask} − {mask}·{mask}"
            ))
        );
    }
}

/// `INIT_TEARDOWN` with its teardown leaf's mask `V[ram_live]` swapped, in the
/// gate and its relation, for `S[0]` — a committed column no booleanity gate
/// holds — and for `V[row]`, which is not 0 or 1 on the cube. Both still lawful
/// circuits, both refused naming the leaf and the mask. Kills a mask rule that
/// covers `M` alone, or that exempts every virtual column.
#[test]
fn a_window_leaf_masked_by_a_setup_column_or_the_row_index_is_refused() {
    let live = PolyAddress::Virtual(VirtualKind::RamLive);
    let cases = [
        (
            PolyAddress::Setup(0),
            "unconstrained mask: leaf `define_teardown` masks with S[0], and gate list 0 has no \
             enforcing gate S[0] − S[0]·S[0]",
        ),
        (
            PolyAddress::Virtual(VirtualKind::RowIndex),
            "unconstrained mask: leaf `define_teardown` masks with V[row], which is not 0 or 1 on \
             every row",
        ),
    ];
    for (mask, expected) in cases {
        let mut a = image_window_artifact(12);
        let entry = &mut a.layers[0].producing[0];
        entry.gate = swap(&entry.gate, live, mask);
        let r = entry.relation as usize;
        a.relations[r].gate = swap(&a.relations[r].gate, live, mask);
        assert_eq!(a.validate(), Ok(()), "{mask}");
        assert_eq!(check_memory(&a), Err(expected.to_string()), "{mask}");
    }
}

/// §8's third rule: the frame's first row-wise product weighted by `γ_M` reads
/// two inner columns that come from `M` alone, so provenance passes; the slot
/// over an inner column is refused. Kills a slot rule that only looks at list
/// 0 or only at `W`.
#[test]
fn a_global_slot_over_an_inner_column_is_refused() {
    let mut a = frame_artifact(4);
    let gamma = Coeff::Challenge(challenge_slot::MEM_GAMMA);
    let entry = &mut a.layers[1].producing[0];
    let GateDef::Product { coeff, .. } = &mut entry.gate else {
        panic!("list 1 multiplies");
    };
    *coeff = gamma;
    let r = entry.relation as usize;
    let GateDef::Product { coeff, .. } = &mut a.relations[r].gate else {
        panic!("its relation multiplies");
    };
    *coeff = gamma;
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(
        check_memory(&a),
        Err(
            "memory slot operands: `define_read_2_0` in gate list 1 carries a global memory slot \
             and reads L{1}[0]; only M, S and V columns may be weighted by one"
                .to_string()
        )
    );
}
