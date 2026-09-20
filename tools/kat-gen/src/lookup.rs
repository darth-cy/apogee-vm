//! The `lookup` group: S15's combined toy circuit, written through
//! `constraints::memory::frame_with_channels_artifact`.
//!
//! This function is the toy's only definition. The prover and verifier never
//! see it: they read the committed file. It is not an oracle — it is this
//! code's output — so what the file pins is the artifact's bytes, and CI
//! regenerates and diffs them. The independent descriptions it is held to are
//! `crates/checker`'s native channel sums and its discharge cross-check.
//!
//! ```text
//! frame     JUMP_BRANCH_SLT's four queries (docs/spec/memory.md §2), w = 4:
//!           M[0] cycle then pc, rs1, rs2, rd; W[0..4] the gap chunks, W[4..7]
//!           the x0 gadget; 8 gap obligations on the timestamp channel
//!
//! range16   word, word_hi: the §7 convention, two obligations under the row's
//!           pc mask
//!
//! generic   and_a, and_b, and_c, and_on   -> the AND byte table
//!           sign_h, sign_s, sign_on       -> U16GetSign
//!           S[0..3] the packed table: key, v1, v2
//!
//! decoder   the row's pc is the frame's own M column; six more columns claim
//!           next_pc, rs1, rs2, rd, imm and the packed mask, and twelve bits,
//!           each boolean, recompose that mask
//!           S[3..10] JUMP_BRANCH_SLT's table in lookup-tuple order
//!
//! last      one multiplicity column per channel, last in the subtree
//! ```

use constants::{family, lookup_channel};
use constraints::lookup::{range_table, ChannelSpec};
use constraints::memory::{
    frame_queries, frame_with_channels_artifact, FamilySpec, FIELD_MASK, FIELD_READ_VALUE,
};
use constraints::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};
use field::Fr;
use program::lookup_tables::{AND_BASE, GENERIC_WIDTH, SIGN_BASE};

use crate::write_bytes;

const FIXTURE: &str = "crates/constraints/tests/vectors/lookup_toy.bin";

/// The toy's height, and the smallest a real execution family can have.
///
/// The timestamp channel's table is `[0, 2^19)`, and a table of `2^n` rows
/// holds at most `2^n` values, so 19 variables is the floor
/// (`docs/spec/lookup.md` §3). A Mercury opening needs an **even** variable
/// count, and `constants::family::HEIGHT_MENU` has only even entries, so the
/// floor rounds up to 20. The generic channel's real tables need 131,105
/// rows, which 20 also covers, and `crates/program` can decode a table at 20
/// because it is on the menu.
pub const TRACE_VARS: u32 = 20;

/// The family the toy is a circuit for: its frame, its cycles and its decoded
/// table. `JUMP_BRANCH_SLT` is the narrowest frame carrying `rs1`, `rs2` and
/// `rd` — four queries — so it holds S14's future-read attack (two `x0` reads
/// with their timestamps swapped) and the x0 gadget, at half the leaves of the
/// widest frame. Its lookup tuple is seven columns, the widest any channel
/// carries, and its packed mask has twelve one-hot bits.
pub const FAMILY: u32 = family::JUMP_BRANCH_SLT;

/// The decoder table's width, `program::lookup_tuple(FAMILY).len()`.
pub const DECODER_WIDTH: usize = 7;

/// How many bits the decoder's packed mask is split into,
/// `constants::extra_mask`'s count for [`FAMILY`].
pub const MASK_BITS: usize = 12;

pub fn generate() {
    write_bytes(FIXTURE, &toy().to_bytes());
}

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(i)
}

fn s(i: u32) -> PolyAddress {
    PolyAddress::Setup(i)
}

/// `Σ c_i·x_i + c_0`, the one shape a lookup expression has.
fn linear(terms: &[(Coeff, PolyAddress)], constant: Coeff) -> GateDef {
    GateDef::Linear {
        terms: terms.to_vec(),
        constant,
    }
}

/// `x` alone: a tuple position above 0 weights its one column by 1 and carries
/// no constant, because `β^j·c` is one `Coeff` only at `c = 1`.
fn column(x: PolyAddress) -> GateDef {
    linear(&[(lit(1), x)], lit(0))
}

/// `x − x·x = 0`.
fn booleanity(x: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), x)],
        products: vec![(Coeff::Literal(Fr::MINUS_ONE), x, x)],
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The frame's `M` address for `slot`, field `field`.
fn frame(slot: usize, field: u32) -> PolyAddress {
    constraints::memory::frame(slot, field)
}

/// The frame's own witness columns: one `<q>_gap_hi` per query, then the x0
/// gadget's three. Everything below follows them.
const FRAME_WITNESS: u32 = 4 + 3;
const WORD: u32 = FRAME_WITNESS;
const WORD_HI: u32 = FRAME_WITNESS + 1;
const AND_A: u32 = FRAME_WITNESS + 2;
const AND_B: u32 = FRAME_WITNESS + 3;
const AND_C: u32 = FRAME_WITNESS + 4;
const AND_ON: u32 = FRAME_WITNESS + 5;
const SIGN_H: u32 = FRAME_WITNESS + 6;
const SIGN_S: u32 = FRAME_WITNESS + 7;
const SIGN_ON: u32 = FRAME_WITNESS + 8;
const DECODED: u32 = FRAME_WITNESS + 9;
const KIND: u32 = DECODED + 6;
const MULT: u32 = KIND + MASK_BITS as u32;

/// The setup layout: the generic table, then the decoder's.
const DECODER_TABLE: u32 = GENERIC_WIDTH as u32;

/// S15's combined toy, over `TRACE_VARS` variables.
pub fn toy() -> CircuitArtifact {
    let pc_mask = frame(0, FIELD_MASK);
    let mut witness = names(&["word", "word_hi", "and_a", "and_b", "and_c", "and_on"]);
    witness.extend(names(&["sign_h", "sign_s", "sign_on"]));
    witness.extend(names(&[
        "decoded_next_pc",
        "decoded_rs1",
        "decoded_rs2",
        "decoded_rd",
        "decoded_imm",
        "decoded_mask",
    ]));
    witness.extend((0..MASK_BITS).map(|k| format!("kind_{k}")));
    witness.extend(
        lookup_channel::NAMES
            .iter()
            .map(|name| format!("mult_{name}")),
    );

    let mut setup = names(&["generic_key", "generic_v1", "generic_v2"]);
    setup.extend(names(&[
        "table_pc",
        "table_next_pc",
        "table_rs1",
        "table_rs2",
        "table_rd",
        "table_imm",
        "table_extra_mask",
    ]));

    // `word` is a 32-bit value under the range convention of
    // `docs/spec/memory.md` §7: one witnessed high halfword and two
    // obligations, both under the row's mask, and no gate.
    let halfword = Coeff::Literal(-Fr::from_u64(1 << 16));
    let lookups = vec![
        LookupExpr {
            name: "word_hi_range".into(),
            channel: lookup_channel::RANGE16,
            selector: pc_mask,
            tuple: vec![column(w(WORD_HI))],
        },
        LookupExpr {
            name: "word_lo_range".into(),
            channel: lookup_channel::RANGE16,
            selector: pc_mask,
            tuple: vec![linear(&[(lit(1), w(WORD)), (halfword, w(WORD_HI))], lit(0))],
        },
        // The gated key is `and_on·(a + AND_BASE + 1)`, the offset of one being
        // the gating's, so a switched-off row lands on the ZeroEntry and no
        // real entry does.
        LookupExpr {
            name: "and_lookup".into(),
            channel: lookup_channel::GENERIC,
            selector: w(AND_ON),
            tuple: vec![
                linear(&[(lit(1), w(AND_A))], lit(AND_BASE as u64)),
                column(w(AND_B)),
                column(w(AND_C)),
            ],
        },
        // `U16GetSign` is the narrower table, zero-padded to the channel's
        // width; its key base keeps its range disjoint from the AND table's.
        LookupExpr {
            name: "sign_lookup".into(),
            channel: lookup_channel::GENERIC,
            selector: w(SIGN_ON),
            tuple: vec![
                linear(&[(lit(1), w(SIGN_H))], lit(SIGN_BASE as u64)),
                column(w(SIGN_S)),
                linear(&[], lit(0)),
            ],
        },
        // The row's pc is the frame's own column, so the decoder binds the
        // cycle to the table rather than a copy of it to a copy of the table.
        // `next_pc` is claimed, not read from the frame: the frame's
        // `pc_write_value` is the pc the row really wrote, and the table's
        // `next_pc` is the fall-through, which an exit row's `HALT_PC` and
        // every taken branch differ from (`docs/spec/memory.md` §5). Tying the
        // two is S16's. The selector is the pc mask — the row's liveness — and
        // a switched-off row looks up the MINUS_ONE padding tuple S11's height
        // rule guarantees is in the table.
        LookupExpr {
            name: "decode_row".into(),
            channel: lookup_channel::DECODER,
            selector: pc_mask,
            tuple: vec![
                column(frame(0, FIELD_READ_VALUE)),
                column(w(DECODED)),
                column(w(DECODED + 1)),
                column(w(DECODED + 2)),
                column(w(DECODED + 3)),
                column(w(DECODED + 4)),
                column(w(DECODED + 5)),
            ],
        },
    ];

    let mut enforcing = vec![
        ("and_on_boolean".to_string(), booleanity(w(AND_ON))),
        ("sign_on_boolean".to_string(), booleanity(w(SIGN_ON))),
    ];
    for k in 0..MASK_BITS {
        enforcing.push((format!("kind_{k}_boolean"), booleanity(w(KIND + k as u32))));
    }
    // The packed mask's bits: booleanity is each bit's, and one-hotness is the
    // table's domain and nothing else.
    let mut terms: Vec<(Coeff, PolyAddress)> = (0..MASK_BITS)
        .map(|k| (lit(1 << k), w(KIND + k as u32)))
        .collect();
    terms.push((Coeff::Literal(Fr::MINUS_ONE), w(DECODED + 5)));
    enforcing.push(("decoded_mask_bits".to_string(), linear(&terms, lit(0))));

    let channels = vec![
        channel(lookup_channel::TIMESTAMP, 0),
        channel(lookup_channel::RANGE16, 1),
        channel(lookup_channel::GENERIC, 2),
        channel(lookup_channel::DECODER, 3),
    ];

    frame_with_channels_artifact(
        frame_queries(FAMILY),
        TRACE_VARS,
        FamilySpec {
            witness,
            setup,
            virtuals: vec![
                (VirtualKind::Range19, "range19".into()),
                (VirtualKind::Range16, "range16".into()),
            ],
            enforcing,
            lookups,
            channels,
        },
    )
}

/// Channel `channel`'s spec: its table, and its multiplicity column at
/// `MULT + at`.
fn channel(channel: u32, at: u32) -> ChannelSpec {
    let table = match range_table(channel) {
        Some(kind) => vec![PolyAddress::Virtual(kind)],
        None if channel == lookup_channel::GENERIC => (0..GENERIC_WIDTH as u32).map(s).collect(),
        None => (0..DECODER_WIDTH as u32)
            .map(|j| s(DECODER_TABLE + j))
            .collect(),
    };
    ChannelSpec {
        channel,
        table,
        multiplicity: w(MULT + at),
    }
}

#[cfg(test)]
mod tests {
    use test_support::{sha256, to_hex};

    /// The committed fixture is the bytes [`super::toy`] writes today.
    ///
    /// Every other suite reads the *file* — `crates/checker/tests/logup.rs`
    /// fills its columns and proves it, `crates/constraints/tests/lookup.rs`
    /// checks its laws and its discharge — so without this the constructor
    /// above is covered by nothing but CI's regenerate-and-diff step, and a
    /// change to it that a developer regenerates over is a change no test sees.
    /// `crates/constraints/tests/memory.rs`' `the_fixtures_are_the_constructors_bytes`
    /// is the same assertion for S14's frames.
    #[test]
    fn the_fixture_is_the_constructors_bytes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(super::FIXTURE);
        let committed =
            std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let built = super::toy().to_bytes();
        assert_eq!(
            to_hex(&sha256(&built)),
            to_hex(&sha256(&committed)),
            "the toy's constructor and `{}` have diverged; `cargo run -p kat-gen -- lookup` \
             writes the constructor's bytes",
            super::FIXTURE
        );
        assert_eq!(built, committed);
    }
}
