//! The keccak-f[1600] delegation circuit, gate by gate.
//!
//! `docs/spec/delegation.md` is what this suite restates: the frame, the
//! anchor's two tuples, the round block, and the two frame-pointer checks that
//! must be in the emitted artifact rather than in a comment. The permutation
//! itself is checked the only way a circuit can be — by running its forward
//! pass and comparing the words it writes with `emulator::keccak_f`, which
//! `crates/emulator/tests/keccak.rs` holds to `tiny-keccak`.
//!
//! Every negative control corrupts one cell of an otherwise honest witness and
//! names the relation that must catch it. A circuit whose gates are right and
//! whose *addressing* is wrong passes no negative control, which is why each
//! one names its gate.

use constants::{challenge_slot, delegation, guest_memory, keccak as k, memory as mem};
use constraints::keccak;
use constraints::{CircuitArtifact, PolyAddress};
use field::Fr;
use gkr::{BaseLayer, ExternalChallenges, LayerValues};
use poly::{MultilinearPoly, PolyBacking};

/// Four rows: enough for two live invocations and two padding rows, and small
/// enough that the forward pass of a 354,762-column circuit is 45 MB.
const VARS: u32 = 2;
const ROWS: usize = 1 << VARS;

/// One invocation as a witness builder sees it.
#[derive(Clone, Copy)]
struct Invocation {
    cycle: u64,
    base: u32,
    state: [u64; k::LANES],
}

fn lanes_to_words(lanes: &[u64; k::LANES]) -> [u32; k::FRAME_WORDS] {
    core::array::from_fn(|j| (lanes[j / 2] >> (32 * (j % 2))) as u32)
}

fn column(values: Vec<u64>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(
        values.into_iter().map(Fr::from_u64).collect(),
    ))
}

/// The base layer for `live` invocations, padded to `ROWS` with zero rows.
///
/// Every cell follows `docs/spec/delegation.md`: the frame word at `base + 4j`
/// read at the previous cycle's slot 3 and written at this one's, the state's
/// bits, each gap's 38 bits, and the frame pointer's two decompositions.
fn witness(live: &[Invocation]) -> Vec<(PolyAddress, MultilinearPoly)> {
    assert!(live.len() <= ROWS);
    let at = |r: usize, f: &dyn Fn(&Invocation) -> u64| -> u64 {
        live.get(r).map_or(0, f)
    };
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let mut push = |address: PolyAddress, f: &dyn Fn(&Invocation) -> u64| {
        out.push((address, column((0..ROWS).map(|r| at(r, f)).collect())));
    };
    push(keccak::CYCLE, &|i| i.cycle);
    push(keccak::LIVE, &|_| 1);
    push(keccak::BASE, &|i| i.base as u64);
    push(keccak::ANCHOR_VALUE, &|_| 0);
    for j in 0..k::FRAME_WORDS {
        push(keccak::word(j, keccak::WORD_ADDR), &move |i| {
            i.base as u64 + 4 * j as u64
        });
        // Read at the previous cycle's last slot, so the gap is 0.
        push(keccak::word(j, keccak::WORD_READ_TS), &move |i| {
            mem::TS_STEP * i.cycle - 1
        });
        push(keccak::word(j, keccak::WORD_READ_VALUE), &move |i| {
            lanes_to_words(&i.state)[j] as u64
        });
        push(keccak::word(j, keccak::WORD_WRITE_VALUE), &move |i| {
            let mut lanes = i.state;
            emulator::keccak_f(&mut lanes);
            lanes_to_words(&lanes)[j] as u64
        });
    }
    for b in 0..k::STATE_BITS {
        push(keccak::in_bit(b), &move |i| {
            (i.state[b / k::LANE_BITS] >> (b % k::LANE_BITS)) & 1
        });
    }
    for j in 0..k::FRAME_WORDS {
        for bit in 0..mem::TS_BITS as usize {
            push(keccak::gap_bit(j, bit), &move |i| {
                let gap = mem::TS_STEP * i.cycle + delegation::FRAME_DELTA
                    - (mem::TS_STEP * i.cycle - 1)
                    - 1;
                (gap >> bit) & 1
            });
        }
    }
    // Wrapping, not saturating: a base the frame rules refuse has no honest
    // decomposition, and these tests are about the gate that says so — a panic
    // here would hide it.
    for bit in 0..29 {
        push(keccak::base_low_bit(bit), &move |i| {
            let q = (i.base as u64).wrapping_sub(guest_memory::RAM_ORIGIN as u64) / 4;
            (q >> bit) & 1
        });
    }
    for bit in 0..31 {
        push(keccak::base_room_bit(bit), &move |i| {
            let room = ((1u64 << 31) - k::STATE_BYTES as u64).wrapping_sub(i.base as u64);
            (room >> bit) & 1
        });
    }
    out
}

fn challenges() -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, value) in [
        (challenge_slot::MEM_GAMMA, 3u64),
        (challenge_slot::MEM_ALPHA_ADDR, 5),
        (challenge_slot::MEM_ALPHA_TS, 7),
        (challenge_slot::MEM_ALPHA_VAL, 11),
    ] {
        ch.insert(slot, Fr::from_u64(value));
    }
    ch
}

fn forward(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> LayerValues {
    gkr::forward(a, &BaseLayer::new(columns), &challenges())
}

/// Replace one cell of one column, returning the corrupted base.
fn corrupt(
    mut columns: Vec<(PolyAddress, MultilinearPoly)>,
    address: PolyAddress,
    row: usize,
    value: Fr,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let slot = columns
        .iter_mut()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("{address} is not a committed column"));
    let mut values: Vec<Fr> = (0..ROWS).map(|r| slot.1.get(r)).collect();
    values[row] = value;
    slot.1 = MultilinearPoly::new(PolyBacking::Fr(values));
    columns
}

/// Two honest invocations: one on the zero state, one pseudo-random.
fn honest() -> Vec<Invocation> {
    let mut rng = test_support::Rng::new(20210521);
    vec![
        Invocation {
            cycle: 7,
            base: guest_memory::RAM_ORIGIN + 4 * 1000,
            state: [0; k::LANES],
        },
        Invocation {
            cycle: 11,
            base: guest_memory::RAM_ORIGIN + 4 * 4096,
            state: core::array::from_fn(|_| rng.next_u64()),
        },
    ]
}

/// The relation `self_check` must name, or a panic saying it passed.
fn refusal(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> String {
    let values = forward(a, columns);
    match gkr::self_check(a, &values, &challenges()) {
        Ok(()) => panic!("the corrupted witness satisfies every gate"),
        Err(e) => e.relation,
    }
}

// ---------------------------------------------------------------------------
// The circuit keeps every rule
// ---------------------------------------------------------------------------

#[test]
fn the_circuit_keeps_every_rule() {
    let a = keccak::artifact(VARS);
    a.validate().expect("the circuit is a circuit");
    checker::check_laws(&a).expect("the standalone validators agree");
    checker::check_padding(&a).expect("the padding contract holds");
    checker::check_padding_identity(&a).expect("a padding row is the product's identity");
    constraints::memory::check_memory(&a).expect("the memory provenance rules hold");
    constraints::lookup::check_discharge(&a, &keccak::channels())
        .expect("a circuit with no channel discharges nothing");
    assert!(
        keccak::channels().is_empty(),
        "the delegation family carries no lookup channel"
    );
}

#[test]
fn the_shape_is_the_documents() {
    let a = keccak::artifact(VARS);
    assert_eq!(a.memory.len(), 4 + 4 * k::FRAME_WORDS);
    assert_eq!(
        a.witness.len(),
        k::STATE_BITS + (mem::TS_BITS as usize) * k::FRAME_WORDS + 29 + 31
    );
    assert!(a.setup.is_empty());
    assert!(a.virtuals.is_empty());
    assert!(a.lookups.is_empty());
    // 24 round blocks of 7 layers, the output list, and the halving phase.
    assert_eq!(a.layers.len(), 24 * 7 + 1 + VARS as usize);
    assert_eq!(a.outputs.len(), 2);
    let root = |i: usize| {
        a.scratch
            .iter()
            .find(|s| s.address == a.outputs[i])
            .map(|s| s.name.as_str())
            .unwrap_or("?")
    };
    assert_eq!(root(mem::READ_ROOT), "read_root");
    assert_eq!(root(mem::WRITE_ROOT), "write_root");
}

#[test]
fn the_frame_checks_are_in_the_artifact() {
    // S21 must-be-exact 4: counted on the emitted artifact, never on the
    // vector handed in, and by name where a name is the point.
    let a = keccak::artifact(VARS);
    let enforcing: Vec<&str> = a
        .relations
        .iter()
        .filter(|r| r.output.is_none())
        .map(|r| r.name.as_str())
        .collect();
    for name in ["base_aligned", "base_in_window", "live_boolean"] {
        assert!(enforcing.contains(&name), "the artifact has no `{name}`");
    }
    for (prefix, want) in [
        ("addr_w", k::FRAME_WORDS),
        ("gap_w", k::FRAME_WORDS),
        ("input_w", k::FRAME_WORDS),
        ("output_w", k::FRAME_WORDS),
        ("in_bit", k::STATE_BITS),
        ("gap0_", mem::TS_BITS as usize),
    ] {
        let got = enforcing.iter().filter(|n| n.starts_with(prefix)).count();
        assert_eq!(got, want, "{got} `{prefix}` gates, not {want}");
    }
    // Every committed column that is a bit carries a booleanity gate: the
    // state's 1600, every gap's 38 and the frame pointer's 60.
    let booleans = enforcing.iter().filter(|n| n.ends_with("_boolean")).count();
    assert_eq!(
        booleans,
        1 + k::STATE_BITS + (mem::TS_BITS as usize) * k::FRAME_WORDS + 29 + 31
    );
    assert!(
        !a.relations.iter().any(|r| r.name.contains("assume")),
        "no gate is an assumption"
    );
}

// ---------------------------------------------------------------------------
// The permutation
// ---------------------------------------------------------------------------

#[test]
fn the_forward_pass_is_keccak_f() {
    // Acceptance 2: the circuit's written words are the reference
    // permutation's, on the zero-state KAT and on a pseudo-random state, with
    // padding rows beside them.
    let a = keccak::artifact(VARS);
    let values = forward(&a, witness(&honest()));
    gkr::self_check(&a, &values, &challenges()).expect("every gate holds on the honest witness");
}

#[test]
fn a_corrupted_output_word_is_caught() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    for j in [0usize, 17, k::FRAME_WORDS - 1] {
        let broken = corrupt(
            columns.clone(),
            keccak::word(j, keccak::WORD_WRITE_VALUE),
            1,
            Fr::from_u64(7),
        );
        assert_eq!(refusal(&a, broken), format!("output_w{j}"));
    }
}

#[test]
fn a_corrupted_state_bit_is_caught() {
    // A flipped input bit breaks the word it recomposes, which is the gate
    // that names it; flipping the word with it moves the failure to the
    // permutation's output instead.
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let broken = corrupt(columns.clone(), keccak::in_bit(0), 1, Fr::ZERO);
    assert_eq!(refusal(&a, broken), "input_w0");

    let words = lanes_to_words(&honest()[1].state);
    let flipped = corrupt(
        columns,
        keccak::word(0, keccak::WORD_READ_VALUE),
        1,
        Fr::from_u64(words[0] as u64 ^ 1),
    );
    let flipped = corrupt(flipped, keccak::in_bit(0), 1, Fr::from_u64(1 ^ (words[0] as u64 & 1)));
    assert_eq!(refusal(&a, flipped), "output_w0");
}

#[test]
fn a_corrupted_bit_is_not_a_bit() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let broken = corrupt(columns, keccak::in_bit(5), 1, Fr::from_u64(2));
    assert_eq!(refusal(&a, broken), "in_bit5_boolean");
}

// ---------------------------------------------------------------------------
// The frame
// ---------------------------------------------------------------------------

#[test]
fn a_misaligned_frame_pointer_is_unprovable() {
    // Acceptance 7. The pointer's low two bits have no witness at all: `base`
    // is `RAM_ORIGIN + 4·q` with `q` a sum of 29 booleans, so a base that is
    // not word-aligned has no decomposition and the gate that asks for one is
    // what refuses it.
    let a = keccak::artifact(VARS);
    let mut live = honest();
    live[1].base += 2;
    assert_eq!(refusal(&a, witness(&live)), "base_aligned");
}

#[test]
fn a_frame_below_ram_is_unprovable() {
    let a = keccak::artifact(VARS);
    let mut live = honest();
    live[1].base = guest_memory::RAM_ORIGIN - 4;
    assert_eq!(refusal(&a, witness(&live)), "base_aligned");
}

#[test]
fn a_frame_over_the_top_of_ram_is_unprovable() {
    // The last frame word would be at `2^31`, which no RAM window covers.
    let a = keccak::artifact(VARS);
    let mut live = honest();
    live[1].base = (1u32 << 31) - k::STATE_BYTES as u32 + 4;
    assert_eq!(refusal(&a, witness(&live)), "base_in_window");
}

#[test]
fn a_frame_word_off_its_offset_is_caught() {
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let broken = corrupt(
        columns,
        keccak::word(9, keccak::WORD_ADDR),
        1,
        Fr::from_u64(guest_memory::RAM_ORIGIN as u64),
    );
    assert_eq!(refusal(&a, broken), "addr_w9");
}

#[test]
fn a_read_that_does_not_precede_its_write_is_caught() {
    // The gap is a sum of 38 booleans, so it is non-negative by construction:
    // a read at or after the write has no decomposition.
    let a = keccak::artifact(VARS);
    let columns = witness(&honest());
    let broken = corrupt(
        columns,
        keccak::word(3, keccak::WORD_READ_TS),
        1,
        Fr::from_u64(mem::TS_STEP * 11 + delegation::FRAME_DELTA),
    );
    assert_eq!(refusal(&a, broken), "gap_w3");
}

#[test]
fn a_padding_row_carries_no_invocation() {
    // Every leaf is 1 on a padding row, so the row contributes the product's
    // identity to both trees — and the permutation still runs there, which is
    // exactly why the output gate is gated on `live`.
    let a = keccak::artifact(VARS);
    let values = forward(&a, witness(&honest()));
    let top = values.layers.last().expect("a top layer");
    // The top layer has one row: the two roots.
    assert_eq!(top.len(), 2);
    // Row 2 and 3 are padding; their leaves are the identity.
    let leaves = &values.layers[0];
    for row in 2..ROWS {
        for leaf in leaves.iter().take(128) {
            assert_eq!(
                leaf.get(row),
                Fr::ONE,
                "a padding row's leaf is not the product's identity"
            );
        }
    }
}
