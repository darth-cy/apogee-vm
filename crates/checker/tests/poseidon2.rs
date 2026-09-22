//! The Poseidon2 delegation circuit, round by round.
//!
//! `docs/spec/delegation.md` §12 is what this suite restates: the 24-word
//! frame, the anchor's two tuples, the three sub-layers a round takes, and the
//! canonicity of every lane that crosses the frame. The permutation itself is
//! checked the only way a circuit can be — by running its forward pass over a
//! witness whose written lanes come from `transcript::poseidon2_permute`, and
//! asserting the circuit accepts it. That is acceptance 2: a circuit whose
//! rounds, constants or matrices differed by one term would refuse an honest
//! witness.

use constants::poseidon2 as p2;
use constants::{challenge_slot, guest_memory, memory as mem};
use constraints::poseidon2;
use constraints::{CircuitArtifact, PolyAddress};
use field::Fr;
use gkr::{BaseLayer, ExternalChallenges, LayerValues};
use poly::{MultilinearPoly, PolyBacking};

/// Four rows: room for live invocations and padding both. The permutation's
/// forward pass is 2,020 inner columns, so this is 0.8 MB.
const VARS: u32 = 2;
const ROWS: usize = 1 << VARS;

/// One invocation as a witness builder sees it.
#[derive(Clone, Copy)]
struct Invocation {
    cycle: u64,
    base: u32,
    state: [Fr; p2::WIDTH],
}

impl Invocation {
    /// The state the permutation leaves, from the transcript crate itself.
    fn out(&self) -> [Fr; p2::WIDTH] {
        let mut state = self.state;
        transcript::poseidon2_permute(&mut state);
        state
    }

    /// The frame's 24 read values and 24 write values: the lanes in, then the
    /// lanes out, each canonical little-endian.
    fn frame(&self) -> ([u32; p2::FRAME_WORDS], [u32; p2::FRAME_WORDS]) {
        let words = |lanes: [Fr; p2::WIDTH]| -> [u32; p2::FRAME_WORDS] {
            core::array::from_fn(|j| {
                let bytes = lanes[j / p2::WORDS_PER_LANE].to_bytes();
                let k = j % p2::WORDS_PER_LANE;
                let mut word = [0u8; 4];
                word.copy_from_slice(&bytes[4 * k..4 * k + 4]);
                u32::from_le_bytes(word)
            })
        };
        (words(self.state), words(self.out()))
    }

    /// Value `v`'s eight words: `0..3` the lanes in, `3..6` the lanes out.
    fn value_words(&self, v: usize) -> [u32; 8] {
        let (read, write) = self.frame();
        let lane = v % p2::WIDTH;
        let src = if v < p2::WIDTH { read } else { write };
        core::array::from_fn(|k| src[p2::WORDS_PER_LANE * lane + k])
    }
}

fn modulus() -> [u64; 8] {
    let mut out = [0u64; 8];
    for (i, limb) in constants::FR_MODULUS.iter().enumerate() {
        out[2 * i] = limb & 0xffff_ffff;
        out[2 * i + 1] = limb >> 32;
    }
    out
}

fn borrow_chain(words: &[u32; 8]) -> ([u64; 8], [u64; 8]) {
    let p = modulus();
    let mut diff = [0u64; 8];
    let mut borrow = [0u64; 8];
    let mut carry = 0i64;
    for i in 0..8 {
        let d = words[i] as i64 - p[i] as i64 - carry;
        if d < 0 {
            diff[i] = (d + (1i64 << 32)) as u64;
            carry = 1;
        } else {
            diff[i] = d as u64;
            carry = 0;
        }
        borrow[i] = carry as u64;
    }
    (diff, borrow)
}

fn column(values: Vec<u64>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(
        values.into_iter().map(Fr::from_u64).collect(),
    ))
}

fn witness(live: &[Invocation]) -> Vec<(PolyAddress, MultilinearPoly)> {
    assert!(live.len() <= ROWS);
    let at = |r: usize, g: &dyn Fn(&Invocation) -> u64| -> u64 { live.get(r).map_or(0, g) };
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let mut push = |address: PolyAddress, g: &dyn Fn(&Invocation) -> u64| {
        out.push((address, column((0..ROWS).map(|r| at(r, g)).collect())));
    };
    push(poseidon2::CYCLE, &|i| i.cycle);
    push(poseidon2::LIVE, &|_| 1);
    push(poseidon2::BASE, &|i| i.base as u64);
    push(poseidon2::ANCHOR_VALUE, &|_| 0);
    for j in 0..p2::FRAME_WORDS {
        push(poseidon2::word(j, poseidon2::WORD_ADDR), &move |i| {
            i.base as u64 + 4 * j as u64
        });
        push(poseidon2::word(j, poseidon2::WORD_READ_TS), &move |i| {
            mem::TS_STEP * i.cycle - 1
        });
        push(poseidon2::word(j, poseidon2::WORD_READ_VALUE), &move |i| {
            i.frame().0[j] as u64
        });
        push(poseidon2::word(j, poseidon2::WORD_WRITE_VALUE), &move |i| {
            i.frame().1[j] as u64
        });
    }
    for j in 0..p2::FRAME_WORDS {
        for bit in 0..38 {
            push(poseidon2::gap_bit(j, bit), &|_| 0);
        }
    }
    for bit in 0..29 {
        push(poseidon2::base_low_bit(bit), &move |i| {
            let q = (i.base as u64).wrapping_sub(guest_memory::RAM_ORIGIN as u64) / 4;
            (q >> bit) & 1
        });
    }
    for bit in 0..31 {
        push(poseidon2::base_room_bit(bit), &move |i| {
            let room = ((1u64 << 31) - p2::FRAME_BYTES as u64).wrapping_sub(i.base as u64);
            (room >> bit) & 1
        });
    }
    for v in 0..2 * p2::WIDTH {
        for k in 0..8 {
            for t in 0..32 {
                push(poseidon2::value_bit(v, k, t), &move |i| {
                    (i.value_words(v)[k] as u64 >> t) & 1
                });
            }
        }
        for k in 0..8 {
            for t in 0..32 {
                push(poseidon2::diff_bit(v, k, t), &move |i| {
                    (borrow_chain(&i.value_words(v)).0[k] >> t) & 1
                });
            }
        }
        for k in 0..8 {
            push(poseidon2::borrow_bit(v, k), &move |i| {
                borrow_chain(&i.value_words(v)).1[k]
            });
        }
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

fn refusal(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> String {
    let values = forward(a, columns);
    match gkr::self_check(a, &values, &challenges()) {
        Ok(()) => panic!("the corrupted witness satisfies every gate"),
        Err(e) => e.relation,
    }
}

fn wide(rng: &mut test_support::Rng) -> Fr {
    let mut x = Fr::ZERO;
    for _ in 0..4 {
        x = x * Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32) + Fr::from_u64(rng.next_u64());
    }
    x
}

/// The spec's KAT state, `[0, 1, 2]`, and two pseudo-random ones.
fn honest() -> Vec<Invocation> {
    let mut rng = test_support::Rng::new(0x5233_0512);
    let base = |k: u32| guest_memory::RAM_ORIGIN + 4 * k;
    vec![
        Invocation {
            cycle: 7,
            base: base(1000),
            state: [Fr::ZERO, Fr::from_u64(1), Fr::from_u64(2)],
        },
        Invocation {
            cycle: 11,
            base: base(4096),
            state: core::array::from_fn(|_| wide(&mut rng)),
        },
        Invocation {
            cycle: 13,
            base: base(8192),
            state: [Fr::ZERO; p2::WIDTH],
        },
    ]
}

// ---------------------------------------------------------------------------

#[test]
fn the_circuit_keeps_every_rule() {
    let a = poseidon2::artifact(VARS);
    a.validate().expect("the circuit is a circuit");
    checker::check_laws(&a).expect("the standalone validators agree");
    checker::check_padding(&a).expect("the padding contract holds");
    checker::check_padding_identity(&a).expect("a padding row is the product's identity");
    constraints::memory::check_memory(&a).expect("the memory provenance rules hold");
    constraints::lookup::check_discharge(&a, &poseidon2::channels())
        .expect("a circuit with no channel discharges nothing");
}

/// Acceptance 2. The written lanes come from `transcript::poseidon2_permute`,
/// and the circuit accepts them: the KAT state and random ones alike.
#[test]
fn the_forward_pass_is_poseidon2_permute() {
    let a = poseidon2::artifact(VARS);
    let values = forward(&a, witness(&honest()));
    gkr::self_check(&a, &values, &challenges())
        .unwrap_or_else(|e| panic!("an honest witness failed `{}`", e.relation));

    let mut rng = test_support::Rng::new(0x0512_5233);
    for round in 0..4 {
        let case: Vec<Invocation> = (0..ROWS)
            .map(|r| Invocation {
                cycle: 3 + (4 * round + r) as u64,
                base: guest_memory::RAM_ORIGIN + 4 * (64 * (r as u32 + 1)),
                state: core::array::from_fn(|_| wide(&mut rng)),
            })
            .collect();
        let values = forward(&a, witness(&case));
        gkr::self_check(&a, &values, &challenges())
            .unwrap_or_else(|e| panic!("round {round}: an honest witness failed `{}`", e.relation));
    }
}

/// The committed vectors, not a self-oracle.
///
/// `crates/transcript/tests/vectors/poseidon2_perm.txt` was produced by
/// `tools/transcript-ref` from the Plonky3 permutation and the HorizenLabs
/// `RC3` constants; its first line is the `[0,1,2]` known-answer vector. The
/// circuit's forward pass is run over those inputs with those outputs as the
/// written lanes, so a circuit that agreed with `transcript` and both with
/// nothing else would still fail here.
#[test]
fn the_forward_pass_matches_the_committed_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../transcript/tests/vectors/poseidon2_perm.txt"
    );
    let text = std::fs::read_to_string(path).expect("the committed permutation vectors");
    let mut cases: Vec<([Fr; p2::WIDTH], [Fr; p2::WIDTH])> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 7, "a perm line is a tag and six elements");
        assert_eq!(f[0], "perm");
        let element = |hex: &str| -> Fr {
            let mut bytes = [0u8; 32];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
            }
            Fr::from_bytes(&bytes).expect("a committed vector is canonical")
        };
        cases.push((
            core::array::from_fn(|i| element(f[1 + i])),
            core::array::from_fn(|i| element(f[4 + i])),
        ));
    }
    assert!(cases.len() >= 16, "the file holds {} vectors", cases.len());
    // The first vector is the `[0,1,2]` KAT.
    assert_eq!(
        cases[0].0,
        [Fr::ZERO, Fr::from_u64(1), Fr::from_u64(2)],
        "the file opens with the known-answer vector"
    );

    let a = poseidon2::artifact(VARS);
    for (batch, chunk) in cases.chunks(ROWS).take(4).enumerate() {
        let live: Vec<Invocation> = chunk
            .iter()
            .enumerate()
            .map(|(r, (input, output))| {
                // The written lanes come from the file, not from the crate.
                let i = Invocation {
                    cycle: 3 + (ROWS * batch + r) as u64,
                    base: guest_memory::RAM_ORIGIN + 4 * (64 * (r as u32 + 1)),
                    state: *input,
                };
                assert_eq!(i.out(), *output, "the crate and the file agree");
                i
            })
            .collect();
        let values = forward(&a, witness(&live));
        gkr::self_check(&a, &values, &challenges()).unwrap_or_else(|e| {
            panic!("batch {batch}: a committed vector failed `{}`", e.relation)
        });
    }
}

#[test]
fn a_corrupted_output_lane_is_refused() {
    let a = poseidon2::artifact(VARS);
    let columns = corrupt(
        witness(&honest()),
        poseidon2::word(p2::WORDS_PER_LANE, poseidon2::WORD_WRITE_VALUE),
        1,
        Fr::from_u64(1),
    );
    assert_eq!(refusal(&a, columns), "out1_word0");
}

/// The lane bits are what the top gate reads, so moving one and its word
/// together is the tamper that reaches the permutation itself.
#[test]
fn a_corrupted_output_lane_and_its_bits_are_refused() {
    let a = poseidon2::artifact(VARS);
    let honest = honest();
    let word = honest[1].value_words(p2::WIDTH)[0];
    let mut columns = witness(&honest);
    columns = corrupt(
        columns,
        poseidon2::word(0, poseidon2::WORD_WRITE_VALUE),
        1,
        Fr::from_u64(word as u64 ^ 1),
    );
    columns = corrupt(columns, poseidon2::value_bit(p2::WIDTH, 0, 0), 1, {
        if word & 1 == 0 {
            Fr::ONE
        } else {
            Fr::ZERO
        }
    });
    // The canonicity chain of the moved word no longer holds either, so the
    // first refusal is its limb equation — which is still a refusal of the
    // corrupted output, and the gate below proves the output gate itself bites.
    let refusal = refusal(&a, columns);
    assert!(
        refusal.starts_with("out0_canonical") || refusal == "out_lane0",
        "unexpected refusal `{refusal}`"
    );
}

/// The permutation's own output, moved where every frame gate still holds: the
/// input state of a live row. Only the round block can catch it.
#[test]
fn a_corrupted_input_lane_is_refused() {
    let a = poseidon2::artifact(VARS);
    let mut moved = honest();
    // The *frame* still describes `moved`, but the written lanes come from the
    // original state, so the permutation's output and the written words differ.
    let original = moved[1].out();
    moved[1].state[0] += Fr::ONE;
    let mut columns = witness(&moved);
    for (j, lane) in original.iter().enumerate() {
        let bytes = lane.to_bytes();
        for k in 0..p2::WORDS_PER_LANE {
            let mut word = [0u8; 4];
            word.copy_from_slice(&bytes[4 * k..4 * k + 4]);
            let word = u32::from_le_bytes(word);
            let at = p2::WORDS_PER_LANE * j + k;
            columns = corrupt(
                columns,
                poseidon2::word(at, poseidon2::WORD_WRITE_VALUE),
                1,
                Fr::from_u64(word as u64),
            );
            for t in 0..32 {
                columns = corrupt(
                    columns,
                    poseidon2::value_bit(p2::WIDTH + j, k, t),
                    1,
                    Fr::from_u64((word as u64 >> t) & 1),
                );
            }
        }
        let words: [u32; 8] = core::array::from_fn(|k| {
            let mut word = [0u8; 4];
            word.copy_from_slice(&bytes[4 * k..4 * k + 4]);
            u32::from_le_bytes(word)
        });
        let (diff, borrow) = borrow_chain(&words);
        for k in 0..8 {
            for t in 0..32 {
                columns = corrupt(
                    columns,
                    poseidon2::diff_bit(p2::WIDTH + j, k, t),
                    1,
                    Fr::from_u64((diff[k] >> t) & 1),
                );
            }
            columns = corrupt(
                columns,
                poseidon2::borrow_bit(p2::WIDTH + j, k),
                1,
                Fr::from_u64(borrow[k]),
            );
        }
    }
    assert_eq!(refusal(&a, columns), "out_lane0");
}

#[test]
fn a_bad_frame_pointer_is_refused() {
    let a = poseidon2::artifact(VARS);
    let mut misaligned = honest();
    misaligned[0].base += 2;
    assert_eq!(refusal(&a, witness(&misaligned)), "base_aligned");

    let mut past = honest();
    past[0].base = (1u32 << 31) - 4;
    assert_eq!(refusal(&a, witness(&past)), "base_in_window");
}

/// A padding row's lanes are not free: `in{j}_word{k}` is ungated, so a state
/// bit moved on a padding row is refused all the same.
#[test]
fn a_padding_rows_lane_is_not_free() {
    let a = poseidon2::artifact(VARS);
    let columns = corrupt(witness(&honest()), poseidon2::value_bit(0, 0, 0), 3, Fr::ONE);
    assert_eq!(refusal(&a, columns), "in0_word0");
}
