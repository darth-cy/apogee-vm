//! The verifier's share of the memory argument, `docs/spec/memory.md` §3.3 and
//! §4: a window shard's derived challenge, the register and PC boundary, and
//! the reconciliation of every shard's roots.

use constants::memory::{HALT_PC, PART_ADDR, PART_AS, PART_TS, PART_VAL};
use constants::{address_space, challenge_slot, guest_memory};
use constraints::memory::read_tuple;
use constraints::MAX_TRACE_VARS;
use field::Fr;

use crate::{eval_gate, ExternalChallenges};

/// The register and PC finals a proof carries: `docs/spec/memory.md` §4.1's 64
/// boundary scalars, which the `MEMORY_BOUNDARY` message absorbs in this order:
/// `reg_ts[0..32]` (`t_0 … t_31`), `pc_ts` (`t_pc`), `reg_values[0..31]`
/// (`v_1 … v_31`). `reg_values[i]` is register `x_{i+1}`'s; `x0`'s final value
/// is the constant 0 and the pc's the constant `HALT_PC`, and neither is
/// carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundaryFinals {
    /// Register `x_r`'s final timestamp: its last query's write, 0 if never
    /// queried.
    pub reg_ts: [u64; 32],
    /// The pc's final timestamp: the last cycle's pc write. Not a cycle count.
    pub pc_ts: u64,
    /// Register `x_{i+1}`'s final value: its last write, 0 if never queried.
    pub reg_values: [u32; 31],
}

/// The byte address a window family's window 0 begins at. RAM's windows start
/// at address 0 — window 0 is `INIT_TEARDOWN`'s, and its rows below
/// `RAM_ORIGIN` are masked by `V[ram_live]` — and the advice region's start at
/// `guest_memory::ADVICE_ORIGIN`, which is exactly where RAM's reach stops
/// (`docs/spec/advice.md` §1.1).
///
/// Panics on any other space: only these two are initialized by windows, and a
/// caller naming a third has confused a delegation anchor for a region.
fn window_origin(space: u8) -> u64 {
    match space {
        address_space::RAM => 0,
        address_space::ADVICE => guest_memory::ADVICE_ORIGIN as u64,
        _ => panic!("window_challenges: address space {space} is not initialized in windows"),
    }
}

/// The challenges one window shard's artifact reads: slots `MEM_GAMMA` through
/// `MEM_ALPHA_VAL` copied from `memory`, and the derived
/// `MEM_WINDOW_CONSTANT = γ_M + space + α_addr·(origin + 4·2^trace_vars·window)`,
/// the tuple part every row of window `window` of `space` shares
/// (`docs/spec/memory.md` §3.3).
///
/// `space` is `address_space::RAM` for the two RAM window families — `window`
/// then being 0 for `INIT_TEARDOWN` — and `address_space::ADVICE` for
/// `ADVICE_WINDOWS`, whose windows are numbered from 0 at
/// [`window_origin`]'s `ADVICE_ORIGIN` and are contiguous
/// (`docs/spec/advice.md` §6). The space enters the constant where the literal
/// `RAM` used to be, so a window shard of one space can never answer a query
/// of the other: the tuples differ in their first term.
///
/// `4·2^trace_vars·window` is the integer, which fits a `u64` for any `u32`
/// window at `trace_vars <= MAX_TRACE_VARS`. Panics above that, on a space
/// with no windows, or naming a slot `memory` lacks.
pub fn window_challenges(
    memory: &ExternalChallenges,
    space: u8,
    window: u32,
    trace_vars: u32,
) -> ExternalChallenges {
    assert!(
        trace_vars <= MAX_TRACE_VARS,
        "window_challenges: trace_vars {trace_vars} is above {MAX_TRACE_VARS}"
    );
    let mut out = ExternalChallenges::new();
    for slot in challenge_slot::MEM_GAMMA..=challenge_slot::MEM_ALPHA_VAL {
        let value = memory.get(slot).unwrap_or_else(|| {
            panic!(
                "window_challenges: slot {slot} ({}) has no value",
                challenge_slot::NAMES[slot as usize]
            )
        });
        out.insert(slot, value);
    }
    let first_address = window_origin(space) + (4u64 << trace_vars) * window as u64;
    let gamma = out.get(challenge_slot::MEM_GAMMA).expect("copied above");
    let alpha_addr = out
        .get(challenge_slot::MEM_ALPHA_ADDR)
        .expect("copied above");
    out.insert(
        challenge_slot::MEM_WINDOW_CONSTANT,
        gamma + Fr::from_u64(space as u64) + alpha_addr * Fr::from_u64(first_address),
    );
    out
}

/// `(W_b, R_b)`, the boundary's write and read factors,
/// `docs/spec/memory.md` §4.2:
///
/// ```text
/// W_b = Π_{r=0}^{31} T(REG, r, 0, 0) · T(PC, 0, 0, entry_pc)
/// R_b = T(REG, 0, t_0, 0) · Π_{r=1}^{31} T(REG, r, t_r, v_r) · T(PC, 0, t_pc, HALT_PC)
/// ```
///
/// Every tuple is the circuits' own tuple gate through the kernel:
/// `constraints::memory::read_tuple` of query 0 (PC) or 1 (REG), whose term
/// `PART_*` is that part, at operand values placed by the same constants: the
/// mask 1 at `PART_AS`, then `addr`, `ts` and `value`. `memory` holds slots 1
/// to 4; the kernel panics on a missing one.
pub fn boundary_factors(
    memory: &ExternalChallenges,
    entry_pc: u32,
    finals: &BoundaryFinals,
) -> (Fr, Fr) {
    let (pc, reg) = (read_tuple(0), read_tuple(1));
    let tuple = |gate, addr: u64, ts: u64, value: u64| {
        let mut values = [Fr::ZERO; 4];
        values[PART_AS] = Fr::ONE;
        values[PART_ADDR] = Fr::from_u64(addr);
        values[PART_TS] = Fr::from_u64(ts);
        values[PART_VAL] = Fr::from_u64(value);
        eval_gate(gate, &values, memory)
    };
    let mut write = tuple(&pc, 0, 0, entry_pc as u64);
    let mut read = tuple(&pc, 0, finals.pc_ts, HALT_PC as u64);
    for r in 0..32 {
        let value = if r == 0 { 0 } else { finals.reg_values[r - 1] };
        write *= tuple(&reg, r as u64, 0, 0);
        read *= tuple(&reg, r as u64, finals.reg_ts[r], value as u64);
    }
    (write, read)
}

/// The memory argument's check, `docs/spec/memory.md` §4.2: over every shard
/// of every family in the statement,
/// `Π read_roots · R_b = Π write_roots · W_b`, and that product is nonzero.
/// `factors` is [`boundary_factors`]' `(W_b, R_b)`.
pub fn reconciles(read_roots: &[Fr], write_roots: &[Fr], factors: (Fr, Fr)) -> bool {
    let (w_b, r_b) = factors;
    let read = read_roots.iter().fold(r_b, |acc, root| acc * *root);
    let write = write_roots.iter().fold(w_b, |acc, root| acc * *root);
    read == write && read != Fr::ZERO
}
