//! The reference emulator: RV32IMAC on one hart, over a [`ProgramImage`].
//!
//! Two entry points, one instruction-execution core. [`run`] executes;
//! [`trace_run`] executes the same way and also hands each cycle's memory
//! queries to a recorder, which fills the memory event log and routes the
//! cycle's row to the family that owns its pc. The recorder is the only
//! difference between the two: neither path has its own copy of the
//! semantics.
//!
//! `docs/spec/execution-trace.md` is the frozen convention the recorder
//! follows — timestamps, slots, the x0 rule, the ecall frame.
//! `crates/emulator/CLAUDE.md` is the design record.
//!
//! # Semantics, in one paragraph
//!
//! One hart, no interrupts, no privilege levels. Every A-extension
//! instruction is its plain read-modify-write, and `aq`/`rl` order nothing.
//! **`sc.w` always succeeds**: it stores and writes 0 to `rd`. The ISA
//! requires an `sc.w` without a valid reservation to fail, so this is a
//! conformance deviation — never a soundness one, since the verifier still
//! knows exactly which program ran, and the circuits share the semantics
//! (`docs/spec/memory-ops.md` §6.5). A halfword or word access at an address
//! that is not a multiple of its width, and any access outside the
//! addressable regions, is a fatal guest error, never rotated, split or
//! emulated. So is `ebreak`, and so is a pc that is not the start of an
//! instruction.

use std::collections::HashMap;
use std::fmt;

use constants::{
    delegation, ec_add, ecall, family, fr_arith, guest_memory, keccak, memory, mod_mul, poseidon2,
    sha256,
};
use field::Fr;
use isa::{decode, Instr};
use loader::{ProgramImage, Slot};
use program::{row_kind, DecodedTables, FamilyId, VmConfig};
use trace::{
    Access, AddressSpace, CycleProfile, DelegationTrace, FamilyTrace, FamilyTraces, IoStreams,
    MemoryEvent, MemoryEventLog, MemoryState, Query, Role, Row, ROLES,
};

/// What a guest is given to read. **Two fields, because there are two things,
/// and what tells them apart is what binds them**
/// (`docs/spec/public-values.md`).
///
/// | field | where the guest finds it | what binds it |
/// | --- | --- | --- |
/// | `input` | the public input window, an ordinary load | the statement, at the window's init column |
/// | `advice` | `guest_memory::ADVICE_ORIGIN`, an ordinary load | **nothing**; the guest owes a check |
///
/// Both are *memory*. There is no third field and no stream: an Apogee guest
/// has no file descriptors, so there is nothing a host could hand it that is
/// neither of these two. It had four fields until the POSIX layer was deleted
/// — `stdin` and `hint` were served over `read`, which was never a provable
/// ecall, so a guest reading either was a guest no proof covered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestIo {
    pub input: Vec<u8>,
    pub advice: Vec<u8>,
}

/// A finished execution: the guest called `exit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    /// The register file after the last cycle.
    pub regs: [u32; 32],
    /// The status passed to `exit`. A nonzero status is a failed execution,
    /// which is still an execution: it is reported, not refused.
    pub exit_code: i32,
    /// Cycles run. Cycles are numbered from 1, so
    /// this is also the last cycle's number.
    pub cycle_count: u64,
    /// The execution's **public values**: the public input it was given, and
    /// the journal its stores left in the public output window
    /// (`docs/spec/public-values.md`). These are the two byte strings a
    /// statement carries and a proof binds.
    pub io: IoStreams,
}

/// Every way an execution stops other than by `exit`. Each is a fatal guest
/// error — the program did something this VM does not define — and neither
/// entry point returns any part of a trace alongside one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmuError {
    /// The pc is not the start of an instruction: the middle of one, data,
    /// the all-zero halfword, or outside the image's code.
    NotAnInstruction { pc: u32 },
    /// An instruction slot holds a word the decoder refuses.
    IllegalInstruction { pc: u32, word: u32 },
    /// `ebreak`: a trap with nothing to trap to.
    Ebreak { pc: u32 },
    /// A halfword or word access at an address that is not a multiple of
    /// its width.
    Misaligned { pc: u32, addr: u32, width: u32 },
    /// A data access, or a byte an ecall would move, outside the RAM window.
    OutOfBounds { pc: u32, addr: u32 },
    /// Cycle `cycle`'s timestamps would pass the 38-bit clock.
    ClockOverflow { cycle: u64 },
    /// The public input handed to the run is longer than a public window's
    /// payload, so no statement could carry it.
    ///
    /// Checked before the first cycle rather than left to panic inside the
    /// window's layout: a host that offers too much input has made a mistake,
    /// and the executor says so by name.
    PublicInputTooLong { len: usize },
    /// The journal's length word is above `guest_memory::PUBLIC_PAYLOAD_BYTES`
    /// at exit, so the public output window does not describe a byte string
    /// any statement could carry.
    ///
    /// Fatal, and it has to be: the verifier reads the window back through
    /// `program::public_io_words`, which has no encoding for such a length, so
    /// an execution this let through would be one no proof could cover.
    /// `guest_sdk::commit` refuses to overflow the window rather than reach
    /// here.
    JournalTooLong { len: u32 },
    /// A delegation ecall whose family the `VmConfig` does not hold.
    ///
    /// Only the tracing path raises it: the family set is a property of the
    /// linked binary (`docs/spec/delegation.md` §7), and a program that calls
    /// a delegation it did not declare is one no trace can describe and no
    /// proof can cover. Loud rather than answered `-ENOSYS`, because the two
    /// are different failures — one is a VM that lacks the circuit, the other
    /// a program whose declaration and whose code disagree.
    DelegationFamilyAbsent { pc: u32, number: u32 },
    /// A delegation's frame does not describe a call its family can answer:
    /// an operation code outside the legal set, or a value that is not a
    /// canonical `Fr`.
    ///
    /// Fatal, and it has to be: the circuit refuses both — the opcode by its
    /// selector sum, a non-canonical value by its borrow chain — so an
    /// execution the emulator let through here would be one no proof could
    /// cover (`docs/spec/delegation.md` §13).
    DelegationFrame { pc: u32, detail: &'static str },
}

impl fmt::Display for EmuError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EmuError::NotAnInstruction { pc } => {
                write!(f, "pc {pc:#010x} is not the start of an instruction")
            }
            EmuError::IllegalInstruction { pc, word } => write!(
                f,
                "illegal instruction at pc {pc:#010x}: {word:#010x} is not RV32IMAC"
            ),
            EmuError::Ebreak { pc } => write!(f, "ebreak at pc {pc:#010x}"),
            EmuError::PublicInputTooLong { len } => write!(
                f,
                "the public input is {len} bytes, above the window's {}",
                guest_memory::PUBLIC_PAYLOAD_BYTES
            ),
            EmuError::JournalTooLong { len } => write!(
                f,
                "the journal's length word is {len}, above the window's {} payload bytes",
                guest_memory::PUBLIC_PAYLOAD_BYTES
            ),
            EmuError::Misaligned { pc, addr, width } => write!(
                f,
                "misaligned data access at pc {pc:#010x}: a {width}-byte access at {addr:#010x}"
            ),
            EmuError::OutOfBounds { pc, addr } => write!(
                f,
                "data access outside the RAM window at pc {pc:#010x}: address {addr:#010x}"
            ),
            EmuError::ClockOverflow { cycle } => write!(
                f,
                "cycle {cycle} would pass the {}-bit timestamp clock",
                memory::TS_BITS
            ),
            EmuError::DelegationFamilyAbsent { pc, number } => write!(
                f,
                "the delegation ecall {number:#x} at pc {pc:#010x} has no family in this \
                 VmConfig, so the program calls a delegation it does not declare"
            ),
            EmuError::DelegationFrame { pc, detail } => write!(
                f,
                "the delegation frame at pc {pc:#010x} is not a call this family answers: {detail}"
            ),
        }
    }
}

/// The Poseidon2 delegation over its 24-word frame: three canonical
/// little-endian `Fr` lanes, permuted in place.
///
/// The permutation is `transcript::poseidon2_permute` and nothing else — the
/// executor and the circuit are held to one definition, not to each other.
/// A lane that is not canonical is refused by the caller before this runs.
fn poseidon2_frame(old: &[u32]) -> Vec<u32> {
    let mut state = [Fr::ZERO; poseidon2::WIDTH];
    for (i, lane) in state.iter_mut().enumerate() {
        *lane = Fr::from_bytes(&value_bytes(old, poseidon2::WORDS_PER_LANE * i))
            .expect("the caller checked canonicity");
    }
    transcript::poseidon2_permute(&mut state);
    let mut out = old.to_vec();
    for (i, lane) in state.iter().enumerate() {
        write_value(&mut out, poseidon2::WORDS_PER_LANE * i, &lane.to_bytes());
    }
    out
}

/// The Fr-arithmetic delegation over its 25-word frame: the opcode word, then
/// `a`, `b` and the result in `field::Fr`'s in-memory representation.
///
/// The three operations are `Fr`'s own `Add`, `Mul` and `inverse`, with
/// `inverse(0) = 0` in place of `None`, which is this delegation's convention
/// (`docs/spec/delegation.md` §13).
fn fr_arith_frame(pc: u32, old: &[u32]) -> Result<Vec<u32>, EmuError> {
    let operand = |first: usize| -> Result<Fr, EmuError> {
        Fr::from_memory_bytes(&value_bytes(old, first)).ok_or(EmuError::DelegationFrame {
            pc,
            detail: "an operand is not a canonical Fr",
        })
    };
    let a = operand(fr_arith::A_WORD)?;
    let b = operand(fr_arith::B_WORD)?;
    // The result's words are read and thrown away, but they must still be a
    // canonical `Fr`: the circuit decomposes every frame value it names, and
    // the words it writes are the ones its canonicity gates bind.
    let out = match old[fr_arith::OPCODE_WORD] {
        fr_arith::OP_ADD => a + b,
        fr_arith::OP_MUL => a * b,
        fr_arith::OP_INV => a.inverse().unwrap_or(Fr::ZERO),
        _ => {
            return Err(EmuError::DelegationFrame {
                pc,
                detail: "the operation code is not add, mul or inverse",
            })
        }
    };
    let mut frame = old.to_vec();
    write_value(&mut frame, fr_arith::OUT_WORD, &out.to_memory_bytes());
    Ok(frame)
}

/// `MOD_MUL`'s frame, permuted: `out = a * b mod m` over eight 32-bit limbs,
/// `m` being the modulus frame word 0 selects.
///
/// **Schoolbook, in `u64` lanes, and long division by shift-and-subtract.** No
/// Montgomery form and no reciprocal: the circuit proves `a*b = q*m + out` with
/// `out < m` and nothing else (`docs/spec/delegation.md` §14), so the executor
/// computes exactly that and the two agree by definition rather than by a
/// shared trick.
///
/// **Three refusals, and each is a frame no proof could cover.** A selector
/// outside `constants::mod_mul::CODES` names no modulus. An operand at or
/// above the selected modulus has no witness: the circuit's `a < m` and
/// `b < m` chains would reject it, and long division would happily return the
/// right answer, so without the refusal here a guest runs clean and the
/// failure surfaces as an anonymous layer inconsistency inside a block proof
/// hours later. `docs/spec/delegation.md` §4's rule is that an execution this
/// refuses is one no proof could have covered, and these are three of them.
fn mod_mul_frame(pc: u32, old: &[u32]) -> Result<Vec<u32>, EmuError> {
    let limb = |first: usize, k: usize| old[first + k] as u64;
    let Some(selected) = mod_mul::modulus(old[mod_mul::SELECTOR_WORD]) else {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "the modulus selector names no field",
        });
    };
    let m: [u64; mod_mul::LIMBS] = core::array::from_fn(|k| selected[k] as u64);
    let a: [u64; mod_mul::LIMBS] = core::array::from_fn(|k| limb(mod_mul::A_WORD, k));
    let b: [u64; mod_mul::LIMBS] = core::array::from_fn(|k| limb(mod_mul::B_WORD, k));
    if !less_than(&a, &m) {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "operand a is not below the modulus",
        });
    }
    if !less_than(&b, &m) {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "operand b is not below the modulus",
        });
    }
    // The 512-bit product, sixteen limbs, carried in `u64` lanes: each partial
    // product is below `2^64` and each accumulation below `2^64` again because
    // the running lane is reduced to 32 bits before the next addend.
    let mut product = [0u64; 2 * mod_mul::LIMBS];
    for (i, ai) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, bj) in b.iter().enumerate() {
            let at = i + j;
            let total = product[at] + ai * bj + carry;
            product[at] = total & 0xffff_ffff;
            carry = total >> 32;
        }
        let mut at = i + mod_mul::LIMBS;
        while carry != 0 {
            let total = product[at] + carry;
            product[at] = total & 0xffff_ffff;
            carry = total >> 32;
            at += 1;
        }
    }
    let rem = reduce(&product, &m);
    let mut frame = old.to_vec();
    for k in 0..mod_mul::LIMBS {
        frame[mod_mul::OUT_WORD + k] = rem[k] as u32;
    }
    Ok(frame)
}

/// What one `SHA256_COMP` invocation does: rounds `4·group..4·group + 4` of
/// FIPS 180-4's compression over the eight working variables, with the
/// window's first four words as their schedule words, then the window shifted
/// by four with the four schedule words it unlocks appended.
///
/// Sixteen of these, groups 0 to 15 on one frame whose window starts as the
/// block, are the compression's 64 rounds; the caller adds the working
/// variables to the chaining state it kept. Calls 12 to 15 append `W_64` and
/// up, which no round reads — the circuit's row is uniform, and so is this.
pub fn sha256_call(
    group: usize,
    state: &mut [u32; sha256::STATE_WORDS],
    window: &mut [u32; sha256::BLOCK_WORDS],
) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, w) in window.iter().take(sha256::ROUNDS_PER_CALL).enumerate() {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(sha256::ROUND_CONSTANTS[sha256::ROUNDS_PER_CALL * group + k])
            .wrapping_add(*w);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    *state = [a, b, c, d, e, f, g, h];
    let mut x = [0u32; sha256::BLOCK_WORDS + sha256::ROUNDS_PER_CALL];
    x[..sha256::BLOCK_WORDS].copy_from_slice(window);
    for m in 0..sha256::ROUNDS_PER_CALL {
        let t = sha256::BLOCK_WORDS + m;
        let s0 = x[t - 15].rotate_right(7) ^ x[t - 15].rotate_right(18) ^ (x[t - 15] >> 3);
        let s1 = x[t - 2].rotate_right(17) ^ x[t - 2].rotate_right(19) ^ (x[t - 2] >> 10);
        x[t] = x[t - 16]
            .wrapping_add(s0)
            .wrapping_add(x[t - 7])
            .wrapping_add(s1);
    }
    window.copy_from_slice(&x[sha256::ROUNDS_PER_CALL..]);
}

/// One `SHA256_COMP` invocation over the 25-word frame, in place.
///
/// **This family can refuse a frame since S26e**, as `KECCAK_F` can: a group
/// word at or above 16 has no one-hot selector in the circuit, so an executor
/// that answered it would produce a trace no honest prover could prove. Every
/// other word is a legal working variable or schedule word. The group word is
/// written back unchanged; the guest's own loop is what advances it.
fn sha256_frame(pc: u32, old: &[u32]) -> Result<Vec<u32>, EmuError> {
    let group = old[sha256::GROUP_WORD];
    if group as usize >= sha256::GROUPS {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "the group word is not a SHA-256 round group",
        });
    }
    let mut state: [u32; sha256::STATE_WORDS] =
        core::array::from_fn(|j| old[sha256::STATE_WORD + j]);
    let mut window: [u32; sha256::BLOCK_WORDS] =
        core::array::from_fn(|i| old[sha256::WINDOW_WORD + i]);
    sha256_call(group as usize, &mut state, &mut window);
    let mut new = Vec::with_capacity(sha256::FRAME_WORDS);
    new.push(group);
    new.extend_from_slice(&state);
    new.extend_from_slice(&window);
    Ok(new)
}

/// One eight-limb value of the `EC_ADD` frame.
type Wide = [u64; ec_add::LIMBS];

/// `a + b mod m`, both operands below `m`.
fn add_mod(a: &Wide, b: &Wide, m: &Wide) -> Wide {
    let mut out = [0u64; ec_add::LIMBS];
    let mut carry = 0u64;
    for k in 0..ec_add::LIMBS {
        let total = a[k] + b[k] + carry;
        out[k] = total & 0xffff_ffff;
        carry = total >> 32;
    }
    // `a + b < 2m`, so one conditional subtraction reduces it — and a carry out
    // of the top limb means it is at least `2^256`, hence at least `m`.
    if carry != 0 || !less_than(&out, m) {
        out = sub_wide(&out, m);
    }
    out
}

/// `a - b mod m`, both operands below `m`.
fn sub_mod(a: &Wide, b: &Wide, m: &Wide) -> Wide {
    if less_than(a, b) {
        sub_wide(&add_wide(a, m), b)
    } else {
        sub_wide(a, b)
    }
}

/// `a + b` over the integers, modulo `2^256` — the carry out is dropped, and
/// every caller has established it is zero or accounted for.
fn add_wide(a: &Wide, b: &Wide) -> Wide {
    let mut out = [0u64; ec_add::LIMBS];
    let mut carry = 0u64;
    for k in 0..ec_add::LIMBS {
        let total = a[k] + b[k] + carry;
        out[k] = total & 0xffff_ffff;
        carry = total >> 32;
    }
    out
}

/// `a - b` over the integers, for `a >= b`.
fn sub_wide(a: &Wide, b: &Wide) -> Wide {
    let mut out = [0u64; ec_add::LIMBS];
    let mut borrow = 0i64;
    for k in 0..ec_add::LIMBS {
        let total = a[k] as i64 - b[k] as i64 - borrow;
        if total < 0 {
            out[k] = (total + (1i64 << 32)) as u64;
            borrow = 1;
        } else {
            out[k] = total as u64;
            borrow = 0;
        }
    }
    out
}

/// `a * b mod m`, through the same 16-limb schoolbook product and the same
/// bitwise reduction `mod_mul_frame` uses. One implementation of the reduction,
/// so the two families cannot disagree about what `mod m` means.
fn mul_mod(a: &Wide, b: &Wide, m: &Wide) -> Wide {
    let mut product = [0u64; 2 * ec_add::LIMBS];
    for (i, ai) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, bj) in b.iter().enumerate() {
            let at = i + j;
            let total = product[at] + ai * bj + carry;
            product[at] = total & 0xffff_ffff;
            carry = total >> 32;
        }
        let mut at = i + ec_add::LIMBS;
        while carry != 0 {
            let total = product[at] + carry;
            product[at] = total & 0xffff_ffff;
            carry = total >> 32;
            at += 1;
        }
    }
    reduce(&product, m)
}

/// `k * a mod m` for a small `k`.
fn scale_mod(k: u32, a: &Wide, m: &Wide) -> Wide {
    let mut scalar = [0u64; ec_add::LIMBS];
    scalar[0] = k as u64;
    mul_mod(&scalar, a, m)
}

/// One third of a complete point addition, in place over the 97-word frame.
///
/// Frame word 0 selects the curve **and** the group; the three invocations of
/// one addition go in ascending group order, and the intermediates each leaves
/// in words 49..97 are what the next reads. `docs/spec/delegation.md` §16.
///
/// **Every bad frame is refused by name**, which is `docs/spec/delegation.md`
/// §14.3's lesson: the reduction answers correctly for operands below `2^256`,
/// so without the refusals a guest with an unreduced coordinate runs clean and
/// the only thing that fails is a gate — anonymously, hours into a block proof.
fn ec_add_frame(pc: u32, old: &[u32]) -> Result<Vec<u32>, EmuError> {
    let code = old[ec_add::SELECTOR_WORD];
    let (Some(selected), Some(b3), Some(g)) = (
        ec_add::modulus(code),
        ec_add::b3(code),
        ec_add::reduction_group(code),
    ) else {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "the selector names no curve and group",
        });
    };
    let m: Wide = core::array::from_fn(|k| selected[k] as u64);
    let value = |first: usize| -> Wide { core::array::from_fn(|k| old[first + k] as u64) };

    // The six words this group reads must be canonical: the quotient's nine
    // limbs are what the circuit bounds, and an operand at or above `m` is a
    // quotient no honest prover can fit.
    let reads: [(&str, usize); 6] = if g == 2 {
        [
            ("xx", ec_add::XX_WORD),
            ("yy", ec_add::YY_WORD),
            ("zz", ec_add::ZZ_WORD),
            ("m4", ec_add::M4_WORD),
            ("m5", ec_add::M5_WORD),
            ("m6", ec_add::M6_WORD),
        ]
    } else {
        [
            ("x1", ec_add::X1_WORD),
            ("y1", ec_add::Y1_WORD),
            ("z1", ec_add::Z1_WORD),
            ("x2", ec_add::X2_WORD),
            ("y2", ec_add::Y2_WORD),
            ("z2", ec_add::Z2_WORD),
        ]
    };
    for (name, first) in reads {
        if !less_than(&value(first), &m) {
            return Err(EmuError::DelegationFrame {
                pc,
                detail: match name {
                    "x1" => "coordinate x1 is not below the modulus",
                    "y1" => "coordinate y1 is not below the modulus",
                    "z1" => "coordinate z1 is not below the modulus",
                    "x2" => "coordinate x2 is not below the modulus",
                    "y2" => "coordinate y2 is not below the modulus",
                    "z2" => "coordinate z2 is not below the modulus",
                    "xx" => "the intermediate xx is not below the modulus",
                    "yy" => "the intermediate yy is not below the modulus",
                    "zz" => "the intermediate zz is not below the modulus",
                    "m4" => "the intermediate m4 is not below the modulus",
                    "m5" => "the intermediate m5 is not below the modulus",
                    _ => "the intermediate m6 is not below the modulus",
                },
            });
        }
    }

    let mut frame = old.to_vec();
    let put = |frame: &mut Vec<u32>, first: usize, v: &Wide| {
        for k in 0..ec_add::LIMBS {
            frame[first + k] = v[k] as u32;
        }
    };
    match g {
        0 => {
            let (x1, y1, z1) = (
                value(ec_add::X1_WORD),
                value(ec_add::Y1_WORD),
                value(ec_add::Z1_WORD),
            );
            let (x2, y2, z2) = (
                value(ec_add::X2_WORD),
                value(ec_add::Y2_WORD),
                value(ec_add::Z2_WORD),
            );
            put(&mut frame, ec_add::XX_WORD, &mul_mod(&x1, &x2, &m));
            put(&mut frame, ec_add::YY_WORD, &mul_mod(&y1, &y2, &m));
            put(&mut frame, ec_add::ZZ_WORD, &mul_mod(&z1, &z2, &m));
        }
        1 => {
            let (x1, y1, z1) = (
                value(ec_add::X1_WORD),
                value(ec_add::Y1_WORD),
                value(ec_add::Z1_WORD),
            );
            let (x2, y2, z2) = (
                value(ec_add::X2_WORD),
                value(ec_add::Y2_WORD),
                value(ec_add::Z2_WORD),
            );
            let m4 = mul_mod(&add_mod(&x1, &y1, &m), &add_mod(&x2, &y2, &m), &m);
            let m5 = mul_mod(&add_mod(&y1, &z1, &m), &add_mod(&y2, &z2, &m), &m);
            let m6 = mul_mod(&add_mod(&x1, &z1, &m), &add_mod(&x2, &z2, &m), &m);
            put(&mut frame, ec_add::M4_WORD, &m4);
            put(&mut frame, ec_add::M5_WORD, &m5);
            put(&mut frame, ec_add::M6_WORD, &m6);
        }
        _ => {
            let xx = value(ec_add::XX_WORD);
            let yy = value(ec_add::YY_WORD);
            let zz = value(ec_add::ZZ_WORD);
            let m4 = value(ec_add::M4_WORD);
            let m5 = value(ec_add::M5_WORD);
            let m6 = value(ec_add::M6_WORD);
            let xy = sub_mod(&sub_mod(&m4, &xx, &m), &yy, &m);
            let yz = sub_mod(&sub_mod(&m5, &yy, &m), &zz, &m);
            let xz = sub_mod(&sub_mod(&m6, &xx, &m), &zz, &m);
            let bzz3 = scale_mod(b3, &zz, &m);
            let ym = sub_mod(&yy, &bzz3, &m);
            let yp = add_mod(&yy, &bzz3, &m);
            let byz3 = scale_mod(b3, &yz, &m);
            let xx3 = scale_mod(3, &xx, &m);
            let bxx9 = scale_mod(3 * b3, &xx, &m);
            let x3 = sub_mod(&mul_mod(&xy, &ym, &m), &mul_mod(&byz3, &xz, &m), &m);
            let y3 = add_mod(&mul_mod(&yp, &ym, &m), &mul_mod(&bxx9, &xz, &m), &m);
            let z3 = add_mod(&mul_mod(&yz, &yp, &m), &mul_mod(&xx3, &xy, &m), &m);
            put(&mut frame, ec_add::X1_WORD, &x3);
            put(&mut frame, ec_add::Y1_WORD, &y3);
            put(&mut frame, ec_add::Z1_WORD, &z3);
        }
    }
    Ok(frame)
}

/// `product mod m`, bit by bit from the top: the remainder doubles, takes the
/// next bit, and the modulus is subtracted once if it fits. 512 iterations of
/// 8-limb arithmetic, which is slow and is the executor's own cost, not the
/// guest's.
///
/// Split out of [`mod_mul_frame`] so the unit test can drive it at a modulus a
/// `u128` can hold. None of the four selectable moduli fits one, and an
/// oracle written in the same 16-limb arithmetic as the thing it checks is not
/// an oracle.
fn reduce(product: &[u64; 2 * mod_mul::LIMBS], m: &[u64; mod_mul::LIMBS]) -> [u64; mod_mul::LIMBS] {
    let mut rem = [0u64; mod_mul::LIMBS];
    for bit in (0..32 * 2 * mod_mul::LIMBS).rev() {
        // rem = 2*rem + bit
        let mut carry = (product[bit / 32] >> (bit % 32)) & 1;
        for word in rem.iter_mut() {
            let total = (*word << 1) | carry;
            *word = total & 0xffff_ffff;
            carry = total >> 32;
        }
        // The shifted-out bit and a remainder at or above `m` both mean one
        // subtraction. `carry` can only be 1 because `rem < m <= 2^256`.
        if carry == 1 || !less_than(&rem, m) {
            let mut borrow = 0i64;
            for k in 0..mod_mul::LIMBS {
                let diff = rem[k] as i64 - m[k] as i64 - borrow;
                borrow = i64::from(diff < 0);
                rem[k] = (diff + if diff < 0 { 1i64 << 32 } else { 0 }) as u64;
            }
        }
    }
    rem
}

/// Whether `a < b` over eight little-endian 32-bit limbs.
fn less_than(a: &[u64; mod_mul::LIMBS], b: &[u64; mod_mul::LIMBS]) -> bool {
    for k in (0..mod_mul::LIMBS).rev() {
        if a[k] != b[k] {
            return a[k] < b[k];
        }
    }
    false
}

/// The 32 bytes a frame value occupies, from its eight little-endian words.
fn value_bytes(frame: &[u32], first: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for k in 0..8 {
        bytes[4 * k..4 * k + 4].copy_from_slice(&frame[first + k].to_le_bytes());
    }
    bytes
}

/// Write 32 bytes back over a frame value's eight words.
fn write_value(frame: &mut [u32], first: usize, bytes: &[u8; 32]) {
    for k in 0..8 {
        let mut word = [0u8; 4];
        word.copy_from_slice(&bytes[4 * k..4 * k + 4]);
        frame[first + k] = u32::from_le_bytes(word);
    }
}

/// What a run's inputs must satisfy before the first cycle: the public input
/// fits the window that will carry it (`docs/spec/public-values.md` §3).
///
/// The advice needs no such rule — the region is sized to what it was given.
fn check_io(io: &GuestIo) -> Result<(), EmuError> {
    if io.input.len() > guest_memory::PUBLIC_PAYLOAD_BYTES as usize {
        return Err(EmuError::PublicInputTooLong {
            len: io.input.len(),
        });
    }
    Ok(())
}

/// Run a guest to its `exit`.
pub fn run(image: &ProgramImage, io: &GuestIo) -> Result<Execution, EmuError> {
    check_io(io)?;
    let mut machine = Machine::new(image, io);
    machine.run()?;
    machine.finish()
}

/// Run a guest to its `exit`, recording its trace: the family buffers, the
/// memory event log, the cycle profile, and the same [`Execution`] [`run`]
/// returns.
///
/// `tables` and `config` must be one `program::decode_program` of `image`:
/// every cycle is routed to the family whose table claims its pc, so a pc no
/// table claims — impossible after S11's partition — panics, as does a
/// `config` that describes other families than `tables`.
pub fn trace_run(
    image: &ProgramImage,
    io: &GuestIo,
    tables: &DecodedTables,
    config: &VmConfig,
) -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, Execution), EmuError> {
    assert!(
        tables.families.len() == config.families.len()
            && tables
                .families
                .iter()
                .zip(&config.families)
                .all(|(t, (f, h))| t.family == *f && t.height == *h),
        "trace_run: the decoded tables and the VmConfig describe different VMs"
    );
    check_io(io)?;
    let mut machine = Machine::new(image, io);
    machine.recorder = Some(Recorder::new(
        tables,
        config,
        Keep::Whole(MemoryEventLog::new()),
    ));
    machine.run()?;
    let recorder = machine
        .recorder
        .take()
        .expect("trace_run installed a recorder");
    let execution = machine.finish()?;
    let profile = recorder.profile();
    assert_eq!(
        profile.total(),
        execution.cycle_count,
        "routing: every cycle lands in exactly one family buffer"
    );
    let Keep::Whole(log) = recorder.memory else {
        unreachable!("trace_run keeps the whole log")
    };
    Ok((recorder.traces, log, profile, execution))
}

// ---------------------------------------------------------------------------
// The streaming run
// ---------------------------------------------------------------------------

/// One completed shard's rows, handed back as soon as the family's buffer fills.
///
/// `index` is the shard index `docs/spec/block-proof.md` §5.1 gives it — rows
/// `[index·h, min((index+1)·h, len))` of the family's buffer — so a streaming
/// run's shards are the same shards `trace::plan_shards` counts and the same
/// cut every family fill has made since S16.
pub struct ShardChunk {
    pub family: FamilyId,
    pub index: u32,
    pub rows: ChunkRows,
}

/// A shard's rows, by the kind of family: cycles for a cycle-owning family,
/// invocations for a delegation one. A window family has neither — its rows are
/// addresses, and what fills them is the final [`MemoryState`].
///
/// The cycle arm is boxed because a `FamilyTrace` is 872 bytes of column
/// headers against a `DelegationTrace`'s 80, and one allocation a shard is
/// nothing beside the rows it points at.
pub enum ChunkRows {
    Cycles(Box<FamilyTrace>),
    Invocations(DelegationTrace),
}

/// What a streaming execution leaves behind when it ends: the last-access
/// tables, the cycle profile and the same [`Execution`] [`run`] returns.
///
/// There is no memory event log and no whole-execution buffer here, and that is
/// the point: both are `O(cycles)` — about 300 bytes a cycle between them — and
/// a block of a billion cycles cannot hold either (`docs/spec/streaming.md` §1).
pub struct StreamedExecution {
    pub state: MemoryState,
    pub profile: CycleProfile,
    pub execution: Execution,
}

/// A guest executing under a **pull-based** tracer: the caller steps it, and
/// every time one family's buffer reaches that family's height the buffer is
/// handed over and a fresh one started.
///
/// The live state is one partial buffer per family — at most `height - 1` rows
/// each — plus the last-access tables. Nothing accumulates: a shard the caller
/// takes and drops is gone.
///
/// `tables` and `config` must be one `program::decode_program` of `image`, as
/// [`trace_run`]'s must, and the execution is the same execution: the emulator
/// is a pure function of `(image, io)`, so two runs give identical cycle
/// numbering, identical rows and identical shard boundaries. That is what lets
/// the streaming prover's two passes agree (`docs/spec/streaming.md` §2).
pub struct StreamingRun<'a> {
    machine: Machine<'a>,
}

impl<'a> StreamingRun<'a> {
    pub fn new(
        image: &ProgramImage,
        io: &'a GuestIo,
        tables: &'a DecodedTables,
        config: &VmConfig,
    ) -> Result<StreamingRun<'a>, EmuError> {
        assert!(
            tables.families.len() == config.families.len()
                && tables
                    .families
                    .iter()
                    .zip(&config.families)
                    .all(|(t, (f, h))| t.family == *f && t.height == *h),
            "StreamingRun: the decoded tables and the VmConfig describe different VMs"
        );
        check_io(io)?;
        let mut machine = Machine::new(image, io);
        machine.recorder = Some(Recorder::new(
            tables,
            config,
            Keep::Streaming(MemoryState::new()),
        ));
        Ok(StreamingRun { machine })
    }

    /// Step the guest until at least one shard is ready, or until it exits.
    ///
    /// The shards are returned in the order they filled, which is **not**
    /// statement order: a caller that needs statement order places them by
    /// `(family, index)`. An empty result means the guest has exited and
    /// [`StreamingRun::finish`] is what comes next.
    pub fn next_shards(&mut self) -> Result<Vec<ShardChunk>, EmuError> {
        loop {
            let recorder = self.recorder();
            if !recorder.ready.is_empty() {
                return Ok(std::mem::take(&mut self.recorder().ready));
            }
            if self.machine.exit.is_some() {
                return Ok(Vec::new());
            }
            self.machine.step()?;
        }
    }

    /// The execution's tail: every partial buffer as a final short shard, and
    /// what the execution left behind. Call it after [`StreamingRun::next_shards`]
    /// has returned empty.
    ///
    /// Panics if the guest has not exited: a partial buffer is not a shard
    /// until no more rows can reach it.
    pub fn finish(mut self) -> Result<(Vec<ShardChunk>, StreamedExecution), EmuError> {
        assert!(
            self.machine.exit.is_some(),
            "StreamingRun::finish before the guest exited"
        );
        let mut recorder = self
            .machine
            .recorder
            .take()
            .expect("a streaming run installed a recorder");
        assert!(
            recorder.ready.is_empty(),
            "StreamingRun::finish with {} shards not taken",
            recorder.ready.len()
        );
        let tail = recorder.flush_partial();
        let profile = recorder.profile();
        let execution = self.machine.finish()?;
        assert_eq!(
            profile.total(),
            execution.cycle_count,
            "routing: every cycle lands in exactly one family buffer"
        );
        let Keep::Streaming(state) = recorder.memory else {
            unreachable!("a streaming run keeps the tables alone")
        };
        Ok((
            tail,
            StreamedExecution {
                state,
                profile,
                execution,
            },
        ))
    }

    fn recorder(&mut self) -> &mut Recorder<'a> {
        self.machine
            .recorder
            .as_mut()
            .expect("a streaming run installed a recorder")
    }
}

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

const PAGE: u32 = 4096;

/// What the pc can find in a slot, decoded once up front.
#[derive(Clone, Copy)]
enum Fetch {
    Code(Instr, bool),
    Illegal(u32),
    NotCode,
}

/// One cycle's queries before they are committed, by role:
/// `(address, value read, value written)`.
///
/// `delegation` is the invocation a delegation request made, if any: the
/// family, the frame base, and one `(address, old, new)` per frame word in
/// frame order. It is not a role — 50 frame words do not fit eight — and it is
/// the invocation's row, not the requesting cycle's
/// (`docs/spec/delegation.md` §4).
struct Cycle {
    queries: [Option<(u32, u32, u32)>; 8],
    delegation: Option<Invocation>,
}

/// One delegation invocation: the family, the frame base, one
/// `(address, old, new)` per frame word in frame order, and the accesses a
/// recursion family makes besides its frame, in the family's order.
type Invocation = (FamilyId, u32, Vec<(u32, u32, u32)>, Vec<Option<Extra>>);

/// What a delegation leaves: its frame's `(address, old, new)` words and its
/// other accesses, an [`Invocation`] without the family and the base.
type Delegated = (Vec<(u32, u32, u32)>, Vec<Option<Extra>>);

/// One access a recursion invocation makes besides its frame
/// (`docs/spec/recursion.md` §2.1): a field cell at its slot, or one of
/// `FIELD_IO`'s RAM data words, which take `field_io::DATA_DELTA`.
#[derive(Clone, Copy, Debug)]
enum Extra {
    Cell {
        cell: u32,
        delta: u64,
        old: Fr,
        new: Fr,
    },
    Word {
        addr: u32,
        old: u32,
        new: u32,
    },
}

impl Cycle {
    fn new() -> Cycle {
        Cycle {
            queries: [None; 8],
            delegation: None,
        }
    }

    fn stage(&mut self, role: Role, addr: u32, read: u32, write: u32) {
        let slot = &mut self.queries[role as usize];
        assert!(slot.is_none(), "one cycle issued two {role:?} queries");
        *slot = Some((addr, read, write));
    }
}

struct Machine<'a> {
    code: Vec<Fetch>,
    slot_base: u32,
    regs: [u32; 32],
    pc: u32,
    /// RAM, 4 KiB pages by page number; an absent page is zeros.
    ram: HashMap<u32, Box<[u8; PAGE as usize]>>,
    /// The number the next cycle gets. The first is 1: timestamp 0 is the
    /// initial write of every address, and a cycle-0 pc query could not
    /// strictly follow it.
    cycle: u64,
    /// The public input this run was given: the window's payload, which
    /// `finish` reports as the statement's `input` whether or not the guest
    /// looked (`docs/spec/public-values.md` §9).
    public_input: &'a [u8],
    /// One past the highest advice byte the host supplied, rounded up to a
    /// word: the top of what a guest may load. Above it the advice region is
    /// addressable in principle and initialized by nothing in this execution,
    /// so a read there is refused loudly here rather than left to fail as an
    /// unprovable trace.
    advice_end: u32,
    /// The field memory (`docs/spec/recursion.md` §2): a cell never written
    /// holds 0.
    field: HashMap<u32, Fr>,
    exit: Option<i32>,
    recorder: Option<Recorder<'a>>,
}

impl<'a> Machine<'a> {
    fn new(image: &ProgramImage, io: &'a GuestIo) -> Machine<'a> {
        let code = image
            .slots
            .iter()
            .map(|slot| match *slot {
                Slot::Instruction { word, compressed } => match decode(word) {
                    Ok(instr) => Fetch::Code(instr, compressed),
                    Err(_) => Fetch::Illegal(word),
                },
                Slot::MidInstruction | Slot::NonInstruction => Fetch::NotCode,
            })
            .collect();
        let mut machine = Machine {
            code,
            slot_base: image.slot_base,
            regs: [0; 32],
            pc: image.entry,
            ram: HashMap::new(),
            cycle: 1,
            public_input: &io.input,
            advice_end: guest_memory::ADVICE_ORIGIN
                + 4 * trace::advice_region_words(&io.advice) as u32,
            field: HashMap::new(),
            exit: None,
            recorder: None,
        };
        for segment in &image.segments {
            for (i, byte) in segment.bytes.iter().enumerate() {
                if *byte != 0 {
                    let addr = segment.vaddr + i as u32;
                    let page = machine.page(addr);
                    page[(addr % PAGE) as usize] = *byte;
                }
            }
        }
        // The public input window: word 0 the payload's byte length, then the
        // payload. `program::public_io_words` is the one spelling of the
        // layout, shared with the prover's column builder and the verifier's
        // check, so the three cannot drift. A zero word is skipped, as advice
        // is below: a page that was never written reads 0 anyway, and the
        // window is 4,096 words since S-STREAM where it was 256, nearly all
        // of them padding on a real input.
        for (y, word) in program::public_io_words(&io.input).iter().enumerate() {
            if *word != 0 {
                machine.set_word(guest_memory::PUBLIC_INPUT_ORIGIN + 4 * y as u32, *word);
            }
        }
        // The advice region: its length word, then the payload. Laid out by
        // `trace::advice_word`, the one spelling `guest_sdk::advice` reads
        // back and the prover's fill commits. The journal window starts at 0
        // and stays there until the guest stores into it.
        for y in 0..trace::advice_region_words(&io.advice) {
            let word = trace::advice_word(&io.advice, y);
            if word != 0 {
                machine.set_word(guest_memory::ADVICE_ORIGIN + 4 * y as u32, word);
            }
        }
        machine
    }

    /// The journal at exit: the public output window's length word, then that
    /// many payload bytes (`docs/spec/public-values.md` §3).
    fn journal(&self) -> Result<Vec<u8>, EmuError> {
        let len = self.word(guest_memory::PUBLIC_OUTPUT_ORIGIN);
        if len > guest_memory::PUBLIC_PAYLOAD_BYTES {
            return Err(EmuError::JournalTooLong { len });
        }
        let mut out = Vec::with_capacity(len as usize);
        for y in 0..len.div_ceil(4) {
            let word = self.word(guest_memory::PUBLIC_OUTPUT_ORIGIN + 4 + 4 * y);
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(len as usize);
        Ok(out)
    }

    fn run(&mut self) -> Result<(), EmuError> {
        while self.exit.is_none() {
            self.step()?;
        }
        Ok(())
    }

    fn finish(self) -> Result<Execution, EmuError> {
        let output = self.journal()?;
        Ok(Execution {
            regs: self.regs,
            exit_code: self.exit.expect("an execution finishes at its exit"),
            cycle_count: self.cycle - 1,
            // The public input is what the statement carries, whether or not
            // the guest read a byte of it: it is the window's contents, not a
            // stream cursor.
            io: IoStreams {
                input: self.public_input.to_vec(),
                output,
            },
        })
    }

    fn fetch(&self, pc: u32) -> Result<(Instr, bool), EmuError> {
        let slot = pc
            .checked_sub(self.slot_base)
            .filter(|d| d.is_multiple_of(2))
            .and_then(|d| self.code.get((d / 2) as usize));
        match slot {
            Some(Fetch::Code(instr, compressed)) => Ok((*instr, *compressed)),
            Some(Fetch::Illegal(word)) => Err(EmuError::IllegalInstruction { pc, word: *word }),
            Some(Fetch::NotCode) | None => Err(EmuError::NotAnInstruction { pc }),
        }
    }

    /// One instruction: one cycle, or for a `read`/`write` ecall one cycle
    /// per word moved and then the ecall's own.
    fn step(&mut self) -> Result<(), EmuError> {
        let pc = self.pc;
        let (instr, compressed) = self.fetch(pc)?;
        let fall = pc.wrapping_add(if compressed { 2 } else { 4 });
        if instr == Instr::Ecall {
            return self.ecall(instr, pc, fall);
        }
        let mut cycle = Cycle::new();
        let next_pc = self.execute(&mut cycle, instr, pc, fall)?;
        self.commit(&cycle, instr, pc, next_pc)
    }

    /// Close a cycle: check the clock, hand the queries to the recorder, and
    /// move the pc. The pc query itself — `pc` read, `next_pc` written, at
    /// slot 0 — is the recorder's to log, since every cycle has one.
    fn commit(
        &mut self,
        cycle: &Cycle,
        instr: Instr,
        pc: u32,
        next_pc: u32,
    ) -> Result<(), EmuError> {
        let number = self.cycle;
        if memory::TS_STEP * number + (memory::TS_STEP - 1) >= 1 << memory::TS_BITS {
            return Err(EmuError::ClockOverflow { cycle: number });
        }
        if let Some(recorder) = &mut self.recorder {
            recorder.record(number, pc, next_pc, instr, cycle);
        }
        self.cycle += 1;
        self.pc = next_pc;
        Ok(())
    }

    // -- registers --------------------------------------------------------

    /// Read a register, staging the query: a read, and a write-back of the
    /// same value. `x0` reads 0 like any register holding 0.
    fn read(&mut self, cycle: &mut Cycle, role: Role, r: u8) -> u32 {
        let value = self.regs[r as usize];
        cycle.stage(role, r as u32, value, value);
        value
    }

    /// Write `rd`, staging the query. `x0` logs a write-back of 0 and keeps it.
    fn write(&mut self, cycle: &mut Cycle, rd: u8, value: u32) {
        let old = self.regs[rd as usize];
        let value = if rd == 0 { 0 } else { value };
        cycle.stage(Role::Rd, rd as u32, old, value);
        self.regs[rd as usize] = value;
    }

    // -- memory -----------------------------------------------------------

    fn page(&mut self, addr: u32) -> &mut [u8; PAGE as usize] {
        self.ram
            .entry(addr / PAGE)
            .or_insert_with(|| Box::new([0; PAGE as usize]))
    }

    /// The word at a 4-aligned address.
    fn word(&self, addr: u32) -> u32 {
        match self.ram.get(&(addr / PAGE)) {
            Some(page) => {
                let at = (addr % PAGE) as usize;
                u32::from_le_bytes([page[at], page[at + 1], page[at + 2], page[at + 3]])
            }
            None => 0,
        }
    }

    fn set_word(&mut self, addr: u32, value: u32) {
        let at = (addr % PAGE) as usize;
        self.page(addr)[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// The word a `width`-byte access at `addr` touches, refusing a
    /// misaligned access and one outside the RAM window.
    fn data_word(&self, pc: u32, addr: u32, width: u32) -> Result<u32, EmuError> {
        if !addr.is_multiple_of(width) {
            return Err(EmuError::Misaligned { pc, addr, width });
        }
        let word = addr & !3;
        let reachable = trace::addressable(word)
            && (word < guest_memory::ADVICE_ORIGIN || word < self.advice_end);
        if !reachable {
            return Err(EmuError::OutOfBounds { pc, addr });
        }
        Ok(word)
    }

    /// Read the `words`-word frame at `base`, checking the two frame rules of
    /// `docs/spec/delegation.md` §4, and nothing else checks them: the base is
    /// word-aligned, and the whole frame lies inside the RAM window. Both are
    /// fatal guest errors, as a misaligned load is — the circuit refuses the
    /// same two, so an execution this refuses is one no proof could cover. The
    /// bound is computed in `u64` because `base + frame bytes` wraps a `u32`
    /// at the top of the window, and a wrapped comparison passes a check it
    /// should fail.
    fn delegation_frame(&mut self, pc: u32, base: u32, words: usize) -> Result<Vec<u32>, EmuError> {
        if !base.is_multiple_of(4) {
            return Err(EmuError::Misaligned {
                pc,
                addr: base,
                width: 4,
            });
        }
        let window = guest_memory::RAM_ORIGIN as u64 + guest_memory::RAM_LENGTH as u64;
        if (base as u64) < guest_memory::RAM_ORIGIN as u64
            || base as u64 + 4 * words as u64 > window
        {
            return Err(EmuError::OutOfBounds { pc, addr: base });
        }
        Ok((0..words).map(|j| self.word(base + 4 * j as u32)).collect())
    }

    /// Write a delegation's answer back over its frame, returning the word
    /// queries as `(address, old, new)` in frame order.
    fn delegation_writeback(
        &mut self,
        base: u32,
        old: &[u32],
        new: &[u32],
    ) -> Vec<(u32, u32, u32)> {
        let mut frame = Vec::with_capacity(old.len());
        for j in 0..old.len() {
            let addr = base + 4 * j as u32;
            self.set_word(addr, new[j]);
            frame.push((addr, old[j], new[j]));
        }
        frame
    }

    /// Execute delegation family `family` over the frame at `base`, in place.
    ///
    /// The one dispatch: every delegation number reaches it, and a family with
    /// no arm here is a `DELEGATIONS` row nobody implemented, which is a build
    /// error rather than a silent `-ENOSYS`.
    fn delegate(&mut self, family: FamilyId, pc: u32, base: u32) -> Result<Delegated, EmuError> {
        let words =
            program::delegation_frame_words(family).expect("the caller matched a delegation");
        let old = self.delegation_frame(pc, base, words)?;
        let new = match family {
            family::KECCAK_F => keccak_frame(pc, &old)?,
            family::POSEIDON2 => poseidon2_frame(&old),
            family::FR_ARITH => fr_arith_frame(pc, &old)?,
            family::MOD_MUL => mod_mul_frame(pc, &old)?,
            family::SHA256_COMP => sha256_frame(pc, &old)?,
            family::EC_ADD => ec_add_frame(pc, &old)?,
            // The recursion families' frames are read-only: the frame is the
            // call, and what it computes lands in the field memory or, for an
            // export, in RAM at its own slot.
            family::FR_OP | family::P2_FIELD | family::FIELD_IO => old.clone(),
            other => panic!("emulator: delegation family {other} has no implementation"),
        };
        assert_eq!(new.len(), words, "a delegation writes its whole frame");
        // The frame's slot is the first, so it is written back before an
        // export writes its data words, which may overlap it.
        let frame = self.delegation_writeback(base, &old, &new);
        let extra = match family {
            family::FR_OP => self.fr_op(pc, &old)?,
            family::P2_FIELD => self.p2_field(pc, &old)?,
            family::FIELD_IO => self.field_io(pc, &old)?,
            _ => Vec::new(),
        };
        Ok((frame, extra))
    }

    /// Field cell `cell`'s value.
    fn cell(&self, cell: u32) -> Fr {
        self.field.get(&cell).copied().unwrap_or(Fr::ZERO)
    }

    /// `FR_OP` over `[op, d, a, b]` (`docs/spec/recursion.md` §3): the
    /// accesses `a`, `b`, `d`, each `None` where the op makes none.
    fn fr_op(&mut self, pc: u32, frame: &[u32]) -> Result<Vec<Option<Extra>>, EmuError> {
        use constants::fr_op as f;
        let (op, dc, ac, bc) = (
            frame[f::OP_WORD],
            frame[f::D_WORD],
            frame[f::A_WORD],
            frame[f::B_WORD],
        );
        let (a, b, d) = (self.cell(ac), self.cell(bc), self.cell(dc));
        let imm = Fr::from_u64(bc as u64);
        let (reads_a, reads_b, new) = match op {
            f::MUL => (true, true, Some(a * b)),
            f::ADD => (true, true, Some(a + b)),
            f::SUB => (true, true, Some(a - b)),
            f::MAC => (true, true, Some(d + a * b)),
            f::INV => (true, false, Some(a.inverse().unwrap_or(Fr::ZERO))),
            f::EQ if a == b => (true, true, None),
            f::EQ => {
                return Err(EmuError::DelegationFrame {
                    pc,
                    detail: "EQ's two cells hold different values",
                })
            }
            f::IMM => (false, false, Some(imm)),
            f::SHL => (true, false, Some(a * Fr::from_u64(1 << 32) + imm)),
            _ => {
                return Err(EmuError::DelegationFrame {
                    pc,
                    detail: "the op is not one FR_OP answers",
                })
            }
        };
        if let Some(v) = new {
            self.field.insert(dc, v);
        }
        let read = |cell, delta, v| Extra::Cell {
            cell,
            delta,
            old: v,
            new: v,
        };
        Ok(vec![
            reads_a.then_some(read(ac, f::DELTA_A, a)),
            reads_b.then_some(read(bc, f::DELTA_B, b)),
            new.map(|v| Extra::Cell {
                cell: dc,
                delta: f::DELTA_D,
                old: d,
                new: v,
            }),
        ])
    }

    /// `P2_FIELD` over `[n, s, x, y, d]` (`docs/spec/recursion.md` §4): one
    /// step of `transcript::Transcript`'s duplex from the state at `s` to the
    /// next at `d`. The accesses are the state's three lanes, `x`, `y` and the
    /// next state's three.
    fn p2_field(&mut self, pc: u32, frame: &[u32]) -> Result<Vec<Option<Extra>>, EmuError> {
        use constants::p2_field as f;
        let (n, s, x, y, d) = (
            frame[f::N_WORD],
            frame[f::S_WORD],
            frame[f::X_WORD],
            frame[f::Y_WORD],
            frame[f::D_WORD],
        );
        if n > 2 || s > u32::MAX - f::STATE_CELLS || d > u32::MAX - f::STATE_CELLS {
            return Err(EmuError::DelegationFrame {
                pc,
                detail: "absorbs more than the rate, or its states leave the cells",
            });
        }
        let state = [self.cell(s), self.cell(s + 1), self.cell(s + 2)];
        let (xv, yv) = (self.cell(x), self.cell(y));
        let mut lanes = [
            if n >= 1 { xv } else { state[0] },
            match n {
                2 => yv,
                1 => Fr::ZERO,
                _ => state[1],
            },
            state[2] + Fr::from_u64(n as u64),
        ];
        transcript::poseidon2_permute(&mut lanes);
        let mut out: Vec<Option<Extra>> = (0..3)
            .map(|i| {
                Some(Extra::Cell {
                    cell: s + i as u32,
                    delta: f::DELTA_STATE,
                    old: state[i],
                    new: state[i],
                })
            })
            .collect();
        out.push((n >= 1).then_some(Extra::Cell {
            cell: x,
            delta: f::DELTA_X,
            old: xv,
            new: xv,
        }));
        out.push((n == 2).then_some(Extra::Cell {
            cell: y,
            delta: f::DELTA_Y,
            old: yv,
            new: yv,
        }));
        for (i, lane) in lanes.iter().enumerate() {
            let cell = d + i as u32;
            out.push(Some(Extra::Cell {
                cell,
                delta: f::DELTA_NEXT,
                old: self.cell(cell),
                new: *lane,
            }));
            self.field.insert(cell, *lane);
        }
        Ok(out)
    }

    /// `FIELD_IO` over `[op, cell, ptr]` (`docs/spec/recursion.md` §5): the
    /// eight data words at `ptr`, then the cell.
    fn field_io(&mut self, pc: u32, frame: &[u32]) -> Result<Vec<Option<Extra>>, EmuError> {
        use constants::field_io as f;
        let (op, cell, ptr) = (frame[f::OP_WORD], frame[f::CELL_WORD], frame[f::PTR_WORD]);
        let mut addrs = [0u32; f::DATA_WORDS];
        for (k, addr) in addrs.iter_mut().enumerate() {
            let at = ptr
                .checked_add(4 * k as u32)
                .ok_or(EmuError::OutOfBounds { pc, addr: ptr })?;
            *addr = self.data_word(pc, at, 4)?;
        }
        let words = addrs.map(|addr| self.word(addr));
        let old = self.cell(cell);
        let (new, written) = match op {
            f::IMPORT => {
                let mut v = Fr::ZERO;
                for word in words.iter().rev() {
                    v = v * Fr::from_u64(1 << 32) + Fr::from_u64(*word as u64);
                }
                (v, words)
            }
            f::EXPORT => {
                let bytes = old.to_bytes();
                let limbs = core::array::from_fn(|k| {
                    u32::from_le_bytes(bytes[4 * k..4 * k + 4].try_into().expect("four bytes"))
                });
                (old, limbs)
            }
            _ => {
                return Err(EmuError::DelegationFrame {
                    pc,
                    detail: "the op is not one FIELD_IO answers",
                })
            }
        };
        let mut out: Vec<Option<Extra>> = Vec::with_capacity(f::ACCESSES);
        for k in 0..f::DATA_WORDS {
            self.set_word(addrs[k], written[k]);
            out.push(Some(Extra::Word {
                addr: addrs[k],
                old: words[k],
                new: written[k],
            }));
        }
        self.field.insert(cell, new);
        out.push(Some(Extra::Cell {
            cell,
            delta: f::CELL_DELTA,
            old,
            new,
        }));
        Ok(out)
    }

    /// Replace a word, staging the slot-3 RAM query.
    fn ram_write(&mut self, cycle: &mut Cycle, word: u32, old: u32, new: u32) {
        cycle.stage(Role::Ram, word, old, new);
        self.set_word(word, new);
    }

    // -- instructions -----------------------------------------------------

    /// Every instruction but `ecall`: stage its queries and return `next_pc`.
    fn execute(
        &mut self,
        c: &mut Cycle,
        instr: Instr,
        pc: u32,
        fall: u32,
    ) -> Result<u32, EmuError> {
        use Instr::*;
        let at = |base: u32, imm: i32| base.wrapping_add(imm as u32);
        let mut next = fall;
        match instr {
            Lui { rd, imm } => self.write(c, rd, imm as u32),
            Auipc { rd, imm } => self.write(c, rd, at(pc, imm)),
            Jal { rd, imm } => {
                self.write(c, rd, fall);
                next = at(pc, imm);
            }
            Jalr { rd, rs1, imm } => {
                let base = self.read(c, Role::Rs1, rs1);
                self.write(c, rd, fall);
                next = at(base, imm) & !1;
            }

            Beq { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| a == b)
            }
            Bne { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| a != b)
            }
            Blt { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| {
                    (a as i32) < (b as i32)
                })
            }
            Bge { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| {
                    (a as i32) >= (b as i32)
                })
            }
            Bltu { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| a < b)
            }
            Bgeu { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| a >= b)
            }

            Lb { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 1, |v| v as u8 as i8 as u32)?,
            Lh { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 2, |v| v as u16 as i16 as u32)?,
            Lw { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 4, |v| v)?,
            Lbu { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 1, |v| v as u8 as u32)?,
            Lhu { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 2, |v| v as u16 as u32)?,
            Sb { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 1)?,
            Sh { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 2)?,
            Sw { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 4)?,

            Addi { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a.wrapping_add(i)),
            Slti { rd, rs1, imm } => {
                self.op_imm(c, rd, rs1, imm, |a, i| ((a as i32) < (i as i32)) as u32)
            }
            Sltiu { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| (a < i) as u32),
            Xori { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a ^ i),
            Ori { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a | i),
            Andi { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a & i),
            Slli { rd, rs1, shamt } => self.op_imm(c, rd, rs1, shamt as i32, |a, s| a << s),
            Srli { rd, rs1, shamt } => self.op_imm(c, rd, rs1, shamt as i32, |a, s| a >> s),
            Srai { rd, rs1, shamt } => {
                self.op_imm(c, rd, rs1, shamt as i32, |a, s| ((a as i32) >> s) as u32)
            }

            Add { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_add(b)),
            Sub { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_sub(b)),
            Sll { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a << (b & 31)),
            Slt { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as i32) < (b as i32)) as u32)
            }
            Sltu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| (a < b) as u32),
            Xor { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a ^ b),
            Srl { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a >> (b & 31)),
            Sra { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as i32) >> (b & 31)) as u32)
            }
            Or { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a | b),
            And { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a & b),

            // One hart: a fence orders nothing, and it has no register queries.
            Fence { .. } => {}
            Ebreak => return Err(EmuError::Ebreak { pc }),
            Ecall => unreachable!("ecall is dispatched before execute"),

            Mul { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_mul(b)),
            Mulh { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                ((a as i32 as i64 * b as i32 as i64) >> 32) as u32
            }),
            Mulhsu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                ((a as i32 as i64 * b as i64) >> 32) as u32
            }),
            Mulhu { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as u64 * b as u64) >> 32) as u32)
            }
            Div { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                if b == 0 {
                    u32::MAX
                } else {
                    (a as i32).wrapping_div(b as i32) as u32
                }
            }),
            Divu { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| a.checked_div(b).unwrap_or(u32::MAX))
            }
            Rem { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                if b == 0 {
                    a
                } else {
                    (a as i32).wrapping_rem(b as i32) as u32
                }
            }),
            Remu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.checked_rem(b).unwrap_or(a)),

            LrW { rd, rs1, .. } => {
                let addr = self.read(c, Role::Rs1, rs1);
                let word = self.data_word(pc, addr, 4)?;
                let old = self.word(word);
                self.ram_write(c, word, old, old);
                self.write(c, rd, old);
            }
            ScW { rd, rs1, rs2, .. } => {
                let addr = self.read(c, Role::Rs1, rs1);
                let src = self.read(c, Role::Rs2, rs2);
                let word = self.data_word(pc, addr, 4)?;
                let old = self.word(word);
                self.ram_write(c, word, old, src);
                self.write(c, rd, 0);
            }
            AmoswapW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |_, b| b)?,
            AmoaddW { rd, rs1, rs2, .. } => {
                self.amo(c, pc, rd, rs1, rs2, |a, b| a.wrapping_add(b))?
            }
            AmoxorW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a ^ b)?,
            AmoandW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a & b)?,
            AmoorW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a | b)?,
            AmominW { rd, rs1, rs2, .. } => {
                self.amo(c, pc, rd, rs1, rs2, |a, b| (a as i32).min(b as i32) as u32)?
            }
            AmomaxW { rd, rs1, rs2, .. } => {
                self.amo(c, pc, rd, rs1, rs2, |a, b| (a as i32).max(b as i32) as u32)?
            }
            AmominuW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a.min(b))?,
            AmomaxuW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a.max(b))?,
        }
        Ok(next)
    }

    fn op(&mut self, c: &mut Cycle, rd: u8, rs1: u8, rs2: u8, f: fn(u32, u32) -> u32) {
        let a = self.read(c, Role::Rs1, rs1);
        let b = self.read(c, Role::Rs2, rs2);
        self.write(c, rd, f(a, b));
    }

    fn op_imm(&mut self, c: &mut Cycle, rd: u8, rs1: u8, imm: i32, f: fn(u32, u32) -> u32) {
        let a = self.read(c, Role::Rs1, rs1);
        self.write(c, rd, f(a, imm as u32));
    }

    fn branch(
        &mut self,
        c: &mut Cycle,
        rs1: u8,
        rs2: u8,
        target: u32,
        fall: u32,
        taken: fn(u32, u32) -> bool,
    ) -> u32 {
        let a = self.read(c, Role::Rs1, rs1);
        let b = self.read(c, Role::Rs2, rs2);
        if taken(a, b) {
            target
        } else {
            fall
        }
    }

    /// A load: `rs1` at slot 1, the word at slot 2, `rd` at slot 3.
    /// `extend` gets the word shifted down to the accessed bytes.
    #[allow(clippy::too_many_arguments)]
    fn load(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
        width: u32,
        extend: fn(u32) -> u32,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1).wrapping_add(imm as u32);
        let word = self.data_word(pc, addr, width)?;
        let value = self.word(word);
        c.stage(Role::Load, word, value, value);
        self.write(c, rd, extend(value >> (8 * (addr & 3))));
        Ok(())
    }

    /// A store: `rs1` at slot 1, `rs2` at slot 2, the word at slot 3 with the
    /// stored bytes merged into it.
    fn store(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        rs1: u8,
        rs2: u8,
        imm: i32,
        width: u32,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1).wrapping_add(imm as u32);
        let value = self.read(c, Role::Rs2, rs2);
        let word = self.data_word(pc, addr, width)?;
        let shift = 8 * (addr & 3);
        let mask = (u32::MAX >> (32 - 8 * width)) << shift;
        let old = self.word(word);
        self.ram_write(c, word, old, (old & !mask) | ((value << shift) & mask));
        Ok(())
    }

    /// An AMO: `rs1` at slot 1, `rs2` at slot 2, then at slot 3 the word
    /// rewritten to `f(old, rs2)` and `rd` given the old value.
    fn amo(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
        f: fn(u32, u32) -> u32,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1);
        let src = self.read(c, Role::Rs2, rs2);
        let word = self.data_word(pc, addr, 4)?;
        let old = self.word(word);
        self.ram_write(c, word, old, f(old, src));
        self.write(c, rd, old);
        Ok(())
    }

    // -- ecall ------------------------------------------------------------

    /// An ecall: one row — `a7` at slot 1, its one argument `a0` at slot 2,
    /// `a0` written at slot 3, and `next_pc` the fall-through — except an
    /// exit's, which is the halting sentinel `HALT_PC`
    /// (`docs/spec/memory.md` §5).
    ///
    /// Every ecall a guest may issue takes exactly one argument and moves no
    /// bytes, so an ecall is one cycle. It was not always: `read` and `write`
    /// brought a **transfer cycle** per word they moved, and both those calls
    /// and that machinery went with the POSIX layer.
    fn ecall(&mut self, instr: Instr, pc: u32, fall: u32) -> Result<(), EmuError> {
        let mut row = Cycle::new();
        let number = self.read(&mut row, Role::Rs1, 17);
        let result = match number {
            ecall::EXIT => {
                let status = self.read(&mut row, Role::Rs2, 10);
                self.exit = Some(status as i32);
                status
            }
            // A delegation call: the frame base is its one argument, read as
            // the ABI table says, and the frame is permuted in place. The
            // invocation is not a cycle of its own — it rides this one, at
            // `delegation::FRAME_DELTA` (`docs/spec/delegation.md` §4.1).
            n if program::delegation_family(n).is_some() => {
                let family = program::delegation_family(n).expect("just matched");
                let base = self.read(&mut row, Role::Rs2, 10);
                if let Some(recorder) = &self.recorder {
                    if recorder.traces.delegation(family).is_none() {
                        return Err(EmuError::DelegationFamilyAbsent { pc, number: n });
                    }
                }
                let (frame, extra) = self.delegate(family, pc, base)?;
                // The mirror query: the request consumes the invocation's
                // answer tuple, whose timestamp and value are both 0
                // (`docs/spec/delegation.md` §5). Its write-back is 0 too,
                // which nothing constrains and the honest fill writes.
                row.stage(Role::Delegate, base, 0, 0);
                row.delegation = Some((family, base, frame, extra));
                // `a0` is 0 after a base type, and the base past the frame
                // after a recursion type (`docs/spec/recursion.md` §1.4); the
                // frame was just read, so it lies in RAM.
                let index = program::DELEGATIONS
                    .iter()
                    .position(|(_, number, ..)| *number == n)
                    .expect("just matched");
                constants::delegation::a0_after(index, base)
            }
            _ => ecall::ENOSYS.wrapping_neg(),
        };
        self.write(&mut row, 10, result);
        let next_pc = if number == ecall::EXIT {
            memory::HALT_PC
        } else {
            fall
        };
        self.commit(&row, instr, pc, next_pc)
    }
}

/// **One round** of keccak-f[1600] over the state as 25 little-endian lanes,
/// lane `5y + x` at index `x + 5y`.
///
/// The reference round, written from `docs/spec/delegation.md` §6 and the two
/// tables of `constants::keccak`. Since S26d this — not the whole permutation —
/// is what one delegation invocation performs, so it is the function the
/// `KECCAK_F` circuit is checked against. `crates/guest-sdk` carries its own
/// copy for the software fallback — the two are held bit-identical by
/// `crates/emulator/tests/keccak.rs` and both to `tiny-keccak` — because the
/// SDK builds only for the guest target and is not a workspace member, and a
/// crate whose only purpose was to be shared by two callers would be the
/// abstraction the master's anti-goals refuse.
///
/// Panics on a `round` at or above `constants::keccak::ROUNDS`: there is no
/// round constant for it, and the circuit has no selector for it either.
pub fn keccak_round(lanes: &mut [u64; keccak::LANES], round: usize) {
    // theta
    let mut c = [0u64; 5];
    for (x, c) in c.iter_mut().enumerate() {
        *c = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
    }
    for x in 0..5 {
        let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            lanes[x + 5 * y] ^= d;
        }
    }
    // rho and pi
    let mut b = [0u64; keccak::LANES];
    for x in 0..5 {
        for y in 0..5 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] =
                lanes[x + 5 * y].rotate_left(keccak::ROTATIONS[y][x]);
        }
    }
    // chi
    for x in 0..5 {
        for y in 0..5 {
            lanes[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        }
    }
    // iota
    lanes[0] ^= keccak::ROUND_CONSTANTS[round];
}

/// keccak-f[1600]: [`keccak_round`] twenty-four times.
///
/// No longer what one invocation does — a guest issues 24 of them and the frame
/// chains them — but still the function every oracle compares against, and the
/// one `guest_sdk`'s software fallback computes.
pub fn keccak_f(lanes: &mut [u64; keccak::LANES]) {
    for round in 0..keccak::ROUNDS {
        keccak_round(lanes, round);
    }
}

/// One `KECCAK_F` invocation: the round the frame's word 0 names, applied to the
/// state in words `STATE_WORD..`, written back in place.
///
/// **This family can refuse a frame**, as `MOD_MUL`, `EC_ADD` and, since S26e,
/// `SHA256_COMP` can: a round at or above 24 has no one-hot selector in the
/// circuit, so an executor that answered it would produce a trace no honest
/// prover could prove. The round word is written back unchanged; the guest's own
/// loop is what advances it.
fn keccak_frame(pc: u32, old: &[u32]) -> Result<Vec<u32>, EmuError> {
    let round = old[keccak::ROUND_WORD];
    if round as usize >= keccak::ROUNDS {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "the round word is not a keccak-f round",
        });
    }
    let state: [u32; keccak::STATE_WORDS] = core::array::from_fn(|j| old[keccak::STATE_WORD + j]);
    let mut lanes = lanes_of(&state);
    keccak_round(&mut lanes, round as usize);
    let mut new = Vec::with_capacity(keccak::FRAME_WORDS);
    new.push(round);
    new.extend_from_slice(&words_of(&lanes));
    Ok(new)
}

/// The 50 state words as 25 lanes: state word `2i` is lane `i`'s low half.
pub fn lanes_of(words: &[u32; keccak::STATE_WORDS]) -> [u64; keccak::LANES] {
    core::array::from_fn(|i| words[2 * i] as u64 | (words[2 * i + 1] as u64) << 32)
}

/// The 25 lanes as 50 state words: the inverse of [`lanes_of`].
pub fn words_of(lanes: &[u64; keccak::LANES]) -> [u32; keccak::STATE_WORDS] {
    core::array::from_fn(|j| (lanes[j / 2] >> (32 * (j % 2))) as u32)
}

// ---------------------------------------------------------------------------
// The recorder: the tracing path's one addition
// ---------------------------------------------------------------------------

struct Recorder<'a> {
    tables: &'a DecodedTables,
    /// The execution's memory: every event for [`trace_run`], the last-access
    /// tables alone for a [`StreamingRun`].
    memory: Keep,
    traces: FamilyTraces,
    /// Rows pushed per `traces.families[i]`, flushed shards included, so the
    /// cycle profile survives a buffer being handed away.
    family_rows: Vec<u64>,
    /// The same per `traces.delegations[i]`, whose rows are invocations.
    deleg_rows: Vec<u64>,
    /// Shards a streaming run has filled and the caller has not taken.
    /// [`Keep::Whole`] never fills it: it holds every row to the end.
    ready: Vec<ShardChunk>,
}

/// How much of the memory argument a recorder keeps.
///
/// The events and the last-access tables answer different questions, and only
/// the first grows with the cycle count: the tables are `O(touched addresses)`
/// and are what the register and pc boundary, the RAM windows' teardown columns
/// and the window list are functions of (`docs/spec/streaming.md` §3). So a
/// streaming run keeps the tables and never collects an event at all.
enum Keep {
    /// The whole log, which is the tables plus every event.
    Whole(MemoryEventLog),
    /// The tables alone.
    Streaming(MemoryState),
}

impl Keep {
    fn record(
        &mut self,
        space: AddressSpace,
        addr: u32,
        ts: u64,
        read_value: u32,
        write_value: u32,
    ) -> MemoryEvent {
        match self {
            Keep::Whole(log) => log.record(space, addr, ts, read_value, write_value),
            Keep::Streaming(state) => state.record(space, addr, ts, read_value, write_value),
        }
    }

    fn record_field(&mut self, cell: u32, ts: u64, read: Fr, write: Fr) -> u64 {
        match self {
            Keep::Whole(log) => log.record_field(cell, ts, read, write),
            Keep::Streaming(state) => state.record_field(cell, ts, read, write),
        }
    }
}

impl<'a> Recorder<'a> {
    /// One recorder over `config`'s families: an empty buffer each, in the
    /// config's order, with the delegation families' buffers apart because
    /// their rows are invocations.
    fn new(tables: &'a DecodedTables, config: &VmConfig, memory: Keep) -> Recorder<'a> {
        let traces = FamilyTraces {
            families: config
                .families
                .iter()
                .filter(|(family, _)| program::delegation_frame_words(*family).is_none())
                .map(|(family, height)| FamilyTrace::new(*family, *height))
                .collect(),
            delegations: config
                .families
                .iter()
                .filter_map(|(family, height)| {
                    program::delegation_frame_words(*family)
                        .map(|width| DelegationTrace::new(*family, *height, width))
                })
                .collect(),
        };
        Recorder {
            tables,
            memory,
            family_rows: vec![0; traces.families.len()],
            deleg_rows: vec![0; traces.delegations.len()],
            traces,
            ready: Vec::new(),
        }
    }

    /// Log one cycle's queries — the pc query, then each role's in role
    /// order — and route its row to the family that owns its pc.
    fn record(&mut self, cycle: u64, pc: u32, next_pc: u32, instr: Instr, queries: &Cycle) {
        let base = memory::TS_STEP * cycle;
        self.memory.record(AddressSpace::Pc, 0, base, pc, next_pc);
        // An invocation's frame accesses ride this cycle at
        // `delegation::FRAME_DELTA`, which is 0, so they follow the pc query
        // and precede the row's roles: the log is in timestamp order
        // (`docs/spec/delegation.md` §4.1).
        let mut invocation: Vec<Query> = Vec::new();
        let mut accesses: Vec<Option<Access>> = Vec::new();
        if let Some((_, _, frame, extra)) = &queries.delegation {
            for (addr, read, write) in frame {
                let event = self.memory.record(
                    AddressSpace::Ram,
                    *addr,
                    base + delegation::FRAME_DELTA,
                    *read,
                    *write,
                );
                invocation.push(Query {
                    addr: *addr,
                    read_ts: event.read_ts,
                    read_value: *read,
                    write_value: *write,
                });
            }
            // A recursion invocation's other accesses, in its own slots: a
            // data word is a RAM event at `DATA_DELTA`, which follows the
            // frame's slot and precedes no role of the requesting row in the
            // same space; a cell is the field memory's, ordered per cell
            // (`docs/spec/recursion.md` §2.1).
            for e in extra {
                accesses.push(e.map(|e| match e {
                    Extra::Word { addr, old, new } => {
                        let event = self.memory.record(
                            AddressSpace::Ram,
                            addr,
                            base + constants::field_io::DATA_DELTA,
                            old,
                            new,
                        );
                        Access {
                            addr,
                            read_ts: event.read_ts,
                            read: Fr::from_u64(old as u64),
                            write: Fr::from_u64(new as u64),
                        }
                    }
                    Extra::Cell {
                        cell,
                        delta,
                        old,
                        new,
                    } => Access {
                        addr: cell,
                        read_ts: self.memory.record_field(cell, base + delta, old, new),
                        read: old,
                        write: new,
                    },
                }));
            }
        }
        // The row's mirror query names the delegation family's own anchor
        // space, which the role alone does not say: the invocation riding this
        // cycle does (`trace::Role::space`).
        let delegation = queries.delegation.as_ref().and_then(|(family, ..)| {
            program::delegation_space(*family).and_then(AddressSpace::from_tag)
        });
        let mut row = Row {
            cycle,
            pc,
            next_pc,
            present: 0,
            queries: [Query::ABSENT; 8],
        };
        for role in ROLES {
            if let Some((addr, read, write)) = queries.queries[role as usize] {
                let event = self.memory.record(
                    role.space(delegation),
                    addr,
                    base + role.delta(),
                    read,
                    write,
                );
                row.queries[role as usize] = Query {
                    addr,
                    read_ts: event.read_ts,
                    read_value: read,
                    write_value: write,
                };
                row.present |= 1 << role as u8;
            }
        }
        if let Some((family, frame_base, ..)) = &queries.delegation {
            let at = self
                .traces
                .delegations
                .iter()
                .position(|t| t.family == *family)
                .expect("the ecall checked the family is in the config");
            self.traces.delegations[at].push(cycle, *frame_base, &invocation, &accesses);
            self.deleg_rows[at] += 1;
            self.flush_delegation(at);
        }
        let owner = self.owner(pc, instr);
        let at = self
            .traces
            .families
            .iter()
            .position(|t| t.family == owner)
            .expect("the owning family has a buffer");
        self.traces.families[at].push(&row);
        self.family_rows[at] += 1;
        self.flush_family(at);
    }

    /// Hand `traces.families[at]` away if it has just reached its height, so a
    /// partial buffer never holds more than `height - 1` rows at a record
    /// boundary — which is what makes a shard's rows exactly the cut
    /// `docs/spec/block-proof.md` §5.1 defines, with nothing to split.
    ///
    /// A whole-run recorder flushes nothing: `Keep::Whole` is the archive's
    /// input and holds every row.
    fn flush_family(&mut self, at: usize) {
        if !matches!(self.memory, Keep::Streaming(_)) {
            return;
        }
        let buffer = &mut self.traces.families[at];
        let height = buffer.height as usize;
        if buffer.len() < height {
            return;
        }
        let (family, rows) = (buffer.family, self.family_rows[at]);
        let full = std::mem::replace(buffer, FamilyTrace::new(family, height as u32));
        self.ready.push(ShardChunk {
            family,
            index: (rows / height as u64 - 1) as u32,
            rows: ChunkRows::Cycles(Box::new(full)),
        });
    }

    /// [`Recorder::flush_family`] for a delegation family, whose rows are
    /// invocations.
    fn flush_delegation(&mut self, at: usize) {
        if !matches!(self.memory, Keep::Streaming(_)) {
            return;
        }
        let buffer = &mut self.traces.delegations[at];
        let height = buffer.height as usize;
        if buffer.len() < height {
            return;
        }
        let (family, rows, width) = (buffer.family, self.deleg_rows[at], buffer.words.len());
        let full = std::mem::replace(buffer, DelegationTrace::new(family, height as u32, width));
        self.ready.push(ShardChunk {
            family,
            index: (rows / height as u64 - 1) as u32,
            rows: ChunkRows::Invocations(full),
        });
    }

    /// Every partial buffer as a final shard, in family order: what an
    /// execution's last, short shard of each family is.
    fn flush_partial(&mut self) -> Vec<ShardChunk> {
        let mut out = Vec::new();
        for (at, buffer) in self.traces.families.iter_mut().enumerate() {
            if buffer.is_empty() {
                continue;
            }
            let (family, height) = (buffer.family, buffer.height);
            let full = std::mem::replace(buffer, FamilyTrace::new(family, height));
            out.push(ShardChunk {
                family,
                index: (self.family_rows[at] / height as u64) as u32,
                rows: ChunkRows::Cycles(Box::new(full)),
            });
        }
        for (at, buffer) in self.traces.delegations.iter_mut().enumerate() {
            if buffer.is_empty() {
                continue;
            }
            let (family, height, width) = (buffer.family, buffer.height, buffer.words.len());
            let full = std::mem::replace(buffer, DelegationTrace::new(family, height, width));
            out.push(ShardChunk {
                family,
                index: (self.deleg_rows[at] / height as u64) as u32,
                rows: ChunkRows::Invocations(full),
            });
        }
        out
    }

    /// The execution's cycle profile: every buffer's total row count, flushed
    /// shards included, ascending by family id — the shape
    /// `FamilyTraces::row_counts` has.
    fn profile(&self) -> CycleProfile {
        let mut counts: Vec<(FamilyId, u64)> = self
            .traces
            .families
            .iter()
            .zip(&self.family_rows)
            .map(|(t, n)| (t.family, *n))
            .chain(
                self.traces
                    .delegations
                    .iter()
                    .zip(&self.deleg_rows)
                    .map(|(t, n)| (t.family, *n)),
            )
            .collect();
        counts.sort_by_key(|(f, _)| *f);
        CycleProfile { counts }
    }

    /// The one family whose table claims `pc`.
    ///
    /// By family id rather than by position: a delegation family is in the
    /// decoded tables — with an empty table, claiming nothing — but its buffer
    /// is a `DelegationTrace`, so the two lists no longer line up by index.
    fn owner(&self, pc: u32, instr: Instr) -> FamilyId {
        let row = (pc / 2) as usize;
        let mut owners = self
            .tables
            .families
            .iter()
            .enumerate()
            .filter(|(_, t)| t.is_live(row));
        let (_at, table) = owners.next().unwrap_or_else(|| {
            panic!(
                "routing: pc {pc:#010x} is claimed by no family, so the decoded tables \
                 are not this program's"
            )
        });
        assert!(
            owners.next().is_none(),
            "routing: pc {pc:#010x} is claimed by two families"
        );
        assert_eq!(
            table.family,
            row_kind(&instr).0,
            "routing: the table claiming pc {pc:#010x} is not the family of the \
             instruction there"
        );
        table.family
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loader::Segment;

    /// The reduction against `u128` arithmetic, which is an independent
    /// reference for every case a `u128` can hold.
    ///
    /// It drives [`reduce`] rather than [`mod_mul_frame`], because none of the
    /// four selectable moduli fits a `u128` and an oracle written in the same
    /// 16-limb arithmetic as the thing it checks is not an oracle. That is the
    /// whole reason the reduction is a function of its own.
    #[test]
    fn the_reduction_agrees_with_u128() {
        for (x, m) in [
            (0u128, 1u128),
            (12345, 97),
            (1, 2),
            ((u64::MAX as u128) * (u64::MAX as u128), (1u128 << 61) - 1),
            (63, 5),
            (42, 42),
            (0xdead_beef * 0xfeed_face, 0xffff_fffb),
            (u128::MAX, (1u128 << 64) - 59),
        ] {
            let mut product = [0u64; 2 * mod_mul::LIMBS];
            for (k, lane) in product.iter_mut().take(4).enumerate() {
                *lane = ((x >> (32 * k)) & 0xffff_ffff) as u64;
            }
            let m_limbs: [u64; mod_mul::LIMBS] = core::array::from_fn(|k| match k < 4 {
                true => ((m >> (32 * k)) & 0xffff_ffff) as u64,
                false => 0,
            });
            let rem = reduce(&product, &m_limbs);
            let got = (0..4).fold(0u128, |acc, k| acc | (rem[k] as u128) << (32 * k));
            assert_eq!(got, x % m, "{x} mod {m}");
            for lane in &rem[4..] {
                assert_eq!(*lane, 0, "the remainder fits 128 bits");
            }
        }
    }

    /// One SHA-256 compression as sixteen invocations, against FIPS 180-4.
    ///
    /// `abc` padded to 64 bytes, from the FIPS initial state: the working
    /// variables after the first call are the appendix's after round 3, the
    /// window moves down four words with `W_16..W_19` appended, and the sum of
    /// the sixteenth call's working variables and the initial state is the
    /// published digest `ba7816bf…`. A group word of 16 is refused.
    #[test]
    fn sha256_frame_compresses_the_published_test_vector() {
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24; // the bit length, big-endian
        let mut frame = vec![0u32; sha256::FRAME_WORDS];
        frame[sha256::STATE_WORD..sha256::WINDOW_WORD].copy_from_slice(&sha256::IV);
        for i in 0..sha256::BLOCK_WORDS {
            frame[sha256::WINDOW_WORD + i] =
                u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
        }
        let window_in = frame[sha256::WINDOW_WORD..].to_vec();
        for group in 0..sha256::GROUPS as u32 {
            frame[sha256::GROUP_WORD] = group;
            frame = sha256_frame(0, &frame).expect("a group below 16");
            if group == 0 {
                // FIPS 180-4's own appendix prints the working variables after
                // every round of this block; after round 3 they are these.
                assert_eq!(
                    &frame[sha256::STATE_WORD..sha256::WINDOW_WORD],
                    &[
                        0xd550_f666,
                        0xc8c3_47a7,
                        0x5a6a_d9ad,
                        0x5d6a_ebcd,
                        0x24e0_0850,
                        0xf929_39eb,
                        0x78ce_7989,
                        0xfa2a_4622,
                    ],
                    "the working variables after the first call's four rounds"
                );
                assert_eq!(
                    &frame[sha256::WINDOW_WORD..sha256::WINDOW_WORD + 12],
                    &window_in[4..],
                    "the window moves down four words"
                );
                assert_eq!(
                    &frame[sha256::WINDOW_WORD + 12..],
                    &[0x6162_6380, 0x000f_0000, 0x7da8_6405, 0x6000_03c6],
                    "W_16..W_19 for this block"
                );
            }
            assert_eq!(
                frame[sha256::GROUP_WORD],
                group,
                "the group is written back"
            );
        }
        let digest: Vec<u32> = (0..sha256::STATE_WORDS)
            .map(|j| sha256::IV[j].wrapping_add(frame[sha256::STATE_WORD + j]))
            .collect();
        let want = [
            0xba78_16bf_u32,
            0x8f01_cfea,
            0x4141_40de,
            0x5dae_2223,
            0xb003_61a3,
            0x9617_7a9c,
            0xb410_ff61,
            0xf200_15ad,
        ];
        assert_eq!(digest, want, "the `abc` digest");
        frame[sha256::GROUP_WORD] = sha256::GROUPS as u32;
        assert!(
            sha256_frame(0, &frame).is_err(),
            "a group at 16 has no selector, so no answer"
        );
    }

    /// The three invocations of one point addition, against **this
    /// repository's own** BN254 G1 arithmetic.
    ///
    /// `curve::G1Projective` is Jacobian — `(X/Z^2, Y/Z^3)` — and this
    /// delegation is homogeneous projective, so the two share no formula. They
    /// are compared on the result cross-multiplied against the oracle's affine
    /// one, which needs no inversion. The identity, `-P`, `P + P` and a
    /// non-normalized `Z` are all in the grid, because the completeness of
    /// Renes-Costello-Batina Algorithm 7 is exactly what lets the guest branch
    /// on nothing.
    #[test]
    fn ec_add_frame_is_this_crate_s_own_bn254_group_law() {
        use curve::{G1Affine, G1Projective};

        let m: Wide = {
            let sel = ec_add::modulus(ec_add::BN254_G1).unwrap();
            core::array::from_fn(|k| sel[k] as u64)
        };
        let limbs_of = |bytes: &[u8], at: usize| -> Wide {
            core::array::from_fn(|k| {
                u32::from_le_bytes(bytes[at + 4 * k..at + 4 * k + 4].try_into().unwrap()) as u64
            })
        };
        // A point as the frame carries it: `(x : y : 1)`, or `(0 : 1 : 0)` for
        // the identity, optionally scaled by `lambda` to test that a
        // non-normalized representative comes out the same.
        let frame_point = |a: &G1Affine, lambda: u32| -> [Wide; 3] {
            if a.infinity {
                let mut one = [0u64; ec_add::LIMBS];
                one[0] = 1;
                return [[0u64; ec_add::LIMBS], one, [0u64; ec_add::LIMBS]];
            }
            let bytes = a.to_bytes();
            let (x, y) = (limbs_of(&bytes, 0), limbs_of(&bytes, 32));
            let mut z = [0u64; ec_add::LIMBS];
            z[0] = 1;
            if lambda == 1 {
                [x, y, z]
            } else {
                [
                    scale_mod(lambda, &x, &m),
                    scale_mod(lambda, &y, &m),
                    scale_mod(lambda, &z, &m),
                ]
            }
        };
        let projective = |a: &G1Affine| -> G1Projective { G1Projective::IDENTITY.add_affine(a) };

        // The delegation, run as the guest runs it: three invocations in
        // ascending group order over one frame.
        let run = |p: [Wide; 3], q: [Wide; 3]| -> Vec<u32> {
            let mut frame = vec![0u32; ec_add::FRAME_WORDS];
            for (first, v) in [
                (ec_add::X1_WORD, p[0]),
                (ec_add::Y1_WORD, p[1]),
                (ec_add::Z1_WORD, p[2]),
                (ec_add::X2_WORD, q[0]),
                (ec_add::Y2_WORD, q[1]),
                (ec_add::Z2_WORD, q[2]),
            ] {
                for k in 0..ec_add::LIMBS {
                    frame[first + k] = v[k] as u32;
                }
            }
            for code in [ec_add::BN254_G1, ec_add::BN254_G2, ec_add::BN254_G3] {
                frame[ec_add::SELECTOR_WORD] = code;
                frame = ec_add_frame(0, &frame).expect("a canonical frame");
            }
            frame
        };

        // The grid: the identity, `G` through `7G`, and `-G`.
        let g = G1Affine::GENERATOR;
        let mut points = vec![G1Affine::IDENTITY, g];
        let mut acc = projective(&g);
        for _ in 0..6 {
            acc = acc.add_affine(&g);
            points.push(acc.to_affine());
        }
        points.push(G1Affine {
            x: g.x,
            y: -g.y,
            infinity: false,
        });

        let mut checked = 0;
        for (i, p) in points.iter().enumerate() {
            for q in points.iter() {
                // Every fourth pair goes in with a scaled `Z`, so the
                // projective-invariance of the formula is exercised without
                // quadrupling the run.
                let lambda = if i % 4 == 3 { 7 } else { 1 };
                let frame = run(frame_point(p, lambda), frame_point(q, 1));
                let got =
                    |first: usize| -> Wide { core::array::from_fn(|k| frame[first + k] as u64) };
                let (x3, y3, z3) = (
                    got(ec_add::X1_WORD),
                    got(ec_add::Y1_WORD),
                    got(ec_add::Z1_WORD),
                );
                let want = projective(p).add(&projective(q));
                checked += 1;
                if want.is_identity() {
                    assert_eq!(z3, [0u64; ec_add::LIMBS], "P + (-P) is the identity");
                    continue;
                }
                let bytes = want.to_affine().to_bytes();
                let (xa, ya) = (limbs_of(&bytes, 0), limbs_of(&bytes, 32));
                // `(X3 : Y3 : Z3) == (x : y : 1)` iff `X3 == x*Z3` and
                // `Y3 == y*Z3`, which needs no inversion.
                assert_eq!(x3, mul_mod(&xa, &z3, &m), "X3");
                assert_eq!(y3, mul_mod(&ya, &z3, &m), "Y3");
            }
        }
        assert_eq!(checked, points.len() * points.len());
    }

    /// Every bad `EC_ADD` frame is refused by name, not by a gate hours later.
    #[test]
    fn ec_add_frame_refuses_a_bad_selector_and_an_unreduced_coordinate() {
        let mut frame = vec![0u32; ec_add::FRAME_WORDS];
        frame[ec_add::SELECTOR_WORD] = 0;
        assert!(ec_add_frame(4, &frame).is_err(), "selector 0 names nothing");
        frame[ec_add::SELECTOR_WORD] = 99;
        assert!(ec_add_frame(4, &frame).is_err(), "a code nothing names");

        // The modulus itself is not below the modulus.
        frame[ec_add::SELECTOR_WORD] = ec_add::SECP256K1_G1;
        let m = ec_add::modulus(ec_add::SECP256K1_G1).unwrap();
        frame[ec_add::X1_WORD..ec_add::X1_WORD + 8].copy_from_slice(&m);
        match ec_add_frame(4, &frame) {
            Err(EmuError::DelegationFrame { detail, .. }) => {
                assert!(detail.contains("x1"), "named the coordinate: {detail}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// `mod_mul_frame` over **every** selectable modulus, held to the identity
    /// `a·b = q·m + out` with `out < m` over the full 256-bit width.
    ///
    /// The small-operand oracle above cannot reach here — these moduli are 254
    /// and 256 bits — so what stands in for it is the identity itself,
    /// recomputed from the frame the executor wrote by this file's own
    /// `wide_mul16`, `sub16` and `divides16`, which share no line with the
    /// reduction. Two operand shapes per modulus: pseudo-random values below
    /// `2^253`, which every modulus exceeds, and `m − 1` squared — the largest
    /// operand the frame admits, and the one a bound off by one would break.
    #[test]
    fn mod_mul_frame_computes_a_times_b_mod_the_selected_modulus() {
        let frame_of = |code: u32, a: [u32; 8], b: [u32; 8]| -> Vec<u32> {
            let mut old = vec![0u32; mod_mul::FRAME_WORDS];
            old[mod_mul::SELECTOR_WORD] = code;
            old[mod_mul::A_WORD..mod_mul::A_WORD + 8].copy_from_slice(&a);
            old[mod_mul::B_WORD..mod_mul::B_WORD + 8].copy_from_slice(&b);
            mod_mul_frame(0, &old).expect("a legal selector and reduced operands")
        };
        let mut seed = 0x0123_4567_89ab_cdefu64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for (code, m) in mod_mul::CODES.iter().zip(mod_mul::MODULI.iter()) {
            let mut minus_one = *m;
            minus_one[0] -= 1; // every modulus here is odd
            let mut cases: Vec<([u32; 8], [u32; 8])> = vec![(minus_one, minus_one)];
            for _ in 0..4 {
                let mut wide = || -> [u32; 8] {
                    let mut v: [u32; 8] = core::array::from_fn(|_| next() as u32);
                    v[7] &= 0x1fff_ffff; // below 2^253, and every modulus is above it
                    v
                };
                cases.push((wide(), wide()));
            }
            for (a, b) in cases {
                let out = frame_of(*code, a, b);
                let result: [u32; 8] = core::array::from_fn(|k| out[mod_mul::OUT_WORD + k]);
                assert!(
                    super::less_than(
                        &core::array::from_fn(|k| result[k] as u64),
                        &core::array::from_fn(|k| m[k] as u64)
                    ),
                    "the result is reduced under selector {code}"
                );
                let mut left = wide_mul16(&a, &b);
                sub16(&mut left, &result);
                assert!(divides16(&left, m), "a·b − out is a multiple of m");
                // Every word but the result's is written back, the selector
                // included: an invocation that could rewrite word 0 would be
                // reporting a field it was not asked for.
                let mut old = [0u32; mod_mul::FRAME_WORDS];
                old[mod_mul::SELECTOR_WORD] = *code;
                old[mod_mul::A_WORD..mod_mul::A_WORD + 8].copy_from_slice(&a);
                old[mod_mul::B_WORD..mod_mul::B_WORD + 8].copy_from_slice(&b);
                for j in 0..mod_mul::OUT_WORD {
                    assert_eq!(out[j], old[j], "word {j} is written back unchanged");
                }
            }
        }
    }

    /// The three frames the executor refuses by name, each one the circuit has
    /// no witness for: an unknown selector, and either operand at or above the
    /// selected modulus.
    ///
    /// Without these the long division answers correctly, the guest exits
    /// clean, and the only thing that fails is a gate — anonymously, inside a
    /// block proof. `docs/spec/delegation.md` §14.
    #[test]
    fn mod_mul_refuses_a_frame_no_proof_could_cover() {
        let frame = |code: u32, a: [u32; 8], b: [u32; 8]| -> Vec<u32> {
            let mut old = vec![0u32; mod_mul::FRAME_WORDS];
            old[mod_mul::SELECTOR_WORD] = code;
            old[mod_mul::A_WORD..mod_mul::A_WORD + 8].copy_from_slice(&a);
            old[mod_mul::B_WORD..mod_mul::B_WORD + 8].copy_from_slice(&b);
            old
        };
        let p = mod_mul::MODULI[0];
        let small = [1u32, 0, 0, 0, 0, 0, 0, 0];
        // A selector the table does not hold — 0, which is what a caller that
        // forgot the modulus leaves behind, and one past the last code.
        for code in [0, mod_mul::CODES[mod_mul::CODES.len() - 1] + 1, 0xffff_ffff] {
            assert_eq!(
                mod_mul_frame(0x1234, &frame(code, small, small)),
                Err(EmuError::DelegationFrame {
                    pc: 0x1234,
                    detail: "the modulus selector names no field",
                }),
                "selector {code}"
            );
        }
        // An operand exactly at the modulus, which is the case the vendored
        // `k256` patch produces whenever a field difference is zero.
        assert_eq!(
            mod_mul_frame(8, &frame(mod_mul::SECP256K1_P, p, small)),
            Err(EmuError::DelegationFrame {
                pc: 8,
                detail: "operand a is not below the modulus",
            })
        );
        assert_eq!(
            mod_mul_frame(8, &frame(mod_mul::SECP256K1_P, small, p)),
            Err(EmuError::DelegationFrame {
                pc: 8,
                detail: "operand b is not below the modulus",
            })
        );
        // And `m − 1` on both sides is admitted, so the bound is `< m` and not
        // something one short of it.
        let mut minus_one = p;
        minus_one[0] -= 1;
        assert!(mod_mul_frame(8, &frame(mod_mul::SECP256K1_P, minus_one, minus_one)).is_ok());
    }

    /// `x · y` over eight 32-bit limbs, as sixteen. Test-only.
    fn wide_mul16(x: &[u32; 8], y: &[u32; 8]) -> [u32; 16] {
        let mut out = [0u64; 16];
        for i in 0..8 {
            let mut carry = 0u64;
            for j in 0..8 {
                let total = out[i + j] + x[i] as u64 * y[j] as u64 + carry;
                out[i + j] = total & 0xffff_ffff;
                carry = total >> 32;
            }
            let mut at = i + 8;
            while carry != 0 {
                let total = out[at] + carry;
                out[at] = total & 0xffff_ffff;
                carry = total >> 32;
                at += 1;
            }
        }
        core::array::from_fn(|k| out[k] as u32)
    }

    /// `x -= y` over sixteen limbs against eight. Test-only.
    fn sub16(x: &mut [u32; 16], y: &[u32; 8]) {
        let mut borrow = 0i64;
        for k in 0..16 {
            let sub = if k < 8 { y[k] as i64 } else { 0 };
            let d = x[k] as i64 - sub - borrow;
            borrow = i64::from(d < 0);
            x[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u32;
        }
        assert_eq!(borrow, 0, "a·b is at least the remainder");
    }

    /// Whether `x` is a multiple of `m`, by long division. Test-only.
    fn divides16(x: &[u32; 16], m: &[u32; 8]) -> bool {
        let mut rem = [0u64; 9];
        for bit in (0..32 * 16).rev() {
            let mut carry = ((x[bit / 32] >> (bit % 32)) & 1) as u64;
            for word in rem.iter_mut() {
                let total = (*word << 1) | carry;
                *word = total & 0xffff_ffff;
                carry = total >> 32;
            }
            let ge = rem[8] != 0
                || (0..8)
                    .rev()
                    .find(|k| rem[*k] != m[*k] as u64)
                    .is_none_or(|k| rem[k] > m[k] as u64);
            if ge {
                let mut borrow = 0i64;
                for k in 0..8 {
                    let d = rem[k] as i64 - m[k] as i64 - borrow;
                    borrow = i64::from(d < 0);
                    rem[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u64;
                }
                rem[8] -= borrow as u64;
            }
        }
        rem.iter().all(|w| *w == 0)
    }

    /// `addi a0, a0, 1` then `jal x0, -4`: an endless loop, two cycles a lap.
    fn spin() -> ProgramImage {
        let words: [u32; 2] = [0x0015_0513, 0xffdf_f06f];
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        ProgramImage {
            entry: guest_memory::RAM_ORIGIN,
            segments: vec![Segment {
                vaddr: guest_memory::RAM_ORIGIN,
                mem_len: 8,
                bytes,
            }],
            slot_base: guest_memory::RAM_ORIGIN,
            slots: vec![
                Slot::Instruction {
                    word: words[0],
                    compressed: false,
                },
                Slot::MidInstruction,
                Slot::Instruction {
                    word: words[1],
                    compressed: false,
                },
                Slot::MidInstruction,
            ],
        }
    }

    /// The last cycle whose four timestamps fit the 38-bit clock runs; the
    /// next is refused, by name, before anything is recorded for it.
    #[test]
    fn the_clock_refuses_the_first_cycle_past_38_bits() {
        let io = GuestIo {
            input: Vec::new(),
            advice: Vec::new(),
        };
        let image = spin();
        let mut machine = Machine::new(&image, &io);
        let last = (1u64 << (memory::TS_BITS - 2)) - 1;
        machine.cycle = last;
        machine
            .step()
            .expect("cycle 2^36 - 1 ends at ts 2^38 - 1, on the clock");
        assert_eq!(
            machine.step(),
            Err(EmuError::ClockOverflow { cycle: last + 1 })
        );
    }
}
