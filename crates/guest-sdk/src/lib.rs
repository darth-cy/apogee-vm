#![no_std]
//! The guest-side runtime: crt0, the entry macro, a bump allocator, a panic
//! handler and the ecall shims.
//!
//! Everything here runs *inside* the proof. It compiles only for
//! `riscv32imac-unknown-none-elf` and links only into guest binaries.
//!
//! # The ABI in one paragraph
//!
//! An ecall carries its number in `a7`, arguments in `a0`-`a5`, and its result
//! in `a0`, with errors as a negated errno — the Linux RISC-V convention, so
//! `qemu-riscv32` runs a guest unmodified. The standard calls keep their Linux
//! numbers. zkVM I/O is expressed with those calls over four fixed file
//! descriptors: fd 0 public input, fd 1 public output, fd 2 diagnostics, fd 3
//! private hints. `docs/spec/ecall-abi.md` is the normative table and every
//! number below comes from [`constants::ecall`].
//!
//! # Two anti-goals this crate is exempt from, and why
//!
//! Master anti-goal 4 bans `unsafe` and anti-goal 7 bans global mutable state.
//! A startup stub, a `#[global_allocator]` and a syscall shim cannot be written
//! without both. Master rule 13 applies: the stage names these deliverables, so
//! the stage wins and the deviation is recorded here and in
//! `docs/handoff/S10-toolchain.md`. Every `unsafe` block in the workspace lives
//! in this file. Nothing else in the repository is allowed to follow suit.

use core::alloc::{GlobalAlloc, Layout};
use core::arch::global_asm;

use constants::{delegation, ecall, ecrecover, guest_memory, keccak, secp256k1};

// ---------------------------------------------------------------------------
// crt0
// ---------------------------------------------------------------------------

// `_start` sits in its own `.text._start` section so the linker script places
// it first, at ORIGIN(RAM). It does exactly four things: point `sp` at
// `__stack_top`, zero `.bss`, call `main`, and exit(0) if `main` returns.
//
// The `.bss` loop is byte-wise on purpose. `__bss_start` is aligned to the
// output section's alignment and `__bss_end` is not aligned at all, so a
// word-wise loop would need bounds this script does not promise. Guests have
// kilobytes of `.bss`, not megabytes.
//
// The zeroing is kept even though VM memory starts zeroed: the same binary
// must run correctly under QEMU, where it does not, and QEMU is the only
// executor this stage has.
//
// The trailing `j .` is unreachable — `exit` does not return under any
// executor — and exists so a hypothetical returning `exit` cannot fall into
// whatever follows.
global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    "  la   sp, __stack_top",
    "  la   t0, __bss_start",
    "  la   t1, __bss_end",
    "1:",
    "  bgeu t0, t1, 2f",
    "  sb   zero, 0(t0)",
    "  addi t0, t0, 1",
    "  j    1b",
    "2:",
    "  call main",
    "  li   a0, 0",
    "  li   a7, {exit}",
    "  ecall",
    "3:",
    "  j    3b",
    exit = const ecall::EXIT,
);

/// Give a function the `main` symbol that crt0 calls.
///
/// ```ignore
/// #![no_std]
/// #![no_main]
///
/// guest_sdk::entry!(main);
///
/// fn main() {
///     // ...
/// }
/// ```
///
/// The named function keeps its own name and may be called `main`: what this
/// emits is a separate wrapper carrying the exported symbol, so the two never
/// collide. The function takes no arguments and returns `()`; returning from it
/// is an `exit(0)`.
///
/// This is a `macro_rules!` and not the `#[entry]` attribute the stage prompt
/// names, because an attribute macro requires a `proc-macro` crate — which
/// cannot export anything else, so it would mean a second package for the sake
/// of one spelling. Recorded in `docs/handoff/S10-toolchain.md`.
#[macro_export]
macro_rules! entry {
    ($f:ident) => {
        #[export_name = "main"]
        pub extern "C" fn __apogee_guest_entry() {
            $f()
        }
    };
}

// ---------------------------------------------------------------------------
// Raw ecall
// ---------------------------------------------------------------------------

// One shim per argument count, rather than one six-argument shim with zeroes
// passed in: an unused `in(...)` register is still a constraint on the
// register allocator, and three near-identical eight-line functions are easier
// to read than a macro that generates them.
//
// No `options(...)`: the default is the conservative one. A `read` writes
// through a pointer we handed the executor, so the compiler must not assume
// this asm leaves memory alone.
//
// No clobber list either, and that is a load-bearing assumption rather than an
// omission: **an ecall preserves every register except `a0`**, which
// `docs/spec/ecall-abi.md` section 1 states as part of the frozen ABI. A
// precompile circuit that scratched `t0` would produce silently wrong guest
// arithmetic, which is why the rule is written down there and not only here.

/// `ecall` with three arguments.
///
/// # Safety
/// The caller guarantees that `num` names a call whose contract is satisfied by
/// `a0`, `a1` and `a2` — in particular that any pointer among them is valid for
/// the access that call performs.
unsafe fn ecall3(num: u32, a0: u32, a1: u32, a2: u32) -> i32 {
    let ret: i32;
    core::arch::asm!(
        "ecall",
        in("a7") num,
        inlateout("a0") a0 => ret,
        in("a1") a1,
        in("a2") a2,
    );
    ret
}

/// `ecall` with one argument.
///
/// # Safety
/// As [`ecall3`].
unsafe fn ecall1(num: u32, a0: u32) -> i32 {
    let ret: i32;
    core::arch::asm!(
        "ecall",
        in("a7") num,
        inlateout("a0") a0 => ret,
    );
    ret
}

// ---------------------------------------------------------------------------
// The I/O shims
// ---------------------------------------------------------------------------

/// Read from `fd` into `buf` until it is full or the stream ends.
///
/// Returns the number of bytes read, which is `buf.len()` unless the stream
/// ended first. A short `read` is not an end of stream, so this loops.
///
/// **The returned count is checked against the buffer.** The executor is the
/// prover, so `a0` is a value an adversary picks; a count larger than the space
/// offered would make `filled` run past `buf.len()`, and every caller — which
/// then slices `buf[..n]` — would panic. A negative return and an over-large
/// one are the same class of executor-level failure and take the same exit.
fn read_fd(fd: u32, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        // SAFETY: `buf[filled..]` is a live, writable slice of exactly the
        // length passed as the count, and `READ`'s contract is to write at most
        // that many bytes through the pointer.
        let n = unsafe {
            ecall3(
                ecall::READ,
                fd,
                buf[filled..].as_mut_ptr() as u32,
                (buf.len() - filled) as u32,
            )
        };
        if n < 0 || n as usize > buf.len() - filled {
            exit(EXIT_IO_ERROR);
        }
        if n == 0 {
            break;
        }
        filled += n as usize;
    }
    filled
}

/// Write all of `bytes` to `fd`.
///
/// The returned count is checked against what was offered, for the reason
/// [`read_fd`]'s is: an executor that claims to have written more than it was
/// asked would end this loop early, and `commit` would return having delivered
/// fewer bytes to the public journal than the guest believes it did.
fn write_fd(fd: u32, bytes: &[u8]) {
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: `bytes[written..]` is a live, readable slice of exactly the
        // length passed as the count.
        let n = unsafe {
            ecall3(
                ecall::WRITE,
                fd,
                bytes[written..].as_ptr() as u32,
                (bytes.len() - written) as u32,
            )
        };
        if n <= 0 || n as usize > bytes.len() - written {
            exit(EXIT_IO_ERROR);
        }
        written += n as usize;
    }
}

/// Read public input: the fd 0 stream, which the public I/O digest binds.
///
/// Returns the number of bytes read. A caller that needs exactly `buf.len()`
/// bytes must check the return value — a short read means the input ended, and
/// silently proceeding on a partly-filled buffer is how a guest ends up proving
/// something about zeroes.
pub fn read_input(buf: &mut [u8]) -> usize {
    read_fd(ecall::FD_PUBLIC_INPUT, buf)
}

/// Commit to public output: append `bytes` to the fd 1 journal, which the
/// public I/O digest binds.
pub fn commit(bytes: &[u8]) {
    write_fd(ecall::FD_PUBLIC_OUTPUT, bytes);
}

/// Read private hint bytes from fd 3.
///
/// Returns the number of bytes read. **These bytes are nondeterministic prover
/// advice.** Nothing binds them: the prover chooses them, and it may choose
/// them differently on every run. A hint is only ever a shortcut to a value the
/// guest then *checks* against something the digest does bind.
pub fn hint(buf: &mut [u8]) -> usize {
    read_fd(ecall::FD_HINT, buf)
}

/// Write diagnostics to fd 2. Free-form, uncommitted, verifier-ignored.
pub fn log(bytes: &[u8]) {
    write_fd(ecall::FD_STDERR, bytes);
}

/// Exit with `code`. A nonzero status is a failed execution.
pub fn exit(code: i32) -> ! {
    // Asked again rather than spun on: `EXIT` does not return under any
    // executor, so the loop exists only so that a broken one cannot fall
    // through into whatever follows, and asking a second time is a more useful
    // thing to do about that than burning cycles.
    loop {
        // SAFETY: `EXIT` takes a status in `a0` and does not return.
        unsafe { ecall1(ecall::EXIT, code as u32) };
    }
}

/// Status used for an executor-level I/O failure.
const EXIT_IO_ERROR: i32 = 70;

/// Status used when an allocation would reach the stack: see [`BumpAllocator`].
const EXIT_OUT_OF_MEMORY: i32 = 71;

/// Status used when a precompile answers something other than success or
/// `-ENOSYS`.
const EXIT_PRECOMPILE_ERROR: i32 = 72;

/// Status used by the panic handler.
const EXIT_PANIC: i32 = 101;

// ---------------------------------------------------------------------------
// Precompile shims
// ---------------------------------------------------------------------------

/// Poseidon2 over a width-3 state, as a precompile.
///
/// `state` is three canonical little-endian `Fr` elements, 32 bytes each, in
/// lane order, permuted in place.
///
/// Returns `false` when the executor answers exactly `-ENOSYS`, which every
/// executor does today: [`constants::ecall::PRECOMPILE_POSEIDON2`] has a number
/// and a documented calling convention but no circuit behind it yet. A caller
/// must have a software path and take it on `false` — that path is the one the
/// proof is about until a delegation circuit exists.
///
/// Any *other* nonzero answer exits nonzero rather than falling back. Collapsing
/// every error into "run the software path" would let a half-implemented
/// precompile fail silently, and the difference between "this VM does not have
/// this yet" and "this call went wrong" is exactly the difference worth keeping.
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool {
    // SAFETY: `state` is a live, writable 96-byte buffer, which is the whole of
    // this call's contract.
    let ret = unsafe { ecall1(ecall::PRECOMPILE_POSEIDON2, state.as_mut_ptr() as u32) };
    match ret {
        0 => true,
        n if n == -(ecall::ENOSYS as i32) => false,
        _ => exit(EXIT_PRECOMPILE_ERROR),
    }
}

// ---------------------------------------------------------------------------
// keccak256, and the delegation it declares
// ---------------------------------------------------------------------------

/// The delegation **declaration record** for keccak-f[1600].
///
/// `docs/spec/delegation.md` §7. The magic, then the ecall number as a
/// little-endian `u32`. It is in an allocated `.rodata` section, which
/// `link.ld`'s `*(.rodata*)` already absorbs, so no guest's layout moves and no
/// loader change is needed: `crates/program` scans the image's own file-backed
/// bytes for it, and program identity binds it through the image column.
///
/// [`keccak_f1600`] reads its ecall number **out of this record**, which is
/// what makes the record load-bearing rather than decorative: a shim that
/// exists has one, and the number it calls is the number it declares.
///
/// **No `#[used]`, deliberately.** The record must be in the image exactly
/// when the shim is, and `#[used]` would put it in *every* guest that links
/// this crate — `guests/Cargo.toml` pins `codegen-units = 1`, so the SDK is
/// one object file — which would declare `KECCAK_F` for `fib` and detachment
/// would mean nothing. Reachability is the whole mechanism: the record is
/// referenced by the shim and by nothing else, so a guest that never calls
/// `keccak256` drops the chain and the record with it.
///
/// **The section name carries the family, and that is load-bearing** (S22).
/// `--gc-sections` collects at *section* granularity, so two records sharing
/// one output section are kept or dropped together: with both in a bare
/// `.rodata.apogee.delegations`, `guests/keccak-test` declared `ECRECOVER`
/// as well — a guest whose `VmConfig` would carry a family it cannot call,
/// and detachment meaning nothing in the other direction from `#[used]`.
/// `link.ld`'s `*(.rodata*)` absorbs the suffixed names unchanged, and
/// `crates/program`'s scan reads bytes and never section names.
/// `crates/program/tests/delegation.rs` holds every committed guest to that,
/// at both optimisation levels.
#[link_section = ".rodata.apogee.delegations.keccak_f"]
static DELEGATION_KECCAK_F: [u8; delegation::MARKER_BYTES] = {
    let mut record = [0u8; delegation::MARKER_BYTES];
    let magic = delegation::MARKER_MAGIC;
    let mut i = 0;
    while i < magic.len() {
        record[i] = magic[i];
        i += 1;
    }
    let number = ecall::PRECOMPILE_KECCAK_F.to_le_bytes();
    let mut j = 0;
    while j < number.len() {
        record[magic.len() + j] = number[j];
        j += 1;
    }
    record
};

/// The declared ecall number, read back out of the record.
///
/// Through `black_box`, which is what keeps the *record* in the image at
/// `opt-level = 3`: without it LLVM folds the read into an immediate, the
/// static becomes unreferenced, and the declaration disappears from exactly
/// the guests that need it. `black_box` is an optimisation barrier and nothing
/// else — a dead call to this function is still dead, which is the other half
/// of what detachment needs.
fn delegation_number(record: &'static [u8; delegation::MARKER_BYTES]) -> u32 {
    let record = core::hint::black_box(record);
    let n = delegation::MARKER_MAGIC.len();
    u32::from_le_bytes([record[n], record[n + 1], record[n + 2], record[n + 3]])
}

/// The 200-byte frame a delegation request hands over, **word-aligned**.
///
/// The alignment is in the type because nothing else supplies it. A bare
/// `[u8; keccak::STATE_BYTES]` has alignment 1, and a stack local's address is
/// the code generator's to choose: LLVM places align-1 stack objects at odd
/// offsets whenever the frame packs that way, at every optimisation level.
/// `docs/spec/delegation.md` §4 rule 1 requires a word-aligned base, and a
/// misaligned one is a fatal `EmuError::Misaligned` — while `qemu-riscv32`,
/// which answers `-ENOSYS` and never dereferences the pointer, runs the
/// software path and agrees with everybody. An unaligned buffer would
/// therefore be a guest that gives the right digest under one executor and
/// dies under the other, decided by codegen rather than by the program.
///
/// `align(4)` and not more: 4 is what the ABI states, what `keccak`'s
/// `base_aligned` decomposes and what `emulator::keccak_frame` checks.
#[repr(C, align(4))]
struct Frame([u8; keccak::STATE_BYTES]);

/// The frame rule of `docs/spec/delegation.md` §4, as a type-level assertion:
/// the buffer the ecall hands over is word-aligned or this crate does not
/// build.
const _: () = assert!(core::mem::align_of::<Frame>() >= 4);

/// keccak-f[1600] over the 200-byte state frame, as a delegation.
///
/// Returns `false` when the executor answers exactly `-ENOSYS` — which
/// `qemu-riscv32` does, having no circuit — and the caller runs the software
/// path. Any other nonzero answer exits nonzero rather than falling back, for
/// [`poseidon2_permute`]'s reason.
fn keccak_f1600(state: &mut Frame) -> bool {
    // SAFETY: `state` is a live, writable 200-byte buffer, word-aligned by its
    // type, which is the whole of this call's contract.
    let ret = unsafe {
        ecall1(
            delegation_number(&DELEGATION_KECCAK_F),
            state.0.as_mut_ptr() as u32,
        )
    };
    match ret {
        0 => true,
        n if n == -(ecall::ENOSYS as i32) => false,
        _ => exit(EXIT_PRECOMPILE_ERROR),
    }
}

/// keccak-f[1600] in software: the fallback, and the definition the delegated
/// path is held to.
///
/// Written from `constants::keccak`'s two tables, which
/// `crates/constants/tests/keccak.rs` re-derives from the Keccak reference's
/// generators. `crates/emulator` carries its own copy for the executor side;
/// the two are held bit-identical, and both to `tiny-keccak`, by
/// `crates/emulator/tests/keccak.rs`. A crate whose only purpose was to be
/// shared by two callers would be the abstraction the master's anti-goals
/// refuse, and this crate is not a workspace member in any case.
fn keccak_f_software(lanes: &mut [u64; keccak::LANES]) {
    for round in 0..keccak::ROUNDS {
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
        let mut b = [0u64; keccak::LANES];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    lanes[x + 5 * y].rotate_left(keccak::ROTATIONS[y][x]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                lanes[x + 5 * y] =
                    b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        lanes[0] ^= keccak::ROUND_CONSTANTS[round];
    }
}

/// One permutation of the sponge state: the delegation, or the software path.
///
/// The frame the delegation dereferences is a [`Frame`], so it satisfies the
/// two frame rules of `docs/spec/delegation.md` §4 for different reasons. The
/// **window** rule holds by construction: the buffer is a stack local, the
/// stack lies below `__stack_top`, and `__stack_top` is the top of the RAM
/// window, so `base + 200` cannot leave it. The **alignment** rule does not
/// hold by construction, which is why [`Frame`] carries it.
fn permute(state: &mut Frame) {
    if keccak_f1600(state) {
        return;
    }
    let mut lanes = [0u64; keccak::LANES];
    for (i, lane) in lanes.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&state.0[8 * i..8 * i + 8]);
        *lane = u64::from_le_bytes(bytes);
    }
    keccak_f_software(&mut lanes);
    for (i, lane) in lanes.iter().enumerate() {
        state.0[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
}

/// keccak256 of `input`: Ethereum's Keccak, not SHA-3.
///
/// **This signature is frozen** (`docs/spec/delegation.md`): it is the patchable
/// entry point a hash hook routes through, and the delegated path and the
/// software fallback are bit-identical behind it.
///
/// The sponge and the padding run here, in guest code, and one delegation ecall
/// covers each keccak-f block. Padding is `pad10*1` in the original Keccak
/// domain — `0x01` first and `0x80` in the block's last byte — which is what
/// makes this keccak256 and not SHA3-256.
pub fn keccak256(input: &[u8]) -> [u8; keccak::DIGEST_BYTES] {
    let mut state = Frame([0u8; keccak::STATE_BYTES]);
    let mut block = input.chunks_exact(keccak::RATE_BYTES);
    for chunk in block.by_ref() {
        for (cell, byte) in state.0.iter_mut().zip(chunk) {
            *cell ^= byte;
        }
        permute(&mut state);
    }
    // The last, partial block, padded. `chunks_exact`'s remainder is shorter
    // than the rate, so the padded block is exactly one rate long — including
    // the empty input, whose only block is the padding.
    let rest = block.remainder();
    let mut last = [0u8; keccak::RATE_BYTES];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] ^= keccak::PAD_FIRST;
    last[keccak::RATE_BYTES - 1] ^= keccak::PAD_LAST;
    for (cell, byte) in state.0.iter_mut().zip(last.iter()) {
        *cell ^= byte;
    }
    permute(&mut state);
    let mut digest = [0u8; keccak::DIGEST_BYTES];
    digest.copy_from_slice(&state.0[..keccak::DIGEST_BYTES]);
    digest
}

// ---------------------------------------------------------------------------
// secp256k1 ecrecover, the second delegation
// ---------------------------------------------------------------------------

/// The delegation declaration record for secp256k1 recovery.
///
/// `docs/spec/delegation.md` §7, and the same shape as
/// `DELEGATION_KECCAK_F`'s above: the magic, then the ecall number as a
/// little-endian `u32`, in an allocated `.rodata` section, kept exactly when
/// the shim that reads it is reachable. No `#[used]`, for that reason.
#[link_section = ".rodata.apogee.delegations.ecrecover"]
static DELEGATION_ECRECOVER: [u8; delegation::MARKER_BYTES] = {
    let mut record = [0u8; delegation::MARKER_BYTES];
    let magic = delegation::MARKER_MAGIC;
    let mut i = 0;
    while i < magic.len() {
        record[i] = magic[i];
        i += 1;
    }
    let number = ecall::PRECOMPILE_ECRECOVER.to_le_bytes();
    let mut j = 0;
    while j < number.len() {
        record[magic.len() + j] = number[j];
        j += 1;
    }
    record
};

/// The recovery frame, `docs/spec/ecrecover.md` §2: 42 little-endian 32-bit
/// words, read and written in place.
///
/// Word-aligned by its element type rather than by an attribute, which is the
/// difference from keccak's [`Frame`]: a `[u32; N]` has alignment 4 wherever
/// the code generator puts it, and a `[u8; N]` does not.
#[repr(C)]
struct EcrecoverFrame([u32; ecrecover::FRAME_WORDS]);

const _: () = assert!(core::mem::align_of::<EcrecoverFrame>() >= 4);

/// The delegation call. `false` means the executor has no circuit and the
/// caller runs the software path; anything but 0 or `-ENOSYS` is fatal, for
/// [`keccak_f1600`]'s reason.
fn ecrecover_delegate(frame: &mut EcrecoverFrame) -> bool {
    // SAFETY: `frame` is a live, writable, word-aligned 168-byte buffer, which
    // is the whole of this call's contract.
    let ret = unsafe {
        ecall1(
            delegation_number(&DELEGATION_ECRECOVER),
            frame.0.as_mut_ptr() as u32,
        )
    };
    match ret {
        0 => true,
        n if n == -(ecall::ENOSYS as i32) => false,
        _ => exit(EXIT_PRECOMPILE_ERROR),
    }
}

/// Write a 32-byte big-endian value into the frame at `offset`, as the frame's
/// little-endian words (`docs/spec/ecrecover.md` §2.1).
fn put_value(frame: &mut EcrecoverFrame, offset: usize, be: &[u8; 32]) {
    for i in 0..ecrecover::VALUE_WORDS {
        // Word `i` is bytes `4i .. 4i + 4` of the little-endian value, which
        // is bytes `28 - 4i .. 32 - 4i` of the big-endian one.
        let hi = 32 - 4 * i;
        frame.0[offset + i] = u32::from_be_bytes([be[hi - 4], be[hi - 3], be[hi - 2], be[hi - 1]]);
    }
}

/// The inverse of [`put_value`].
fn get_value(frame: &EcrecoverFrame, offset: usize) -> [u8; 32] {
    let mut be = [0u8; 32];
    for i in 0..ecrecover::VALUE_WORDS {
        let hi = 32 - 4 * i;
        be[hi - 4..hi].copy_from_slice(&frame.0[offset + i].to_be_bytes());
    }
    be
}

/// secp256k1 public-key recovery, the EVM's `0x01` precompile.
///
/// **This signature is frozen** (`docs/spec/delegation.md`, S22 handoff): it is
/// the patchable entry point a precompile hook routes through, and the
/// delegated path and the software fallback are bit-identical behind it —
/// which they are by construction, because both fill the *same frame* and the
/// address is derived from the frame afterwards, once.
///
/// `v` is 27 or 28; `r` and `s` are 32-byte big-endian, as the EVM passes
/// them. `None` is every failure the precompile has: a bad `v`, an `r` or `s`
/// outside `[1, n)`, an `r` that is no curve point's `x`, and a recovered
/// identity. The address is `keccak256(x ‖ y)[12..]` through [`keccak256`] —
/// the circuit proves the public key and never hashes (stage prompt,
/// must-be-exact 4).
pub fn ecrecover(msg_hash: &[u8; 32], v: u8, r: &[u8; 32], s: &[u8; 32]) -> Option<[u8; 20]> {
    let mut frame = EcrecoverFrame([0u32; ecrecover::FRAME_WORDS]);
    put_value(&mut frame, ecrecover::OFF_HASH, msg_hash);
    frame.0[ecrecover::OFF_V] = u32::from(v);
    put_value(&mut frame, ecrecover::OFF_R, r);
    put_value(&mut frame, ecrecover::OFF_S, s);

    if !ecrecover_delegate(&mut frame) {
        ecrecover_software(&mut frame);
    }

    if frame.0[ecrecover::OFF_SUCCESS] == 0 {
        return None;
    }
    let mut serialized = [0u8; 64];
    serialized[..32].copy_from_slice(&get_value(&frame, ecrecover::OFF_PUBKEY_X));
    serialized[32..].copy_from_slice(&get_value(&frame, ecrecover::OFF_PUBKEY_Y));
    let digest = keccak256(&serialized);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    Some(address)
}

// ---------------------------------------------------------------------------
// The software recovery
// ---------------------------------------------------------------------------
//
// A deliberate duplicate of `program::secp256k1`, for `keccak_f_software`'s
// reason: this crate is not a workspace member, links only `constants`, and
// compiles for one target. The two are held to each other by
// `guests/ecrecover-test`, which runs this path under `qemu-riscv32` and the
// delegated path under the emulator over the same committed corpus, and by
// `crates/loader/tests/qemu.rs`.
//
// Everything is four 64-bit limbs, least significant first, as the circuit's
// unit is (`constants::secp256k1::LIMBS`).

type U256 = [u64; secp256k1::LIMBS];

const ZERO: U256 = [0; secp256k1::LIMBS];
const ONE: U256 = [1, 0, 0, 0];

fn u_add(a: &U256, b: &U256) -> (U256, bool) {
    let mut out = ZERO;
    let mut carry = 0u64;
    for i in 0..secp256k1::LIMBS {
        let (t, c1) = a[i].overflowing_add(b[i]);
        let (t, c2) = t.overflowing_add(carry);
        out[i] = t;
        carry = u64::from(c1) + u64::from(c2);
    }
    (out, carry != 0)
}

fn u_sub(a: &U256, b: &U256) -> (U256, bool) {
    let mut out = ZERO;
    let mut borrow = 0u64;
    for i in 0..secp256k1::LIMBS {
        let (t, b1) = a[i].overflowing_sub(b[i]);
        let (t, b2) = t.overflowing_sub(borrow);
        out[i] = t;
        borrow = u64::from(b1) + u64::from(b2);
    }
    (out, borrow != 0)
}

fn u_less(a: &U256, b: &U256) -> bool {
    let mut i = secp256k1::LIMBS;
    while i > 0 {
        i -= 1;
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn u_is_zero(a: &U256) -> bool {
    let mut i = 0;
    while i < secp256k1::LIMBS {
        if a[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

fn u_mul_wide(a: &U256, b: &U256) -> [u64; 2 * secp256k1::LIMBS] {
    let mut out = [0u64; 2 * secp256k1::LIMBS];
    for i in 0..secp256k1::LIMBS {
        let mut carry = 0u128;
        for j in 0..secp256k1::LIMBS {
            let t = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[i + j]) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + secp256k1::LIMBS] = carry as u64;
    }
    out
}

/// `x % m` for a normalized `m`, by Knuth's algorithm D. The quotient is not
/// wanted here — the guest never witnesses one — so only the remainder is
/// returned.
fn u_rem_wide(x: &[u64; 2 * secp256k1::LIMBS], m: &U256) -> U256 {
    const N: usize = secp256k1::LIMBS;
    let mut u = [0u64; 2 * N + 1];
    u[..2 * N].copy_from_slice(x);
    let mut j = N + 1;
    while j > 0 {
        j -= 1;
        if j + N >= u.len() {
            continue;
        }
        let top = (u128::from(u[j + N]) << 64) | u128::from(u[j + N - 1]);
        let mut qhat = top / u128::from(m[N - 1]);
        let mut rhat = top % u128::from(m[N - 1]);
        loop {
            let too_big = qhat >> 64 != 0
                || qhat * u128::from(m[N - 2]) > (rhat << 64) | u128::from(u[j + N - 2]);
            if !too_big {
                break;
            }
            qhat -= 1;
            rhat += u128::from(m[N - 1]);
            if rhat >> 64 != 0 {
                break;
            }
        }
        let mut borrow = 0u64;
        let mut carry = 0u128;
        for (i, limb) in m.iter().enumerate() {
            let prod = qhat * u128::from(*limb) + carry;
            carry = prod >> 64;
            let (d, b1) = u[i + j].overflowing_sub(prod as u64);
            let (d, b2) = d.overflowing_sub(borrow);
            u[i + j] = d;
            borrow = u64::from(b1) + u64::from(b2);
        }
        let (d, b1) = u[j + N].overflowing_sub(carry as u64);
        let (d, b2) = d.overflowing_sub(borrow);
        u[j + N] = d;
        if b1 || b2 {
            let mut c = 0u128;
            for (i, limb) in m.iter().enumerate() {
                let t = u128::from(u[i + j]) + u128::from(*limb) + c;
                u[i + j] = t as u64;
                c = t >> 64;
            }
            u[j + N] = (u128::from(u[j + N]) + c) as u64;
        }
    }
    let mut r = ZERO;
    r.copy_from_slice(&u[..N]);
    r
}

fn u_rem(x: &U256, m: &U256) -> U256 {
    let mut wide = [0u64; 2 * secp256k1::LIMBS];
    wide[..secp256k1::LIMBS].copy_from_slice(x);
    u_rem_wide(&wide, m)
}

fn addmod(a: &U256, b: &U256, m: &U256) -> U256 {
    let (s, carry) = u_add(a, b);
    if carry || !u_less(&s, m) {
        u_sub(&s, m).0
    } else {
        s
    }
}

fn submod(a: &U256, b: &U256, m: &U256) -> U256 {
    let (d, borrow) = u_sub(a, b);
    if borrow {
        u_add(&d, m).0
    } else {
        d
    }
}

fn mulmod(a: &U256, b: &U256, m: &U256) -> U256 {
    u_rem_wide(&u_mul_wide(a, b), m)
}

fn shr1(x: &U256) -> U256 {
    let mut out = ZERO;
    for i in 0..secp256k1::LIMBS {
        out[i] = x[i] >> 1;
        if i + 1 < secp256k1::LIMBS {
            out[i] |= x[i + 1] << 63;
        }
    }
    out
}

fn half_mod(x: &U256, m: &U256) -> U256 {
    if x[0] & 1 == 0 {
        shr1(x)
    } else {
        let (s, carry) = u_add(x, m);
        let mut out = shr1(&s);
        if carry {
            out[secp256k1::LIMBS - 1] |= 1 << 63;
        }
        out
    }
}

/// The binary extended Euclidean inverse, for a prime `m`; `None` at 0.
fn invmod(a: &U256, m: &U256) -> Option<U256> {
    if u_is_zero(a) {
        return None;
    }
    let mut u = *a;
    let mut v = *m;
    let mut x1 = ONE;
    let mut x2 = ZERO;
    while !(u == ONE || v == ONE) {
        while u[0] & 1 == 0 {
            u = shr1(&u);
            x1 = half_mod(&x1, m);
        }
        while v[0] & 1 == 0 {
            v = shr1(&v);
            x2 = half_mod(&x2, m);
        }
        if !u_less(&u, &v) {
            u = u_sub(&u, &v).0;
            x1 = submod(&x1, &x2, m);
        } else {
            v = u_sub(&v, &u).0;
            x2 = submod(&x2, &x1, m);
        }
    }
    Some(if u == ONE { x1 } else { x2 })
}

fn powmod(a: &U256, e: &U256, m: &U256) -> U256 {
    let mut out = ONE;
    let mut i = secp256k1::LIMBS;
    while i > 0 {
        i -= 1;
        let mut bit = secp256k1::LIMB_BITS;
        while bit > 0 {
            bit -= 1;
            out = mulmod(&out, &out, m);
            if e[i] >> bit & 1 == 1 {
                out = mulmod(&out, a, m);
            }
        }
    }
    out
}

/// An affine point; the identity has no coordinates, so it carries a flag.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Point {
    infinity: bool,
    x: U256,
    y: U256,
}

const INFINITY: Point = Point {
    infinity: true,
    x: ZERO,
    y: ZERO,
};

fn chord(a: &Point, b: &Point, lambda: &U256) -> Point {
    let p = &secp256k1::P;
    let l2 = mulmod(lambda, lambda, p);
    let x3 = submod(&submod(&l2, &a.x, p), &b.x, p);
    let y3 = submod(&mulmod(lambda, &submod(&a.x, &x3, p), p), &a.y, p);
    Point {
        infinity: false,
        x: x3,
        y: y3,
    }
}

fn point_double(a: &Point) -> Point {
    let p = &secp256k1::P;
    if a.infinity || u_is_zero(&a.y) {
        return INFINITY;
    }
    let x2 = mulmod(&a.x, &a.x, p);
    let three_x2 = addmod(&addmod(&x2, &x2, p), &x2, p);
    let two_y = addmod(&a.y, &a.y, p);
    let inv = match invmod(&two_y, p) {
        Some(i) => i,
        None => return INFINITY,
    };
    let lambda = mulmod(&three_x2, &inv, p);
    chord(a, a, &lambda)
}

fn point_add(a: &Point, b: &Point) -> Point {
    let p = &secp256k1::P;
    if a.infinity {
        return *b;
    }
    if b.infinity {
        return *a;
    }
    if a.x == b.x {
        if a.y == b.y {
            return point_double(a);
        }
        return INFINITY;
    }
    let num = submod(&b.y, &a.y, p);
    let den = submod(&b.x, &a.x, p);
    let inv = match invmod(&den, p) {
        Some(i) => i,
        None => return INFINITY,
    };
    chord(a, b, &mulmod(&num, &inv, p))
}

/// `u1*G + u2*base`, the joint ladder with shared doublings — the schedule the
/// circuit proves, so that a disagreement is a disagreement about the answer
/// and not about the route.
fn joint_mul(u1: &U256, u2: &U256, base: &Point) -> Point {
    let g = Point {
        infinity: false,
        x: secp256k1::G_X,
        y: secp256k1::G_Y,
    };
    let mut table_g = [INFINITY; secp256k1::WINDOW_ENTRIES];
    let mut table_b = [INFINITY; secp256k1::WINDOW_ENTRIES];
    table_g[0] = g;
    table_b[0] = *base;
    for i in 1..secp256k1::WINDOW_ENTRIES {
        table_g[i] = point_add(&table_g[i - 1], &g);
        table_b[i] = point_add(&table_b[i - 1], base);
    }
    let mut acc = INFINITY;
    for w in 0..secp256k1::WINDOWS {
        if w > 0 {
            for _ in 0..secp256k1::WINDOW_BITS {
                acc = point_double(&acc);
            }
        }
        let index = secp256k1::WINDOWS - 1 - w;
        let d1 = (u1[index / 16] >> (4 * (index % 16))) & 0xF;
        if d1 != 0 {
            acc = point_add(&acc, &table_g[d1 as usize - 1]);
        }
        let d2 = (u2[index / 16] >> (4 * (index % 16))) & 0xF;
        if d2 != 0 {
            acc = point_add(&acc, &table_b[d2 as usize - 1]);
        }
    }
    acc
}

/// Fill the frame's output words from its input words: the software half of
/// [`ecrecover`], and the same function the circuit proves.
///
/// On failure every output word is zero, including the flag — which is the
/// circuit's rule too (stage prompt, must-be-exact 2), so a caller cannot tell
/// the two paths apart by what they leave behind.
fn ecrecover_software(frame: &mut EcrecoverFrame) {
    for i in 0..ecrecover::VALUE_WORDS {
        frame.0[ecrecover::OFF_PUBKEY_X + i] = 0;
        frame.0[ecrecover::OFF_PUBKEY_Y + i] = 0;
    }
    frame.0[ecrecover::OFF_SUCCESS] = 0;

    let read = |offset: usize| -> U256 {
        let mut out = ZERO;
        for (i, limb) in out.iter_mut().enumerate() {
            *limb =
                u64::from(frame.0[offset + 2 * i]) | (u64::from(frame.0[offset + 2 * i + 1]) << 32);
        }
        out
    };
    let hash = read(ecrecover::OFF_HASH);
    let v = frame.0[ecrecover::OFF_V];
    let r = read(ecrecover::OFF_R);
    let s = read(ecrecover::OFF_S);

    if !(ecrecover::V_MIN..=ecrecover::V_MAX).contains(&v) {
        return;
    }
    let n = &secp256k1::N;
    let p = &secp256k1::P;
    if u_is_zero(&r) || !u_less(&r, n) || u_is_zero(&s) || !u_less(&s, n) {
        return;
    }

    // R from (r, v): y^2 = r^3 + 7, with y's parity the recovery id. p = 3 mod
    // 4, so a residue's root is one exponentiation.
    let x2 = mulmod(&r, &r, p);
    let x3 = mulmod(&x2, &r, p);
    let c = addmod(&x3, &[7, 0, 0, 0], p);
    let root = powmod(&c, &secp256k1::P_PLUS_1_OVER_4, p);
    if mulmod(&root, &root, p) != c {
        return;
    }
    let parity = u64::from(v - ecrecover::V_MIN);
    let y = if root[0] & 1 == parity {
        root
    } else {
        u_sub(p, &root).0
    };
    let big_r = Point {
        infinity: false,
        x: r,
        y,
    };

    // Q = u1*G + u2*R with u1 = -h/r and u2 = s/r, both mod n. A hash at or
    // above n is reduced, which is not an error.
    let e = u_rem(&hash, n);
    let r_inv = match invmod(&r, n) {
        Some(i) => i,
        None => return,
    };
    let u1 = mulmod(&submod(&ZERO, &e, n), &r_inv, n);
    let u2 = mulmod(&s, &r_inv, n);
    let q = joint_mul(&u1, &u2, &big_r);
    if q.infinity {
        return;
    }

    for i in 0..secp256k1::LIMBS {
        frame.0[ecrecover::OFF_PUBKEY_X + 2 * i] = q.x[i] as u32;
        frame.0[ecrecover::OFF_PUBKEY_X + 2 * i + 1] = (q.x[i] >> 32) as u32;
        frame.0[ecrecover::OFF_PUBKEY_Y + 2 * i] = q.y[i] as u32;
        frame.0[ecrecover::OFF_PUBKEY_Y + 2 * i + 1] = (q.y[i] >> 32) as u32;
    }
    frame.0[ecrecover::OFF_SUCCESS] = 1;
}

// ---------------------------------------------------------------------------
// The heap
// ---------------------------------------------------------------------------

extern "C" {
    /// First byte above `.bss`, 16-aligned. Defined by `link.ld`.
    static __heap_start: u8;
    /// One past the last byte of RAM; the initial `sp`. Defined by `link.ld`.
    static __stack_top: u8;
}

/// The bump: the next free heap address, or `0` before the first allocation.
///
/// `0` is a safe "not yet initialised" marker because RAM starts at `0x10000`,
/// so a real heap pointer is never zero.
///
/// A `static mut` and not a `Cell`: the guest is single-threaded with no
/// interrupts and no re-entrancy, so the plainest form is also the honest one.
static mut BUMP: usize = 0;

/// A bump allocator. `alloc` moves a pointer up; `dealloc` does nothing.
///
/// Guest programs are short-lived and single-threaded, and the VM charges for
/// every cycle a free list would cost. Memory is reclaimed when the program
/// exits and not before — so what runs a guest out of heap is the *total* it
/// allocates over the run, not its peak.
///
/// # The ceiling
///
/// The heap and the stack share `[__heap_start, __stack_top)`, the heap growing
/// up and the stack down, with nothing between them but this check. A block is
/// refused — `exit(71)`, never a null — when it would end above either of:
///
/// - `__stack_top - STACK_RESERVE`. The top
///   [`guest_memory::STACK_RESERVE`] bytes are the stack's whatever the heap
///   wants, so a program whose recursion fits in them never meets a heap block.
/// - The live `sp`. A stack already deeper than its reserve still never has a
///   block handed out on top of a frame in use.
///
/// Until S12 the ceiling was `__stack_top` itself, and running out of heap was
/// silent corruption rather than an exit: a block ending anywhere between the
/// live `sp` and the top was handed out *over live stack frames*, so safe code
/// writing into a `Vec` rewrote the caller's locals and return addresses. The
/// consistency suite found it by running this guest's source on the host and
/// comparing; `crates/emulator/tests/consistency.rs` holds the fix to both
/// halves of the rule.
///
/// What no allocator can see is a stack that grows past its reserve *after* the
/// heap has filled the space below it. Catching that needs a guard below every
/// frame — instrumentation, not allocation. The reserve is sized so it takes a
/// program the host would also reject: 8 MiB is a native main thread's default
/// stack on Linux and macOS.
struct BumpAllocator;

/// The live stack pointer: nothing at or above it may be handed out.
///
/// Read from inside the allocator, so it is below every frame that could be
/// using the memory a block would cover.
fn stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: copies one register into another and touches no memory.
    unsafe {
        core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    sp
}

// SAFETY: `alloc` returns a fresh, correctly-aligned block of `layout.size()`
// bytes that starts at or above `__heap_start` and ends at or below both the
// live stack pointer and `__stack_top - STACK_RESERVE`; it never hands the
// block out again, since `BUMP` only ever moves up, and where no such block
// exists it exits instead of returning. The guest is single-threaded, so the
// read-modify-write of `BUMP` cannot race.
//
// The `sp` term makes the block disjoint from every frame in use *at the
// moment of the call*; what keeps it disjoint for the block's whole life is the
// reserve, which no allocation may enter, so the stack has 8 MiB to grow in
// without meeting one. A stack that grows past that is the case the type's docs
// say nothing here can see.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let bump = core::ptr::addr_of_mut!(BUMP);
        let mut next = *bump;
        if next == 0 {
            next = core::ptr::addr_of!(__heap_start) as usize;
        }

        // `align` is a power of two, so this is the usual round-up. It cannot
        // overflow in practice — RAM ends far below `usize::MAX` — but a
        // checked form costs nothing and turns a wrap into an exit.
        let Some(aligned) = next.checked_add(layout.align() - 1) else {
            exit(EXIT_OUT_OF_MEMORY);
        };
        let aligned = aligned & !(layout.align() - 1);
        let Some(end) = aligned.checked_add(layout.size()) else {
            exit(EXIT_OUT_OF_MEMORY);
        };

        // Past the ceiling — see the type's docs — this exits nonzero rather
        // than returning null: a guest that quietly gets a null pointer here
        // reports a Rust allocation error through a path that needs an
        // allocation. `saturating_sub` guards `__stack_top` itself being below
        // the reserve, which the frozen memory map makes impossible; it is
        // three instructions for a case that cannot arise, kept because a map
        // is a thing that can change and an underflow here would hand out the
        // whole address space.
        let ceiling = (core::ptr::addr_of!(__stack_top) as usize)
            .saturating_sub(guest_memory::STACK_RESERVE as usize)
            .min(stack_pointer());
        if end > ceiling {
            exit(EXIT_OUT_OF_MEMORY);
        }

        *bump = end;
        aligned as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// ---------------------------------------------------------------------------
// Panic
// ---------------------------------------------------------------------------

/// fd 2 as a `core::fmt` sink, so the panic handler can format without
/// allocating.
struct Diagnostics;

impl core::fmt::Write for Diagnostics {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        log(s.as_bytes());
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    // `PanicInfo`'s own `Display` is "panicked at FILE:LINE:COL:\nMESSAGE",
    // which is the message and the location the stage asks for. The result is
    // discarded because there is nothing to do about a failed write while
    // panicking.
    let _ = writeln!(Diagnostics, "guest {info}");
    exit(EXIT_PANIC)
}
