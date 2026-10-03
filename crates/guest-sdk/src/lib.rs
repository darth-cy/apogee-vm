#![no_std]
//! The guest-side runtime: crt0, the entry macro, a bump allocator, a panic
//! handler and the ecall shims.
//!
//! Everything here runs *inside* the proof. It compiles only for
//! `riscv32imac-unknown-none-elf` and links only into guest binaries.
//!
//! # The I/O model in one paragraph
//!
//! **An Apogee guest is an Apogee-SDK program, not a Linux one.** It has no
//! file descriptors, no streams and no I/O syscall. An execution's three kinds
//! of input and output are *memory*, reached with ordinary loads and stores:
//! [`public_input`] is the verifier-bound input, [`advice`] is prover-supplied
//! and bound by nothing, and [`commit`] appends to the verifier-bound journal.
//! `docs/spec/public-values.md` is normative for all three.
//!
//! What is left of the ecall ABI is [`exit`] and the four delegation calls. An
//! ecall carries its number in `a7`, its argument in `a0` and its result in
//! `a0`, with errors as a negated errno; `docs/spec/ecall-abi.md` is the
//! normative table and every number comes from [`constants::ecall`].
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

use constants::{delegation, ec_add, ecall, guest_memory, keccak, poseidon2, sha256 as sha256c};

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
// The zeroing is kept even though this VM's memory starts zeroed: `.bss` being
// zero is a guarantee the Rust that runs above it relies on, and crt0 is the
// one place that can make it true of the image rather than of the executor.
//
// The trailing `j .` is unreachable — `exit` does not return — and exists so a
// hypothetical returning `exit` cannot fall into whatever follows.
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

// One shim, one argument: every ecall a guest may now issue takes exactly one.
// `EXIT` takes a status and the four delegations take a frame base pointer.
// A six-argument shim with zeroes passed in would be strictly worse -- an
// unused `in(...)` register is still a constraint on the register allocator.
//
// No `options(...)`: the default is the conservative one. A delegation writes
// its frame in place through the pointer in `a0`, so the compiler must not
// assume this asm leaves memory alone.
//
// No clobber list either, and that is a load-bearing assumption rather than an
// omission: **an ecall preserves every register except `a0`**, which
// `docs/spec/ecall-abi.md` section 1 states as part of the frozen ABI. A
// precompile circuit that scratched `t0` would produce silently wrong guest
// arithmetic, which is why the rule is written down there and not only here.

/// `ecall` with one argument.
///
/// # Safety
/// The caller guarantees that `num` names a call whose contract is satisfied
/// by `a0` — in particular that, where `a0` is a pointer, it is valid for the
/// access that call performs.
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
// Public values, and advice
// ---------------------------------------------------------------------------

/// The word at `addr`, read straight out of guest memory.
///
/// A plain volatile load: the public windows and the advice region are ordinary
/// memory to every instruction, which is the whole point of putting them there
/// (`docs/spec/public-values.md` §2). Volatile because the compiler has no
/// reason to believe anything ever wrote them.
fn word_at(addr: u32) -> u32 {
    // SAFETY: `addr` is 4-aligned and inside a region the executor makes
    // addressable; every caller here derives it from a window origin.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// A `&'static [u8]` over `len` bytes at `addr`.
///
/// # Safety
/// `addr .. addr + len` must lie inside one addressable region.
unsafe fn slice_at(addr: u32, len: usize) -> &'static [u8] {
    core::slice::from_raw_parts(addr as *const u8, len)
}

/// The **public input**: the verifier-known bytes this execution is about.
///
/// No ecall, no stream, no cursor — the bytes are in memory at
/// `guest_memory::PUBLIC_INPUT_ORIGIN`, and the proof binds them to the
/// statement through the memory argument (`docs/spec/public-values.md` §5).
/// Reading it is optional: nothing forces a guest to look.
pub fn public_input() -> &'static [u8] {
    let len = word_at(guest_memory::PUBLIC_INPUT_ORIGIN).min(guest_memory::PUBLIC_PAYLOAD_BYTES);
    // SAFETY: `len` is clamped to the window's payload, so the slice is inside
    // the window the executor initialized.
    unsafe { slice_at(guest_memory::PUBLIC_INPUT_ORIGIN + 4, len as usize) }
}

/// The public input, copied into `buf`; returns how many bytes it copied,
/// which is `min(buf.len(), public_input().len())`.
///
/// For a program ported from a stream API. [`public_input`] copies nothing.
pub fn read_input(buf: &mut [u8]) -> usize {
    let input = public_input();
    let n = buf.len().min(input.len());
    buf[..n].copy_from_slice(&input[..n]);
    n
}

/// Append `bytes` to the **journal**: the public output this execution
/// publishes.
///
/// Ordinary stores into the public output window, and word 0 of that window is
/// the journal's byte length — which is what makes the proof bind a byte string
/// rather than a zero-padded word vector (`docs/spec/public-values.md` §3).
///
/// Exits [`EXIT_IO_ERROR`] rather than truncating on a journal that would not
/// fit: a caller reads [`journal`] back, and must not see one it did not write.
///
/// **A guest that panics has still published what it committed**, because the
/// journal is memory and the panic handler does not have to know about it.
pub fn commit(bytes: &[u8]) {
    let len = word_at(guest_memory::PUBLIC_OUTPUT_ORIGIN) as usize;
    if len > guest_memory::PUBLIC_PAYLOAD_BYTES as usize
        || bytes.len() > guest_memory::PUBLIC_PAYLOAD_BYTES as usize - len
    {
        exit(EXIT_IO_ERROR);
    }
    let payload = guest_memory::PUBLIC_OUTPUT_ORIGIN + 4;
    for (i, byte) in bytes.iter().enumerate() {
        // SAFETY: `len + bytes.len()` is inside the window's payload, checked
        // just above, so the address is inside the window.
        unsafe { core::ptr::write_volatile((payload + (len + i) as u32) as *mut u8, *byte) };
    }
    // SAFETY: word 0 of the window, which the executor initialized.
    unsafe {
        core::ptr::write_volatile(
            guest_memory::PUBLIC_OUTPUT_ORIGIN as *mut u32,
            (len + bytes.len()) as u32,
        )
    };
}

/// The journal so far: everything [`commit`] has appended.
pub fn journal() -> &'static [u8] {
    let len = word_at(guest_memory::PUBLIC_OUTPUT_ORIGIN).min(guest_memory::PUBLIC_PAYLOAD_BYTES);
    // SAFETY: `len` is clamped to the window's payload.
    unsafe { slice_at(guest_memory::PUBLIC_OUTPUT_ORIGIN + 4, len as usize) }
}

/// The **advice**: prover-supplied bytes at `guest_memory::ADVICE_ORIGIN`.
///
/// **Nothing binds these bytes.** The prover chooses them and may choose them
/// differently on every run, so a guest owes a check of them against something
/// a proof *does* bind — the public input, or a hash the public input carries.
/// That is the whole contract (`docs/spec/public-values.md` §6): advice is
/// only ever a shortcut to a value the guest then checks.
///
/// The length word is the prover's too, so it is clamped to the region rather
/// than trusted. Reading past what the host supplied is a fatal executor error,
/// which costs the prover a trace and nobody else anything.
///
/// **Calling this on a run given no advice is that fatal error**, not an empty
/// slice: no advice means no advice region at all, so that a program which uses
/// none pays no `ADVICE_WINDOWS` shard (`docs/spec/public-values.md` §6).
pub fn advice() -> &'static [u8] {
    let len = word_at(guest_memory::ADVICE_ORIGIN);
    let len = len.min(4 * guest_memory::ADVICE_WORDS - 4);
    // SAFETY: `len` is clamped to the region, and the executor refuses a read
    // past the bytes it was given rather than returning something else.
    unsafe { slice_at(guest_memory::ADVICE_ORIGIN + 4, len as usize) }
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

/// Status used when [`commit`] is handed more bytes than the journal holds.
///
/// Named for an executor-level I/O failure, which is what it meant while the
/// SDK had descriptors to fail on; the journal overflow is the one case left,
/// and the number is kept because it appears in recorded exit statuses.
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
/// lane order, permuted in place. S10 froze this signature and S23 gave the
/// number a circuit; the call is now a **delegation**
/// (`docs/spec/delegation.md` §12), so an executor that has the circuit
/// answers 0 and one that does not answers `-ENOSYS`.
///
/// Returns `false` on exactly `-ENOSYS`, and a caller must have a software
/// path and take it on `false`. This VM implements every delegation, so its
/// executor never answers `-ENOSYS` here; the fallback is the ABI's contract
/// (`docs/spec/delegation.md` §2) rather than a path taken in this repository.
///
/// Any *other* nonzero answer exits nonzero rather than falling back.
/// Collapsing every error into "run the software path" would let a
/// half-implemented precompile fail silently, and the difference between "this
/// VM does not have this yet" and "this call went wrong" is exactly the
/// difference worth keeping.
///
/// The buffer is copied into an aligned frame and back: the ABI requires a
/// word-aligned base (`docs/spec/delegation.md` §4) and a bare `[u8; 96]` has
/// alignment 1, so a caller's buffer cannot be handed over as it stands. A
/// caller that wants the copies gone calls [`recursion::poseidon2`] with a
/// [`recursion::Poseidon2Frame`] of its own, which is what `transcript` does.
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool {
    let mut frame = recursion::Poseidon2Frame([0u8; poseidon2::FRAME_BYTES]);
    frame.0.copy_from_slice(state);
    let answered = recursion::poseidon2(&mut frame);
    if answered {
        state.copy_from_slice(&frame.0);
    }
    answered
}

/// The delegation shims the recursion guest's field and hash work rides on.
///
/// Every entry point here is a raw delegation call over a word-aligned frame:
/// it hands the frame over, and it answers `false` on exactly `-ENOSYS` so the
/// caller can run its own software path. **There is no software path in this
/// module**, and there must not be: the callers are `field` and `transcript`,
/// whose own implementations *are* the fallback, so the delegated path and the
/// fallback are the same function by construction rather than two copies held
/// equal by a test.
///
/// The declaration records live here too. One per shim, referenced by that
/// shim and by nothing else, so a guest that never reaches a shim drops the
/// record with it and declares nothing (`docs/spec/delegation.md` §7).
pub mod recursion {
    use super::{delegation_number, ecall1, exit, EXIT_PRECOMPILE_ERROR};
    use constants::{delegation, ec_add as ec, ecall, fr_arith, mod_mul, poseidon2, sha256 as sha};

    /// The Poseidon2 delegation's declaration record.
    #[link_section = ".rodata.apogee.delegations.poseidon2"]
    static DELEGATION_POSEIDON2: [u8; delegation::MARKER_BYTES] =
        super::record(ecall::PRECOMPILE_POSEIDON2);

    /// The Fr-arithmetic delegation's declaration record.
    #[link_section = ".rodata.apogee.delegations.fr_arith"]
    static DELEGATION_FR_ARITH: [u8; delegation::MARKER_BYTES] =
        super::record(ecall::PRECOMPILE_FR_ARITH);

    /// The 256-bit modular multiplication delegation's declaration record.
    #[link_section = ".rodata.apogee.delegations.mod_mul"]
    static DELEGATION_MOD_MUL: [u8; delegation::MARKER_BYTES] =
        super::record(ecall::PRECOMPILE_MOD_MUL);

    /// The SHA-256 compression delegation's declaration record.
    #[link_section = ".rodata.apogee.delegations.sha256_comp"]
    static DELEGATION_SHA256_COMP: [u8; delegation::MARKER_BYTES] =
        super::record(ecall::PRECOMPILE_SHA256_COMP);

    /// The elliptic-curve addition delegation's declaration record.
    #[link_section = ".rodata.apogee.delegations.ec_add"]
    static DELEGATION_EC_ADD: [u8; delegation::MARKER_BYTES] =
        super::record(ecall::PRECOMPILE_EC_ADD);

    /// `FR_OP`'s declaration record (S-RECURSION).
    #[link_section = ".rodata.apogee.delegations.fr_op"]
    static DELEGATION_FR_OP: [u8; delegation::MARKER_BYTES] =
        super::record(ecall::PRECOMPILE_FR_OP);

    /// `P2_FIELD`'s declaration record (S-RECURSION).
    #[link_section = ".rodata.apogee.delegations.p2_field"]
    static DELEGATION_P2_FIELD: [u8; delegation::MARKER_BYTES] =
        super::record(ecall::PRECOMPILE_P2_FIELD);

    /// `FIELD_IO`'s declaration record (S-RECURSION).
    #[link_section = ".rodata.apogee.delegations.field_io"]
    static DELEGATION_FIELD_IO: [u8; delegation::MARKER_BYTES] =
        super::record(ecall::PRECOMPILE_FIELD_IO);

    /// One field operation over field cells (`docs/spec/recursion.md` §3):
    /// `[op, d, a, b]`, one of `constants::fr_op::OPS`.
    ///
    /// **Any answer but 0 is fatal.** The field memory exists only where its
    /// circuits do, so there is no software path to fall back on — and an
    /// `EQ` whose cells differ is not an answer but a fatal frame error.
    pub fn fr_op(frame: &mut [u32; constants::fr_op::FRAME_WORDS]) {
        // SAFETY: as [`poseidon2`]; the frame is four words, read and written
        // back unchanged.
        let ret = unsafe {
            ecall1(
                delegation_number(&DELEGATION_FR_OP),
                frame.as_mut_ptr() as u32,
            )
        };
        if ret != 0 {
            exit(EXIT_PRECOMPILE_ERROR);
        }
    }

    /// One step of the transcript's duplex (`docs/spec/recursion.md` §4):
    /// `[n, s, x, y, d]` absorbs `n` of `x, y` into the state at `s` and
    /// writes the permuted state to `d`. Fatal on any answer but 0, as
    /// [`fr_op`].
    pub fn p2_field(frame: &mut [u32; constants::p2_field::FRAME_WORDS]) {
        // SAFETY: as [`fr_op`].
        let ret = unsafe {
            ecall1(
                delegation_number(&DELEGATION_P2_FIELD),
                frame.as_mut_ptr() as u32,
            )
        };
        if ret != 0 {
            exit(EXIT_PRECOMPILE_ERROR);
        }
    }

    /// One move between RAM and a field cell (`docs/spec/recursion.md` §5):
    /// `[op, cell, ptr]` imports the eight words at `ptr` into `cell` or
    /// exports `cell` into them. `ptr` names eight words the call may read,
    /// and for an export write. Fatal on any answer but 0, as [`fr_op`].
    pub fn field_io(frame: &mut [u32; constants::field_io::FRAME_WORDS]) {
        // SAFETY: as [`fr_op`]; the caller vouches for the eight words.
        let ret = unsafe {
            ecall1(
                delegation_number(&DELEGATION_FIELD_IO),
                frame.as_mut_ptr() as u32,
            )
        };
        if ret != 0 {
            exit(EXIT_PRECOMPILE_ERROR);
        }
    }

    /// The Poseidon2 delegation's 96-byte frame: three canonical
    /// little-endian `Fr` lanes, permuted in place.
    ///
    /// Word-aligned **by its type**, because nothing else supplies it: a bare
    /// `[u8; 96]` has alignment 1, a stack local's address is the code
    /// generator's to choose, and a misaligned base is a fatal
    /// `EmuError::Misaligned` — a guest killed by where codegen happened to
    /// put a local, which is why the alignment is the type's and not a
    /// caller's promise.
    #[repr(C, align(4))]
    pub struct Poseidon2Frame(pub [u8; poseidon2::FRAME_BYTES]);

    /// The Fr-arithmetic delegation's 100-byte frame: the operation code, then
    /// `a`, `b` and the result, each 32 bytes of `Fr`'s in-memory
    /// representation (`docs/spec/delegation.md` §13).
    #[repr(C, align(4))]
    pub struct FrArithFrame(pub [u8; fr_arith::FRAME_BYTES]);

    /// The modulus codes [`ModMulFrame::of`] takes, the limbs each names, and
    /// the two Montgomery corrections a caller holding arkworks-style
    /// representatives needs — re-exported so a caller, including a vendored
    /// crate under `guests/vendor` whose only apogee dependency is this one,
    /// names the constant rather than spelling a number a second time.
    pub use constants::mod_mul::{
        BN254_P, BN254_P_R_INV, BN254_R, BN254_R_R_INV, MODULI, SECP256K1_N, SECP256K1_P,
    };

    /// The Ethereum field multiplication delegation's 100-byte frame: the
    /// modulus selector, then `a`, `b` and the result, each eight
    /// little-endian 32-bit limbs (`docs/spec/delegation.md` §14).
    ///
    /// **Limbs and not bytes**, because every caller already holds its values as
    /// 32-bit limbs and a byte frame would cost a pack and an unpack per call —
    /// which on a 256-bit multiply is a fifth of what the delegation saves. The
    /// `u32` element type is also what gives the type its alignment for free.
    #[repr(C, align(4))]
    pub struct ModMulFrame(pub [u32; mod_mul::FRAME_WORDS]);

    // The frame's word layout, which [`ModMulFrame::of`]'s array literal spells
    // out rather than indexing: a literal is 25 stores where an all-zero array
    // followed by 17 writes was a `memset` and then those stores, and at 6,705
    // invocations on S26's pinned mini-block that zeroing pass alone was 0.5
    // million guest cycles — 6% of what the delegation saves. So the layout is
    // pinned here instead, and a renumbering fails the build.
    //
    // **Re-point these, never delete them.** They are the only thing holding
    // this hand-spelled literal equal to the executor's indexed reads: a
    // 25-word executor reading `out` from words 17..25 against a guest whose
    // `result()` reads 24..32 is a wrong answer with no error anywhere in the
    // emulator, the trace, the prover or the verifier.
    const _: () = assert!(mod_mul::SELECTOR_WORD == 0);
    const _: () = assert!(mod_mul::A_WORD == 1);
    const _: () = assert!(mod_mul::B_WORD == 9);
    const _: () = assert!(mod_mul::OUT_WORD == 17);
    const _: () = assert!(mod_mul::FRAME_WORDS == 25);

    impl ModMulFrame {
        /// A callable frame: the modulus selector, then the two operands, then
        /// the eight result words, which the delegation overwrites and whose
        /// initial value is therefore free.
        ///
        /// `modulus` is one of [`SECP256K1_P`], [`SECP256K1_N`], [`BN254_P`]
        /// and [`BN254_R`], and **both operands must already be below it** —
        /// the circuit enforces `a < m` and `b < m`, and the executor refuses
        /// a frame that is not, by name, so a caller holding a lazily reduced
        /// representation reduces before it calls.
        ///
        /// One pass over the words and no zeroing pass before it. There is no
        /// empty-then-fill constructor, because a frame with no modulus is not a
        /// frame this ABI has a meaning for.
        pub fn of(modulus: u32, a: &[u32; 8], b: &[u32; 8]) -> ModMulFrame {
            ModMulFrame([
                modulus, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3],
                b[4], b[5], b[6], b[7], 0, 0, 0, 0, 0, 0, 0, 0,
            ])
        }

        /// The result's eight limbs, after a successful call.
        pub fn result(&self) -> [u32; 8] {
            let w = &self.0;
            [
                w[mod_mul::OUT_WORD],
                w[mod_mul::OUT_WORD + 1],
                w[mod_mul::OUT_WORD + 2],
                w[mod_mul::OUT_WORD + 3],
                w[mod_mul::OUT_WORD + 4],
                w[mod_mul::OUT_WORD + 5],
                w[mod_mul::OUT_WORD + 6],
                w[mod_mul::OUT_WORD + 7],
            ]
        }
    }

    /// The selector triples one complete [`EcAddFrame`] addition walks, and
    /// SHA-256's initial hash value — re-exported so a caller, including a
    /// vendored crate under `guests/vendor` whose only apogee dependency is
    /// this one, names the constant rather than spelling it a second time.
    pub use constants::ec_add::{BN254_GROUPS, SECP256K1_GROUPS};
    pub use constants::sha256::IV as SHA256_IV;

    /// The SHA-256 delegation's 100-byte frame: the round group, the eight
    /// working variables, then the sixteen-word schedule window
    /// (`docs/spec/delegation.md` §15).
    ///
    /// **Words and not bytes**, for [`ModMulFrame`]'s reason: the caller has
    /// already decoded the block into `u32`s, so a byte frame would cost a pack
    /// and an unpack per block. The `u32` element type is also what gives the
    /// type its alignment for free.
    #[repr(C, align(4))]
    pub struct Sha256Frame(pub [u32; sha::FRAME_WORDS]);

    /// The elliptic-curve addition delegation's 388-byte frame: the selector,
    /// the two input points in homogeneous projective coordinates, and the six
    /// intermediates the three invocations pass between them
    /// (`docs/spec/delegation.md` §16).
    #[repr(C, align(4))]
    pub struct EcAddFrame(pub [u32; ec::FRAME_WORDS]);

    // The two frames' word layouts, which the constructors below index through
    // these names and never by a literal. **Re-point these, never delete
    // them**: they are what holds a guest's reads and writes equal to the
    // executor's, and a frame whose `Z1` a guest reads at word 17 against an
    // executor that writes it at 18 is a wrong answer with no error anywhere in
    // the emulator, the trace, the prover or the verifier.
    const _: () = assert!(sha::GROUP_WORD == 0);
    const _: () = assert!(sha::STATE_WORD == 1);
    const _: () = assert!(sha::WINDOW_WORD == 9);
    const _: () = assert!(sha::FRAME_WORDS == 25);
    const _: () = assert!(ec::SELECTOR_WORD == 0);
    const _: () = assert!(ec::X1_WORD == 1);
    const _: () = assert!(ec::Y1_WORD == 9);
    const _: () = assert!(ec::Z1_WORD == 17);
    const _: () = assert!(ec::X2_WORD == 25);
    const _: () = assert!(ec::Y2_WORD == 33);
    const _: () = assert!(ec::Z2_WORD == 41);
    const _: () = assert!(ec::FRAME_WORDS == 97);

    impl Sha256Frame {
        /// A frame ready for call 0: group 0, the chaining state as the
        /// working variables `a..h`, and the block's sixteen words as the
        /// window. One pass over the words and no zeroing pass before it,
        /// [`ModMulFrame::of`]'s reason applying here too.
        pub fn of(state: &[u32; sha::STATE_WORDS], block: &[u32; sha::BLOCK_WORDS]) -> Sha256Frame {
            let (s, w) = (state, block);
            Sha256Frame([
                0, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], w[0], w[1], w[2], w[3], w[4],
                w[5], w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15],
            ])
        }

        /// The eight working variables the frame holds. After [`sha256_comp`]
        /// they are the compression's `a..h` after round 63, which the caller
        /// adds to the chaining state it kept: the frame never held that state
        /// past call 0.
        pub fn working(&self) -> [u32; sha::STATE_WORDS] {
            let w = &self.0;
            [
                w[sha::STATE_WORD],
                w[sha::STATE_WORD + 1],
                w[sha::STATE_WORD + 2],
                w[sha::STATE_WORD + 3],
                w[sha::STATE_WORD + 4],
                w[sha::STATE_WORD + 5],
                w[sha::STATE_WORD + 6],
                w[sha::STATE_WORD + 7],
            ]
        }
    }

    impl EcAddFrame {
        /// A callable frame for the first group of `codes`: the two points, in
        /// homogeneous projective coordinates, every limb already **below the
        /// selected curve's modulus** — which the circuit enforces and the
        /// executor refuses by name, so a caller holding a lazily reduced
        /// representation reduces before it calls.
        ///
        /// The six intermediate lanes are zeroed rather than left as whatever
        /// the stack held. Their value before the group that writes them is
        /// free to the arithmetic, and zero is below every modulus, so a frame
        /// built here is canonical in **every** lane at every group — which is
        /// one fewer thing for a caller to get right, at 48 stores a call
        /// against the three modular multiplications this replaces.
        ///
        /// **One pass, every word written once** (S26e): an array literal in
        /// the order the `const` assertions above pin, where S26c zeroed all
        /// 388 bytes and then copied the six input lanes over 192 of them.
        /// `k256`'s point additions call this about 27,000 times on one
        /// stateless block.
        ///
        /// The zeros are one value through `core::hint::black_box`, which
        /// changes no word and is there for the code it produces: as 48
        /// literal zeros LLVM merges them into a 192-byte `memset` call, which
        /// measured 163 cycles a frame against 48 plain stores.
        #[inline]
        pub fn of(
            codes: &[u32; ec::GROUPS],
            p: &[[u32; ec::LIMBS]; 3],
            q: &[[u32; ec::LIMBS]; 3],
        ) -> EcAddFrame {
            let [x1, y1, z1] = p;
            let [x2, y2, z2] = q;
            let o = core::hint::black_box(0u32);
            #[rustfmt::skip]
            let words = [
                codes[0],
                x1[0], x1[1], x1[2], x1[3], x1[4], x1[5], x1[6], x1[7],
                y1[0], y1[1], y1[2], y1[3], y1[4], y1[5], y1[6], y1[7],
                z1[0], z1[1], z1[2], z1[3], z1[4], z1[5], z1[6], z1[7],
                x2[0], x2[1], x2[2], x2[3], x2[4], x2[5], x2[6], x2[7],
                y2[0], y2[1], y2[2], y2[3], y2[4], y2[5], y2[6], y2[7],
                z2[0], z2[1], z2[2], z2[3], z2[4], z2[5], z2[6], z2[7],
                o, o, o, o, o, o, o, o,
                o, o, o, o, o, o, o, o,
                o, o, o, o, o, o, o, o,
                o, o, o, o, o, o, o, o,
                o, o, o, o, o, o, o, o,
                o, o, o, o, o, o, o, o,
            ];
            EcAddFrame(words)
        }

        /// The sum, after a successful [`ec_add_complete`]: the third group
        /// writes `X3`, `Y3` and `Z3` over the `X1`, `Y1` and `Z1` lanes the
        /// first two groups have by then finished reading.
        #[inline]
        pub fn result(&self) -> [[u32; ec::LIMBS]; 3] {
            let limbs = |first: usize| core::array::from_fn(|k| self.0[first + k]);
            [limbs(ec::X1_WORD), limbs(ec::Y1_WORD), limbs(ec::Z1_WORD)]
        }
    }

    // The frame rule of `docs/spec/delegation.md` §4 as a type-level
    // assertion: what the ecall hands over is word-aligned or this crate does
    // not build.
    const _: () = assert!(core::mem::align_of::<Poseidon2Frame>() >= 4);
    const _: () = assert!(core::mem::align_of::<FrArithFrame>() >= 4);
    const _: () = assert!(core::mem::align_of::<ModMulFrame>() >= 4);
    const _: () = assert!(core::mem::align_of::<Sha256Frame>() >= 4);
    const _: () = assert!(core::mem::align_of::<EcAddFrame>() >= 4);

    /// Permute the frame in place. `false` on exactly `-ENOSYS`.
    pub fn poseidon2(frame: &mut Poseidon2Frame) -> bool {
        // SAFETY: `frame` is a live, writable, word-aligned buffer of the
        // declared width, which is the whole of this call's contract.
        let ret = unsafe {
            ecall1(
                delegation_number(&DELEGATION_POSEIDON2),
                frame.0.as_mut_ptr() as u32,
            )
        };
        answered(ret)
    }

    /// Run one `Fr` operation over the frame in place. `false` on exactly
    /// `-ENOSYS`.
    pub fn fr_arith(frame: &mut FrArithFrame) -> bool {
        // SAFETY: as [`poseidon2`].
        let ret = unsafe {
            ecall1(
                delegation_number(&DELEGATION_FR_ARITH),
                frame.0.as_mut_ptr() as u32,
            )
        };
        answered(ret)
    }

    /// Compute `out = a * b mod m` over the frame in place, `m` being the
    /// field the frame's selector names. `false` on exactly `-ENOSYS`, which
    /// is the caller's signal to run its own multiply.
    ///
    /// Both operands must already be below the selected modulus; a frame that
    /// breaks that is a fatal guest error, not a wrapped answer.
    pub fn mod_mul(frame: &mut ModMulFrame) -> bool {
        // SAFETY: as [`poseidon2`].
        let ret = unsafe {
            ecall1(
                delegation_number(&DELEGATION_MOD_MUL),
                frame.0.as_mut_ptr() as u32,
            )
        };
        answered(ret)
    }

    /// **Four rounds** over the frame, in place: rounds `4r..4r + 4` for the
    /// group `r` in frame word 0, and the window shifted by four with the four
    /// schedule words those rounds unlock appended. `false` on exactly
    /// `-ENOSYS`.
    ///
    /// A caller compressing a block wants [`sha256_comp`]; this is the raw
    /// call, for a caller driving the group itself.
    pub fn sha256_rounds(frame: &mut Sha256Frame) -> bool {
        // SAFETY: as [`poseidon2`].
        let ret = unsafe {
            ecall1(
                delegation_number(&DELEGATION_SHA256_COMP),
                frame.0.as_mut_ptr() as u32,
            )
        };
        answered(ret)
    }

    /// One compression's 64 rounds: the sixteen calls in group order, leaving
    /// the working variables after round 63 in the frame for
    /// [`Sha256Frame::working`]. `false` on exactly `-ENOSYS` from the
    /// **first** call, and then the frame is untouched, so the caller's own
    /// compression can run from the same inputs. A later call answering
    /// `-ENOSYS` is a broken executor, and skipping rounds silently would be
    /// worse than exiting, as it is for `keccak256`.
    ///
    /// The frame is transformed in place, so nothing is copied between calls
    /// and the chain a proof reads is the frame's own RAM history
    /// (`docs/spec/delegation.md` §15).
    pub fn sha256_comp(frame: &mut Sha256Frame) -> bool {
        frame.0[sha::GROUP_WORD] = 0;
        if !sha256_rounds(frame) {
            return false;
        }
        for group in 1..sha::GROUPS as u32 {
            frame.0[sha::GROUP_WORD] = group;
            if !sha256_rounds(frame) {
                exit(EXIT_PRECOMPILE_ERROR);
            }
        }
        true
    }

    /// Run **one group** of a point addition over the frame in place, the group
    /// and the curve being what the frame's selector word names. `false` on
    /// exactly `-ENOSYS`.
    ///
    /// A caller adding two points wants [`ec_add_complete`]; this is the raw
    /// call, for a caller driving the selector itself.
    pub fn ec_add(frame: &mut EcAddFrame) -> bool {
        // SAFETY: as [`poseidon2`].
        let ret = unsafe {
            ecall1(
                delegation_number(&DELEGATION_EC_ADD),
                frame.0.as_mut_ptr() as u32,
            )
        };
        answered(ret)
    }

    /// One complete addition: the three groups of `codes` in order, leaving the
    /// sum in the frame's first three lanes for [`EcAddFrame::result`].
    /// `false` on exactly `-ENOSYS` from the **first** group, and then the
    /// frame's two input points are untouched, so the caller's own formulas
    /// have their operands still.
    ///
    /// The order is the whole of this function's content and the reason it
    /// exists: group 0 leaves `xx`, `yy` and `zz`, group 1 leaves `m4`, `m5`
    /// and `m6`, and group 2 consumes all six. Two of them transposed is not a
    /// refusal anywhere — it is a different point, computed from lanes whose
    /// previous contents were zero.
    pub fn ec_add_complete(frame: &mut EcAddFrame, codes: &[u32; ec::GROUPS]) -> bool {
        for code in codes {
            frame.0[ec::SELECTOR_WORD] = *code;
            if !ec_add(frame) {
                return false;
            }
        }
        true
    }

    /// 0 is "the circuit ran it", `-ENOSYS` is "this executor has no circuit",
    /// and anything else is a call that went wrong.
    fn answered(ret: i32) -> bool {
        match ret {
            0 => true,
            n if n == -(ecall::ENOSYS as i32) => false,
            _ => exit(EXIT_PRECOMPILE_ERROR),
        }
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
/// **Each record has a section name of its own**, and that is load-bearing:
/// the linker's garbage collection works at section granularity, so three
/// records sharing one `#[link_section]` are one input section and are kept
/// or dropped together. With one name every guest that reached *any* shim
/// declared *every* family, and detachment said nothing. The names all begin
/// `.rodata.`, so `link.ld` absorbs them unchanged and the byte-wise scan does
/// not care what they are called.
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
/// `crates/program/tests/delegation.rs` holds every committed guest to that,
/// at both optimisation levels.
#[link_section = ".rodata.apogee.delegations.keccak_f"]
static DELEGATION_KECCAK_F: [u8; delegation::MARKER_BYTES] = record(ecall::PRECOMPILE_KECCAK_F);

/// One declaration record: the magic, then the declared number as a
/// little-endian `u32`. `const`-evaluated, so it is a constant in `.rodata`
/// and not code that runs.
const fn record(number: u32) -> [u8; delegation::MARKER_BYTES] {
    let mut record = [0u8; delegation::MARKER_BYTES];
    let magic = delegation::MARKER_MAGIC;
    let mut i = 0;
    while i < magic.len() {
        record[i] = magic[i];
        i += 1;
    }
    let number = number.to_le_bytes();
    let mut j = 0;
    while j < number.len() {
        record[magic.len() + j] = number[j];
        j += 1;
    }
    record
}

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

/// The 204-byte frame a delegation request hands over, **word-aligned**: the
/// round this invocation performs, then the 1,600-bit state.
///
/// The alignment is in the type because nothing else supplies it. A bare byte
/// array has alignment 1, and a stack local's address is the code generator's
/// to choose: LLVM places align-1 stack objects at odd offsets whenever the
/// frame packs that way, at every optimisation level.
/// `docs/spec/delegation.md` §4 rule 1 requires a word-aligned base, and a
/// misaligned one is a fatal `EmuError::Misaligned`. An unaligned buffer would
/// therefore be a guest killed by where codegen happened to put a local, which
/// is why the alignment is the type's and not a caller's promise.
///
/// `align(4)` and not more: 4 is what the ABI states, what `keccak`'s
/// `base_aligned` decomposes and what `emulator::delegation_frame` checks. The
/// `u32` first is what makes `round` frame word 0 under `repr(C)`.
#[repr(C, align(4))]
struct Frame {
    round: u32,
    state: [u8; keccak::STATE_BYTES],
}

/// The frame rules of `docs/spec/delegation.md` §4 and §6 as type-level
/// assertions: word-aligned, and laid out as the frame table says.
const _: () = assert!(core::mem::align_of::<Frame>() >= 4);
const _: () = assert!(core::mem::size_of::<Frame>() == keccak::FRAME_BYTES);
const _: () = assert!(keccak::ROUND_WORD == 0 && keccak::STATE_WORD == 1);

/// **One round** of keccak-f[1600] over the frame, as a delegation.
///
/// Returns `false` when the executor answers exactly `-ENOSYS` — an executor
/// with no keccak circuit — and the caller runs the software path. Any other
/// nonzero answer exits nonzero rather than falling back, for
/// [`poseidon2_permute`]'s reason.
fn keccak_round_delegated(frame: &mut Frame) -> bool {
    // SAFETY: `frame` is a live, writable 204-byte buffer, word-aligned by its
    // type, which is the whole of this call's contract.
    let ret = unsafe {
        ecall1(
            delegation_number(&DELEGATION_KECCAK_F),
            frame as *mut Frame as u32,
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

/// One permutation of the sponge state: **24 delegated rounds**, or the
/// software path.
///
/// The frame the delegation dereferences is a [`Frame`], so it satisfies the
/// two frame rules of `docs/spec/delegation.md` §4 for different reasons. The
/// **window** rule holds by construction: the buffer is a stack local, the
/// stack lies below `__stack_top`, and `__stack_top` is the top of the RAM
/// window, so `base + 204` cannot leave it. The **alignment** rule does not
/// hold by construction, which is why [`Frame`] carries it.
///
/// The 24 calls transform the frame **in place**, so nothing is copied between
/// them and the chain the proof reads is the frame's own RAM history
/// (`docs/spec/delegation.md` §6.4). Only the **first** call may answer
/// `-ENOSYS`, which is an executor with no keccak circuit at all; one answering
/// it halfway through a permutation is a broken executor, and skipping a round
/// silently would be worse than exiting.
fn permute(frame: &mut Frame) {
    frame.round = 0;
    if keccak_round_delegated(frame) {
        for round in 1..keccak::ROUNDS as u32 {
            frame.round = round;
            if !keccak_round_delegated(frame) {
                exit(EXIT_PRECOMPILE_ERROR);
            }
        }
        return;
    }
    let mut lanes = [0u64; keccak::LANES];
    for (i, lane) in lanes.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&frame.state[8 * i..8 * i + 8]);
        *lane = u64::from_le_bytes(bytes);
    }
    keccak_f_software(&mut lanes);
    for (i, lane) in lanes.iter().enumerate() {
        frame.state[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
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
    let mut state = Frame {
        round: 0,
        state: [0u8; keccak::STATE_BYTES],
    };
    let mut block = input.chunks_exact(keccak::RATE_BYTES);
    for chunk in block.by_ref() {
        for (cell, byte) in state.state.iter_mut().zip(chunk) {
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
    for (cell, byte) in state.state.iter_mut().zip(last.iter()) {
        *cell ^= byte;
    }
    permute(&mut state);
    let mut digest = [0u8; keccak::DIGEST_BYTES];
    digest.copy_from_slice(&state.state[..keccak::DIGEST_BYTES]);
    digest
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/// One SHA-256 compression in software: the fallback, and the definition the
/// delegated path is held to.
///
/// FIPS 180-4 §6.2.2 over one block's sixteen schedule words, the remaining
/// forty-eight derived here. `crates/emulator`'s `sha256_frame` carries the
/// executor's own copy and `crates/constraints::sha256` the circuit's; all
/// three are held equal to the published test vectors, and a crate whose only
/// purpose was to be shared by them would be the abstraction the master's
/// anti-goals refuse.
fn sha256_compress_software(
    state: &mut [u32; sha256c::STATE_WORDS],
    block: &[u32; sha256c::BLOCK_WORDS],
) {
    let mut w = [0u32; sha256c::ROUNDS];
    w[..sha256c::BLOCK_WORDS].copy_from_slice(block);
    for i in sha256c::BLOCK_WORDS..sha256c::ROUNDS {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (i, wi) in w.iter().enumerate() {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(sha256c::ROUND_CONSTANTS[i])
            .wrapping_add(*wi);
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
    for (slot, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(v);
    }
}

/// One compression: the delegation's sixteen calls and the final `H + V`, or
/// the software path.
///
/// The frame satisfies `docs/spec/delegation.md` §4's two rules exactly as
/// keccak's does — the window rule by construction, the stack lying below
/// `__stack_top`, and the alignment rule by [`recursion::Sha256Frame`]'s type.
fn sha256_compress(state: &mut [u32; sha256c::STATE_WORDS], block: &[u32; sha256c::BLOCK_WORDS]) {
    let mut frame = recursion::Sha256Frame::of(state, block);
    if recursion::sha256_comp(&mut frame) {
        for (h, v) in state.iter_mut().zip(frame.working()) {
            *h = h.wrapping_add(v);
        }
        return;
    }
    sha256_compress_software(state, block);
}

/// SHA-256 of `input`: Ethereum's `0x02` precompile, and FIPS 180-4.
///
/// **This signature is the patchable entry point**, as [`keccak256`]'s is: the
/// delegated path and the software fallback are bit-identical behind it and a
/// guest never chooses between them and cannot tell which ran.
///
/// The padding and the block loop run here, in guest code, and one delegation
/// ecall covers each compression. Padding is Merkle-Damgård's — `0x80`, zeros,
/// then the message's **bit** length as a 64-bit big-endian integer — and every
/// word crossing the frame is big-endian decoded, SHA-256 being a big-endian
/// design where keccak is a little-endian one.
pub fn sha256(input: &[u8]) -> [u8; 4 * sha256c::STATE_WORDS] {
    const BLOCK_BYTES: usize = 4 * sha256c::BLOCK_WORDS;

    let mut state = sha256c::IV;
    let decode = |bytes: &[u8]| -> [u32; sha256c::BLOCK_WORDS] {
        core::array::from_fn(|i| {
            u32::from_be_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ])
        })
    };

    let mut blocks = input.chunks_exact(BLOCK_BYTES);
    for chunk in blocks.by_ref() {
        sha256_compress(&mut state, &decode(chunk));
    }

    // The tail, padded. `chunks_exact`'s remainder is shorter than a block, so
    // the padded tail is one block when the `0x80` and the eight length bytes
    // fit in what is left and two when they do not — which is the case for a
    // remainder of 56 bytes or more, the empty input included in the first.
    let rest = blocks.remainder();
    let mut tail = [0u8; 2 * BLOCK_BYTES];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let padded = if rest.len() + 9 > BLOCK_BYTES {
        2 * BLOCK_BYTES
    } else {
        BLOCK_BYTES
    };
    let bits = (input.len() as u64) * 8;
    tail[padded - 8..padded].copy_from_slice(&bits.to_be_bytes());
    for chunk in tail[..padded].chunks_exact(BLOCK_BYTES) {
        sha256_compress(&mut state, &decode(chunk));
    }

    let mut digest = [0u8; 4 * sha256c::STATE_WORDS];
    for (i, word) in state.iter().enumerate() {
        digest[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

// ---------------------------------------------------------------------------
// Elliptic-curve point operations
// ---------------------------------------------------------------------------

/// A point in **homogeneous projective** coordinates: `x = X/Z`, `y = Y/Z`,
/// each coordinate eight little-endian 32-bit limbs **below the curve's
/// modulus**.
///
/// It is not Jacobian. arkworks' `Projective` is (`x = X/Z²`), so a caller
/// holding one converts — `(X·Z, Y·Z², Z)` in and `(X·Z, Y, Z³)` out — and
/// `guests/vendor/k256`'s `ProjectivePoint` is already homogeneous and converts
/// not at all. The identity is `(0 : 1 : 0)`.
pub type ProjectivePoint = [[u32; ec_add::LIMBS]; 3];

/// `p + q` on the curve `codes` names, or `None` on exactly `-ENOSYS`.
///
/// **This is the whole of the `EC_ADD` ABI a caller needs**, and the reason it
/// is a function here rather than three calls at a call site: a complete
/// addition is the three codes of one curve **in group order**, and two
/// transposed is not a refusal anywhere — it is a different point, computed from
/// lanes whose previous contents were zero. `codes` is
/// [`recursion::SECP256K1_GROUPS`] or [`recursion::BN254_GROUPS`].
///
/// Renes–Costello–Batina 2015 Algorithm 7, which is **complete**: `P + P`,
/// `P + (−P)`, `P + O` and a non-normalized `Z` all come out right, so a caller
/// branches on nothing.
pub fn ec_add(
    codes: &[u32; ec_add::GROUPS],
    p: &ProjectivePoint,
    q: &ProjectivePoint,
) -> Option<ProjectivePoint> {
    let mut frame = recursion::EcAddFrame::of(codes, p, q);
    match recursion::ec_add_complete(&mut frame, codes) {
        true => Some(frame.result()),
        false => None,
    }
}

/// `k · p`, by double-and-add from the top bit. `None` on exactly `-ENOSYS`,
/// and then **nothing has been computed** — the first doubling is what asks.
///
/// `k` is eight little-endian limbs and is used as given: reducing it modulo the
/// group order is the caller's business, and every caller already holds a
/// reduced scalar.
///
/// Completeness is what makes this five lines, and it is worth saying what it
/// replaces: a ladder over an incomplete formula needs a case for the first
/// iteration, a case for a doubling and a case for the identity, and each is a
/// place to be wrong only on inputs a test does not reach. Here the accumulator
/// starts at the identity and every step is one addition.
pub fn ec_mul(
    codes: &[u32; ec_add::GROUPS],
    p: &ProjectivePoint,
    k: &[u32; ec_add::LIMBS],
) -> Option<ProjectivePoint> {
    let mut acc = ec_identity();
    let mut bit = 32 * ec_add::LIMBS;
    while bit > 0 {
        bit -= 1;
        acc = ec_add(codes, &acc, &acc)?;
        if (k[bit / 32] >> (bit % 32)) & 1 == 1 {
            acc = ec_add(codes, &acc, p)?;
        }
    }
    Some(acc)
}

/// The projective identity, `(0 : 1 : 0)`.
pub fn ec_identity() -> ProjectivePoint {
    let mut one = [0u32; ec_add::LIMBS];
    one[0] = 1;
    [[0u32; ec_add::LIMBS], one, [0u32; ec_add::LIMBS]]
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
/// writing into a `Vec` rewrote the caller's locals and return addresses. It
/// was found by running a guest's own source on the host and comparing the two
/// runs — the suite that did so is gone, and what holds the rule now is that
/// each half exits 71 rather than corrupting anything.
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // **A panic is silent, and that is the design.** An Apogee guest has no
    // diagnostic stream: the only bytes leaving an execution are the journal,
    // which a proof binds, and the exit status. Writing the message anywhere a
    // host could read it would need an unprovable ecall, and routing it into
    // the journal would break `exit` publishing nothing -- a guest that panics
    // has still published exactly what it committed
    // (`docs/spec/public-values.md` section 7).
    //
    // What this buys is worth more than the message: with no write on the
    // panic path, **a panicking guest is provable**. Until the POSIX layer was
    // deleted it was not, because its handler reached fd 2.
    exit(EXIT_PANIC)
}
