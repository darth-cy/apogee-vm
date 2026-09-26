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

use constants::{delegation, ecall, guest_memory, keccak, poseidon2};

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

/// Read the POSIX standard input stream, fd 0. **Not provable, and not the
/// public input.**
///
/// `read` is not a provable ecall (`docs/spec/public-values.md` §1), so a guest
/// that takes this path is one no proof covers. It exists because a guest built
/// for a POSIX host runs under `qemu-riscv32`, and the executor serves the same
/// bytes here that it lays out in the public input window, so one source can be
/// compared under both. A guest that wants to be proven calls [`public_input`],
/// which issues no ecall at all.
pub fn read_stdin(buf: &mut [u8]) -> usize {
    read_fd(ecall::FD_STDIN, buf)
}

/// Write the POSIX standard output stream, fd 1. **Not provable, and not the
/// journal.** [`read_stdin`]'s note applies: this is the compatibility path,
/// and [`commit`] is what a proof binds.
pub fn write_stdout(bytes: &[u8]) {
    write_fd(ecall::FD_STDOUT, bytes);
}

/// Read private hint bytes from fd 3. **Not provable**, for [`read_stdin`]'s
/// reason; [`advice`] is the provable spelling of the same idea.
///
/// Returns the number of bytes read. **These bytes are nondeterministic prover
/// advice.** Nothing binds them: the prover chooses them, and it may choose
/// them differently on every run. A hint is only ever a shortcut to a value the
/// guest then *checks* against something a proof does bind.
pub fn hint(buf: &mut [u8]) -> usize {
    read_fd(ecall::FD_HINT, buf)
}

/// Write diagnostics to fd 2. Free-form, uncommitted, verifier-ignored, and
/// not provable.
pub fn log(bytes: &[u8]) {
    write_fd(ecall::FD_STDERR, bytes);
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
/// That is the whole contract (`docs/spec/public-values.md` §6), and it is the
/// same one [`hint`] carries; advice differs only in being ordinary memory, so
/// a provable guest can read it.
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
/// lane order, permuted in place. S10 froze this signature and S23 gave the
/// number a circuit; the call is now a **delegation**
/// (`docs/spec/delegation.md` §12), so an executor that has the circuit
/// answers 0 and one that does not answers `-ENOSYS`.
///
/// Returns `false` on exactly `-ENOSYS`, and a caller must have a software
/// path and take it on `false` — under `qemu-riscv32` that is the path the
/// proof is about.
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
    use constants::{delegation, ecall, fr_arith, mod_mul, poseidon2};

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

    /// The Poseidon2 delegation's 96-byte frame: three canonical
    /// little-endian `Fr` lanes, permuted in place.
    ///
    /// Word-aligned **by its type**, because nothing else supplies it: a bare
    /// `[u8; 96]` has alignment 1, a stack local's address is the code
    /// generator's to choose, and a misaligned base is a fatal
    /// `EmuError::Misaligned` under this VM while `qemu-riscv32` answers
    /// `-ENOSYS` and never dereferences it — the same binary correct under one
    /// executor and dead under the other, decided by codegen.
    #[repr(C, align(4))]
    pub struct Poseidon2Frame(pub [u8; poseidon2::FRAME_BYTES]);

    /// The Fr-arithmetic delegation's 100-byte frame: the operation code, then
    /// `a`, `b` and the result, each 32 bytes of `Fr`'s in-memory
    /// representation (`docs/spec/delegation.md` §13).
    #[repr(C, align(4))]
    pub struct FrArithFrame(pub [u8; fr_arith::FRAME_BYTES]);

    /// The modular multiplication delegation's 128-byte frame: the modulus,
    /// `a`, `b` and the result, each eight little-endian 32-bit limbs
    /// (`docs/spec/delegation.md` §14).
    ///
    /// **Limbs and not bytes**, because every caller already holds its values as
    /// 32-bit limbs and a byte frame would cost a pack and an unpack per call —
    /// which on a 256-bit multiply is a fifth of what the delegation saves. The
    /// `u32` element type is also what gives the type its alignment for free.
    #[repr(C, align(4))]
    pub struct ModMulFrame(pub [u32; mod_mul::FRAME_WORDS]);

    // The frame's word layout, which [`ModMulFrame::of`]'s array literal spells
    // out rather than indexing: a literal is 32 stores where an all-zero array
    // followed by 24 writes was a `memset` and then those stores, and at 6,705
    // invocations on S26's pinned mini-block that zeroing pass alone was 0.5
    // million guest cycles — 6% of what the delegation saves. So the layout is
    // pinned here instead, and a renumbering fails the build.
    const _: () = assert!(mod_mul::M_WORD == 0);
    const _: () = assert!(mod_mul::A_WORD == 8);
    const _: () = assert!(mod_mul::B_WORD == 16);
    const _: () = assert!(mod_mul::OUT_WORD == 24);
    const _: () = assert!(mod_mul::FRAME_WORDS == 32);

    impl ModMulFrame {
        /// A callable frame: the modulus, then the two operands, then the eight
        /// result words, which the delegation overwrites and whose initial value
        /// is therefore free.
        ///
        /// One pass over the words and no zeroing pass before it. There is no
        /// empty-then-fill constructor, because a frame with no modulus is not a
        /// frame this ABI has a meaning for.
        pub fn of(m: &[u32; 8], a: &[u32; 8], b: &[u32; 8]) -> ModMulFrame {
            ModMulFrame([
                m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], a[0], a[1], a[2], a[3], a[4], a[5],
                a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0, 0, 0, 0, 0, 0, 0, 0,
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

    // The frame rule of `docs/spec/delegation.md` §4 as a type-level
    // assertion: what the ecall hands over is word-aligned or this crate does
    // not build.
    const _: () = assert!(core::mem::align_of::<Poseidon2Frame>() >= 4);
    const _: () = assert!(core::mem::align_of::<FrArithFrame>() >= 4);
    const _: () = assert!(core::mem::align_of::<ModMulFrame>() >= 4);

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

    /// Compute `out = a * b mod m` over the frame in place. `false` on exactly
    /// `-ENOSYS`, which is the caller's signal to run its own multiply.
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
