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

use constants::{ecall, guest_memory};

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
/// portability suite found it by running this guest's source on the host and
/// comparing; `crates/emulator/tests/portability.rs` holds the fix to both
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
