#![no_std]
//! The guest-side runtime: crt0, the entry macro, a bump allocator, a panic
//! handler, the exit call and the delegation shims.
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
//! `docs/spec/public-values.md` specifies all three.
//!
//! The ecall ABI is [`exit`] and the delegation shims, [`keccak_f`] and
//! [`sha256_compress`]. An ecall carries its number in `a7` and its argument in
//! `a0`; `docs/spec/ecall-abi.md` is the table, every number [`constants::ecall`]'s.
//!
//! # `unsafe`, and global state
//!
//! A startup stub, a `#[global_allocator]` and a syscall shim cannot be written
//! without `unsafe` and global mutable state, so this crate has both. No crate
//! of the root workspace has an `unsafe` block.

use core::alloc::{GlobalAlloc, Layout};
use core::arch::global_asm;

use constants::{delegation, ecall, guest_memory, keccak, sha256};

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
/// This is a `macro_rules!` and not an `#[entry]` attribute, because an
/// attribute macro requires a `proc-macro` crate — which cannot export anything
/// else, so it would mean a second package for the sake of one spelling.
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

// One shim, one argument: `EXIT` takes a status, and a delegation call its
// frame's base. A six-argument shim with zeroes passed in would be strictly worse --
// an unused `in(...)` register is still a constraint on the register
// allocator.
//
// No `options(...)`: the default is the conservative one.
//
// No clobber list either, and that is a load-bearing assumption rather than an
// omission: **an ecall preserves every register except `a0`**, which
// `docs/spec/ecall-abi.md` §1 states as part of the ABI. An executor that
// scratched `t0` would produce silently wrong guest arithmetic, which is why
// the rule is written down there and not only here.

/// `ecall` with one argument.
///
/// # Safety
/// The caller guarantees that `num` names a call whose contract is satisfied
/// by `a0`.
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

/// Status used when [`commit`] is handed more bytes than the journal holds:
/// the one I/O failure a guest can have.
const EXIT_IO_ERROR: i32 = 70;

/// Status used when an allocation would reach the stack: see [`BumpAllocator`].
const EXIT_OUT_OF_MEMORY: i32 = 71;

/// Status used by the panic handler.
const EXIT_PANIC: i32 = 101;

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
///   wants, so a program whose call depth fits in them never meets a heap block.
/// - The live `sp`. A stack already deeper than its reserve still never has a
///   block handed out on top of a frame in use.
///
/// With `__stack_top` itself as the ceiling, running out of heap would be
/// silent corruption rather than an exit: a block ending anywhere between the
/// live `sp` and the top would be handed out *over live stack frames*, so safe
/// code writing into a `Vec` would rewrite the caller's locals and return
/// addresses. Each half of the ceiling exits 71 rather than corrupting
/// anything.
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
        // the reserve, which the memory map makes impossible; it is
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
    // (`docs/spec/public-values.md` §7).
    //
    // What this buys is worth more than the message: with no write on the
    // panic path, **a panicking guest is provable**.
    exit(EXIT_PANIC)
}

// ---------------------------------------------------------------------------
// Delegation shims
// ---------------------------------------------------------------------------
//
// Last in the file, so a guest that calls no delegation links none of it and
// the line numbers -- the panic locations -- of everything above stay put.

/// Status used when a delegation call answers anything but 0.
const EXIT_DELEGATION_ERROR: i32 = 72;

/// A declaration record (`constants::delegation`): the magic, then `number`
/// little-endian. `const`-evaluated, so it is `.rodata` and not code.
const fn record(number: u32) -> [u8; delegation::MARKER_BYTES] {
    let magic = delegation::MARKER_MAGIC;
    let number = number.to_le_bytes();
    let mut out = [0u8; delegation::MARKER_BYTES];
    let mut i = 0;
    while i < delegation::MARKER_BYTES {
        out[i] = if i < magic.len() {
            magic[i]
        } else {
            number[i - magic.len()]
        };
        i += 1;
    }
    out
}

// The records, one section each: the linker keeps or drops sections whole, so
// two records in one would declare both families for a guest that reaches
// either. And no `#[used]`: a record must be in the image exactly when its shim
// is, so what keeps it is the shim reading its ecall number out of it.

#[link_section = ".rodata.apogee.delegations.keccak_f"]
static DECLARE_KECCAK_F: [u8; delegation::MARKER_BYTES] = record(ecall::PRECOMPILE_KECCAK_F);

#[link_section = ".rodata.apogee.delegations.sha256_comp"]
static DECLARE_SHA256_COMP: [u8; delegation::MARKER_BYTES] = record(ecall::PRECOMPILE_SHA256_COMP);

/// One delegation call over `frame`, its ecall number read back out of
/// `declared`. Through `black_box`: folded to an immediate, the read would
/// leave the record unreferenced and the declaration out of the image.
fn delegate(declared: &'static [u8; delegation::MARKER_BYTES], frame: &mut [u32]) {
    let declared = core::hint::black_box(declared);
    let n = delegation::MARKER_MAGIC.len();
    let number = u32::from_le_bytes([
        declared[n],
        declared[n + 1],
        declared[n + 2],
        declared[n + 3],
    ]);
    // SAFETY: `frame` is live, writable and word-aligned, and the caller sizes
    // it to the frame `number`'s family reads and writes in place.
    if unsafe { ecall1(number, frame.as_mut_ptr() as u32) } != 0 {
        exit(EXIT_DELEGATION_ERROR);
    }
}

/// keccak-f[1600] over 25 lanes, lane `x + 5y` at index `x + 5y`: 24
/// `KECCAK_F` delegation calls on one frame, one round each.
pub fn keccak_f(lanes: &mut [u64; keccak::LANES]) {
    let mut frame = [0u32; keccak::FRAME_WORDS];
    for (i, lane) in lanes.iter().enumerate() {
        frame[keccak::STATE_WORD + 2 * i] = *lane as u32;
        frame[keccak::STATE_WORD + 2 * i + 1] = (*lane >> 32) as u32;
    }
    for round in 0..keccak::ROUNDS as u32 {
        frame[keccak::ROUND_WORD] = round;
        delegate(&DECLARE_KECCAK_F, &mut frame);
    }
    for (i, lane) in lanes.iter_mut().enumerate() {
        let (lo, hi) = (
            frame[keccak::STATE_WORD + 2 * i],
            frame[keccak::STATE_WORD + 2 * i + 1],
        );
        *lane = lo as u64 | (hi as u64) << 32;
    }
}

/// One SHA-256 compression of `block`, big-endian decoded, into `state`: 16
/// `SHA256_COMP` delegation calls on one frame, four rounds each, then the
/// feed-forward. Padding and the block loop are the caller's.
pub fn sha256_compress(state: &mut [u32; sha256::STATE_WORDS], block: &[u32; sha256::BLOCK_WORDS]) {
    let mut frame = [0u32; sha256::FRAME_WORDS];
    frame[sha256::STATE_WORD..sha256::WINDOW_WORD].copy_from_slice(state);
    frame[sha256::WINDOW_WORD..].copy_from_slice(block);
    for group in 0..sha256::GROUPS as u32 {
        frame[sha256::GROUP_WORD] = group;
        delegate(&DECLARE_SHA256_COMP, &mut frame);
    }
    for (h, v) in state
        .iter_mut()
        .zip(&frame[sha256::STATE_WORD..sha256::WINDOW_WORD])
    {
        *h = h.wrapping_add(*v);
    }
}
