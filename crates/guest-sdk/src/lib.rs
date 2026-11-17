#![no_std]
//! The guest-side runtime: crt0, the entry macro, a bump allocator, a panic
//! handler, the exit call and the delegation call — and, last in the file, the
//! C ABI over them, which a C or C++ guest links as `libapogee_guest.a`
//! (`include/apogee_guest.h`, `docs/guest-program-manual.md` §11).
//!
//! Everything here runs *inside* the proof. It compiles only for
//! `riscv64imac-unknown-none-elf` and links only into guest binaries.
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
//! The ecall ABI is [`exit`] and the delegation calls, each a shim over one
//! frame: [`poseidon2_permute`], [`merkle_root`], [`falcon512`]'s decoder,
//! sampler and [`falcon512::s1_norm`], and [`U256`]'s divisions. An ecall carries its number in `a7` and its
//! argument in `a0`; `docs/spec/ecall-abi.md` is the table, every number
//! [`constants::ecall`]'s.
//!
//! # `unsafe`, and global state
//!
//! A startup stub, a `#[global_allocator]` and a syscall shim cannot be written
//! without `unsafe` and global mutable state, so this crate has both. No crate
//! of the root workspace has an `unsafe` block.

use core::alloc::{GlobalAlloc, Layout};
use core::arch::global_asm;

use constants::{ecall, guest_memory};

// ---------------------------------------------------------------------------
// crt0
// ---------------------------------------------------------------------------

// `_start` sits in its own `.text._start` section so the linker script places
// it first, at ORIGIN(RAM). It does exactly five things: point `sp` at
// `__stack_top`, zero `.bss`, call each initializer in
// `__init_array_start..__init_array_end` in order, call `__apogee_main`, and
// exit with what it returned in `a0`. `apogee.ld` makes `__apogee_main` the
// guest's `main` — C's `int main(void)`, and 0 from the `entry!` wrapper —
// unless the guest has destructors: C++'s, registered through `__cxa_atexit`
// for its static objects, or C's destructor functions. Then it is `main`
// followed by them, `__apogee_main_then_destructors`. The initializers are
// C++'s dynamic initialization and C's constructor functions; a Rust guest has
// none, and pays five instructions for the empty loop and none for destructors.
// The pointers are walked in `s0` and `s1`, which every initializer preserves.
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
    "  la   s0, __init_array_start",
    "  la   s1, __init_array_end",
    "3:",
    "  bgeu s0, s1, 4f",
    "  ld   t0, 0(s0)",
    "  jalr t0",
    "  addi s0, s0, 8",
    "  j    3b",
    "4:",
    "  call __apogee_main",
    "  li   a7, {exit}",
    "  ecall",
    "5:",
    "  j    5b",
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
/// is an `exit(0)`, the wrapper returning 0 to crt0.
///
/// This is a `macro_rules!` and not an `#[entry]` attribute, because an
/// attribute macro requires a `proc-macro` crate — which cannot export anything
/// else, so it would mean a second package for the sake of one spelling.
#[macro_export]
macro_rules! entry {
    ($f:ident) => {
        #[export_name = "main"]
        pub extern "C" fn __apogee_guest_entry() -> i32 {
            $f();
            0
        }
    };
}

// ---------------------------------------------------------------------------
// Raw ecall
// ---------------------------------------------------------------------------

// One shim, one argument: `EXIT` takes a status. A delegation call, which
// takes its frame's base and preserves `a0`, has its own (`delegate`). A
// six-argument shim with zeroes passed in would be strictly worse -- an unused
// `in(...)` register is still a constraint on the register allocator.
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
unsafe fn ecall1(num: usize, a0: usize) -> isize {
    let ret: isize;
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
fn word_at(addr: usize) -> u32 {
    // SAFETY: `addr` is 4-aligned and inside a region the executor makes
    // addressable; every caller here derives it from a window origin.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// A `&'static [u8]` over `len` bytes at `addr`.
///
/// # Safety
/// `addr .. addr + len` must lie inside one addressable region.
unsafe fn slice_at(addr: usize, len: usize) -> &'static [u8] {
    core::slice::from_raw_parts(addr as *const u8, len)
}

/// The **public input**: the verifier-known bytes this execution is about.
///
/// No ecall, no stream, no cursor — the bytes are in memory at
/// `guest_memory::PUBLIC_INPUT_ORIGIN`, and the proof binds them to the
/// statement through the memory argument (`docs/spec/public-values.md` §5).
/// Reading it is optional: nothing forces a guest to look.
pub fn public_input() -> &'static [u8] {
    let origin = guest_memory::PUBLIC_INPUT_ORIGIN as usize;
    let len = word_at(origin).min(guest_memory::PUBLIC_PAYLOAD_BYTES);
    // SAFETY: `len` is clamped to the window's payload, so the slice is inside
    // the window the executor initialized.
    unsafe { slice_at(origin + 4, len as usize) }
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
    let origin = guest_memory::PUBLIC_OUTPUT_ORIGIN as usize;
    let len = word_at(origin) as usize;
    if len > guest_memory::PUBLIC_PAYLOAD_BYTES as usize
        || bytes.len() > guest_memory::PUBLIC_PAYLOAD_BYTES as usize - len
    {
        exit(EXIT_IO_ERROR);
    }
    let payload = origin + 4;
    for (i, byte) in bytes.iter().enumerate() {
        // SAFETY: `len + bytes.len()` is inside the window's payload, checked
        // just above, so the address is inside the window.
        unsafe { core::ptr::write_volatile((payload + len + i) as *mut u8, *byte) };
    }
    // SAFETY: word 0 of the window, which the executor initialized.
    unsafe { core::ptr::write_volatile(origin as *mut u32, (len + bytes.len()) as u32) };
}

/// The journal so far: everything [`commit`] has appended.
pub fn journal() -> &'static [u8] {
    let origin = guest_memory::PUBLIC_OUTPUT_ORIGIN as usize;
    let len = word_at(origin).min(guest_memory::PUBLIC_PAYLOAD_BYTES);
    // SAFETY: `len` is clamped to the window's payload.
    unsafe { slice_at(origin + 4, len as usize) }
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
    let origin = guest_memory::ADVICE_ORIGIN as usize;
    let len = word_at(origin).min(4 * guest_memory::ADVICE_WORDS - 4);
    // SAFETY: `len` is clamped to the region, and the executor refuses a read
    // past the bytes it was given rather than returning something else.
    unsafe { slice_at(origin + 4, len as usize) }
}

/// Exit with `code`. A nonzero status is a failed execution.
pub fn exit(code: i32) -> ! {
    // Asked again rather than spun on: `EXIT` does not return under any
    // executor, so the loop exists only so that a broken one cannot fall
    // through into whatever follows, and asking a second time is a more useful
    // thing to do about that than burning cycles.
    loop {
        // SAFETY: `EXIT` takes a status in `a0` and does not return.
        unsafe { ecall1(ecall::EXIT as usize, code as isize as usize) };
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
    /// First byte above `.bss`, 16-aligned. Defined by `apogee.ld`.
    static __heap_start: u8;
    /// One past the last byte of RAM; the initial `sp`. Defined by `apogee.ld`.
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

// A shim's record is a `static`, its ecall number, in a section of its own,
// `.apogee.delegations.<name>`, which `apogee.ld` gathers into
// `constants::delegation::SECTION`: the linker keeps or drops sections whole,
// so two records in one would declare both families for a guest that reaches
// either. And no `#[used]`: a record must be in the image exactly when its
// shim is, so what keeps it is the shim reading its ecall number out of it.

#[link_section = ".apogee.delegations.poseidon2"]
static POSEIDON2: u32 = ecall::POSEIDON2;

#[link_section = ".apogee.delegations.mul_div_u256"]
static MUL_DIV_U256: u32 = ecall::MUL_DIV_U256;

#[link_section = ".apogee.delegations.merkle_root"]
static MERKLE_ROOT: u32 = ecall::MERKLE_ROOT;

#[link_section = ".apogee.delegations.falcon512"]
static FALCON512: u32 = ecall::FALCON512;

#[link_section = ".apogee.delegations.falcon512_sample"]
static FALCON512_SAMPLE: u32 = ecall::FALCON512_SAMPLE;

#[link_section = ".apogee.delegations.falcon512_decode"]
static FALCON512_DECODE: u32 = ecall::FALCON512_DECODE;

/// One delegation call over the frame at `frame`, its ecall number read back
/// out of `declared`. Through `black_box`: folded to an immediate, the read
/// would leave the record unreferenced and the declaration out of the image.
///
/// # Safety
/// `frame` is word-aligned, below the advice region, and valid for reads and
/// writes of the whole frame `declared`'s family reads and writes in place.
unsafe fn delegate(declared: &'static u32, frame: *mut u32) {
    let number = *core::hint::black_box(declared);
    // `a0` is preserved, and the default options let the call read and write
    // the memory `frame` reaches.
    core::arch::asm!("ecall", in("a7") number as usize, in("a0") frame as usize);
}

/// The Poseidon2-A64-C5 permutation of `state`, in place: the precompile,
/// `transcript::poseidon2_permute` (`docs/spec/precompiles.md` §3). A lane is
/// read mod `p` and written below it.
pub fn poseidon2_permute(state: &mut [u64; 16]) {
    // SAFETY: a `[u64; 16]` is 32 words, 8-aligned, and is the whole frame.
    unsafe { delegate(&POSEIDON2, state.as_mut_ptr().cast()) }
}

/// Eight lanes, each canonical, below `p = 2^64 − 59` (`field::A64_C5`): a
/// digest, the transcript's width, and what [`poseidon2_compress`] takes. The
/// call reads a lane mod `p`, so `x` and `x + p` would be two encodings of one
/// node, and a `Digest` has one: a digest decoded from input or advice is
/// [`Digest::new`]'s to check, once, and a node the call wrote is canonical
/// already.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Digest([u64; 8]);

impl Digest {
    /// `lanes`, if every one is below `p`.
    pub const fn new(lanes: [u64; 8]) -> Option<Digest> {
        let mut i = 0;
        while i < lanes.len() {
            if lanes[i] >= field::A64_C5 {
                return None;
            }
            i += 1;
        }
        Some(Digest(lanes))
    }

    pub const fn lanes(&self) -> &[u64; 8] {
        &self.0
    }

    /// `path` as [`merkle_root`] takes it, 64 bytes a digest: a path the guest
    /// holds in its own memory.
    pub fn bytes(path: &[Digest]) -> &[u8] {
        // SAFETY: a `Digest` is `[u64; 8]`, `repr(transparent)`: 64 bytes, no
        // padding, 8-aligned.
        unsafe { core::slice::from_raw_parts(path.as_ptr().cast(), 64 * path.len()) }
    }
}

/// A Merkle node: the first 8 lanes of the permutation of `left ‖ right`,
/// truncated with no feed-forward.
pub fn poseidon2_compress(left: &Digest, right: &Digest) -> Digest {
    let mut state = [0u64; 16];
    state[..8].copy_from_slice(&left.0);
    state[8..].copy_from_slice(&right.0);
    poseidon2_permute(&mut state);
    let mut out = [0u64; 8];
    out.copy_from_slice(&state[..8]);
    Digest(out)
}

/// The root of the Merkle path from `leaf` at `slot` up `siblings`, by the
/// precompile (`docs/spec/precompiles.md` §6): 64 bytes a sibling, level 0's
/// first, each eight little-endian lanes read mod `p`. Level `L`'s node is
/// [`poseidon2_compress`] of the node below and its sibling, the node below on
/// the left where bit `L` of `slot` is 0, so this is that fold's root in one
/// call. The depth is `siblings.len() / 64`.
///
/// The siblings may be anywhere a load reaches, the advice included, so a
/// proof advised is hashed in place. Panics unless the depth is in `16..=32`,
/// `slot` is below `2^depth` and `siblings` is word-aligned whole siblings.
pub fn merkle_root(slot: u32, leaf: &Digest, siblings: &[u8]) -> Digest {
    let depth = siblings.len() / 64;
    assert!(
        siblings.len().is_multiple_of(64) && merkle_path(slot, depth, siblings.as_ptr()),
        "merkle_root: 16 to 32 word-aligned siblings, and a slot below 2^depth"
    );
    let mut frame = MerkleFrame {
        lanes: leaf.0,
        slot,
        depth: depth as u32,
        siblings: siblings.as_ptr() as u32,
    };
    // SAFETY: the frame is 19 words, 8-aligned, the call's whole frame, below
    // the advice region on the stack; the siblings are a borrow apart from it,
    // readable for `64·depth` bytes.
    unsafe { delegate(&MERKLE_ROOT, (&mut frame as *mut MerkleFrame).cast()) };
    Digest(frame.lanes)
}

/// `MERKLE_ROOT`'s frame, word for word `constants::delegation::merkle`'s.
#[repr(C)]
struct MerkleFrame {
    lanes: [u64; 8],
    slot: u32,
    depth: u32,
    siblings: u32,
}

const _: () = {
    use constants::delegation::merkle as m;
    assert!(core::mem::offset_of!(MerkleFrame, slot) == 4 * m::SLOT);
    assert!(core::mem::offset_of!(MerkleFrame, depth) == 4 * m::DEPTH);
    assert!(core::mem::offset_of!(MerkleFrame, siblings) == 4 * m::SIBLINGS);
    assert!(m::SIBLINGS + 1 == m::FRAME && 2 * 8 == m::LANES);
};

/// Whether a path of `depth` siblings at `siblings` from `slot` is one the
/// call answers: the depth in `16..=32`, the slot below `2^depth`, the
/// siblings word-aligned.
fn merkle_path(slot: u32, depth: usize, siblings: *const u8) -> bool {
    use constants::delegation::merkle::{MAX_DEPTH, MIN_DEPTH};
    (MIN_DEPTH as usize..=MAX_DEPTH as usize).contains(&depth)
        && (slot as u64) >> depth == 0
        && (siblings as usize).is_multiple_of(4)
}

/// `(floor(a·b/d), a·b mod d)` by the precompile (`docs/spec/precompiles.md`
/// §4). The caller owes `d ≠ 0` and a quotient below `2^256`, which an
/// executor refuses; [`U256::mul_div`] checks both first.
fn mul_div_u256(a: U256, b: U256, d: U256) -> (U256, U256) {
    let mut frame = [a.0, b.0, d.0];
    // SAFETY: three `[u64; 4]` are 24 words, 8-aligned, and the whole frame.
    unsafe { delegate(&MUL_DIV_U256, frame.as_mut_ptr().cast()) };
    (U256(frame[0]), U256(frame[1]))
}

mod u256;
pub use u256::U256;

pub mod falcon512;

// ---------------------------------------------------------------------------
// The C ABI
// ---------------------------------------------------------------------------
//
// What `include/apogee_guest.h` declares, for a C or C++ guest that links this
// crate built as a static library, `libapogee_guest.a`: crt0 above calls its
// `main`, and these four are the whole surface it calls. After them come the
// destructors: their registration, which `guest-sdk-cxa`'s `__cxa_atexit` calls,
// and the teardown that runs them and C's destructor functions. Last in the
// file, for the same reason the delegation shims are: a Rust guest that calls
// none links none.

// Linked for its `__cxa_atexit`, which nothing in this crate calls: an archive
// member of its own, in an image only where a guest calls it (`cxa/Cargo.toml`,
// `apogee.ld`).
extern crate guest_sdk_cxa;

/// `public_input()`: its address, its length through `len` where not null.
///
/// # Safety
/// `len` is null or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn apogee_public_input(len: *mut usize) -> *const u8 {
    let bytes = public_input();
    if !len.is_null() {
        *len = bytes.len();
    }
    bytes.as_ptr()
}

/// `advice()`: its address, its length through `len` where not null.
///
/// # Safety
/// `len` is null or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn apogee_advice(len: *mut usize) -> *const u8 {
    let bytes = advice();
    if !len.is_null() {
        *len = bytes.len();
    }
    bytes.as_ptr()
}

/// `commit()`: append `len` bytes at `bytes` to the journal.
///
/// # Safety
/// `bytes` is valid for `len` reads, or `len` is 0.
#[no_mangle]
pub unsafe extern "C" fn apogee_commit(bytes: *const u8, len: usize) {
    if len > 0 {
        commit(core::slice::from_raw_parts(bytes, len));
    }
}

/// `exit()`.
#[no_mangle]
pub extern "C" fn apogee_exit(code: i32) -> ! {
    exit(code)
}

/// `poseidon2_permute()` over the 16 lanes at `state`.
///
/// # Safety
/// `state` is 8-aligned and valid for reads and writes of 16 `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn apogee_poseidon2_permute(state: *mut u64) {
    poseidon2_permute(&mut *state.cast::<[u64; 16]>())
}

/// `merkle_root()` over `depth` siblings at `siblings`, 64 bytes each, from
/// the 8 lanes at `leaf`: the root written to `root`. Returns 0, or 1 and
/// writes nothing when the depth is outside `16..=32`, `slot` is not below
/// `2^depth`, a leaf lane is not below `p`, or `siblings` is not word-aligned.
///
/// # Safety
/// `leaf` is valid for reads and `root` for writes of 8 `uint64_t`, and
/// `siblings` for reads of `64·depth` bytes.
#[no_mangle]
pub unsafe extern "C" fn apogee_merkle_root(
    slot: u32,
    depth: u32,
    leaf: *const u64,
    siblings: *const u8,
    root: *mut u64,
) -> i32 {
    let depth = depth as usize;
    match Digest::new(*leaf.cast::<[u64; 8]>()) {
        Some(leaf) if merkle_path(slot, depth, siblings) => {
            let path = core::slice::from_raw_parts(siblings, 64 * depth);
            *root.cast::<[u64; 8]>() = merkle_root(slot, &leaf, path).0;
            0
        }
        _ => 1,
    }
}

/// `falcon512::s1_norm()` over the 512 coefficients at each of `h`, `s2` and
/// `c`. Panics unless each is 4-aligned and the three are apart.
///
/// # Safety
/// `h`, `s2` and `c` are each valid for reads of 512 `uint16_t`.
#[no_mangle]
pub unsafe extern "C" fn apogee_falcon512_s1_norm(
    h: *const u16,
    s2: *const u16,
    c: *const u16,
) -> u64 {
    falcon512::s1_norm_at(h, s2, c)
}

/// `falcon512::sample()` over the 8 lanes at `lanes`, in place. Panics unless
/// each is below `808·q^4`.
///
/// # Safety
/// `lanes` is 8-aligned and valid for reads and writes of 8 `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn apogee_falcon512_sample(lanes: *mut u64) {
    falcon512::sample(&mut *lanes.cast::<[u64; 8]>())
}

/// The `FALCON512_DECODE` call in `mode` over the encoding at `src` into the
/// 512 coefficients at `dst`: returns `‖s2‖²`, 0 for a key, and stores the
/// stream's end through `end` where not null. The call refuses everything
/// else, ending the execution.
///
/// # Safety
/// `src` and `dst` are 4-aligned; `src` is readable through the word holding
/// the stream's last bit, and `dst` writable for 512 `uint16_t`, apart.
#[no_mangle]
pub unsafe extern "C" fn apogee_falcon512_decode(
    mode: u32,
    src: *const u8,
    dst: *mut u16,
    end: *mut u32,
) -> u32 {
    let (norm, at) = falcon512::decode_at(mode, src, dst);
    if !end.is_null() {
        *end = at;
    }
    norm
}

/// `U256::mul_div_rem()`: `q = floor(a·b/d)` and `r = a·b mod d`, four
/// little-endian limbs each. Returns 0, or 1 and writes nothing when `d = 0`
/// or the quotient is not below `2^256`.
///
/// # Safety
/// `a`, `b`, `d` are valid for reads and `q`, `r` for writes of 4 `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn apogee_mul_div_u256(
    a: *const u64,
    b: *const u64,
    d: *const u64,
    q: *mut u64,
    r: *mut u64,
) -> i32 {
    let get = |x: *const u64| U256(*x.cast::<[u64; 4]>());
    match get(a).mul_div_rem(get(b), get(d)) {
        Some((quo, rem)) => {
            *q.cast::<[u64; 4]>() = quo.0;
            *r.cast::<[u64; 4]>() = rem.0;
            0
        }
        None => 1,
    }
}

/// A destructor `__cxa_atexit` registered: the function, its argument and the
/// destructor registered before it.
struct Destructor {
    f: unsafe extern "C" fn(*mut u8),
    arg: *mut u8,
    next: *mut Destructor,
}

/// The registered destructors, the latest first; null when there are none.
///
/// In `.data`, not `.bss`, so a guest with no static destructor pays nothing
/// at startup: crt0 zeroes `.bss` a byte at a time, and in `.bss` LLVM merges
/// this pointer with the allocator's `BUMP`, so every guest would carry and
/// zero both.
#[link_section = ".data"]
static mut DESTRUCTORS: *mut Destructor = core::ptr::null_mut();

/// Record `f(arg)` to run when `main` returns: `__cxa_atexit`'s body, which
/// `guest-sdk-cxa`'s `__cxa_atexit` calls. The record comes from the bump
/// allocator, so registering more than the heap holds exits 71, like any
/// allocation.
///
/// # Safety
/// `f` may be called once with `arg` after `main` returns.
#[no_mangle]
unsafe extern "C" fn __apogee_register_destructor(
    f: unsafe extern "C" fn(*mut u8),
    arg: *mut u8,
) -> i32 {
    let record = ALLOCATOR
        .alloc(Layout::new::<Destructor>())
        .cast::<Destructor>();
    let head = core::ptr::addr_of_mut!(DESTRUCTORS);
    record.write(Destructor {
        f,
        arg,
        next: *head,
    });
    *head = record;
    0
}

extern "C" {
    /// The guest's entry: a C guest's own, or the one `entry!` exports.
    fn main() -> i32;
    /// The bounds of `.fini_array`, C's destructor functions. Defined by
    /// `apogee.ld`.
    static __fini_array_start: u8;
    static __fini_array_end: u8;
}

/// What crt0 calls for a guest with destructors (`apogee.ld`): `main`; then
/// the destructors `__cxa_atexit` registered, the latest first, each once;
/// then the destructor functions, the last in `.fini_array` first; and `main`'s
/// status. A destructor that registers another one runs it next, in the order
/// C++ requires. `apogee_exit`, a panic and every other exit skip them all,
/// like C's `_Exit`.
#[no_mangle]
extern "C" fn __apogee_main_then_destructors() -> i32 {
    // SAFETY: `main` takes nothing and returns the exit status, in its C form
    // and in `entry!`'s alike.
    let status = unsafe { main() };
    // SAFETY: the guest is single-threaded. Each record was written whole by
    // `__apogee_register_destructor` and is never freed. It is unlinked before
    // its function runs, so a destructor that registers another, or exits,
    // leaves the list well formed.
    unsafe {
        let head = core::ptr::addr_of_mut!(DESTRUCTORS);
        while let Some(d) = (*head).as_ref() {
            *head = d.next;
            (d.f)(d.arg);
        }
    }
    let start = core::ptr::addr_of!(__fini_array_start) as usize;
    let mut at = core::ptr::addr_of!(__fini_array_end) as usize;
    while at > start {
        at -= core::mem::size_of::<unsafe extern "C" fn()>();
        // SAFETY: `apogee.ld` lays `.fini_array` out between the two symbols
        // as 8-aligned function pointers, each one the compiler emitted for a
        // destructor function.
        unsafe { (*(at as *const unsafe extern "C" fn()))() };
    }
    status
}
