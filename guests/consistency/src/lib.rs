#![no_std]
//! The consistency guest's program: ordinary `no_std + alloc` Rust, compiled
//! from this one source twice — for the host, where
//! `crates/emulator/tests/consistency.rs` calls [`run`] directly, and for
//! `riscv32imac-unknown-none-elf`, where `src/main.rs` hands it fd 0 and
//! commits what it emits to fd 1. The suite runs one input on the host, under
//! `qemu-riscv32` and on the zkVM's emulator, and holds the three to one
//! answer.
//!
//! Nothing here knows which of the three it runs on, and nothing may: **every
//! byte a workload emits is a function of the input alone**, the same on a
//! 64-bit host as on the 32-bit guest. The exceptions are declared rather than
//! tolerated: [`hazards`] emits the values Rust itself lets differ between
//! targets, and [`hazards::PLATFORM_DEPENDENT`] names each one and says why.
//!
//! # fd 0
//!
//! ```text
//!    0       mode       u8      MODE_RUN; src/main.rs's heap probes take the others
//!    1..9    seed       u64 LE  every generated datum derives from it
//!    9..13   scale      u32 LE  workload size, clamped to MAX_SCALE
//!   13..17   workloads  u32 LE  bit i selects WORKLOADS[i]; 0 selects all of them
//!   17       fault      u8      0, or a code from some workload's `faults`
//!   18..     payload            bytes every workload but `hazards` reads as given
//! ```
//!
//! # fd 1
//!
//! A sequence of sections, each `tag u8 ‖ len u32 LE ‖ len bytes`, emitted —
//! and on the guest committed — the moment it is produced, so a run that
//! panics has written exactly the sections before the panic. Each workload
//! owns a range of tags ([`Workload::tags`]) and [`Ctx::section`] refuses one
//! outside it, so a section always names the workload that wrote it. An input
//! that does not parse gets one [`TAG_BAD_INPUT`] section and nothing else.
//!
//! # Rules for a workload
//!
//! - **No `usize` reaches the output unconverted, and no `core::hash::Hash`.**
//!   Slices and `usize` hash through `write_usize`, whose width is the
//!   target's. Feed [`Digest`], which takes only fixed-width values.
//! - **`usize` arithmetic stays small.** Overflow checks are on in every build
//!   here, so a product that fits in 64 bits but not in 32 panics on the guest
//!   alone.
//! - **Nothing address-dependent**: no `{:p}`, no pointer-to-integer casts.
//! - **NaN bits never reach the output raw**: [`Digest::f64`] folds every NaN
//!   to one, and a float printed with `{}` prints `NaN` for all of them.
//! - **Bounded allocation.** The guest allocator never frees, so the *total* a
//!   run allocates is what counts: stay under 4 MiB per workload at
//!   [`MAX_SCALE`].
//! - **Bounded work.** [`hazards`] alone is held near 20k guest instructions,
//!   because it is the one workload the instruction-by-instruction QEMU
//!   differential runs. Every other workload's budget is the three-way suite's
//!   wall clock: hundreds of thousands of instructions at scale 0 and a few
//!   million at [`MAX_SCALE`] is the shape it has settled at, and `crypto` is
//!   thirty times that because the repository's own field and permutation
//!   compile at the guests' `opt-level = 0`. The measured numbers are the
//!   suite's `workload_costs` report, which is where to check a change rather
//!   than guess at one.
//! - **Faults panic on purpose**, at a data-dependent point, only when
//!   [`Ctx::fault`] says so. The suite checks that the host and the guest panic
//!   with the same message at the same line and column.

extern crate alloc;

pub mod alloc_patterns;
pub mod codec;
pub mod collections;
pub mod crypto;
pub mod hazards;
pub mod numeric;
pub mod structures;
pub mod text;

use alloc::format;
use alloc::vec::Vec;
use core::fmt;

/// fd 0's first byte for an input this crate runs.
pub const MODE_RUN: u8 = 0;

/// Guest-only, in `src/main.rs`: walk the heap up to its ceiling under the
/// stack's reserve, commit, then ask for one byte more, which guest-sdk's
/// allocator must refuse with exit 71.
pub const MODE_HEAP_CEILING: u8 = 1;

/// Guest-only, in `src/main.rs`: recurse past the stack's reserve, take a block
/// ending below the live stack, commit, then ask for one that would cover a
/// live frame, which guest-sdk's allocator must refuse with exit 71.
pub const MODE_HEAP_UNDER_DEEP_STACK: u8 = 2;

/// Bytes of fd 0 before the payload.
pub const HEADER_LEN: usize = 18;

/// The largest `scale` a workload sees; a larger one is clamped to it.
pub const MAX_SCALE: u32 = 16;

/// The one section [`run`] writes, alone, when fd 0 is not an input.
pub const TAG_BAD_INPUT: u8 = 0x01;

/// fd 0, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input<'a> {
    pub seed: u64,
    pub scale: u32,
    pub workloads: u32,
    pub fault: u8,
    pub payload: &'a [u8],
}

/// Why fd 0 is not an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    /// Shorter than the header.
    Short { len: usize },
    /// A mode byte this crate does not run.
    Mode(u8),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::Short { len } => {
                write!(f, "fd 0 holds {len} bytes and the header is {HEADER_LEN}")
            }
            InputError::Mode(mode) => write!(f, "mode {mode} is not MODE_RUN"),
        }
    }
}

impl<'a> Input<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Input<'a>, InputError> {
        if bytes.len() < HEADER_LEN {
            return Err(InputError::Short { len: bytes.len() });
        }
        if bytes[0] != MODE_RUN {
            return Err(InputError::Mode(bytes[0]));
        }
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        Ok(Input {
            seed: u64::from(word(1)) | (u64::from(word(5)) << 32),
            scale: word(9),
            workloads: word(13),
            fault: bytes[17],
            payload: &bytes[HEADER_LEN..],
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.payload.len());
        bytes.push(MODE_RUN);
        bytes.extend_from_slice(&self.seed.to_le_bytes());
        bytes.extend_from_slice(&self.scale.to_le_bytes());
        bytes.extend_from_slice(&self.workloads.to_le_bytes());
        bytes.push(self.fault);
        bytes.extend_from_slice(self.payload);
        bytes
    }
}

/// One body of work, and the section tags and faults it owns.
pub struct Workload {
    pub name: &'static str,
    /// The inclusive range of section tags it may write.
    pub tags: (u8, u8),
    /// The panics fd 0 can ask it for.
    pub faults: &'static [Fault],
    pub run: fn(&mut Ctx<'_>),
}

/// A deliberate panic: `code` in fd 0's fault byte triggers it.
pub struct Fault {
    pub code: u8,
    pub what: &'static str,
}

/// Every workload, in fd 0's bit order: bit `i` of `workloads` selects entry
/// `i`.
pub const WORKLOADS: [Workload; 8] = [
    Workload {
        name: "numeric",
        tags: numeric::TAGS,
        faults: numeric::FAULTS,
        run: numeric::run,
    },
    Workload {
        name: "collections",
        tags: collections::TAGS,
        faults: collections::FAULTS,
        run: collections::run,
    },
    Workload {
        name: "text",
        tags: text::TAGS,
        faults: text::FAULTS,
        run: text::run,
    },
    Workload {
        name: "structures",
        tags: structures::TAGS,
        faults: structures::FAULTS,
        run: structures::run,
    },
    Workload {
        name: "codec",
        tags: codec::TAGS,
        faults: codec::FAULTS,
        run: codec::run,
    },
    Workload {
        name: "crypto",
        tags: crypto::TAGS,
        faults: crypto::FAULTS,
        run: crypto::run,
    },
    Workload {
        name: "alloc_patterns",
        tags: alloc_patterns::TAGS,
        faults: alloc_patterns::FAULTS,
        run: alloc_patterns::run,
    },
    Workload {
        name: "hazards",
        tags: hazards::TAGS,
        faults: hazards::FAULTS,
        run: hazards::run,
    },
];

/// Run the workloads fd 0 selects, handing each framed section to `out` as it
/// is produced.
pub fn run(input: &[u8], out: &mut dyn FnMut(&[u8])) {
    let input = match Input::parse(input) {
        Ok(input) => input,
        Err(e) => return frame(out, TAG_BAD_INPUT, format!("{e}").as_bytes()),
    };
    for (i, workload) in WORKLOADS.iter().enumerate() {
        if input.workloads != 0 && input.workloads & (1 << i) == 0 {
            continue;
        }
        let mut cx = Ctx {
            scale: input.scale.min(MAX_SCALE),
            fault: input.fault,
            payload: input.payload,
            tags: workload.tags,
            // Seeded per workload, so what a workload writes does not depend
            // on which others ran before it: a one-workload run and the full
            // run agree section for section.
            rng: Rng::new(input.seed ^ (i as u64 + 1).wrapping_mul(0xa24b_aed4_963e_e407)),
            out: &mut *out,
        };
        (workload.run)(&mut cx);
    }
}

fn frame(out: &mut dyn FnMut(&[u8]), tag: u8, bytes: &[u8]) {
    let mut section = Vec::with_capacity(5 + bytes.len());
    section.push(tag);
    section.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    section.extend_from_slice(bytes);
    out(&section);
}

/// fd 1 split back into `(tag, bytes)` sections, or `None` when it does not
/// split — a run cut off inside a section.
pub fn sections(mut output: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut sections = Vec::new();
    while let Some((&tag, rest)) = output.split_first() {
        let len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        // Sliced in two steps rather than through `4 + len`, which overflows a
        // 32-bit `usize` on a hostile length — in the one function of this
        // crate whose whole subject is 32-bit behaviour.
        let body = rest.get(4..)?;
        sections.push((tag, body.get(..len)?));
        output = &body[len..];
    }
    Some(sections)
}

/// What a workload sees: its size, the fault fd 0 asked for, the payload, a
/// generator seeded for it alone, and fd 1.
pub struct Ctx<'a> {
    scale: u32,
    fault: u8,
    payload: &'a [u8],
    tags: (u8, u8),
    rng: Rng,
    out: &'a mut dyn FnMut(&[u8]),
}

impl<'a> Ctx<'a> {
    /// `0..=MAX_SCALE`.
    pub fn scale(&self) -> u32 {
        self.scale
    }

    /// fd 0 after the header, exactly as given: any bytes, valid UTF-8 or not.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub fn rng(&mut self) -> &mut Rng {
        &mut self.rng
    }

    /// Whether fd 0 asked for the fault `code`.
    pub fn fault(&self, code: u8) -> bool {
        self.fault != 0 && self.fault == code
    }

    /// Emit one section. Panics on a tag outside this workload's range.
    pub fn section(&mut self, tag: u8, bytes: &[u8]) {
        let (lo, hi) = self.tags;
        assert!(
            (lo..=hi).contains(&tag),
            "section tag {tag:#04x} is outside this workload's {lo:#04x}..={hi:#04x}"
        );
        frame(self.out, tag, bytes);
    }

    /// Emit a digest as an 8-byte section.
    pub fn digest(&mut self, tag: u8, digest: &Digest) {
        self.section(tag, &digest.finish().to_le_bytes());
    }
}

/// FNV-1a over fixed-width little-endian values: a fingerprint that is the
/// same on every target, which `core::hash` is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digest(u64);

impl Default for Digest {
    fn default() -> Digest {
        Digest::new()
    }
}

impl Digest {
    pub const fn new() -> Digest {
        Digest(0xcbf2_9ce4_8422_2325)
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Digest {
        for b in bytes {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        self
    }

    pub fn u8(&mut self, v: u8) -> &mut Digest {
        self.bytes(&[v])
    }

    pub fn u16(&mut self, v: u16) -> &mut Digest {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> &mut Digest {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> &mut Digest {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u128(&mut self, v: u128) -> &mut Digest {
        self.bytes(&v.to_le_bytes())
    }

    pub fn i32(&mut self, v: i32) -> &mut Digest {
        self.bytes(&v.to_le_bytes())
    }

    pub fn i64(&mut self, v: i64) -> &mut Digest {
        self.bytes(&v.to_le_bytes())
    }

    pub fn i128(&mut self, v: i128) -> &mut Digest {
        self.bytes(&v.to_le_bytes())
    }

    /// A `usize` that is the same number on every target — a length, an
    /// index — widened so it fingerprints the same.
    pub fn count(&mut self, n: usize) -> &mut Digest {
        self.u64(n as u64)
    }

    /// Length-prefixed, so `("ab", "c")` and `("a", "bc")` differ.
    pub fn str(&mut self, s: &str) -> &mut Digest {
        self.count(s.len()).bytes(s.as_bytes())
    }

    /// A float's bits, every NaN folded to one: the bits of a NaN an operation
    /// produces are the host's business, which [`hazards`] declares.
    pub fn f64(&mut self, v: f64) -> &mut Digest {
        self.u64(if v.is_nan() {
            0x7ff8_0000_0000_0000
        } else {
            v.to_bits()
        })
    }

    /// As [`Digest::f64`].
    pub fn f32(&mut self, v: f32) -> &mut Digest {
        self.u32(if v.is_nan() { 0x7fc0_0000 } else { v.to_bits() })
    }

    pub fn finish(&self) -> u64 {
        self.0
    }
}

/// SplitMix64: the same sequence on every target.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// In `0..n`. `n` must be nonzero.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n != 0, "Rng::below(0)");
        self.next_u64() % n
    }

    /// An index into `len` elements. `len` must be nonzero.
    pub fn index(&mut self, len: usize) -> usize {
        self.below(len as u64) as usize
    }

    /// True with probability `num / den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut bytes = alloc::vec![0; n];
        self.fill(&mut bytes);
        bytes
    }
}
