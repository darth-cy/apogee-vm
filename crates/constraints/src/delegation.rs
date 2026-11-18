//! What every delegation circuit is built on (`docs/spec/precompiles.md` §1):
//! [`Builder`], which names a family's committed columns once and holds its
//! gates, obligations and memory leaves, and [`frame`], the anchor and the RAM
//! words every frame family carries.
//!
//! ```text
//! every family   M[0] live: the default leaf mask, every obligation's selector
//! a frame        M[1] cycle, M[2] number, then per frame word j
//!                M[..] w{j}_addr w{j}_read_ts w{j}_read_value [w{j}_write_value]
//!                W[..] w{j}_gap_c0 w{j}_gap_c1, RANGE16 chunks of 4·cycle − 1 − read_ts
//!                W[..] room_h16: ADVICE_ORIGIN − 4·words − addr_0 is a word
//!   read leaves  word j (RAM, addr_j, read_ts_j, read_value_j); the anchor
//!                (DELEGATION, addr_0, cycle, number)
//!   write leaves word j (RAM, addr_j, 4·cycle + FRAME_DELTA, write_value_j), the
//!                read value for a word written back
//! ```
//!
//! A row is live or padding. Every leaf is masked by `live` or by a boolean
//! column zero wherever `live` is ([`Builder::leaf_under`]), and every
//! obligation's selector is `live`, so a padding row, all zero, is the
//! identity of both products and under no obligation. Every enforcing gate is
//! zero on the all-zero row, and every artifact keeps [`MAX_COMMITTED`] and
//! [`MAX_OBLIGATIONS`].

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{
    address_space, challenge_slot, delegation, guest_memory, lookup_channel, memory as mem,
};
use field::Fp;

use crate::family::{Expr, T16};
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// Akita's widest commitment at `2^22` rows (measured): a circuit committing
/// more `M`, `W` and `S` columns has no opening schedule there.
pub const MAX_COMMITTED: usize = 372;
/// The most obligations a channel takes a row: with its table's fraction, 256
/// leaves, the next being 512.
pub const MAX_OBLIGATIONS: usize = 255;

/// One part of a memory tuple, `docs/spec/memory.md` §1: the sum of `columns`,
/// each weighted 1, plus the integer `plus`. A coefficient is one literal or
/// one challenge, so the part's challenge times `plus` is the mask term
/// `plus` times over.
#[derive(Clone, Debug, Default)]
pub struct Part {
    pub columns: Vec<PolyAddress>,
    pub plus: u64,
}

impl Part {
    /// The part that is one column.
    pub fn of(x: PolyAddress) -> Part {
        Part {
            columns: vec![x],
            plus: 0,
        }
    }
    /// The part that is one column plus `plus`.
    pub fn plus(x: PolyAddress, plus: u64) -> Part {
        Part {
            columns: vec![x],
            plus,
        }
    }
    /// The constant part `plus`.
    pub fn constant(plus: u64) -> Part {
        Part {
            columns: Vec::new(),
            plus,
        }
    }
}

/// `mask·T(space, addr, ts, val, hi) + 1 − mask`, one flat `Quadratic`, as
/// `docs/spec/memory.md` §2.2 writes a leaf: every column term multiplied by
/// the mask, every constant on it.
pub fn masked_leaf(mask: PolyAddress, space: u8, parts: [Part; 4]) -> GateDef {
    let slots = [
        challenge_slot::MEM_ALPHA_ADDR,
        challenge_slot::MEM_ALPHA_TS,
        challenge_slot::MEM_ALPHA_VAL,
        challenge_slot::MEM_ALPHA_HI,
    ];
    let lit = |v: u64| Coeff::Literal(Fp::from_u64(v));
    let mut linear = vec![
        (Coeff::Challenge(challenge_slot::MEM_GAMMA), mask),
        (Coeff::Literal(Fp::MINUS_ONE), mask),
        (lit(space as u64), mask),
    ];
    let mut products = Vec::new();
    for (slot, part) in slots.into_iter().zip(parts) {
        for x in part.columns {
            products.push((Coeff::Challenge(slot), x, mask));
        }
        for _ in 0..part.plus {
            linear.push((Coeff::Challenge(slot), mask));
        }
    }
    GateDef::Quadratic {
        constant: lit(1),
        linear,
        products,
    }
}

/// A delegation family's circuit, column by column. Columns are named once,
/// here, and a fill finds them by name (`CircuitArtifact::column`).
pub struct Builder {
    family: u32,
    memory: Vec<String>,
    witness: Vec<String>,
    gates: Vec<(String, GateDef)>,
    lookups: Vec<LookupExpr>,
    /// Copower-scaled chunks, each with its direct bound beside it.
    scaled: Vec<PolyAddress>,
    reads: Vec<(String, GateDef)>,
    writes: Vec<(String, GateDef)>,
    /// `M[0]`, boolean: a live row.
    pub live: PolyAddress,
}

impl Builder {
    /// A family's builder, with `M[0] live` and its booleanity.
    pub fn new(family: u32) -> Builder {
        let mut b = Builder {
            family,
            memory: Vec::new(),
            witness: Vec::new(),
            gates: Vec::new(),
            lookups: Vec::new(),
            scaled: Vec::new(),
            reads: Vec::new(),
            writes: Vec::new(),
            live: PolyAddress::Memory(0),
        };
        let live = b.mcol("live");
        b.gate("live_boolean", live - live * live);
        b
    }

    fn named(&self, name: &str) {
        assert!(
            !self.memory.iter().chain(&self.witness).any(|n| n == name),
            "family {}: a second column named `{name}`",
            self.family
        );
    }

    /// A new `M` column: one a memory leaf may read.
    pub fn mcol(&mut self, name: &str) -> PolyAddress {
        self.named(name);
        self.memory.push(name.to_string());
        PolyAddress::Memory(self.memory.len() as u32 - 1)
    }

    /// A new `W` column.
    pub fn col(&mut self, name: &str) -> PolyAddress {
        self.named(name);
        self.witness.push(name.to_string());
        PolyAddress::Witness(self.witness.len() as u32 - 1)
    }

    /// A new `W` column held boolean by `<name>_boolean`.
    pub fn bit(&mut self, name: &str) -> PolyAddress {
        let x = self.col(name);
        self.gate(&format!("{name}_boolean"), x - x * x);
        x
    }

    /// An enforcing gate, `e = 0` on every row. Panics unless `e` is zero on
    /// the all-zero row, which every padding row is.
    pub fn gate(&mut self, name: &str, e: Expr) {
        assert!(
            e.constant == Fp::ZERO,
            "family {}: gate `{name}` is not zero on the all-zero row",
            self.family
        );
        self.gates.push((name.to_string(), e.gate()));
    }

    /// An enforcing gate already built, such as `gadgets::is_zero`'s.
    pub fn push_gate(&mut self, name: &str, g: GateDef) {
        self.gates.push((name.to_string(), g));
    }

    /// A `RANGE16` obligation under `live`: `e < 2^16`.
    pub fn range16(&mut self, name: &str, e: Expr) {
        self.lookups.push(LookupExpr {
            name: name.to_string(),
            channel: lookup_channel::RANGE16,
            selector: self.live,
            tuple: vec![e.gate()],
        });
    }

    /// `value` is a word: a new column `<name>_h16`, its high halfword, and
    /// both halfwords in `RANGE16` (`docs/spec/memory.md` §7). Returns the
    /// halfword.
    pub fn word(&mut self, name: &str, value: Expr) -> PolyAddress {
        let h = self.col(&format!("{name}_h16"));
        self.range16(&format!("{name}_hi_range"), h.into());
        self.range16(&format!("{name}_lo_range"), value - h * T16);
        h
    }

    /// The column `x ∈ [0, 2^bits)` for `bits < 16`: `<name>_range`, `x <
    /// 2^16`, and `<name>_scaled`, `2^(16 − bits)·x < 2^16`, which bounds
    /// nothing alone (as [`Builder::bounded`]'s top chunk).
    pub fn small(&mut self, name: &str, x: PolyAddress, bits: u32) {
        assert!(bits < 16, "{name}: {bits} bits is a halfword's or more");
        self.range16(&format!("{name}_range"), x.into());
        self.range16(&format!("{name}_scaled"), x * (1u64 << (16 - bits)));
        self.scaled.push(x);
    }

    /// `value ∈ [0, 2^bits)` for a `bits` that is not a multiple of 16: `q`
    /// committed chunks of weight `2^16 … 2^16q`, the remainder derived.
    ///
    /// ```text
    /// chunk_c < 2^16                    direct, one a chunk
    /// 2^(16 − r)·chunk_top < 2^16       scaled: chunk_top < 2^r, given the direct one
    /// value − Σ 2^16(c+1)·chunk_c < 2^16
    /// ```
    ///
    /// The maximum is `2^bits − 1` exactly. The scaled obligation alone bounds
    /// nothing, `2^(16−r)` being a unit of `Fp` (`lookup::check_copowers`, run
    /// at assembly over every top chunk).
    pub fn bounded(&mut self, name: &str, value: Expr, bits: u32) {
        let (q, r) = (bits / 16, bits % 16);
        assert!(q >= 1 && r > 0, "{name}: {bits} bits is not 16q + r");
        let chunks: Vec<PolyAddress> = (0..q).map(|c| self.col(&format!("{name}_c{c}"))).collect();
        let mut low = value;
        for (c, chunk) in chunks.iter().enumerate() {
            self.range16(&format!("{name}_c{c}_range"), (*chunk).into());
            low = low - *chunk * (1u64 << (16 * (c + 1)));
        }
        let top = chunks[chunks.len() - 1];
        self.range16(&format!("{name}_top_scaled"), top * (1u64 << (16 - r)));
        self.range16(&format!("{name}_lo_range"), low);
        self.scaled.push(top);
    }

    /// A memory leaf under `live`, on the read side or the write side.
    pub fn leaf(&mut self, write: bool, name: &str, space: u8, parts: [Part; 4]) {
        self.leaf_under(self.live, write, name, space, parts);
    }

    /// A memory leaf under `mask`, a boolean column zero wherever `live` is.
    pub fn leaf_under(
        &mut self,
        mask: PolyAddress,
        write: bool,
        name: &str,
        space: u8,
        parts: [Part; 4],
    ) {
        let side = match write {
            false => &mut self.reads,
            true => &mut self.writes,
        };
        side.push((name.to_string(), masked_leaf(mask, space, parts)));
    }

    /// The family's one channel, `RANGE16`, if it has an obligation: its table
    /// `V[range16]` and its multiplicity the last `W` column.
    pub fn channels(&self) -> Vec<ChannelSpec> {
        match self.lookups.is_empty() {
            true => Vec::new(),
            false => vec![ChannelSpec {
                channel: lookup_channel::RANGE16,
                table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
                multiplicity: PolyAddress::Witness(self.witness.len() as u32),
            }],
        }
    }

    /// The circuit over `2^trace_vars` rows: the two product trees, each side
    /// padded to one power of two with leaves that are literally 1, and the
    /// `RANGE16` tree where there is an obligation. Panics on every refusal of
    /// the assembly, on a copower chunk with no direct bound, and on a circuit
    /// over a budget, [`MAX_COMMITTED`] or [`MAX_OBLIGATIONS`]: a bound only a
    /// comment states is not a bound.
    pub fn artifact(mut self, trace_vars: u32) -> CircuitArtifact {
        let channels = self.channels();
        let mut virtuals = Vec::new();
        if !channels.is_empty() {
            self.witness.push("mult_range16".to_string());
            virtuals.push((VirtualKind::Range16, "range16".to_string()));
        }
        let side = self.reads.len().max(self.writes.len()).next_power_of_two();
        for (leaves, name) in [(&mut self.reads, "read"), (&mut self.writes, "write")] {
            for i in leaves.len()..side {
                leaves.push((
                    format!("{name}_pad_{i}"),
                    GateDef::Linear {
                        terms: Vec::new(),
                        constant: Coeff::Literal(Fp::ONE),
                    },
                ));
            }
        }
        let a = crate::memory::assemble(
            trace_vars,
            [self.memory, self.witness, Vec::new()],
            virtuals,
            [self.reads, self.writes],
            self.gates,
            self.lookups,
            &channels,
        );
        assert!(
            a.padding.zero_row_valid,
            "family {}: a gate is nonzero on the all-zero row",
            self.family
        );
        let committed = a.memory.len() + a.witness.len() + a.setup.len();
        assert!(
            committed <= MAX_COMMITTED,
            "family {}: {committed} committed columns, over Akita's {MAX_COMMITTED} at 2^22",
            self.family
        );
        for channel in channels.iter().map(|spec| spec.channel) {
            let n = a.lookups.iter().filter(|l| l.channel == channel).count();
            let label = lookup_channel::NAMES[channel as usize];
            assert!(
                n <= MAX_OBLIGATIONS,
                "family {}: {n} {label} obligations a row, over a tree of 256 leaves",
                self.family
            );
        }
        let scaled: Vec<(PolyAddress, PolyAddress)> =
            self.scaled.iter().map(|x| (*x, self.live)).collect();
        if let Err(e) = crate::lookup::check_copowers(&a, &scaled) {
            panic!("family {}: {e}", self.family);
        }
        a
    }
}

/// One frame word's columns.
#[derive(Clone, Copy, Debug)]
pub struct Word {
    pub addr: PolyAddress,
    pub read_ts: PolyAddress,
    pub read: PolyAddress,
    /// What the call writes; the read value for a word written back.
    pub write: PolyAddress,
}

/// A frame's columns: the requesting cycle and its words.
pub struct Frame {
    pub cycle: PolyAddress,
    pub words: Vec<Word>,
}

/// The frame of the delegation `number`, of `words` RAM words at `base + 4j`,
/// `written(j)` saying which the call writes: `docs/spec/precompiles.md` §1.
///
/// ```text
/// number_rule   number − NUMBER·live
/// addr_w{j}     addr_j − addr_0 − 4j·live                      j ≥ 1
/// room          ADVICE_ORIGIN·live − 4·words·live − addr_0, a word
/// gap_w{j}      4·cycle + FRAME_DELTA − 1 − read_ts_j ∈ [0, 2^38)
/// ```
///
/// `room` keeps the frame below the advice region, where every value is a
/// word: its init is the image's, the public input's or 0, and every family
/// writes words. So a frame's reads need no bound of their own; a word advice
/// initialized could be any field element. `addr_0` is the anchor's `a0`, a
/// word, so `room` is one exactly when the frame ends at or below
/// `ADVICE_ORIGIN`. A
/// word off initialized memory there, unaligned or in the hole, reads a tuple
/// nothing wrote, and the memory argument refuses it (`docs/spec/memory.md`
/// §9). The anchor read pairs the row with the ecall that requested it, its
/// `(base, cycle, number)`, so `cycle` is that live row's, an integer below
/// `2^36` (`docs/spec/memory.md` §4.2).
pub fn frame(b: &mut Builder, number: u32, words: usize, written: impl Fn(usize) -> bool) -> Frame {
    let live = b.live;
    frame_under(b, live, number, words, written)
}

/// [`frame`] on the rows `mask` selects, a boolean `M` column zero wherever
/// `live` is: each rule above with `mask` for `live`, every leaf under it. A
/// live row `mask` leaves out reads and writes nothing and holds zeros, but
/// in each word's gap chunks ([`access_under`]).
pub fn frame_under(
    b: &mut Builder,
    mask: PolyAddress,
    number: u32,
    words: usize,
    written: impl Fn(usize) -> bool,
) -> Frame {
    let live = mask;
    let cycle = b.mcol("cycle");
    let n = b.mcol("number");
    b.gate("number_rule", n - live * number as u64);
    let mut out = Vec::with_capacity(words);
    for j in 0..words {
        let addr = b.mcol(&format!("w{j}_addr"));
        let read_ts = b.mcol(&format!("w{j}_read_ts"));
        let read = b.mcol(&format!("w{j}_read_value"));
        let write = match written(j) {
            true => b.mcol(&format!("w{j}_write_value")),
            false => read,
        };
        out.push(Word {
            addr,
            read_ts,
            read,
            write,
        });
    }
    let end = guest_memory::ADVICE_ORIGIN as u64 - 4 * words as u64;
    b.word("room", live * end - out[0].addr);
    for (j, w) in out.iter().enumerate() {
        if j > 0 {
            b.gate(
                &format!("addr_w{j}"),
                w.addr - out[0].addr - live * (4 * j as u64),
            );
        }
        let addr = Part::of(w.addr);
        let name = format!("w{j}");
        access_under(b, mask, &name, cycle, addr, w.read_ts, w.read, w.write);
    }
    b.leaf_under(
        mask,
        false,
        "read_anchor",
        address_space::DELEGATION,
        [
            Part::of(out[0].addr),
            Part::of(cycle),
            Part::of(n),
            Part::default(),
        ],
    );
    Frame { cycle, words: out }
}

/// One RAM word an entry's row accesses at the requesting cycle's
/// `4·cycle + FRAME_DELTA`, `docs/spec/precompiles.md` §1: `<name>_gap`, the
/// gap below it in `[0, 2^38)`, the read leaf `(RAM, addr, read_ts, read)` and
/// the write leaf `(RAM, addr, 4·cycle + FRAME_DELTA, write)`. `cycle` is a
/// requesting ecall's: a frame's through its anchor, a trie op's through its
/// call's state (`docs/spec/memory.md` §4.2).
pub fn access(
    b: &mut Builder,
    name: &str,
    cycle: PolyAddress,
    addr: Part,
    read_ts: PolyAddress,
    read: PolyAddress,
    write: PolyAddress,
) {
    let live = b.live;
    access_under(b, live, name, cycle, addr, read_ts, read, write);
}

/// [`access`] on the rows `mask` selects, a boolean `M` column zero wherever
/// `live` is: both leaves under it, and the gap `4·cycle − read_ts +
/// mask·(FRAME_DELTA − 1)` bounded under `live`, as every obligation is. A
/// live row `mask` leaves out holds `read_ts = 0` and the chunks of the gap
/// `4·cycle`, below `2^38`.
#[allow(clippy::too_many_arguments)]
pub fn access_under(
    b: &mut Builder,
    mask: PolyAddress,
    name: &str,
    cycle: PolyAddress,
    addr: Part,
    read_ts: PolyAddress,
    read: PolyAddress,
    write: PolyAddress,
) {
    let live = mask;
    let gap = cycle * mem::TS_STEP - read_ts + Expr::from(live) * delegation::FRAME_DELTA
        - Expr::from(live);
    b.bounded(&format!("{name}_gap"), gap, mem::TS_BITS);
    b.leaf_under(
        mask,
        false,
        &format!("read_{name}"),
        address_space::RAM,
        [
            addr.clone(),
            Part::of(read_ts),
            Part::of(read),
            Part::default(),
        ],
    );
    let stamp = Part {
        columns: vec![cycle; mem::TS_STEP as usize],
        plus: delegation::FRAME_DELTA,
    };
    b.leaf_under(
        mask,
        true,
        &format!("write_{name}"),
        address_space::RAM,
        [addr, stamp, Part::of(write), Part::default()],
    );
}

// A frame's write is at `(RAM, FRAME_DELTA)`, which no query of
// `constraints::memory`'s frame holds, so a frame word's event is never filed
// into the requesting row. A `const` assertion: a violation is a broken ABI.
const _: () = {
    let mut q = 0;
    while q < crate::memory::FRAME_QUERIES {
        assert!(
            !(crate::memory::FRAME_SPACE[q] == address_space::RAM
                && crate::memory::FRAME_DELTA[q] == delegation::FRAME_DELTA),
            "a frame query already holds (RAM, FRAME_DELTA)"
        );
        q += 1;
    }
};
