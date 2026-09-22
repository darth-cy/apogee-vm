//! The step schedule: what each row of an `ECRECOVER` invocation block does.
//!
//! A recovery is a straight-line program over 256-bit values, and this module
//! is that program — built once, the same for every invocation, and a function
//! of the row's **step** (`row mod ROWS_PER_INVOCATION`) and of nothing a
//! prover chooses (`docs/spec/ecrecover.md` §6.2).
//!
//! # One row shape
//!
//! Every row runs the same congruence, and the only thing that varies is where
//! its operands come from:
//!
//! ```text
//! A·B  +  c·C  +  e·E  +  d·D  +  k  ≡  0   (mod m)
//! ```
//!
//! `A·B` is the one product a step may take — the quotient's `Q·m` is the
//! second, and §3.2's magnitude argument allows exactly two. The coefficients
//! `c`, `e`, `d` and the constant `k` are **schedule values**, so a linear term
//! may be scaled by a small integer without a bused constant to multiply by;
//! the product may not, which is why `2y` and `3x²` are steps of their own.
//! The modulus is a schedule value too, so one shape serves `p` and `n`.
//!
//! Exactly one slot is the step's **output** — `A`, for a step that divides,
//! or `D` for one that does not — and the rest are read from the bus. An
//! output is written to as many bus addresses as the program has readers for
//! it: a multiset pairs one write with one read, so fan-out is spelled out
//! rather than assumed (§2.3).
//!
//! # What this module is not
//!
//! It computes no values. A `Step` says where operands live and what shape the
//! congruence takes; the limbs themselves are the prover's, and
//! `program::secp256k1` is what the witness builder computes them with. The
//! interpreter in `crates/program/tests/ecrecover_schedule.rs` runs this
//! program over that arithmetic and checks it recovers what `recover` does,
//! which is how the schedule is known to be the right program before a single
//! gate exists.

use alloc::vec;
use alloc::vec::Vec;

/// Which modulus a step works in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modulus {
    /// The curve's base field, `p`.
    Field,
    /// The group order, `n`.
    Order,
}

/// Which slot a step writes. A step that writes nothing is an assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// Nothing: the congruence is an assertion about values already on the bus.
    None,
    /// `A`, the product's left operand — a step that divides by `B`.
    A,
    /// `A`, with `B` the same column: a step that takes a square root.
    /// `A·A + … ≡ 0` with `A` written is the one shape whose solution is not
    /// a rational function of its inputs, and the one place the prover's
    /// witness is genuinely a choice between two values.
    Sqrt,
    /// `D`, the linear slot — every step that does not divide.
    D,
}

/// A value in the program, by the step that produces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Val(pub u32);

/// One row's worth of work, with bus addresses resolved.
///
/// A slot's `None` is an unused slot, whose limbs a gate holds to zero — which
/// is what keeps an absent operand from being a free field element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The product's operands.
    pub a: Option<u32>,
    pub b: Option<u32>,
    /// The written `A`'s own linear coefficient, for a step whose shape reads
    /// its output linearly as well as in the product — `A² − A ≡ 0`, the one
    /// step that introduces a free boolean.
    pub a_coeff: i64,
    /// The linear slots, each with its schedule coefficient.
    pub c: Option<(i64, u32)>,
    pub e: Option<(i64, u32)>,
    pub d: Option<(i64, u32)>,
    /// The constant added, limb by limb. Small: a step's constant is a curve
    /// constant or a table entry, never a scaled value.
    pub literal: [u64; 4],
    /// What the row does with its selector columns.
    pub digit: Digit,
    /// A windowed table's entries on the bus, selected by the row's one-hot
    /// selector columns. Empty on a row that selects nothing.
    pub table: Vec<u32>,
    /// A windowed table's entries as schedule constants — how `G`'s multiples
    /// ship, since they are the same on every row
    /// (`docs/spec/ecrecover.md` §5.1). Empty, or one per selector.
    pub table_literals: Vec<[u64; 4]>,
    pub modulus: Modulus,
    /// Which slot this step writes.
    pub output: Output,
    /// The coefficient the written slot carries in the congruence, which is
    /// `−1` unless the step says otherwise. A doubling's `x₃` carries `−4`
    /// and its `y₃` carries `−2`, because the slope it is written against is
    /// `2λ` rather than `λ`; a parity split carries `2`.
    pub out_coeff: i64,
    /// Whether the output reaches the bus. A witness the row needs and no
    /// later step reads — a doubling's `1/y`, a non-residue certificate, a
    /// parity's halved value — is **not** bused: a write with no read leaves
    /// the global multiset unbalanced, and the honest prover is the one
    /// refused.
    pub bused: bool,
    /// The bus addresses the output is copied to, one per reader.
    pub writes: Vec<u32>,
    /// Whether the row's is-zero test is enabled. Its result is the output,
    /// and the congruence is then `output = z` rather than arithmetic.
    pub is_zero: bool,
    /// Whether the quotient is held to zero, making the congruence an
    /// **integer** identity rather than one modulo `m`. A parity split
    /// `y = 2h + b` is only a statement about `y` over ℤ: modulo `p` it holds
    /// for either parity, with `h = (y − b)/2`, and proves nothing.
    pub exact: bool,
    /// The frame words this row moves, and which way. A frame value is eight
    /// 32-bit words, low word first, at fixed offsets from the frame base.
    pub frame: Frame,
    /// A name for the dump, and for a failing interpreter to point at.
    pub note: &'static str,
}

impl Step {
    /// Every bus address this step reads.
    pub fn reads(&self) -> Vec<u32> {
        let mut out = Vec::new();
        out.extend(
            self.a
                .filter(|_| !matches!(self.output, Output::A | Output::Sqrt)),
        );
        out.extend(self.b.filter(|_| self.output != Output::Sqrt));
        out.extend(self.c.map(|(_, v)| v));
        out.extend(self.e.map(|(_, v)| v));
        out.extend(self.d.filter(|_| self.output != Output::D).map(|(_, v)| v));
        if let Digit::Check(at) = self.digit {
            out.push(at);
        }
        out.extend(self.table.iter().copied());
        out
    }
}

// ---------------------------------------------------------------------------
// The program, before addresses
// ---------------------------------------------------------------------------

/// What a row does with its one-hot **selector** columns.
///
/// A window's digit drives three rows — the one that accumulates it into the
/// scalar and the two that select a table entry's `x` and `y` — and each has
/// selector columns of its own. Nothing ties one row's selectors to
/// another's, so a prover would otherwise take `x` from one table entry and
/// `y` from a different one, and the "point" the ladder then adds is on no
/// curve at all. So one row **emits** the digit onto the bus and the others
/// **check** their selectors against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digit {
    /// No selectors on this row: they are all zero.
    None,
    /// This row's output is its own digit, shifted into `[1, 2^WINDOW_BITS]`
    /// so that a negative digit is still a small non-negative value and its
    /// bus limbs above the lowest are zero.
    Emit,
    /// This row's selectors encode the shifted digit at this bus address.
    Check(u32),
}

/// The frame words a row moves. `docs/spec/ecrecover.md` §2.1 is the layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    None,
    /// Read eight frame words and make them this step's value.
    Read([u32; 8]),
    /// Write this step's operand out as eight frame words.
    Write([u32; 8]),
}

/// One step before its bus addresses are known: the same shape over [`Val`]s.
#[derive(Clone, Debug)]
struct Unplaced {
    a: Option<Val>,
    a_coeff: i64,
    b: Option<Val>,
    c: Option<(i64, Val)>,
    e: Option<(i64, Val)>,
    d: Option<(i64, Val)>,
    literal: [u64; 4],
    digit: UnplacedDigit,
    table: Vec<Val>,
    table_literals: Vec<[u64; 4]>,
    modulus: Modulus,
    output: Output,
    bused: bool,
    is_zero: bool,
    exact: bool,
    frame: Frame,
    note: &'static str,
}

/// [`Digit`], before the bus addresses are known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnplacedDigit {
    None,
    Emit,
    Check(Val),
}

/// The straight-line program being built.
///
/// A builder is an assembler, not an optimizer: it emits what it is told, in
/// order, and the only thing it works out for itself is where on the bus each
/// value lives and how many copies of it the program reads.
pub struct Builder {
    steps: Vec<Unplaced>,
    /// `produced[v]` is the step that writes `Val(v)`.
    produced: Vec<usize>,
    /// The most bus addresses one step may write, which is the most readers
    /// one value may have. A value read more often is fanned out through
    /// copy steps by [`Builder::fanout`].
    cap: usize,
    /// Reads each value has left before it needs a copy step.
    remaining: Vec<usize>,
    /// Reads [`Builder::fanout`] has handed out that have not happened yet.
    /// Without this a value fanned out twice spends the same budget twice,
    /// and the program silently asks one step to write more copies than a row
    /// has slots for.
    pending: Vec<usize>,
}

impl Builder {
    pub fn new(cap: usize) -> Builder {
        assert!(cap >= 2, "a fan-out cap below two cannot copy");
        Builder {
            steps: Vec::new(),
            produced: Vec::new(),
            cap,
            remaining: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// The fan-out cap this builder was made with.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Steps emitted so far.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    fn push(&mut self, step: Unplaced) -> Val {
        let at = self.steps.len();
        let out = step.output;
        for v in step.operands() {
            let i = v.0 as usize;
            assert!(
                self.remaining[i] > 0,
                "`{}` at step {} reads a value with no copies left: fan it out first",
                step.note,
                self.steps.len()
            );
            self.remaining[i] -= 1;
            self.pending[i] = self.pending[i].saturating_sub(1);
        }
        self.steps.push(step);
        match out {
            Output::None => Val(u32::MAX),
            _ => {
                self.produced.push(at);
                self.remaining.push(self.cap);
                self.pending.push(0);
                Val((self.produced.len() - 1) as u32)
            }
        }
    }

    /// `x·y + Σ terms + k`, as a new value. At most two linear terms.
    pub fn mul_add(
        &mut self,
        note: &'static str,
        modulus: Modulus,
        x: Val,
        y: Val,
        terms: &[(i64, Val)],
        literal: [u64; 4],
    ) -> Val {
        assert!(
            terms.len() <= 2,
            "{note}: a written step has two linear slots"
        );
        self.push(Unplaced {
            a: Some(x),
            a_coeff: 0,
            b: Some(y),
            c: terms.first().copied(),
            e: terms.get(1).copied(),
            d: None,
            literal,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            modulus,
            bused: true,
            output: Output::D,
            is_zero: false,
            exact: false,
            frame: Frame::None,
            note,
        })
    }

    /// `x·y + Σ terms + k`, as a new value the equation reads with the
    /// coefficient `scale` rather than the usual `−1`: `x·y + Σ + k + scale·v ≡ 0`.
    ///
    /// A doubling needs it. `x₃ = λ² − 2x` with `λ = lam/2` is
    /// `lam² − 4x₃ − 8x ≡ 0`, and halving in the field would cost a step where
    /// a coefficient costs nothing.
    pub fn mul_add_scaled(
        &mut self,
        note: &'static str,
        modulus: Modulus,
        product: (Val, Val),
        terms: &[(i64, Val)],
        literal: [u64; 4],
        scale: i64,
    ) -> Val {
        let v = self.mul_add(note, modulus, product.0, product.1, terms, literal);
        let at = *self.produced.last().expect("the step produced a value");
        self.steps[at].d = Some((scale, v));
        v
    }

    /// One entry of a windowed table, chosen by the row's one-hot selectors:
    /// `Σ_k s_k·(T_k + L_k)`, as a new value.
    ///
    /// `T` is the bused table and `L` the schedule one; a caller passes one or
    /// the other. `G`'s multiples are the same on every row and ship as `L`,
    /// which is what `docs/spec/ecrecover.md` §5.1 means by "gate literals":
    /// no commitment, no bus traffic, and no fan-out to pay for.
    ///
    /// The selectors are the row's own columns, held boolean and one-hot by
    /// the circuit, and the digit they encode is tied to the scalar by the
    /// accumulation the caller emits beside this. One-hotness alone would let
    /// a prover multiply by any scalar at all (§5.2).
    pub fn select_table(
        &mut self,
        note: &'static str,
        modulus: Modulus,
        digit: Val,
        table: &[Val],
        literals: &[[u64; 4]],
    ) -> Val {
        self.selection(
            note,
            modulus,
            UnplacedDigit::Check(digit),
            table,
            literals,
            [0; 4],
        )
    }

    fn selection(
        &mut self,
        note: &'static str,
        modulus: Modulus,
        digit: UnplacedDigit,
        table: &[Val],
        literals: &[[u64; 4]],
        literal: [u64; 4],
    ) -> Val {
        assert!(
            table.is_empty() != literals.is_empty(),
            "{note}: a selection reads one table, bused or literal"
        );
        self.push(Unplaced {
            a: None,
            a_coeff: 0,
            b: None,
            c: None,
            e: None,
            d: None,
            literal,
            digit,
            table: table.to_vec(),
            table_literals: literals.to_vec(),
            modulus,
            bused: true,
            output: Output::D,
            is_zero: false,
            exact: false,
            frame: Frame::None,
            note,
        })
    }

    /// A window's digit, from the row's own one-hot selectors, as a value.
    ///
    /// The digit table is the signed digits themselves, so this is the same
    /// selection every other row of the window runs — the difference is only
    /// that **this** row's selectors are free and the others are checked
    /// against what this one buses. The digit is shifted into
    /// `[1, 2^(w+1))` by `shift`, so a negative digit is still a small
    /// positive bus value whose limbs above the lowest are zero.
    pub fn emit_digit(&mut self, note: &'static str, digits: &[[u64; 4]], shift: [u64; 4]) -> Val {
        self.selection(
            note,
            Modulus::Order,
            UnplacedDigit::Emit,
            &[],
            digits,
            shift,
        )
    }

    /// `x·y`, as a new value.
    pub fn mul(&mut self, note: &'static str, modulus: Modulus, x: Val, y: Val) -> Val {
        self.mul_add(note, modulus, x, y, &[], [0; 4])
    }

    /// `Σ terms + k`, as a new value. At most two terms.
    pub fn lin(
        &mut self,
        note: &'static str,
        modulus: Modulus,
        terms: &[(i64, Val)],
        literal: [u64; 4],
    ) -> Val {
        assert!(
            terms.len() <= 2,
            "{note}: a written step has two linear slots"
        );
        self.push(Unplaced {
            a: None,
            a_coeff: 0,
            b: None,
            c: terms.first().copied(),
            e: terms.get(1).copied(),
            d: None,
            literal,
            modulus,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            bused: true,
            output: Output::D,
            is_zero: false,
            exact: false,
            frame: Frame::None,
            note,
        })
    }

    /// A constant, as a new value.
    pub fn constant(&mut self, note: &'static str, modulus: Modulus, v: [u64; 4]) -> Val {
        self.lin(note, modulus, &[], v)
    }

    /// The `v` with `v·denominator + Σ terms + k ≡ 0`: division, with the
    /// quotient written into the product's left slot. Up to three linear
    /// terms, `D` being free here.
    ///
    /// A zero denominator makes `v` free, which is why every use of this is
    /// paired with a proof that the denominator is nonzero — and why
    /// `docs/spec/ecrecover.md` §5.3 spends five cases rather than trusting
    /// one.
    pub fn div(
        &mut self,
        note: &'static str,
        modulus: Modulus,
        denominator: Val,
        terms: &[(i64, Val)],
        literal: [u64; 4],
    ) -> Val {
        assert!(
            terms.len() <= 3,
            "{note}: a dividing step has three linear slots"
        );
        self.push(Unplaced {
            a: None,
            a_coeff: 0,
            b: Some(denominator),
            c: terms.first().copied(),
            e: terms.get(1).copied(),
            d: terms.get(2).copied(),
            literal,
            modulus,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            bused: true,
            output: Output::A,
            is_zero: false,
            exact: false,
            frame: Frame::None,
            note,
        })
    }

    /// The value the step just produced is a row-local witness after all:
    /// drop it from the bus.
    ///
    /// A step whose output nothing reads must not write one. There are three
    /// in the program — an invertibility witness, a non-residue certificate
    /// and a parity's halved value — and each exists to prove something
    /// exists, not to be used.
    fn witness_only(&mut self) {
        let at = self.produced.pop().expect("a step produced a value");
        self.remaining.pop();
        self.pending.pop();
        self.steps[at].bused = false;
    }

    /// `v` is invertible: the row witnesses `1/v` and nothing buses it.
    ///
    /// A chord's gap and a tangent's `2y` each need this, and each for the
    /// same reason: a zero denominator leaves the slope free, and a free
    /// slope anywhere in the ladder recovers an arbitrary public key from an
    /// honest signature (`docs/spec/ecrecover.md` §5.3).
    pub fn assert_invertible(&mut self, note: &'static str, modulus: Modulus, v: Val) {
        let one_less = match modulus {
            Modulus::Field => constants::secp256k1::P,
            Modulus::Order => constants::secp256k1::N,
        };
        let literal = [one_less[0] - 1, one_less[1], one_less[2], one_less[3]];
        self.push(Unplaced {
            a: None,
            a_coeff: 0,
            b: Some(v),
            c: None,
            e: None,
            d: None,
            literal,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            modulus,
            bused: true,
            output: Output::A,
            is_zero: false,
            exact: false,
            frame: Frame::None,
            note,
        });
        self.witness_only();
    }

    /// `x·y + Σ terms + k ≡ 0`, asserted. Up to three linear terms.
    pub fn assert_zero(
        &mut self,
        note: &'static str,
        modulus: Modulus,
        product: Option<(Val, Val)>,
        terms: &[(i64, Val)],
        literal: [u64; 4],
    ) {
        assert!(
            terms.len() <= 3,
            "{note}: an assertion has three linear slots"
        );
        self.push(Unplaced {
            a: product.map(|(x, _)| x),
            a_coeff: 0,
            b: product.map(|(_, y)| y),
            c: terms.first().copied(),
            e: terms.get(1).copied(),
            d: terms.get(2).copied(),
            literal,
            modulus,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            bused: true,
            output: Output::None,
            is_zero: false,
            exact: false,
            frame: Frame::None,
            note,
        });
    }

    /// `[x = 0]`, as a boolean value. The test is on 128-bit halves, never on
    /// one `Fr` (`docs/spec/ecrecover.md` §3.4); the gadget is
    /// `constraints::gadgets::is_zero` over each half, and the row's output is
    /// the product of the two.
    pub fn is_zero(&mut self, note: &'static str, x: Val) -> Val {
        self.push(Unplaced {
            a: Some(x),
            a_coeff: 0,
            b: None,
            c: None,
            e: None,
            d: None,
            literal: [0; 4],
            modulus: Modulus::Field,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            bused: true,
            output: Output::D,
            is_zero: true,
            exact: false,
            frame: Frame::None,
            note,
        })
    }

    /// `if s { x } else { y }`, for a boolean `s`: `s·(x − y) + y`, which is
    /// the one shape again with the boolean in the product.
    ///
    /// Both branches are **computed** and one is chosen. A branch that is
    /// degenerate — a chord through equal points, say — produces a free value,
    /// and the whole soundness of the ladder is that such a value is never the
    /// one selected (§5.3).
    pub fn select(&mut self, note: &'static str, modulus: Modulus, s: Val, x: Val, y: Val) -> Val {
        let diff = self.lin(note, modulus, &[(1, x), (-1, y)], [0; 4]);
        self.mul_add(note, modulus, s, diff, &[(1, y)], [0; 4])
    }

    /// The `v` with `v² + Σ terms + k ≡ 0`: a witnessed square root, the one
    /// step whose solution is not a rational function of its inputs.
    ///
    /// Where the right-hand side is a non-residue there is no witness at all,
    /// which is what makes `docs/spec/ecrecover.md` §1.3's failure direction
    /// provable — and why a caller pairs this with the complementary root of
    /// `−rhs`, exactly one of which exists because `p ≡ 3 mod 4` makes `−1` a
    /// non-residue.
    pub fn sqrt(
        &mut self,
        note: &'static str,
        modulus: Modulus,
        terms: &[(i64, Val)],
        literal: [u64; 4],
    ) -> Val {
        assert!(
            terms.len() <= 3,
            "{note}: a square root has three linear slots"
        );
        self.push(Unplaced {
            a: None,
            a_coeff: 0,
            b: None,
            c: terms.first().copied(),
            e: terms.get(1).copied(),
            d: terms.get(2).copied(),
            literal,
            modulus,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            bused: true,
            output: Output::Sqrt,
            is_zero: false,
            exact: false,
            frame: Frame::None,
            note,
        })
    }

    /// A free boolean: the square root of itself, `b² − b ≡ 0`.
    pub fn boolean(&mut self, note: &'static str) -> Val {
        let v = self.sqrt(note, Modulus::Field, &[], [0; 4]);
        let at = *self
            .produced
            .last()
            .expect("the square root produced a value");
        self.steps[at].a_coeff = -1;
        v
    }

    /// `Σ terms + k = 0` **over the integers**, with the quotient held to
    /// zero, producing the first term's value.
    ///
    /// `y = 2h + b` is the case that needs it: modulo `p` it holds for either
    /// parity, with `h = (y − b)/2`, and says nothing at all.
    pub fn exact(
        &mut self,
        note: &'static str,
        coefficient: i64,
        terms: &[(i64, Val)],
        literal: [u64; 4],
    ) -> Val {
        assert!(
            terms.len() <= 2,
            "{note}: a written step has two linear slots"
        );
        let v = self.push(Unplaced {
            a: None,
            a_coeff: 0,
            b: None,
            c: terms.first().copied(),
            e: terms.get(1).copied(),
            d: None,
            literal,
            modulus: Modulus::Field,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            bused: true,
            output: Output::D,
            is_zero: false,
            exact: true,
            frame: Frame::None,
            note,
        });
        let at = *self
            .produced
            .last()
            .expect("the exact step produced a value");
        self.steps[at].d = Some((coefficient, v));
        v
    }

    /// Eight frame words, low word first, as a value. `u32::MAX` is a word
    /// the value does not use, which contributes zero.
    pub fn frame_read(&mut self, note: &'static str, words: [u32; 8]) -> Val {
        self.push(Unplaced {
            a: None,
            a_coeff: 0,
            b: None,
            c: None,
            e: None,
            d: None,
            literal: [0; 4],
            modulus: Modulus::Field,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            bused: true,
            output: Output::D,
            is_zero: false,
            exact: true,
            frame: Frame::Read(words),
            note,
        })
    }

    /// A value out to eight frame words.
    pub fn frame_write(&mut self, note: &'static str, words: [u32; 8], v: Val) {
        self.push(Unplaced {
            a: None,
            a_coeff: 0,
            b: None,
            c: Some((1, v)),
            e: None,
            d: None,
            literal: [0; 4],
            modulus: Modulus::Field,
            digit: UnplacedDigit::None,
            table: Vec::new(),
            table_literals: Vec::new(),
            bused: true,
            output: Output::None,
            is_zero: false,
            exact: true,
            frame: Frame::Write(words),
            note,
        });
    }

    /// `k` uses of one value, through as many copy steps as the fan-out cap
    /// needs. The returned list names a value once per use, so a caller reads
    /// straight down it.
    ///
    /// A multiset pairs one write with one read: a value read more often than
    /// its producer writes copies has no witness at all, so fan-out is a
    /// thing the program spends rows on rather than a thing it assumes.
    pub fn fanout(&mut self, note: &'static str, modulus: Modulus, v: Val, k: usize) -> Vec<Val> {
        let mut out = Vec::with_capacity(k);
        let mut src = v;
        loop {
            let i = src.0 as usize;
            let available = self.remaining[i] - self.pending[i];
            let want = k - out.len();
            if available >= want {
                for _ in 0..want {
                    out.push(src);
                    self.pending[i] += 1;
                }
                return out;
            }
            assert!(
                available >= 1,
                "`{note}` at step {}: a value with no reads left cannot be copied",
                self.steps.len()
            );
            // Every read left but one goes to the caller; the last buys a
            // copy, which comes back with a full budget of its own.
            for _ in 0..available - 1 {
                out.push(src);
                self.pending[i] += 1;
            }
            // The last read left goes on the copy itself.
            src = self.lin(note, modulus, &[(1, src)], [0; 4]);
        }
    }

    /// The last step's output is a witness the bus never sees. See
    /// [`Builder::witness_only`].
    pub fn discard_last(&mut self) {
        self.witness_only();
    }

    /// Resolve every value to bus addresses and emit the schedule.
    ///
    /// A value's address range is as long as the program reads it: the `j`th
    /// reader of a value reads the `j`th copy, and the producing step writes
    /// every copy. That is the whole fan-out rule, and it is static, so an
    /// honest prover's writes and reads pair up by construction.
    pub fn finish(self) -> Schedule {
        // How many times each value is read.
        let mut readers = vec![0usize; self.produced.len()];
        for step in &self.steps {
            for v in step.operands() {
                readers[v.0 as usize] += 1;
            }
        }
        // Address ranges, in value order.
        let mut base = Vec::with_capacity(readers.len());
        let mut next = 0u32;
        for r in &readers {
            base.push(next);
            // A value nothing reads still occupies one address: the write has
            // to go somewhere, and a write with no reader is what a dangling
            // computation is.
            next += (*r).max(1) as u32;
        }

        let mut taken = vec![0usize; readers.len()];
        let address = |v: Val, taken: &mut Vec<usize>| -> u32 {
            let i = v.0 as usize;
            let a = base[i] + taken[i] as u32;
            taken[i] += 1;
            a
        };

        let mut steps = Vec::with_capacity(self.steps.len());
        let mut produced_at = 0usize;
        for step in &self.steps {
            // Reads first, in slot order, so the interpreter and the circuit
            // agree on which copy is which.
            let a_read = (!matches!(step.output, Output::A | Output::Sqrt))
                .then(|| step.a.map(|v| address(v, &mut taken)))
                .flatten();
            let b_read = (step.output != Output::Sqrt)
                .then(|| step.b.map(|v| address(v, &mut taken)))
                .flatten();
            let c = step.c.map(|(k, v)| (k, address(v, &mut taken)));
            let e = step.e.map(|(k, v)| (k, address(v, &mut taken)));
            let d_read = (step.output != Output::D)
                .then(|| step.d.map(|(k, v)| (k, address(v, &mut taken))))
                .flatten();

            let writes = match (step.output, step.bused) {
                (Output::None, _) | (_, false) => Vec::new(),
                _ => {
                    let v = produced_at;
                    produced_at += 1;
                    (0..readers[v].max(1)).map(|j| base[v] + j as u32).collect()
                }
            };
            // The written slot names where its output lives, so the circuit
            // and the interpreter read one field for a slot whether it is a
            // read or a write. A `D` written with no coefficient of its own
            // carries the usual `−1`; a square root's `B` is its `A`.
            let home = writes.first().copied();
            let (a, b, d) = match step.output {
                Output::A => (home, b_read, d_read),
                Output::Sqrt => (home, home, d_read),
                Output::D => (a_read, b_read, None),
                Output::None => (a_read, b_read, d_read),
            };
            steps.push(Step {
                a,
                a_coeff: step.a_coeff,
                b,
                c,
                e,
                d,
                literal: step.literal,
                digit: match step.digit {
                    UnplacedDigit::None => Digit::None,
                    UnplacedDigit::Emit => Digit::Emit,
                    UnplacedDigit::Check(v) => Digit::Check(address(v, &mut taken)),
                },
                table: step.table.iter().map(|v| address(*v, &mut taken)).collect(),
                table_literals: step.table_literals.clone(),
                modulus: step.modulus,
                output: step.output,
                out_coeff: step.d.map(|(k, _)| k).unwrap_or(-1),
                bused: step.bused,
                writes,
                is_zero: step.is_zero,
                exact: step.exact,
                frame: step.frame,
                note: step.note,
            });
        }
        let fan_out = steps.iter().map(|s| s.writes.len()).max().unwrap_or(0);
        if fan_out > self.cap {
            let worst = steps
                .iter()
                .max_by_key(|s| s.writes.len())
                .expect("a step exists");
            panic!(
                "`{}` is read {fan_out} times and the fan-out cap is {}: the program \
                 owes it copy steps",
                worst.note, self.cap
            );
        }
        Schedule {
            steps,
            values: next as usize,
            fan_out,
        }
    }
}

impl Unplaced {
    /// Every value this step reads, in slot order.
    fn operands(&self) -> Vec<Val> {
        let mut out = Vec::new();
        if !matches!(self.output, Output::A | Output::Sqrt) {
            out.extend(self.a);
        }
        if self.output != Output::Sqrt {
            out.extend(self.b);
        }
        out.extend(self.c.map(|(_, v)| v));
        out.extend(self.e.map(|(_, v)| v));
        if self.output != Output::D {
            out.extend(self.d.map(|(_, v)| v));
        }
        if let UnplacedDigit::Check(v) = self.digit {
            out.push(v);
        }
        out.extend(self.table.iter().copied());
        out
    }
}

/// A finished step program: the rows of one invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub steps: Vec<Step>,
    /// Bus addresses the program occupies, per invocation.
    pub values: usize,
    /// The most copies any one step writes — the write slots a row needs.
    pub fan_out: usize,
}
