//! The scaffolding every execution family's circuit is written on: [`Expr`],
//! a polynomial of degree at most 2 over committed columns, and [`Family`], a
//! builder that lays a family's columns out after its memory frame, names
//! each, adds what every family shares — the decoded row and its kind bits, the
//! mask, address and masked-value rules, word ranges, signs and the tagged
//! generic lookups — and assembles the artifact with its channels.
//!
//! A register value is two 32-bit words, `(lo, hi)` (`docs/spec/memory.md`
//! §2.1), so a word range, a sign and a 64-bit comparison are the pieces the
//! families keep reaching for; `docs/spec/circuits.md` §2 lists what this adds
//! and each family's page the rest. A column is named once, here, and a fill
//! finds it by that name.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};

use constants::extra_mask::IMM_NEGATIVE;
use constants::{address_space, generic_table, lookup_channel};
use field::Fp;

use crate::lookup::ChannelSpec;
use crate::memory::{
    frame, frame_hi, frame_queries, frame_with_channels_artifact, rd_selected, rd_selected_hi,
    FamilySpec, FIELD_ADDR, FIELD_MASK, FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_NAMES,
    FRAME_SPACE, PC,
};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// `2^32`, the weight of a register's high word.
pub const T32: u64 = 1 << 32;
/// `2^16`, the weight of a word's high halfword.
pub const T16: u64 = 1 << 16;

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

/// `c + Σ a·x + Σ b·y·z` over committed columns, literal coefficients only:
/// what every family gate and lookup expression is written as. Terms are kept
/// merged, so a gate names each column and each product once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expr {
    pub constant: Fp,
    pub linear: Vec<(Fp, PolyAddress)>,
    pub products: Vec<(Fp, PolyAddress, PolyAddress)>,
}

impl Default for Expr {
    /// The zero polynomial.
    fn default() -> Expr {
        Expr {
            constant: Fp::ZERO,
            linear: Vec::new(),
            products: Vec::new(),
        }
    }
}

/// The constant `v`.
pub fn k(v: u64) -> Expr {
    Expr {
        constant: Fp::from_u64(v),
        ..Expr::default()
    }
}

/// The sum of `columns`, each weighted 1.
pub fn sum(columns: &[PolyAddress]) -> Expr {
    columns.iter().fold(Expr::default(), |acc, x| acc + *x)
}

impl From<PolyAddress> for Expr {
    fn from(x: PolyAddress) -> Expr {
        Expr {
            linear: vec![(Fp::ONE, x)],
            ..Expr::default()
        }
    }
}

impl Expr {
    /// Whether the expression has a product term.
    pub fn is_quadratic(&self) -> bool {
        !self.products.is_empty()
    }

    fn scale(mut self, c: Fp) -> Expr {
        self.constant *= c;
        self.linear.iter_mut().for_each(|t| t.0 *= c);
        self.products.iter_mut().for_each(|t| t.0 *= c);
        self.merged()
    }

    /// Like terms added, zero terms dropped, products ordered by their factors.
    fn merged(mut self) -> Expr {
        let mut linear: Vec<(Fp, PolyAddress)> = Vec::new();
        for (c, x) in self.linear.drain(..) {
            match linear.iter_mut().find(|t| t.1 == x) {
                Some(t) => t.0 += c,
                None => linear.push((c, x)),
            }
        }
        let mut products: Vec<(Fp, PolyAddress, PolyAddress)> = Vec::new();
        for (c, y, z) in self.products.drain(..) {
            let (y, z) = if y <= z { (y, z) } else { (z, y) };
            match products.iter_mut().find(|t| t.1 == y && t.2 == z) {
                Some(t) => t.0 += c,
                None => products.push((c, y, z)),
            }
        }
        linear.retain(|t| t.0 != Fp::ZERO);
        products.retain(|t| t.0 != Fp::ZERO);
        Expr {
            constant: self.constant,
            linear,
            products,
        }
    }

    /// The gate this expression is: `Linear` without a product term,
    /// `Quadratic` with one.
    pub fn gate(self) -> GateDef {
        let lit = Coeff::Literal;
        let constant = lit(self.constant);
        let linear = self.linear.into_iter().map(|(c, x)| (lit(c), x)).collect();
        match self.products.is_empty() {
            true => GateDef::Linear {
                terms: linear,
                constant,
            },
            false => GateDef::Quadratic {
                constant,
                linear,
                products: self
                    .products
                    .into_iter()
                    .map(|(c, y, z)| (lit(c), y, z))
                    .collect(),
            },
        }
    }
}

impl<T: Into<Expr>> Add<T> for Expr {
    type Output = Expr;
    fn add(mut self, rhs: T) -> Expr {
        let rhs = rhs.into();
        self.constant += rhs.constant;
        self.linear.extend(rhs.linear);
        self.products.extend(rhs.products);
        self.merged()
    }
}

impl<T: Into<Expr>> Sub<T> for Expr {
    type Output = Expr;
    fn sub(self, rhs: T) -> Expr {
        self + (-rhs.into())
    }
}

impl Neg for Expr {
    type Output = Expr;
    fn neg(self) -> Expr {
        self.scale(Fp::MINUS_ONE)
    }
}

impl Mul<u64> for Expr {
    type Output = Expr;
    fn mul(self, c: u64) -> Expr {
        self.scale(Fp::from_u64(c))
    }
}

impl Mul<Fp> for Expr {
    type Output = Expr;
    fn mul(self, c: Fp) -> Expr {
        self.scale(c)
    }
}

/// The product of two expressions of degree at most 1. Panics on a product
/// of degree 3 or more, which no gate can carry.
impl<T: Into<Expr>> Mul<T> for Expr {
    type Output = Expr;
    fn mul(self, rhs: T) -> Expr {
        let rhs = rhs.into();
        assert!(
            !self.is_quadratic() && !rhs.is_quadratic(),
            "a product of degree above 2"
        );
        let mut out = Expr {
            constant: self.constant * rhs.constant,
            ..Expr::default()
        };
        for (a, x) in &self.linear {
            out.linear.push((*a * rhs.constant, *x));
            for (b, y) in &rhs.linear {
                out.products.push((*a * *b, *x, *y));
            }
        }
        for (b, y) in &rhs.linear {
            out.linear.push((*b * self.constant, *y));
        }
        out.merged()
    }
}

impl<T: Into<Expr>> Add<T> for PolyAddress {
    type Output = Expr;
    fn add(self, rhs: T) -> Expr {
        Expr::from(self) + rhs
    }
}

impl<T: Into<Expr>> Sub<T> for PolyAddress {
    type Output = Expr;
    fn sub(self, rhs: T) -> Expr {
        Expr::from(self) - rhs
    }
}

impl<T: Into<Expr>> Mul<T> for PolyAddress {
    type Output = Expr;
    fn mul(self, rhs: T) -> Expr {
        Expr::from(self) * rhs
    }
}

impl Mul<u64> for PolyAddress {
    type Output = Expr;
    fn mul(self, c: u64) -> Expr {
        Expr::from(self) * c
    }
}

// ---------------------------------------------------------------------------
// The family builder
// ---------------------------------------------------------------------------

/// Which immediate a family's decoded row carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Imm {
    /// None: the tuple has no `imm` (`ATOMICS`).
    None,
    /// An immediate that is never negative: a shift amount, or 0.
    Unsigned,
    /// A sign-extended immediate, its sign bit `IMM_NEGATIVE` of the mask.
    Signed,
}

/// One execution family's circuit, built column by column over its memory
/// frame. `docs/spec/circuits.md` §2.
pub struct Family {
    pub family: u32,
    pub queries: &'static [usize],
    witness: Vec<String>,
    enforcing: Vec<(String, GateDef)>,
    lookups: Vec<LookupExpr>,
    setup: Vec<String>,
    decoded: Vec<PolyAddress>,
    /// The decoded fall-through, `pc + 2` or `pc + 4`.
    pub seq: PolyAddress,
    /// The decoded register indices.
    pub rs1: PolyAddress,
    pub rs2: PolyAddress,
    pub rd: PolyAddress,
    /// The decoded immediate's low word, if the tuple has one.
    pub imm: Option<PolyAddress>,
    /// The kind bits, in the family's `extra_mask` order.
    pub kinds: Vec<PolyAddress>,
    /// The immediate's sign, 1 where its 64-bit extension's high word is
    /// `2^32 − 1`; `None` for a family whose immediate is never negative.
    pub neg: Option<PolyAddress>,
}

impl Family {
    /// A family's builder over its frame, with its decoded row as the first
    /// witness columns after the frame's, then one boolean column per kind in
    /// `kinds` and the immediate's sign, and the gate tying them to the packed
    /// mask: `Σ_k 2^k·b_k + 2^31·neg − mask` (`docs/spec/program.md` §6).
    pub fn new(family: u32, kinds: &[&str], imm: Imm) -> Family {
        let mut f = Family {
            family,
            queries: frame_queries(family),
            witness: Vec::new(),
            enforcing: Vec::new(),
            lookups: Vec::new(),
            setup: Vec::new(),
            decoded: Vec::new(),
            seq: PolyAddress::Witness(0),
            rs1: PolyAddress::Witness(0),
            rs2: PolyAddress::Witness(0),
            rd: PolyAddress::Witness(0),
            imm: None,
            kinds: Vec::new(),
            neg: None,
        };
        let mut fields = vec!["next_pc", "rs1", "rs2", "rd"];
        if imm != Imm::None {
            fields.push("imm");
        }
        fields.push("extra_mask");
        f.setup.push("table_pc".into());
        for field in &fields {
            let column = f.col(&format!("decoded_{field}"));
            f.decoded.push(column);
            f.setup.push(format!("table_{field}"));
        }
        let d = f.decoded.clone();
        (f.seq, f.rs1, f.rs2, f.rd) = (d[0], d[1], d[2], d[3]);
        f.imm = (imm != Imm::None).then_some(d[4]);
        let mask = *d.last().expect("the mask is in every tuple");
        f.kinds = kinds.iter().map(|k| f.bit(&format!("kind_{k}"))).collect();
        let mut bits = Expr::default();
        for (j, b) in f.kinds.clone().into_iter().enumerate() {
            bits = bits + b * (1u64 << j);
        }
        if imm == Imm::Signed {
            let neg = f.bit("imm_negative");
            f.neg = Some(neg);
            bits = bits + neg * (1u64 << IMM_NEGATIVE);
        }
        f.gate("decoded_mask_bits", bits - mask);
        f
    }

    // -- the frame ----------------------------------------------------------

    fn slot(&self, q: usize) -> usize {
        self.queries
            .iter()
            .position(|&x| x == q)
            .unwrap_or_else(|| panic!("{}: no {} query", self.family, FRAME_NAMES[q]))
    }

    /// Query `q`'s mask.
    pub fn m(&self, q: usize) -> PolyAddress {
        frame(self.slot(q), FIELD_MASK)
    }
    /// Query `q`'s address.
    pub fn addr(&self, q: usize) -> PolyAddress {
        frame(self.slot(q), FIELD_ADDR)
    }
    /// Query `q`'s read value, a register's low word.
    pub fn v(&self, q: usize) -> PolyAddress {
        frame(self.slot(q), FIELD_READ_VALUE)
    }
    /// Query `q`'s written value, a register's low word.
    pub fn wv(&self, q: usize) -> PolyAddress {
        frame(self.slot(q), FIELD_WRITE_VALUE)
    }
    /// Register query `q`'s read high word.
    pub fn vh(&self, q: usize) -> PolyAddress {
        frame_hi(self.queries, self.slot(q), false)
    }
    /// The row's liveness, `m_pc`.
    pub fn live(&self) -> PolyAddress {
        self.m(PC)
    }
    /// The pc the row runs.
    pub fn pc(&self) -> PolyAddress {
        self.v(PC)
    }
    /// The pc the row writes.
    pub fn next_pc(&self) -> PolyAddress {
        self.wv(PC)
    }
    /// The value the frame writes to a nonzero `rd`: its low word, and its
    /// high word.
    pub fn sel(&self) -> PolyAddress {
        rd_selected(self.queries.len())
    }
    pub fn sel_hi(&self) -> PolyAddress {
        rd_selected_hi(self.queries.len())
    }

    // -- columns and gates --------------------------------------------------

    /// A new witness column named `name`, after every column before it.
    pub fn col(&mut self, name: &str) -> PolyAddress {
        assert!(
            !self.witness.iter().any(|n| n == name),
            "{}: a second column named `{name}`",
            self.family
        );
        self.witness.push(name.to_string());
        // The frame's witness columns come first: a gap chunk per query, then
        // the x0 gadget's four.
        PolyAddress::Witness((self.queries.len() + 4 + self.witness.len() - 1) as u32)
    }

    /// A new witness column held boolean by `<name>_boolean`.
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
            "{}: gate `{name}` is not zero on the all-zero row",
            self.family
        );
        self.enforcing.push((name.to_string(), e.gate()));
    }

    /// An enforcing gate already built, such as `gadgets::is_zero`'s.
    pub fn push_gate(&mut self, name: &str, g: GateDef) {
        self.enforcing.push((name.to_string(), g));
    }

    /// `m_q − m_pc·uses`: query `q` is present exactly on a live row whose
    /// kind uses it.
    pub fn mask_rule(&mut self, q: usize, uses: Expr) {
        let e = self.m(q) - self.live() * uses;
        self.gate(&format!("{}_mask_rule", FRAME_NAMES[q]), e);
    }

    /// `m_q·(a_q − target)`: a present query's address is `target`.
    pub fn addr_rule(&mut self, q: usize, target: Expr) {
        let e = self.m(q) * (self.addr(q) - target);
        self.gate(&format!("{}_addr_rule", FRAME_NAMES[q]), e);
    }

    /// `v − m·v` for each of a query's read words: an absent query reads 0.
    pub fn value_masked(&mut self, q: usize) {
        let (m, v) = (self.m(q), self.v(q));
        self.gate(&format!("{}_value_masked", FRAME_NAMES[q]), v - m * v);
        if FRAME_SPACE[q] == address_space::REG {
            let vh = self.vh(q);
            self.gate(&format!("{}_value_masked_hi", FRAME_NAMES[q]), vh - m * vh);
        }
    }

    // -- lookups ------------------------------------------------------------

    fn range(&mut self, channel: u32, name: &str, e: Expr, selector: PolyAddress) {
        self.lookups.push(LookupExpr {
            name: name.to_string(),
            channel,
            selector,
            tuple: vec![e.gate()],
        });
    }

    /// A `RANGE16` obligation: `e < 2^16` where `selector` is 1.
    pub fn range16(&mut self, name: &str, e: Expr, selector: PolyAddress) {
        self.range(lookup_channel::RANGE16, name, e, selector);
    }

    /// A 19-bit obligation on the `TIMESTAMP` channel's table: a carry's,
    /// offset to be non-negative.
    pub fn range19(&mut self, name: &str, e: Expr, selector: PolyAddress) {
        self.range(lookup_channel::TIMESTAMP, name, e, selector);
    }

    /// `value` is a word: a new column `<name>_h16`, its high halfword, and
    /// both halfwords in `RANGE16`, under the row's liveness
    /// (`docs/spec/memory.md` §7). Returns the high halfword.
    pub fn word(&mut self, name: &str, value: Expr) -> PolyAddress {
        let live = self.live();
        let h = self.col(&format!("{name}_h16"));
        self.range16(&format!("{name}_hi_range"), h.into(), live);
        self.range16(&format!("{name}_lo_range"), value - h * T16, live);
        h
    }

    /// `value` is a word with sign `<name>_sign`: [`Family::word`], but the
    /// high halfword bounded by its `SIGN` lookup, which also gives its bit 15.
    /// Returns `(high halfword, sign)`.
    pub fn signed_word(&mut self, name: &str, value: Expr) -> (PolyAddress, PolyAddress) {
        let live = self.live();
        let h = self.col(&format!("{name}_h16"));
        let sign = self.col(&format!("{name}_sign"));
        self.range16(&format!("{name}_lo_range"), value - h * T16, live);
        self.generic(
            &format!("{name}_get_sign"),
            k(generic_table::SIGN as u64),
            [Some(h), Some(sign), None],
            live,
        );
        (h, sign)
    }

    /// A `GENERIC` lookup of `(tag, x1, x2, x3)` under `selector`; the tag, a
    /// linear form, names the sub-table and so bounds the rest
    /// (`docs/spec/lookup.md` §9).
    pub fn generic(
        &mut self,
        name: &str,
        tag: Expr,
        rest: [Option<PolyAddress>; 3],
        selector: PolyAddress,
    ) {
        let mut tuple = vec![tag.gate()];
        tuple.extend(
            rest.iter()
                .map(|x| x.map_or_else(Expr::default, Expr::from).gate()),
        );
        self.lookups.push(LookupExpr {
            name: name.to_string(),
            channel: lookup_channel::GENERIC,
            selector,
            tuple,
        });
    }

    /// `lhs < rhs` over two 64-bit values, `(lo, hi)` each, signed where the
    /// linear form `signed` is 1 (`docs/spec/jump-branch-slt.md` §3):
    ///
    /// ```text
    /// <p>_lo   lhs_lo − rhs_lo + 2^32·borrow − gap_lo
    /// <p>_hi   lhs_hi − rhs_hi − borrow − 2^32·signed·(lhs_sign − rhs_sign) + 2^32·lt − gap_hi
    /// ```
    ///
    /// with `borrow`, `lt` boolean and `gap_lo`, `gap_hi` words, each high
    /// word's sign from its own `SIGN` lookup. Ungated: every row satisfies them
    /// with the gap its own values give. Returns `(lt, gap_lo, gap_hi)`;
    /// `gap_lo + gap_hi` is 0 exactly when the two are equal.
    pub fn compare64(
        &mut self,
        p: &str,
        lhs: (Expr, PolyAddress),
        rhs: (Expr, PolyAddress),
        signed: Expr,
    ) -> (PolyAddress, PolyAddress, PolyAddress) {
        let (_, lhs_sign) = self.signed_word(&format!("{p}_lhs_hi"), lhs.1.into());
        let (_, rhs_sign) = self.signed_word(&format!("{p}_rhs_hi"), rhs.1.into());
        let borrow = self.bit(&format!("{p}_borrow"));
        let lt = self.bit(&format!("{p}_lt"));
        let gap_lo = self.col(&format!("{p}_gap_lo"));
        let gap_hi = self.col(&format!("{p}_gap_hi"));
        self.word(&format!("{p}_gap_lo"), gap_lo.into());
        self.word(&format!("{p}_gap_hi"), gap_hi.into());
        self.gate(&format!("{p}_lo"), lhs.0 - rhs.0 + borrow * T32 - gap_lo);
        let e = lhs.1 - rhs.1 - borrow - signed.clone() * lhs_sign * T32
            + signed * rhs_sign * T32
            + lt * T32
            - gap_hi;
        self.gate(&format!("{p}_hi"), e);
        (lt, gap_lo, gap_hi)
    }

    /// The enforcing gates built so far, by name.
    pub fn gates(&self) -> &[(String, GateDef)] {
        &self.enforcing
    }

    // -- assembly -----------------------------------------------------------

    fn uses(&self, channel: u32) -> bool {
        self.lookups.iter().any(|l| l.channel == channel)
    }

    /// The channels this family's lookups need, in output order: `TIMESTAMP`,
    /// `RANGE16` and `GENERIC` where used, `DECODER`; each multiplicity is one
    /// of the last witness columns, in that order.
    pub fn channels(&self) -> Vec<ChannelSpec> {
        let mut used = vec![lookup_channel::TIMESTAMP];
        used.extend(
            [lookup_channel::RANGE16, lookup_channel::GENERIC]
                .into_iter()
                .filter(|c| self.uses(*c)),
        );
        used.push(lookup_channel::DECODER);
        let first = (self.queries.len() + 4 + self.witness.len()) as u32;
        let table = self.decoded.len() as u32 + 1;
        used.iter()
            .enumerate()
            .map(|(i, &channel)| ChannelSpec {
                channel,
                table: match channel {
                    lookup_channel::TIMESTAMP => vec![PolyAddress::Virtual(VirtualKind::Range19)],
                    lookup_channel::RANGE16 => vec![PolyAddress::Virtual(VirtualKind::Range16)],
                    lookup_channel::GENERIC => (table..table + generic_table::WIDTH as u32)
                        .map(PolyAddress::Setup)
                        .collect(),
                    _ => (0..table).map(PolyAddress::Setup).collect(),
                },
                multiplicity: PolyAddress::Witness(first + i as u32),
            })
            .collect()
    }

    /// The family's circuit over `2^trace_vars` rows: the frame, the columns
    /// built so far, the multiplicities, the decoded table and the generic
    /// table where read, and the decoder lookup last. Panics on every refusal
    /// of the assembly, and if a gate is nonzero on the all-zero row.
    pub fn artifact(mut self, trace_vars: u32) -> CircuitArtifact {
        let channels = self.channels();
        for spec in &channels {
            self.witness.push(format!(
                "mult_{}",
                lookup_channel::NAMES[spec.channel as usize]
            ));
        }
        if self.uses(lookup_channel::GENERIC) {
            for name in [
                "generic_tag",
                "generic_key",
                "generic_value",
                "generic_result",
            ] {
                self.setup.push(name.to_string());
            }
        }
        let mut virtuals = vec![(VirtualKind::Range19, "range19".to_string())];
        if self.uses(lookup_channel::RANGE16) {
            virtuals.push((VirtualKind::Range16, "range16".to_string()));
        }
        let mut decode = vec![Expr::from(self.pc()).gate()];
        decode.extend(self.decoded.iter().map(|x| Expr::from(*x).gate()));
        self.lookups.push(LookupExpr {
            name: "decode_row".into(),
            channel: lookup_channel::DECODER,
            selector: self.live(),
            tuple: decode,
        });
        let a = frame_with_channels_artifact(
            self.queries,
            trace_vars,
            FamilySpec {
                witness: self.witness,
                setup: self.setup,
                virtuals,
                enforcing: self.enforcing,
                lookups: self.lookups,
                channels,
            },
        );
        assert!(
            a.padding.zero_row_valid,
            "family {}: a gate is nonzero on the all-zero row",
            self.family
        );
        a
    }
}
