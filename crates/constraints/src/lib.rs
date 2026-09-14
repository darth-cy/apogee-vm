#![no_std]
//! Circuit families as data: the addresses that name every polynomial, the
//! closed set of gate shapes, the layer specification, and the
//! `CircuitArtifact` that holds a whole circuit twice — as a flat constraint
//! list and as layered gates — with the laws that tie the two together.
//!
//! `docs/spec/gkr.md` is normative; §1–§4 are this crate. Nothing here
//! evaluates a gate: the kernel, which is the semantic authority, is
//! `gkr-verify`'s. What lives here is the formula *representation*, the
//! construction-time checks, and the wire form.
//!
//! `#![no_std]` + `alloc`, because `gkr-verify` reads an artifact and the
//! recursion guest links `gkr-verify`.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use field::Fr;

mod laws;
mod wire;

pub use laws::ConstraintError;

/// The artifact format this crate reads and writes. The first word of every
/// artifact.
pub const FORMAT_VERSION: u32 = 0;

/// The one coefficient encoding: every `Fr` is its canonical 32-byte
/// little-endian integer. The second word of every artifact, which is how the
/// file declares it.
pub const COEFFICIENT_ENCODING_CANONICAL_LE: u32 = 0;

/// The largest `trace_vars` an artifact may declare: a trace of `2^30` rows.
/// Far above the height menu's `2^22`, and low enough that `1 << trace_vars`
/// fits a 32-bit `usize`, which the recursion guest has.
pub const MAX_TRACE_VARS: u32 = 30;

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// A virtual setup table's closed form. `docs/spec/gkr.md` §2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VirtualKind {
    /// `V[row]`: the row index. Its value at row `y` is `y`, and its
    /// multilinear extension is `Σ_j 2^j · y_j`.
    RowIndex,
}

/// The one way any polynomial is named. `docs/spec/gkr.md` §2 says which
/// variants may appear where; `Display` is the short notation every dump and
/// diagnostic uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolyAddress {
    /// `M[i]`: a committed column of the memory-argument subtree.
    Memory(u32),
    /// `W[i]`: a committed column of the witness subtree, not memory-tied.
    Witness(u32),
    /// `S[i]`: a committed setup column.
    Setup(u32),
    /// `V[..]`: a virtual setup table, never materialized in a layer and never
    /// committed; its closed form is its kind.
    Virtual(VirtualKind),
    /// `L{k}[j]`: column `j` of inner layer `k >= 1`.
    Inner { layer: u32, offset: u32 },
    /// `scratch[i]`: an intermediate value of the flat constraint list.
    Scratch(u32),
    /// `C{k}[j]`: shared sub-expression `j` of gate list `k`.
    Cached { layer: u32, offset: u32 },
}

impl fmt::Display for PolyAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PolyAddress::Memory(i) => write!(f, "M[{i}]"),
            PolyAddress::Witness(i) => write!(f, "W[{i}]"),
            PolyAddress::Setup(i) => write!(f, "S[{i}]"),
            PolyAddress::Virtual(VirtualKind::RowIndex) => write!(f, "V[row]"),
            PolyAddress::Inner { layer, offset } => write!(f, "L{{{layer}}}[{offset}]"),
            PolyAddress::Scratch(i) => write!(f, "scratch[{i}]"),
            PolyAddress::Cached { layer, offset } => write!(f, "C{{{layer}}}[{offset}]"),
        }
    }
}

// ---------------------------------------------------------------------------
// Gate shapes
// ---------------------------------------------------------------------------

/// A coefficient: a literal, or an external challenge slot of
/// `constants::challenge_slot`, resolved at forward, prove and verify time. A
/// challenge is degree 0 in the layer below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coeff {
    Literal(Fr),
    Challenge(u32),
}

/// The closed set of gate shapes. `docs/spec/gkr.md` §3 is the table; the
/// kernel in `gkr-verify` is the semantic authority, and the order of
/// [`GateDef::operands`] is the order it reads values in.
///
/// Later stages extend the enum additively, each variant with a wire tag of
/// its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateDef {
    /// `Σ c_i·x_i + c_0`.
    Linear {
        terms: Vec<(Coeff, PolyAddress)>,
        constant: Coeff,
    },
    /// `c·x·y`.
    Product {
        coeff: Coeff,
        left: PolyAddress,
        right: PolyAddress,
    },
    /// `x·m + (1 − m)`: `x` where the mask is 1, the multiplicative identity
    /// where it is 0.
    MaskIntoIdentity {
        input: PolyAddress,
        mask: PolyAddress,
    },
    /// `(Σ a_i·x_i + a_0)·(Σ b_j·y_j + b_0)`.
    AffineProduct {
        left: Vec<(Coeff, PolyAddress)>,
        left_constant: Coeff,
        right: Vec<(Coeff, PolyAddress)>,
        right_constant: Coeff,
    },
    /// `x(·,0)·x(·,1)`: one step of a product tree, in a halving list.
    TreeProduct { input: PolyAddress },
}

impl GateDef {
    /// The addresses the gate reads, in kernel order. `TreeProduct`'s one
    /// operand is read twice by the kernel, as its two children.
    pub fn operands(&self) -> Vec<PolyAddress> {
        match self {
            GateDef::Linear { terms, .. } => terms.iter().map(|(_, a)| *a).collect(),
            GateDef::Product { left, right, .. } => alloc::vec![*left, *right],
            GateDef::MaskIntoIdentity { input, mask } => alloc::vec![*input, *mask],
            GateDef::AffineProduct { left, right, .. } => {
                left.iter().chain(right.iter()).map(|(_, a)| *a).collect()
            }
            GateDef::TreeProduct { input } => alloc::vec![*input],
        }
    }

    /// Every coefficient the gate carries, constants included.
    pub fn coefficients(&self) -> Vec<Coeff> {
        match self {
            GateDef::Linear { terms, constant } => {
                let mut c: Vec<Coeff> = terms.iter().map(|(c, _)| *c).collect();
                c.push(*constant);
                c
            }
            GateDef::Product { coeff, .. } => alloc::vec![*coeff],
            GateDef::MaskIntoIdentity { .. } | GateDef::TreeProduct { .. } => Vec::new(),
            GateDef::AffineProduct {
                left,
                left_constant,
                right,
                right_constant,
            } => {
                let mut c: Vec<Coeff> = left.iter().map(|(c, _)| *c).collect();
                c.push(*left_constant);
                c.extend(right.iter().map(|(c, _)| *c));
                c.push(*right_constant);
                c
            }
        }
    }

    /// This variant's row of [`CATALOGUE`].
    pub fn catalogue_index(&self) -> usize {
        match self {
            GateDef::Linear { .. } => 0,
            GateDef::Product { .. } => 1,
            GateDef::MaskIntoIdentity { .. } => 2,
            GateDef::AffineProduct { .. } => 3,
            GateDef::TreeProduct { .. } => 4,
        }
    }
}

/// One row of the gate catalogue: what a `GateDef` variant is, where it is
/// defined and evaluated, what it reads and writes, its formula in the one
/// template, and what it is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogueEntry {
    pub variant: &'static str,
    pub defined_in: &'static str,
    pub evaluated_in: &'static str,
    pub inputs: &'static str,
    pub output: &'static str,
    pub template: &'static str,
    pub purpose: &'static str,
}

const DEFINED_IN: &str = "crates/constraints/src/lib.rs, GateDef";
const EVALUATED_IN: &str = "crates/gkr-verify/src/lib.rs, eval_gate: gkr::forward per row, \
     gkr::prove per round node, gkr_verify::verify at the final check";
const ROW_WISE_OUTPUT: &str =
    "producing: L{k+1}[j]; enforcing: nothing; cached: C{k}[j] (row-wise lists)";

/// The gate catalogue, indexed by [`GateDef::catalogue_index`].
pub const CATALOGUE: [CatalogueEntry; 5] = [
    CatalogueEntry {
        variant: "Linear",
        defined_in: DEFINED_IN,
        evaluated_in: EVALUATED_IN,
        inputs: "x_1..x_t: addresses list k may read",
        output: ROW_WISE_OUTPUT,
        template: "out(x) = Σ_y eq(x,y)·(Σ c_i·x_i(y) + c_0)",
        purpose: "sums, copies across a layer, and challenge-weighted compressions",
    },
    CatalogueEntry {
        variant: "Product",
        defined_in: DEFINED_IN,
        evaluated_in: EVALUATED_IN,
        inputs: "x, y: addresses list k may read",
        output: ROW_WISE_OUTPUT,
        template: "out(x) = Σ_y eq(x,y)·c·x(y)·y(y)",
        purpose: "one degree-2 step of a product chain",
    },
    CatalogueEntry {
        variant: "MaskIntoIdentity",
        defined_in: DEFINED_IN,
        evaluated_in: EVALUATED_IN,
        inputs: "x, m: addresses list k may read; m is 0 or 1 on every row",
        output: ROW_WISE_OUTPUT,
        template: "out(x) = Σ_y eq(x,y)·(x(y)·m(y) + 1 − m(y))",
        purpose: "an inactive row contributes the multiplicative identity to a product",
    },
    CatalogueEntry {
        variant: "AffineProduct",
        defined_in: DEFINED_IN,
        evaluated_in: EVALUATED_IN,
        inputs: "x_1..x_t, y_1..y_u: addresses list k may read",
        output: ROW_WISE_OUTPUT,
        template: "out(x) = Σ_y eq(x,y)·(Σ a_i·x_i(y) + a_0)·(Σ b_j·y_j(y) + b_0)",
        purpose: "a gated or selected relation; the inline form of a product over a linear \
                  cached entry",
    },
    CatalogueEntry {
        variant: "TreeProduct",
        defined_in: DEFINED_IN,
        evaluated_in: EVALUATED_IN,
        inputs: "x: an L{k} column, read at both children",
        output: "producing: L{k+1}[j], one variable fewer (halving lists only)",
        template: "out(x) = Σ_y eq(x,y)·x(y,0)·x(y,1)",
        purpose: "one level of a product tree; the child bit is layer k's highest variable",
    },
];

// ---------------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------------

/// `C{k}[j] = gate`: a shared sub-expression of gate list `k`, substituted into
/// every gate naming it. Not a column. `docs/spec/gkr.md` §3.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedEntry {
    pub name: String,
    /// `C{k}[j]`, where `j` is the entry's position in its list.
    pub address: PolyAddress,
    pub gate: GateDef,
}

/// `output = gate`, one relation of the flat list in layered form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducingEntry {
    /// The index of the relation this gate encodes.
    pub relation: u32,
    /// `L{k+1}[j]`, where `j` is the entry's position in its list.
    pub output: PolyAddress,
    pub gate: GateDef,
}

/// `0 = gate` on every row, one relation of the flat list in layered form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcingEntry {
    /// The index of the relation this gate encodes.
    pub relation: u32,
    pub gate: GateDef,
}

/// Gate list `k`: reads layer `k`, writes layer `k + 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerSpec {
    /// A halving list writes one variable fewer and holds only `TreeProduct`s.
    pub halving: bool,
    /// The variable count of layer `k + 1`, derived and stored (Law 2).
    pub num_vars: u32,
    /// The column count of layer `k + 1`, derived and stored (Law 2).
    pub width: u32,
    pub cached: Vec<CachedEntry>,
    pub producing: Vec<ProducingEntry>,
    pub enforcing: Vec<EnforcingEntry>,
}

/// One entry of the flat constraint list, over `M`, `W`, `S`, `V` and
/// `scratch` addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relation {
    pub name: String,
    /// `Some(i)`: the relation defines `scratch[i]`. `None`: it is enforcing.
    pub output: Option<u32>,
    pub gate: GateDef,
}

/// A lookup expression: a tuple of expressions looked up in a channel. The
/// list exists at S13 and must be empty; S15 gives it meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupExpr {
    pub name: String,
    pub channel: u32,
    pub tuple: Vec<GateDef>,
}

/// `scratch[i]`, its name, and the inner-layer address it is: one entry of
/// the scratch bijection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScratchSlot {
    pub name: String,
    pub address: PolyAddress,
}

/// The padding contract. `docs/spec/gkr.md` §4.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Padding {
    /// The committed columns' values on an inactive row, in layout order.
    pub row: Vec<Fr>,
    /// Whether the all-zero committed row satisfies every row-local relation.
    pub zero_row_valid: bool,
}

/// A whole circuit, as data. Fields are in wire order.
///
/// Every field is public, so a checker can be handed an artifact that breaks a
/// law. [`CircuitArtifact::validate`] is the construction-time check; every
/// engine entry point asserts it, and whatever builds an artifact calls it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitArtifact {
    /// [`FORMAT_VERSION`].
    pub format_version: u32,
    /// [`COEFFICIENT_ENCODING_CANONICAL_LE`].
    pub coefficient_encoding: u32,
    /// Layer 0's variable count: the trace length is `2^trace_vars`.
    pub trace_vars: u32,
    /// The committed layout: one name per column, per subtree.
    pub memory: Vec<String>,
    pub witness: Vec<String>,
    pub setup: Vec<String>,
    /// The virtual tables the circuit reads, with their names.
    pub virtuals: Vec<(VirtualKind, String)>,
    /// Gate list `k`, for `k = 0..N`.
    pub layers: Vec<LayerSpec>,
    /// The flat constraint list.
    pub relations: Vec<Relation>,
    /// Empty at S13.
    pub lookups: Vec<LookupExpr>,
    /// The scratch bijection: `scratch[i]` is `scratch[i].address`.
    pub scratch: Vec<ScratchSlot>,
    /// The output map: a permutation of the top layer, in `OutputClaims` order.
    pub outputs: Vec<PolyAddress>,
    pub padding: Padding,
}

impl CircuitArtifact {
    /// The number of layers above the base, `N`.
    pub fn depth(&self) -> usize {
        self.layers.len()
    }

    /// `n_k`: layer 0's is `trace_vars`, layer `k >= 1`'s is gate list
    /// `k - 1`'s stored `num_vars`.
    pub fn layer_vars(&self, layer: usize) -> u32 {
        if layer == 0 {
            self.trace_vars
        } else {
            self.layers[layer - 1].num_vars
        }
    }

    /// `w_k`: layer 0's is the committed column count, layer `k >= 1`'s is
    /// gate list `k - 1`'s stored `width`.
    pub fn layer_width(&self, layer: usize) -> u32 {
        if layer == 0 {
            self.committed().len() as u32
        } else {
            self.layers[layer - 1].width
        }
    }

    /// The committed columns in layout order: `M`, then `W`, then `S`.
    pub fn committed(&self) -> Vec<PolyAddress> {
        let m = (0..self.memory.len() as u32).map(PolyAddress::Memory);
        let w = (0..self.witness.len() as u32).map(PolyAddress::Witness);
        let s = (0..self.setup.len() as u32).map(PolyAddress::Setup);
        m.chain(w).chain(s).collect()
    }

    /// Every law and construction rule of `docs/spec/gkr.md` §4.2, and the
    /// degree ceiling of §3.1.
    pub fn validate(&self) -> Result<(), ConstraintError> {
        laws::validate(self)
    }

    /// The cache-free compilation: every cached reference inlined, every
    /// cached list emptied. `docs/spec/gkr.md` §3.1.
    pub fn inline_cached(&self) -> Result<CircuitArtifact, ConstraintError> {
        laws::inline_cached(self)
    }

    /// The artifact's `postcard` wire form, `docs/spec/gkr.md` §4.1.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire::to_bytes(self)
    }

    /// Exactly the bytes [`CircuitArtifact::to_bytes`] writes, and nothing
    /// else: the decoded artifact must re-encode to the same bytes. Checks no
    /// law — [`CircuitArtifact::validate`] does.
    pub fn from_bytes(bytes: &[u8]) -> Result<CircuitArtifact, String> {
        wire::from_bytes(bytes)
    }
}
