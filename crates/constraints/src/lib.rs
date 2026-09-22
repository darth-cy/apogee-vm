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

pub mod add_sub;
pub mod atomics;
mod build;
pub mod ecrecover;
pub mod gadgets;
pub mod jump_branch_slt;
pub mod keccak;
mod laws;
pub mod lookup;
pub mod mem_subword;
pub mod mem_word;
pub mod memory;
pub mod mul_div;
pub mod nonnative;
pub mod shift_bitwise;
mod wire;

pub use laws::ConstraintError;

/// The artifact format this crate reads and writes. The first word of every
/// artifact. 1 since S14, whose lookup element carries a selector; a reader
/// refuses every other version before it decodes anything after it.
pub const FORMAT_VERSION: u32 = 1;

/// The one coefficient encoding: every `Fr` is its canonical 32-byte
/// little-endian integer. The second word of every artifact, which is how the
/// file declares it.
pub const COEFFICIENT_ENCODING_CANONICAL_LE: u32 = 0;

/// The largest `trace_vars` an artifact may declare: a trace of `2^30` rows.
/// Far above the height menu's `2^22`, and low enough that `1 << trace_vars`
/// fits a 32-bit `usize`, which the recursion guest has.
pub const MAX_TRACE_VARS: u32 = 30;

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// A family's circuit as a verifying key conveys it: the artifact **and** the
/// channel specs that say which output pair is whose root, which columns are a
/// table and which column counts it — none of which an artifact records
/// (`docs/spec/lookup.md` §13). `docs/spec/shard-proof.md` §7.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyCircuit {
    pub family: u32,
    pub artifact: CircuitArtifact,
    pub channels: Vec<lookup::ChannelSpec>,
}

impl FamilyCircuit {
    /// Whether the circuit reads the generic channel, and so names the packed
    /// generic table as its last `constants::generic_table::WIDTH` setup
    /// columns, which a shard opens against the verifying key's generic-table
    /// commitments (`docs/spec/jump-branch-slt.md` §6).
    pub fn reads_generic_table(&self) -> bool {
        self.channels
            .iter()
            .any(|spec| spec.channel == constants::lookup_channel::GENERIC)
    }
}

/// The circuit that proves `family` over `2^trace_vars` rows, or `None` for a
/// family no stage has built yet, or a height it cannot be built at.
///
/// **The one registry of circuits**, `docs/spec/shard-proof.md` §11: a
/// verifying key's circuits must be byte for byte what this returns, and a
/// later family is added here, with one constructor, and nowhere in the
/// verifier. Every execution family needs 19 variables for its timestamp
/// channel (`docs/spec/lookup.md` §3) — which also holds the packed generic
/// table's rows, which five of the seven read; the two RAM window families and
/// every delegation family take any height up to `MAX_TRACE_VARS`. **The
/// minimum-height arm names every execution family**: one missing from it
/// would reach `lookup::channel_trees`' assertion and panic inside
/// `VerifyingKey::check`, on bytes a verifier was handed, instead of returning
/// `None`. A family with no channel reaches no such assertion, which is why a
/// delegation family is not in the arm and must carry no channel.
pub fn family_circuit(family: u32, trace_vars: u32) -> Option<FamilyCircuit> {
    use constants::family as f;
    if trace_vars > MAX_TRACE_VARS {
        return None;
    }
    let timestamp = constants::lookup_channel::BITS[constants::lookup_channel::TIMESTAMP as usize];
    let (artifact, channels) = match family {
        f::ADD_SUB_LUI_AUIPC
        | f::JUMP_BRANCH_SLT
        | f::SHIFT_BITWISE
        | f::MUL_DIV
        | f::MEM_WORD
        | f::MEM_SUBWORD
        | f::ATOMICS
            if trace_vars < timestamp =>
        {
            return None
        }
        f::ADD_SUB_LUI_AUIPC => (add_sub::artifact(trace_vars), add_sub::channels()),
        f::JUMP_BRANCH_SLT => (
            jump_branch_slt::artifact(trace_vars),
            jump_branch_slt::channels(),
        ),
        f::SHIFT_BITWISE => (
            shift_bitwise::artifact(trace_vars),
            shift_bitwise::channels(),
        ),
        f::MUL_DIV => (mul_div::artifact(trace_vars), mul_div::channels()),
        f::MEM_WORD => (mem_word::artifact(trace_vars), mem_word::channels()),
        f::MEM_SUBWORD => (mem_subword::artifact(trace_vars), mem_subword::channels()),
        f::ATOMICS => (atomics::artifact(trace_vars), atomics::channels()),
        f::INIT_TEARDOWN => (memory::image_window_artifact(trace_vars), Vec::new()),
        f::ZERO_WINDOWS => (memory::zero_window_artifact(trace_vars), Vec::new()),
        // A delegation family carries no channel at all, so no minimum height
        // applies to it — and none could: at a channel's height its
        // permutation does not fit (`docs/spec/delegation.md` §9).
        f::KECCAK_F => (keccak::artifact(trace_vars), keccak::channels()),
        _ => return None,
    };
    Some(FamilyCircuit {
        family,
        artifact,
        channels,
    })
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// A virtual setup table's closed form. `docs/spec/gkr.md` §2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VirtualKind {
    /// `V[row]`: the row index. Its value at row `y` is `y`, and its
    /// multilinear extension is `Σ_j 2^j · y_j`.
    RowIndex,
    /// `V[ram_live]`: 1 at row `y >= 2^RAM_LIVE_BIT`, 0 below
    /// (`constants::memory::RAM_LIVE_BIT`). Its multilinear extension over `n`
    /// variables is `1 − Π_{j = RAM_LIVE_BIT}^{n−1} (1 − y_j)`, which is 0 when
    /// `n <= RAM_LIVE_BIT`. `docs/spec/memory.md` §3.3.
    RamLive,
    /// `V[range19]`: the 19-bit range channel's table, the low 19 bits of the
    /// row index. Its multilinear extension over `n` variables is
    /// `Σ_{j < min(19, n)} 2^j·y_j`, so at `n >= 19` the table holds every
    /// value of `[0, 2^19)` and nothing else. `docs/spec/lookup.md` §3.
    Range19,
    /// `V[range16]`: the 16-bit range channel's table, the low 16 bits of the
    /// row index. `docs/spec/lookup.md` §3.
    Range16,
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
            PolyAddress::Virtual(VirtualKind::RamLive) => write!(f, "V[ram_live]"),
            PolyAddress::Virtual(VirtualKind::Range19) => write!(f, "V[range19]"),
            PolyAddress::Virtual(VirtualKind::Range16) => write!(f, "V[range16]"),
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
    /// `p(·,0)·q(·,1) + p(·,1)·q(·,0)`: the numerator of one fraction-pair
    /// addition, in a halving list. With `TreeProduct { q }` writing the
    /// denominator, the pair `(p, q)` at layer `k` becomes
    /// `p/q(·,0) + p/q(·,1)` at layer `k + 1`. `docs/spec/lookup.md` §6.
    TreeCross {
        left: PolyAddress,
        right: PolyAddress,
    },
    /// `c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j`: any degree-2 polynomial written out
    /// term by term, including those no single product of affine forms spells,
    /// such as `a·b + c·d − e·f`.
    Quadratic {
        constant: Coeff,
        linear: Vec<(Coeff, PolyAddress)>,
        products: Vec<(Coeff, PolyAddress, PolyAddress)>,
    },
}

impl GateDef {
    /// The addresses the gate reads, in kernel order. A halving gate's
    /// operands are each read twice by the kernel, as their two children:
    /// `TreeProduct`'s one operand gives `x(·,0), x(·,1)` and `TreeCross`'s
    /// two give `p(·,0), p(·,1), q(·,0), q(·,1)`. `Quadratic`'s
    /// are its linear operands, then each product's two factors in turn:
    /// `x_1..x_t, y_1, z_1, .., y_u, z_u`.
    pub fn operands(&self) -> Vec<PolyAddress> {
        match self {
            GateDef::Linear { terms, .. } => terms.iter().map(|(_, a)| *a).collect(),
            GateDef::Product { left, right, .. } => alloc::vec![*left, *right],
            GateDef::MaskIntoIdentity { input, mask } => alloc::vec![*input, *mask],
            GateDef::AffineProduct { left, right, .. } => {
                left.iter().chain(right.iter()).map(|(_, a)| *a).collect()
            }
            GateDef::TreeProduct { input } => alloc::vec![*input],
            GateDef::TreeCross { left, right } => alloc::vec![*left, *right],
            GateDef::Quadratic {
                linear, products, ..
            } => {
                let mut o: Vec<PolyAddress> = linear.iter().map(|(_, x)| *x).collect();
                for (_, y, z) in products {
                    o.push(*y);
                    o.push(*z);
                }
                o
            }
        }
    }

    /// Every coefficient the gate carries, constants included, in the order
    /// of the gate's fields. `Quadratic`'s is `c_0, a_1..a_t, b_1..b_u`.
    pub fn coefficients(&self) -> Vec<Coeff> {
        match self {
            GateDef::Linear { terms, constant } => {
                let mut c: Vec<Coeff> = terms.iter().map(|(c, _)| *c).collect();
                c.push(*constant);
                c
            }
            GateDef::Product { coeff, .. } => alloc::vec![*coeff],
            GateDef::MaskIntoIdentity { .. }
            | GateDef::TreeProduct { .. }
            | GateDef::TreeCross { .. } => Vec::new(),
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
            GateDef::Quadratic {
                constant,
                linear,
                products,
            } => {
                let mut c = alloc::vec![*constant];
                c.extend(linear.iter().map(|(a, _)| *a));
                c.extend(products.iter().map(|(b, _, _)| *b));
                c
            }
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

/// The gate catalogue: one row per `GateDef` variant, in wire-tag order, each
/// naming its variant in `variant`.
pub const CATALOGUE: [CatalogueEntry; 7] = [
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
    CatalogueEntry {
        variant: "Quadratic",
        defined_in: DEFINED_IN,
        evaluated_in: EVALUATED_IN,
        inputs: "x_1..x_t, y_1 z_1..y_u z_u: addresses list k may read",
        output: ROW_WISE_OUTPUT,
        template: "out(x) = Σ_y eq(x,y)·(c_0 + Σ a_i·x_i(y) + Σ b_j·y_j(y)·z_j(y))",
        purpose: "a degree-2 relation that is no single product of affine forms, such as \
                  a·b + c·d − e·f",
    },
    CatalogueEntry {
        variant: "TreeCross",
        defined_in: DEFINED_IN,
        evaluated_in: EVALUATED_IN,
        inputs: "p, q: L{k} columns, each read at both children",
        output: "producing: L{k+1}[j], one variable fewer (halving lists only)",
        template: "out(x) = Σ_y eq(x,y)·(p(y,0)·q(y,1) + p(y,1)·q(y,0))",
        purpose: "the numerator of one level of a LogUp fraction tree; the denominator \
                  beside it is a TreeProduct of q",
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

/// A lookup expression: on every row where `selector` is nonzero, `tuple` is
/// looked up in `channel`, one of `constants::lookup_channel`. Every channel is
/// a range channel at S14: its tuple is one `Linear` expression with literal
/// coefficients, which holds when its canonical integer is below
/// `2^BITS[channel]`. `docs/spec/memory.md` §7; S15 discharges it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupExpr {
    pub name: String,
    pub channel: u32,
    /// An `M`, `W` or `S` column.
    pub selector: PolyAddress,
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
/// law. [`CircuitArtifact::validate`] is the construction-time check: whatever
/// builds or loads an artifact calls it, once. The engine's entry points assume
/// an artifact has passed it and do not check it again.
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
    /// The range obligations, `docs/spec/memory.md` §7.
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
