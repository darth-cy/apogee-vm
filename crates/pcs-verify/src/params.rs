//! Schedules: every parameter of one opening, from the shape of what is
//! opened. `docs/spec/pcs.md` §5–§6.
//!
//! A schedule is a deterministic, integer-only function of the root shape —
//! the columns' variable count and how many there are — so the prover, the
//! verifier and every commitment formed before the opening derive the same
//! one. It stays inside the paper's analyzed family F1–F3 (Def. 9.2): levels
//! 0 and 1 fold by direct coefficient packing under coefficient-ℓ∞ bounds,
//! every later level and the terminal by evaluation trace under Euclidean
//! bounds, every ring row is checked by quotient lifting, and compression
//! runs from the root and stops at most once.
//!
//! Every Module-SIS rank comes from [`crate::table`] at its certified
//! collision bound; the search over block lengths and digit bases only trades
//! proof bytes against prover work and cannot affect soundness.

use alloc::vec::Vec;

use crate::ring::{digit_top, full_digits};
use crate::sample::Family;
use crate::table::{L2_64, LINF};

/// `[E : F_q]`.
pub const EXT: usize = 2;

/// The ring dimension of every outer (B) and opening (D) map.
pub const D_C: usize = 64;

/// The compression maps (paper §4.5, Table 10): rank one at these dimensions,
/// the first reading the image's binary digits, the second the first's.
pub const D_F1: usize = 32;
pub const D_F2: usize = 16;

/// Bits of a canonical residue, and so binary digits per compressed coefficient.
pub const Q_BITS: usize = 64;

/// The packing family at the root and level 1, and the trace family of every
/// later fold and the terminal (`log2 |C|` = 129.6 and 128.1).
pub const FAMILY_128: Family = Family {
    dim: 128,
    ones: 31,
    twos: 0,
};
pub const FAMILY_64: Family = Family {
    dim: 64,
    ones: 31,
    twos: 10,
};

/// Nonces a response stage may try before the prover gives up.
pub const NONCES: u32 = 1 << 8;

/// The root's source digits: four balanced base-`2^16` digits per value.
pub const ROOT_LOG: u32 = 16;
pub const ROOT_DIGITS: usize = 4;

/// How a level reduces its claim to partial evaluations (paper §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// Direct coefficient packing with subring challenges.
    Pack,
    /// Tensor reduction, then trace-packed partials and full-ring challenges.
    Trace,
}

/// One fold: the commitment shape of its input and everything it sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Level {
    pub method: Method,
    /// The inner (A) ring dimension.
    pub d_a: usize,
    pub family: Family,
    /// Ring elements per block.
    pub m: usize,
    /// Base-field entries of the input vector, and its blocks.
    pub input_len: usize,
    pub blocks: usize,
    /// Source digits: base `2^src_log`, `src_digits` per value; `src_log` 0 is
    /// the identity source of a recursive witness.
    pub src_log: u32,
    pub src_digits: usize,
    pub n_a: usize,
    pub n_b: usize,
    pub n_d: usize,
    /// `b⋆ = 2^log_b`: the successor's digit base and range alphabet.
    pub log_b: u32,
    /// Digits of a full-field coefficient, `⌈64 / log_b⌉`.
    pub open_digits: usize,
    /// Digits of a response coefficient.
    pub fold_digits: usize,
    /// Blocks per outer slice.
    pub slice_blocks: usize,
    /// Whether this level's input payloads and opening payload are compressed.
    pub compress: bool,
    /// The response's squared-norm bound on the Euclidean route.
    pub s_max: Option<u128>,
}

impl Level {
    /// Base-field coordinates of one partial evaluation.
    pub fn d_op(&self) -> usize {
        match self.method {
            Method::Pack => EXT * self.family.dim,
            Method::Trace => self.d_a,
        }
    }

    /// The stride `k·h_car` at which a packing challenge acts on the A ring.
    pub fn stride(&self) -> usize {
        match self.method {
            Method::Pack => self.d_a / self.family.dim,
            Method::Trace => 1,
        }
    }

    /// Base-field entries per block.
    pub fn block_len(&self) -> usize {
        self.d_a * self.m
    }
}

/// The terminal (paper §8.2): evaluation trace, revealed response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terminal {
    pub d_a: usize,
    pub family: Family,
    pub m: usize,
    pub n_a: usize,
    /// The revealed response's squared-norm bound.
    pub s_max: u128,
}

/// Every parameter of one opening of columns of `num_vars` variables, held in
/// groups — separately formed commitments — of `groups[g]` columns each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub num_vars: u32,
    pub groups: Vec<usize>,
    pub levels: Vec<Level>,
    pub terminal: Terminal,
}

// ---------------------------------------------------------------------------
// Ranks
// ---------------------------------------------------------------------------

/// The least rank whose coefficient-ℓ∞ instance at `d` and bound `eta` stays
/// above the floor at `width` columns: the first table row with bound at
/// least `eta`. Panics if the table has none, which is a schedule this
/// table was not generated for.
pub fn linf_rank(d: usize, eta: u64, width: usize) -> usize {
    let (_, _, widths) = LINF
        .iter()
        .find(|(rd, re, _)| *rd == d && *re >= eta)
        .unwrap_or_else(|| panic!("no SIS table row for d = {d}, η ≥ {eta}"));
    rank_of(widths, width)
}

/// The least rank of a Euclidean instance at `d = 64` with squared bound
/// `bound_sq`.
pub fn l2_rank(bound_sq: u128, width: usize) -> usize {
    let key = 128 - (bound_sq - 1).leading_zeros();
    let (_, widths) = L2_64
        .iter()
        .find(|(k, _)| *k >= key)
        .unwrap_or_else(|| panic!("no Euclidean SIS table row for η² = 2^{key}"));
    rank_of(widths, width)
}

fn rank_of(widths: &[u64], width: usize) -> usize {
    1 + widths
        .iter()
        .position(|&w| w >= width as u64)
        .expect("a table row ends at the cap")
}

/// The least digit count whose balanced base-`2^log` interval holds
/// `±bound`, given `bound²`.
fn digits_covering(log: u32, bound_sq: u128) -> usize {
    (1..)
        .find(|&k| {
            let top = digit_top(log, k);
            top.checked_mul(top).is_none_or(|t| t >= bound_sq)
        })
        .expect("some digit count covers every bound")
}

/// The squared Hoeffding bound on one response coefficient, at failure
/// `2^-40` per coefficient over `coefs` of them: a coefficient is a sum of
/// `blocks·Σc²`-weighted terms of magnitude at most `src` under independent
/// uniform signs, so `t² = 2V·ln(2·coefs·2^40)`, with `ln 2` rounded up to
/// `7/10`.
fn hoeffding_sq(blocks: usize, family: Family, src: u128, coefs: usize) -> u128 {
    let var = blocks as u128 * family.l2_sq() as u128 * src * src;
    let log = 41 + usize::BITS - coefs.leading_zeros();
    (2 * var * log as u128 * 7).div_ceil(10)
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

impl Schedule {
    /// The schedule for groups of `groups[g]` columns of `2^num_vars` entries.
    pub fn new(num_vars: u32, groups: &[usize]) -> Schedule {
        assert!(
            num_vars >= 12,
            "Akita opens columns of at least 2^12 entries"
        );
        assert!(
            groups.iter().all(|&g| g > 0),
            "a group commits at least one column"
        );
        let columns: usize = groups.iter().sum();
        let mut len = columns << num_vars;
        // Level 0: the root, packing over full-field sources, blocks within a
        // column, each group sliced on its own.
        let root_len = |l: &Level| {
            let per_column = (1usize << num_vars) / l.block_len();
            let blocks: Vec<usize> = groups.iter().map(|g| g * per_column).collect();
            crate::relation::Layout::new(l, &blocks).len
        };
        let root = best(len, root_len, |m| {
            (m * 2048 <= 1 << num_vars).then(|| {
                level(
                    len,
                    Method::Pack,
                    2048,
                    FAMILY_128,
                    m,
                    ROOT_LOG,
                    ROOT_DIGITS,
                    1 << 15,
                    3,
                    true,
                )
            })
        });
        let mut levels = Vec::new();
        let mut src = 1u128 << (root.log_b - 1);
        len = root_len(&root);
        levels.push(root);
        loop {
            // Level 1 packs; every later level traces, over packed sources of
            // twice the digit bound. Another fold is taken while it costs
            // less than the terminal bytes it saves.
            let packed = 2 * src;
            let here = terminal(len, packed);
            let compress = levels.last().is_some_and(|l| l.compress) && len > 1 << 19;
            let next = if levels.len() == 1 {
                best(len, successor_len, |m| {
                    [3, 4]
                        .into_iter()
                        .map(|lb| {
                            level(
                                len,
                                Method::Pack,
                                256,
                                FAMILY_128,
                                m,
                                0,
                                1,
                                src,
                                lb,
                                compress,
                            )
                        })
                        .min_by_key(successor_len)
                })
            } else {
                best(len, successor_len, |m| {
                    [4, 5, 6]
                        .into_iter()
                        .map(|lb| {
                            level(
                                len,
                                Method::Trace,
                                64,
                                FAMILY_64,
                                m,
                                0,
                                1,
                                packed,
                                lb,
                                compress,
                            )
                        })
                        .min_by_key(successor_len)
                })
            };
            let next_len = successor_len(&next);
            let next_src = 1u128 << next.log_b;
            let later = terminal(next_len, next_src);
            if level_bytes(&next) + terminal_bytes(&later, next_len, next_src)
                >= terminal_bytes(&here, len, packed)
            {
                return Schedule {
                    num_vars,
                    groups: groups.to_vec(),
                    levels,
                    terminal: here,
                };
            }
            src = 1u128 << (next.log_b - 1);
            len = next_len;
            levels.push(next);
        }
    }

    /// The number of folds before the terminal.
    pub fn folds(&self) -> usize {
        self.levels.len()
    }

    /// The shape of a commitment to `columns` columns under this schedule's
    /// root: its payload count, one per outer slice — none for no column —
    /// and each payload's length.
    pub fn commitment_shape(&self, columns: usize) -> (usize, usize) {
        let root = &self.levels[0];
        let blocks = columns * ((1usize << self.num_vars) / root.block_len());
        let len = if root.compress { D_F2 } else { root.n_b * D_C };
        (blocks.div_ceil(root.slice_blocks), len)
    }

    /// Whether `c` has [`Schedule::commitment_shape`]`(columns)`.
    pub fn fits(&self, c: &crate::Commitment, columns: usize) -> bool {
        let (n, len) = self.commitment_shape(columns);
        c.0.len() == n && c.0.iter().all(|p| p.len() == len)
    }
}

/// The candidate with the shortest successor over block lengths `2^0 … 2^14`.
fn best(
    len: usize,
    succ: impl Fn(&Level) -> usize,
    candidate: impl Fn(usize) -> Option<Level>,
) -> Level {
    (0..15)
        .filter(|j| len.div_ceil(1 << j) >= 2)
        .filter_map(|j| candidate(1 << j))
        .filter(|l| l.blocks >= 2)
        .min_by_key(|l| succ(l))
        .expect("some block length fits")
}

/// One level over `len` source entries of magnitude at most `src`.
#[allow(clippy::too_many_arguments)]
fn level(
    len: usize,
    method: Method,
    d_a: usize,
    family: Family,
    m: usize,
    src_log: u32,
    src_digits: usize,
    src: u128,
    log_b: u32,
    compress: bool,
) -> Level {
    let blocks = len.div_ceil(d_a * m);
    let coefs = m * src_digits * d_a;
    let fold_digits = digits_covering(log_b, hoeffding_sq(blocks, family, src, coefs));
    let open_digits = full_digits(log_b);
    let (n_a, s_max) = match method {
        Method::Pack => {
            let eta = 4 * family.l1() * ((1u64 << (log_b as usize * fold_digits)) - 1);
            (linf_rank(d_a, eta, m * src_digits), None)
        }
        Method::Trace => {
            let s_max = euclid_cap(family, len, src);
            (l2_rank(collision_sq(family, s_max), m), Some(s_max))
        }
    };
    let slice_blocks = blocks.min(32);
    let b_width = slice_blocks * n_a * open_digits * d_a / D_C;
    let d_op = match method {
        Method::Pack => EXT * family.dim,
        Method::Trace => d_a,
    };
    let eta_bd = (1u64 << log_b) - 1;
    Level {
        method,
        d_a,
        family,
        m,
        input_len: len,
        blocks,
        src_log,
        src_digits,
        n_a,
        n_b: linf_rank(D_C, eta_bd, b_width),
        n_d: linf_rank(D_C, eta_bd, blocks * d_op * open_digits / D_C),
        log_b,
        open_digits,
        fold_digits,
        slice_blocks,
        compress,
        s_max,
    }
}

/// `S_max = ⌈1.1·Σc²·len·src²⌉`: the honest response's squared norm has mean
/// `Σc²·‖s‖² ≤ Σc²·len·src²` over the challenge signs and concentrates within a
/// fraction of a percent of it, so a tenth of slack never rejects an honest
/// response.
pub fn euclid_cap(family: Family, len: usize, src: u128) -> u128 {
    (11 * family.l2_sq() as u128 * len as u128 * src * src).div_ceil(10)
}

/// `η² = 64·Γ²·S_max` with `Γ = ‖c‖_1`, which bounds every challenge's
/// multiplication operator norm (paper Cor. 10.35 (ii), Lemma 3.1).
pub fn collision_sq(family: Family, s_max: u128) -> u128 {
    64 * (family.l1() as u128).pow(2) * s_max
}

/// The successor witness length of a level whose input is one group: the end
/// of [`crate::relation::Layout`]. A root of several groups has at most one
/// more partial slice per group, which only its true layout counts.
pub fn successor_len(l: &Level) -> usize {
    crate::relation::Layout::new(l, &[l.blocks]).len
}

/// The terminal over `len` entries of packed magnitude at most `src`: the
/// block length that minimizes its bytes.
fn terminal(len: usize, src: u128) -> Terminal {
    (0..13)
        .map(|j| 1usize << j)
        .filter(|m| len.div_ceil(64 * m) >= 2)
        .map(|m| {
            let s_max = euclid_cap(FAMILY_64, len, src);
            Terminal {
                d_a: 64,
                family: FAMILY_64,
                m,
                n_a: l2_rank(collision_sq(FAMILY_64, s_max), m),
                s_max,
            }
        })
        .min_by_key(|t| terminal_bytes(t, len, src))
        .expect("a terminal fits")
}

/// Estimated terminal bytes: every inner image and partial but the last, two
/// digests, and the Rice-coded response at about `log2 σ + 2` bits a
/// coefficient.
fn terminal_bytes(t: &Terminal, len: usize, src: u128) -> usize {
    let blocks = len.div_ceil(t.d_a * t.m);
    let var = blocks as u128 * t.family.l2_sq() as u128 * src * src / 8;
    let bits = (128 - var.leading_zeros()) as usize / 2 + 2;
    (blocks - 1) * (t.n_a + 1) * t.d_a * 8 + 128 + t.m * t.d_a * bits / 8
}

/// Estimated bytes of one fold over `len` entries: its sumcheck rounds and
/// payloads.
fn level_bytes(l: &Level) -> usize {
    let len = l.input_len;
    let succ = successor_len(l);
    let mu = usize::BITS - (succ - 1).leading_zeros();
    let range = match l.log_b {
        3 => 5,
        4 => 8,
        5 => 10,
        _ => 13,
    };
    let tensor = if l.method == Method::Trace {
        2 * (usize::BITS - (len - 1).leading_zeros()) as usize
    } else {
        0
    };
    let payload = if l.compress {
        2 * D_F2
    } else {
        (l.n_b + l.n_d) * D_C
    };
    16 * (mu as usize * (range + 3) + tensor) + 8 * payload
}
