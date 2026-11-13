//! An opening proof's messages, in transcript order. `docs/spec/pcs.md` §7.
//! Every length is fixed by the schedule, which the verifier checks before it
//! reads a message; the wire forms are `verifier_core::wire`'s.

use alloc::vec::Vec;

use field::{Fp, Fp2};

/// A commitment: per outer slice, its payload — the second compression map's
/// image, [`crate::params::D_F2`] field elements (paper (46)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment(pub Vec<Vec<Fp>>);

/// One sumcheck round: the round polynomial at `0, 2, 3, …, degree`; the
/// verifier recovers its value at 1 from the running claim.
pub type Round = Vec<Fp2>;

/// The tensor reduction of an evaluation-trace level (paper §3.7, §5.2): the
/// column partials `S₀, S₁`, then the degree-2 sumcheck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tensor {
    pub partials: [Fp2; 2],
    pub rounds: Vec<Round>,
}

/// One stage of the digit range tree (paper §6.1): its rounds, then the claims
/// it leaves — the next level's node values, or at the leaves `s̃(r_virt)`
/// and, on the Euclidean route, `z̃_int(r_virt)` (paper (91)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage {
    pub rounds: Vec<Round>,
    pub claims: Vec<Fp2>,
}

/// One fold (paper Fig. 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fold {
    /// Evaluation-trace levels only.
    pub tensor: Option<Tensor>,
    /// The opening payload: compressed, or the raw image `D·ê`.
    pub opening: Vec<Fp>,
    pub nonce: u32,
    /// The successor's payloads, one per slice; at the final fold, the
    /// terminal's inner images but the last (paper §8.2).
    pub successor: Vec<Vec<Fp>>,
    /// At the final fold, the digest of the last inner image.
    pub digest: Option<[Fp; 8]>,
    /// The squared response norm, on the Euclidean route (paper (83)).
    pub norm: Option<Fp>,
    pub range: Vec<Stage>,
    pub fused: Vec<Round>,
    /// `w̃(r₂)`, the claim passed on.
    pub value: Fp2,
}

/// The terminal (paper §8.2): every partial but the last in the clear, the
/// last's digest, and the Rice-coded response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terminal {
    pub tensor: Tensor,
    pub partials: Vec<Vec<Fp>>,
    pub digest: [Fp; 8],
    pub nonce: u32,
    pub response: Vec<u8>,
}

/// An opening proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub folds: Vec<Fold>,
    pub terminal: Terminal,
}

/// The empty opening: no fold and a zero terminal, which every schedule
/// refuses. What a proof refused before its opening may carry.
impl Default for Proof {
    fn default() -> Proof {
        Proof {
            folds: Vec::new(),
            terminal: Terminal {
                tensor: Tensor {
                    partials: [Fp2::ZERO; 2],
                    rounds: Vec::new(),
                },
                partials: Vec::new(),
                digest: [Fp::ZERO; 8],
                nonce: 0,
                response: Vec::new(),
            },
        }
    }
}
