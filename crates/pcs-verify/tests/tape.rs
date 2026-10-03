//! `verifier_core::tape`'s Mercury against this crate's: the batch preamble and
//! the twelve scalars over the same instance, natively and replayed over cells.
//!
//! The field side reads a proof's points only as transcript limbs, so random
//! bytes are an instance here — the all-zero point among them, which absorbs
//! the infinity sentinel — and nothing needs a curve. A last challenge from
//! each transcript holds the two to the same sponge state, not only to the same
//! outputs.

use field::Fr;
use pcs_verify::{batch_preamble, scalars};
use test_support::Rng;
use transcript::{g1_limbs, Transcript};
use verifier_core::tape::{self, Cell, CellTranscript, Limbs, Tape};

const SEED: u64 = 13;

fn fr(rng: &mut Rng) -> Fr {
    let mut b = rng.next_le32();
    b[31] &= 0x1f;
    Fr::from_bytes(&b).expect("below 2^253")
}

fn point(rng: &mut Rng) -> [u8; 64] {
    rng.next_bytes(64).try_into().expect("64 bytes")
}

/// A tape and the blob its imports read.
struct Blob {
    t: Tape,
    bytes: Vec<u8>,
}

impl Blob {
    fn fr(&mut self, v: Fr) -> Cell {
        self.bytes.extend_from_slice(&v.to_bytes());
        self.t.input()
    }
    fn point(&mut self, p: &[u8; 64]) -> Limbs {
        g1_limbs(p).map(|l| self.fr(l))
    }
}

#[test]
fn the_tape_is_the_batch_preamble_and_the_scalars() {
    let mut rng = Rng::new(0x5245_4331);
    for (k, n) in [(1, 2), (3, 4), (5, 8)] {
        let seed = fr(&mut rng);
        let mut cms: Vec<[u8; 64]> = (0..k).map(|_| point(&mut rng)).collect();
        cms[k - 1] = [0; 64];
        let u: Vec<Fr> = (0..n).map(|_| fr(&mut rng)).collect();
        let vs: Vec<Fr> = (0..k).map(|_| fr(&mut rng)).collect();
        let cm_star = point(&mut rng);
        let points: [[u8; 64]; 8] = core::array::from_fn(|_| point(&mut rng));
        let evals: [Fr; 6] = core::array::from_fn(|_| fr(&mut rng));

        let mut native = Transcript::new();
        native.append_scalars(SEED, &[seed]);
        let (weights, v_star) = batch_preamble(&cms, &u, &vs, &mut native);
        let want =
            scalars(&cm_star, &u, v_star, &points, &evals, &mut native).expect("not degenerate");
        let last = native.challenge_scalar(SEED);

        let mut b = Blob {
            t: Tape::new(3),
            bytes: Vec::new(),
        };
        let mut tr = CellTranscript::new();
        let s = b.fr(seed);
        tr.append(&mut b.t, SEED, &[s]);
        let cm_cells: Vec<Limbs> = cms.iter().map(|p| b.point(p)).collect();
        let u_cells: Vec<Cell> = u.iter().map(|x| b.fr(*x)).collect();
        let v_cells: Vec<Cell> = vs.iter().map(|x| b.fr(*x)).collect();
        let (w_cells, v_star_cell) =
            tape::batch_preamble(&mut b.t, &mut tr, &cm_cells, &u_cells, &v_cells);
        let star = b.point(&cm_star);
        let point_cells: [Limbs; 8] = core::array::from_fn(|i| b.point(&points[i]));
        let eval_cells: [Cell; 6] = core::array::from_fn(|i| b.fr(evals[i]));
        let got = tape::mercury_scalars(
            &mut b.t,
            &mut tr,
            star,
            &u_cells,
            v_star_cell,
            &point_cells,
            &eval_cells,
        );
        let last_cell = tr.challenge(&mut b.t, SEED);

        let mut memory = Vec::new();
        tape::run(&b.t.ops, &mut memory, &b.bytes).expect("no assertion fails on a sound instance");
        let read = |c: Cell| memory.get(c as usize).copied().unwrap_or(Fr::ZERO);
        let w: Vec<Fr> = w_cells.iter().map(|c| read(*c)).collect();
        assert_eq!(w, weights, "k {k}");
        assert_eq!(read(v_star_cell), v_star, "k {k}");
        assert_eq!(got.map(read), want, "k {k}, n {n}");
        assert_eq!(read(last_cell), last, "the sponge states differ");
    }
}
