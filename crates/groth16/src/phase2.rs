//! A circuit's own half of its key's setup, as a ceremony.
//!
//! A powers-of-tau transcript gives `τ`: its Lagrange basis `[L_j(τ)]` and its
//! powers. What it cannot give is the circuit's five other trapdoors, and
//! those are made here, by **contributions**: each multiplies a trapdoor by a
//! factor only its contributor knew, so a trapdoor is unknown as long as one
//! contributor to it was honest and forgot the factor.
//!
//! ```text
//! init      α = β = γ = δ = η = 1 over the transcript's τ: a wire's
//!           [A_i(τ)]_1, [B_i(τ)]_1 and [C_i(τ)]_1, and [τ^k·Z(τ)]_1
//! round 1   contributions to α and β: [β·A_i]_1 and [α·B_i]_1, kept apart
//! seal      a wire's three terms summed: [β·A_i + α·B_i + C_i]_1
//! round 2   contributions to γ, δ and η: that sum over the wire's trapdoor,
//!           and [τ^k·Z(τ)/δ]_1
//! finish    the last state, verified, as a key
//! ```
//!
//! **Two rounds, and their order is the soundness.** A proof is sound because
//! a prover holds a wire's three terms only summed, over `δ` or `η`: holding
//! them apart, it could give `A`, `B` and `C` three different witnesses. A
//! contribution to `α` or `β` has to scale the terms apart, so those two are
//! finished, and the terms summed, before anything is divided.
//!
//! A state carries every contribution's record: its factor in G1 with a
//! Schnorr proof of knowing it, bound to the records before it, and the
//! trapdoor in G2 afterwards. [`State::verify`] checks that chain, and then
//! the state's elements against `init`'s under those trapdoors — one pairing
//! equation over a random combination of them all. So a state is checked
//! against its circuit and the transcript alone, whoever handed it over.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use curve::pairing::pairing_check;
use curve::{Fq2, G1Affine, G1Projective, G2Affine};
use field::Fr;
use rayon::prelude::*;

use crate::{
    bind, bound_set, hashed, inverse, msm_g1, shape, Circuit, Group, Lc, ProvingKey, Sink, Var,
    VerifyingKey, PUBLIC,
};

/// The trapdoors a ceremony makes, as a state and a record index them: round
/// 1's two, then round 2's three.
const ALPHA: usize = 0;
const BETA: usize = 1;
const GAMMA: usize = 2;
const DELTA: usize = 3;
const ETA: usize = 4;
const NAMES: [&str; 5] = ["alpha", "beta", "gamma", "delta", "eta"];

/// One contributor's factor of one trapdoor.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Factor {
    trapdoor: usize,
    /// The factor in G1, and a Schnorr proof of knowing it: a nonce in G1 and
    /// the response to the challenge the records before this one give.
    point: G1Affine,
    nonce: G1Affine,
    response: Fr,
    /// The trapdoor in G2 with this factor in it.
    after: G2Affine,
}

/// A ceremony, as far as it has gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    constraints: usize,
    /// The bound wires, each once, ascending.
    bound: Vec<Var>,
    /// 1 while `α` and `β` take contributions, 2 for `γ`, `δ` and `η`.
    round: u8,
    /// `[α]_1`, and the five trapdoors in G2.
    alpha: G1Affine,
    trapdoors: [G2Affine; 5],
    records: Vec<Factor>,
    /// A wire's terms. In round 1 `[β·A_i(τ)]_1`, `[α·B_i(τ)]_1` and
    /// `[C_i(τ)]_1`; in round 2 their sum over the wire's trapdoor, alone.
    terms: [Vec<G1Affine>; 3],
    /// `[τ^k·Z(τ)/δ]_1`.
    h: Vec<G1Affine>,
}

/// The trapdoor a wire's sum is over: `γ` for a public wire, `η` for a bound
/// one, `δ` for the rest.
fn class(bound: &[Var], wire: usize) -> usize {
    match wire {
        w if w < PUBLIC => GAMMA,
        w if bound.binary_search(&(w as Var)).is_ok() => ETA,
        _ => DELTA,
    }
}

/// `k·point` for a coefficient, which far more often than not is small or the
/// negative of something small: only its significant bits are walked.
fn times(point: &G1Affine, k: &Fr) -> G1Projective {
    let bits = |b: &[u8; 32]| {
        let top = b.iter().rposition(|x| *x != 0);
        top.map_or(0, |i| 8 * i + 8 - b[i].leading_zeros() as usize)
    };
    let (plus, minus) = (k.to_bytes(), (-*k).to_bytes());
    let (bytes, negative) = match bits(&minus) < bits(&plus) {
        true => (minus, true),
        false => (plus, false),
    };
    let mut acc = G1Projective::IDENTITY;
    for i in (0..bits(&bytes)).rev() {
        acc = acc.double();
        if bytes[i / 8] >> (i % 8) & 1 == 1 {
            acc = acc.add_affine(point);
        }
    }
    match negative {
        true => -acc,
        false => acc,
    }
}

/// Each wire's `[A_i(τ)]_1`, `[B_i(τ)]_1` and `[C_i(τ)]_1`: a term adds its
/// coefficient times its constraint's basis point. Nobody knows `τ`, so this
/// is a scalar multiplication a term — taken a batch at a time, multiplied
/// and summed a wire in parallel.
struct Commit<'a> {
    lagrange: &'a [G1Affine],
    at: usize,
    /// Terms not yet added: the side and the wire, the constraint, the
    /// coefficient.
    pending: Vec<((usize, Var), u32, Fr)>,
    abc: [Vec<G1Projective>; 3],
}

impl Commit<'_> {
    fn flush(&mut self) {
        let lagrange = self.lagrange;
        let mut products: Vec<((usize, Var), G1Projective)> = self
            .pending
            .par_iter()
            .map(|(to, row, k)| (*to, times(&lagrange[*row as usize], k)))
            .collect();
        products.par_sort_unstable_by_key(|p| p.0);
        let sums: Vec<((usize, Var), G1Projective)> = products
            .par_chunk_by(|a, b| a.0 == b.0)
            .map(|wire| {
                let sum = wire.iter().fold(G1Projective::IDENTITY, |s, p| s.add(&p.1));
                (wire[0].0, sum)
            })
            .collect();
        for ((side, wire), sum) in sums {
            let slot = &mut self.abc[side][wire as usize];
            *slot = slot.add(&sum);
        }
        self.pending.clear();
    }
}

impl Sink for Commit<'_> {
    fn alloc(&mut self, _: Fr) -> Var {
        for side in &mut self.abc {
            side.push(G1Projective::IDENTITY);
        }
        self.abc[0].len() as Var - 1
    }
    fn enforce(&mut self, a: Lc, b: Lc, c: Lc) {
        for (side, lc) in [a, b, c].into_iter().enumerate() {
            let row = self.at as u32;
            self.pending
                .extend(lc.iter().map(|(v, k)| ((side, *v), row, *k)));
        }
        self.at += 1;
        if self.pending.len() >= 1 << 22 {
            self.flush();
        }
    }
}

/// A ceremony's first state for `circuit`, every trapdoor 1, over a
/// transcript's `[L_j(τ)]_1` — at [`crate::domain`]'s size — and its powers
/// `[τ^k]_1`, of which a quotient takes twice the domain less one.
/// Deterministic: anyone with the circuit and the transcript makes the same.
pub fn init(circuit: Circuit, lagrange: &[G1Affine], tau: &[G1Affine]) -> State {
    let (constraints, _, bound) = shape(circuit);
    let n = lagrange.len();
    assert!(
        n == constraints.next_power_of_two().max(2) && tau.len() >= 2 * n - 1,
        "phase2: the transcript, at the circuit's domain"
    );
    let mut sink = Commit {
        lagrange,
        at: 0,
        pending: Vec::new(),
        abc: core::array::from_fn(|_| vec![G1Projective::IDENTITY; PUBLIC]),
    };
    assert_eq!(
        circuit(&mut sink),
        bound,
        "phase2: a circuit is one circuit"
    );
    bind(&mut sink, &bound);
    sink.flush();
    assert_eq!(sink.at, constraints, "phase2: a circuit is one circuit");
    // `τ^k·Z(τ)`, `Z = X^n − 1`.
    let h: Vec<G1Projective> = (0..n - 1)
        .into_par_iter()
        .map(|k| G1Projective::from(tau[k + n]).add_affine(&-tau[k]))
        .collect();
    State {
        constraints,
        bound: bound_set(bound),
        round: 1,
        alpha: G1Affine::GENERATOR,
        trapdoors: [G2Affine::GENERATOR; 5],
        records: Vec::new(),
        terms: sink.abc.map(|side| G1Projective::normalize(&side)),
        h: G1Projective::normalize(&h),
    }
}

/// Each point times the scalar its index takes.
fn scaled(points: &[G1Affine], by: &(dyn Fn(usize) -> Fr + Sync)) -> Vec<G1Affine> {
    let moved: Vec<G1Projective> = points
        .par_iter()
        .enumerate()
        .map(|(i, p)| match p.infinity {
            true => G1Projective::IDENTITY,
            false => G1Projective::from(*p).mul(&by(i)),
        })
        .collect();
    G1Projective::normalize(&moved)
}

impl State {
    /// The round's trapdoors: `α` and `β`, or after [`State::seal`] `γ`, `δ`
    /// and `η`.
    fn round(&self) -> &'static [usize] {
        match self.round {
            1 => &[ALPHA, BETA],
            _ => &[GAMMA, DELTA, ETA],
        }
    }

    /// What record `k`'s challenge binds it to: the circuit's shape and every
    /// record before it.
    fn context(&self, k: usize) -> Vec<u8> {
        let mut bytes = b"apogee groth16 phase 2".to_vec();
        for size in [self.constraints, self.terms[0].len()] {
            bytes.extend((size as u64).to_le_bytes());
        }
        bytes.extend(self.bound.iter().flat_map(|w| w.to_le_bytes()));
        for r in &self.records[..k] {
            bytes.push(r.trapdoor as u8);
            bytes.extend(r.point.to_bytes());
            bytes.extend(r.nonce.to_bytes());
            bytes.extend(r.response.to_bytes());
            bytes.extend(r.after.to_bytes());
        }
        bytes
    }

    /// Record `k`'s Schnorr challenge.
    fn challenge(&self, k: usize, r: &Factor) -> Fr {
        let mut bytes = self.context(k);
        bytes.push(r.trapdoor as u8);
        bytes.extend(r.point.to_bytes());
        bytes.extend(r.nonce.to_bytes());
        bytes.extend(r.after.to_bytes());
        hashed(&bytes)
    }

    /// A contribution to this round's trapdoors, each multiplied by a factor
    /// derived from `entropy` — the contributor's secret: fresh, unguessable,
    /// and forgotten once this returns. The factors depend on the records so
    /// far too, so one entropy never gives the same factor twice.
    pub fn contribute(&mut self, entropy: &[u8]) {
        let context = self.context(self.records.len());
        let secret =
            |label: &[u8], t: usize| hashed(&[entropy, &context[..], label, &[t as u8]].concat());
        self.apply(&|t| (secret(b"factor", t), secret(b"nonce", t)));
    }

    /// A contribution under the factor and the nonce `secrets` gives a
    /// trapdoor.
    fn apply(&mut self, secrets: &dyn Fn(usize) -> (Fr, Fr)) {
        let mut factors = [Fr::ONE; 5];
        for t in self.round() {
            let (factor, nonce) = secrets(*t);
            let g = G1Projective::GENERATOR;
            self.trapdoors[*t] = self.trapdoors[*t].mul(&factor);
            let mut record = Factor {
                trapdoor: *t,
                point: g.mul(&factor).to_affine(),
                nonce: g.mul(&nonce).to_affine(),
                response: Fr::ZERO,
                after: self.trapdoors[*t],
            };
            record.response = nonce + self.challenge(self.records.len(), &record) * factor;
            self.records.push(record);
            factors[*t] = factor;
        }
        if self.round == 1 {
            self.alpha = G1Projective::from(self.alpha)
                .mul(&factors[ALPHA])
                .to_affine();
            self.terms[0] = scaled(&self.terms[0], &|_| factors[BETA]);
            self.terms[1] = scaled(&self.terms[1], &|_| factors[ALPHA]);
        } else {
            let over = factors.map(inverse);
            let bound = &self.bound;
            self.terms[0] = scaled(&self.terms[0], &|i| over[class(bound, i)]);
            self.h = scaled(&self.h, &|_| over[DELTA]);
        }
    }

    /// Whether every one of `trapdoors` has a contribution on record.
    fn contributed(&self, trapdoors: &[usize]) -> bool {
        let has = |t: &usize| self.records.iter().any(|r| r.trapdoor == *t);
        trapdoors.iter().all(has)
    }

    /// `α` and `β` are finished: each wire's three terms become their sum,
    /// and the round is `γ`, `δ` and `η`'s.
    pub fn seal(&mut self) -> Result<(), String> {
        if self.round != 1 || !self.contributed(&[ALPHA, BETA]) {
            return Err("only a state with contributions to alpha and beta is sealed".into());
        }
        let [p, q, r] = &self.terms;
        let sums: Vec<G1Projective> = (0..p.len())
            .into_par_iter()
            .map(|i| G1Projective::from(p[i]).add_affine(&q[i]).add_affine(&r[i]))
            .collect();
        self.terms = [G1Projective::normalize(&sums), Vec::new(), Vec::new()];
        self.round = 2;
        Ok(())
    }

    /// Whether this state is `init`'s — the same circuit over the same
    /// transcript — under trapdoors that are the product of the contributions
    /// on record, each by someone who knew its factor. `coin` must be
    /// unpredictable to whoever made the state: its powers weigh the elements
    /// in the one combination that is checked.
    pub fn verify(&self, init: &State, coin: Fr) -> Result<(), String> {
        let wires = init.terms[0].len();
        let lens = [0, 1, 2].map(|k| self.terms[k].len());
        let apart = self.round == 1;
        if (self.constraints, &self.bound, self.h.len())
            != (init.constraints, &init.bound, init.h.len())
            || lens != [wires, wires * apart as usize, wires * apart as usize]
        {
            return Err("the state is not this circuit's".into());
        }

        // The records: each a known factor, and the trapdoors their product.
        let (g1, g2) = (G1Affine::GENERATOR, G2Affine::GENERATOR);
        let same =
            |a: G1Affine, b: G2Affine, c: G1Affine, d: G2Affine| pairing_check(&[(a, b), (-c, d)]);
        let mut now = [g2; 5];
        for (k, r) in self.records.iter().enumerate() {
            let t = r.trapdoor;
            // Round 1's are all before round 2's.
            let ordered = t <= ETA
                && !(t < GAMMA && self.records[..k].iter().any(|e| e.trapdoor >= GAMMA))
                && !(t >= GAMMA && apart);
            let known = || {
                let claim = G1Projective::from(r.point).mul(&self.challenge(k, r));
                G1Projective::GENERATOR.mul(&r.response) == claim.add_affine(&r.nonce)
            };
            if !ordered || r.point.infinity || !known() || !same(r.point, now[t], g1, r.after) {
                let name = NAMES.get(t).unwrap_or(&"nothing");
                return Err(format!("record {k}, to {name}, is not a contribution"));
            }
            now[t] = r.after;
        }
        if now != self.trapdoors || !same(self.alpha, g2, g1, now[ALPHA]) {
            return Err("the trapdoors are not the contributions'".into());
        }

        // The elements, each list in one combination under the coin's powers.
        let mut weights = Vec::with_capacity(wires.max(self.h.len()));
        let mut power = coin;
        for _ in 0..wires.max(self.h.len()) {
            weights.push(power);
            power *= coin;
        }
        let fold = |points: &[G1Affine], of: &[usize]| -> G1Affine {
            let (bases, scalars): (Vec<G1Affine>, Vec<Fr>) =
                of.iter().map(|i| (points[*i], weights[*i])).unzip();
            msm_g1(&bases, &scalars).to_affine()
        };
        let all: Vec<usize> = (0..wires).collect();
        let t = &self.trapdoors;
        let held = if apart {
            same(
                fold(&self.terms[0], &all),
                g2,
                fold(&init.terms[0], &all),
                t[BETA],
            ) && same(
                fold(&self.terms[1], &all),
                g2,
                fold(&init.terms[1], &all),
                t[ALPHA],
            ) && self.terms[2] == init.terms[2]
                && self.h == init.h
        } else {
            let quotient: Vec<usize> = (0..self.h.len()).collect();
            let summed = |x: usize| {
                let of: Vec<usize> = all
                    .iter()
                    .copied()
                    .filter(|i| class(&self.bound, *i) == x)
                    .collect();
                pairing_check(&[
                    (fold(&self.terms[0], &of), t[x]),
                    (-fold(&init.terms[0], &of), t[BETA]),
                    (-fold(&init.terms[1], &of), t[ALPHA]),
                    (-fold(&init.terms[2], &of), g2),
                ])
            };
            [GAMMA, DELTA, ETA].into_iter().all(summed)
                && same(
                    fold(&self.h, &quotient),
                    t[DELTA],
                    fold(&init.h, &quotient),
                    g2,
                )
        };
        match held {
            true => Ok(()),
            false => Err("the state's elements are not the circuit's under its trapdoors".into()),
        }
    }

    /// The key the ceremony made, over the transcript's Lagrange basis in
    /// both groups: of a state that [verifies](State::verify), is past both
    /// rounds and has a contribution to every trapdoor, and of no other.
    fn key(
        self,
        init: &State,
        coin: Fr,
        lagrange: (Vec<G1Affine>, Vec<G2Affine>),
    ) -> Result<ProvingKey, String> {
        self.verify(init, coin)?;
        if self.round != 2 || !self.contributed(&[ALPHA, BETA, GAMMA, DELTA, ETA]) {
            return Err("the ceremony is not complete: every trapdoor takes a contribution".into());
        }
        if [lagrange.0.len(), lagrange.1.len()] != [self.h.len() + 1; 2] {
            return Err("the Lagrange basis is not the circuit's domain's".into());
        }
        let [l, ..] = self.terms;
        let [_, beta, gamma, delta, eta] = self.trapdoors;
        Ok(ProvingKey {
            vk: VerifyingKey {
                alpha: self.alpha,
                beta,
                gamma,
                delta,
                eta,
                ic: [l[0], l[1], l[2]],
            },
            constraints: self.constraints,
            lagrange,
            l,
            h: self.h,
            bound: self.bound,
        })
    }

    /// The ceremony's output: [`State::key`]'s key, written to `path`. It is
    /// the one way a key file comes to exist, so a key [`ProvingKey::read`]
    /// reads is a completed, verified ceremony's.
    pub fn finish(
        self,
        init: &State,
        coin: Fr,
        lagrange: (Vec<G1Affine>, Vec<G2Affine>),
        path: &Path,
    ) -> Result<ProvingKey, String> {
        let key = self.key(init, coin, lagrange)?;
        let mut out = BufWriter::new(File::create(path).map_err(|e| e.to_string())?);
        let written = (|| {
            out.write_all(KEY)?;
            out.write_all(&(key.constraints as u64).to_le_bytes())?;
            put_u32s(&mut out, &key.bound)?;
            let vk = &key.vk;
            put_g1(&mut out, &[&[vk.alpha][..], &vk.ic[..]].concat())?;
            put_g2(&mut out, &[vk.beta, vk.gamma, vk.delta, vk.eta])?;
            put_g1(&mut out, &key.lagrange.0)?;
            put_g2(&mut out, &key.lagrange.1)?;
            put_g1(&mut out, &key.l)?;
            put_g1(&mut out, &key.h)?;
            out.flush()
        })();
        written.map_err(|e| e.to_string()).map(|()| key)
    }

    pub fn write(&self, path: &Path) -> Result<(), String> {
        let mut out = BufWriter::new(File::create(path).map_err(|e| e.to_string())?);
        let written = (|| {
            out.write_all(STATE)?;
            out.write_all(&(self.constraints as u64).to_le_bytes())?;
            put_u32s(&mut out, &self.bound)?;
            put_u32s(&mut out, &[self.round as u32])?;
            put_g1(&mut out, &[self.alpha])?;
            put_g2(&mut out, &self.trapdoors)?;
            let r = &self.records;
            let column = |of: &dyn Fn(&Factor) -> G1Affine| r.iter().map(of).collect::<Vec<_>>();
            put_u32s(
                &mut out,
                &r.iter().map(|f| f.trapdoor as u32).collect::<Vec<_>>(),
            )?;
            put_g1(&mut out, &column(&|f| f.point))?;
            put_g1(&mut out, &column(&|f| f.nonce))?;
            let responses: Vec<Fr> = r.iter().map(|f| f.response).collect();
            write_vec(&mut out, &responses, 32, |x, b| {
                b.copy_from_slice(&x.to_bytes())
            })?;
            put_g2(&mut out, &r.iter().map(|f| f.after).collect::<Vec<_>>())?;
            for list in self.terms.iter().chain([&self.h]) {
                put_g1(&mut out, list)?;
            }
            out.flush()
        })();
        written.map_err(|e| e.to_string())
    }

    /// A state as [`State::write`] wrote it. Its G2 points are held to the
    /// subgroup, being a stranger's; what they are worth is
    /// [`State::verify`]'s to say.
    pub fn read(path: &Path) -> Result<State, String> {
        let mut input = open(path, STATE)?;
        let constraints = get_u64(&mut input)? as usize;
        let bound = get_u32s(&mut input)?;
        let round = get_u32s(&mut input)?;
        let alpha = get_g1(&mut input)?;
        let trapdoors: Result<[G2Affine; 5], _> = get_g2(&mut input, true)?.try_into();
        let t = get_u32s(&mut input)?;
        let (points, nonces) = (get_g1(&mut input)?, get_g1(&mut input)?);
        let responses = read_vec(&mut input, 32, |b| Fr::from_bytes(b.try_into().ok()?))?;
        let afters = get_g2(&mut input, true)?;
        let records = (0..t.len())
            .map(|k| {
                Some(Factor {
                    trapdoor: t[k] as usize,
                    point: *points.get(k)?,
                    nonce: *nonces.get(k)?,
                    response: *responses.get(k)?,
                    after: *afters.get(k)?,
                })
            })
            .collect::<Option<Vec<Factor>>>();
        let terms = [
            get_g1(&mut input)?,
            get_g1(&mut input)?,
            get_g1(&mut input)?,
        ];
        let h = get_g1(&mut input)?;
        match (&round[..], &alpha[..], trapdoors, records) {
            ([round @ 1..=2], [alpha], Ok(trapdoors), Some(records)) => Ok(State {
                constraints,
                bound,
                round: *round as u8,
                alpha: *alpha,
                trapdoors,
                records,
                terms,
                h,
            }),
            _ => Err("the file is not a ceremony's state".into()),
        }
    }

    /// How far the ceremony has gone: its round, and every contribution on
    /// record, by its trapdoor and its factor's point. A contributor keeps
    /// its own lines, and finds them again under the state a key is made of.
    pub fn progress(&self) -> String {
        let lines: String = self
            .records
            .iter()
            .map(|r| {
                let x = &r.point.to_bytes()[..32];
                let hex: String = x.iter().rev().map(|b| format!("{b:02x}")).collect();
                format!("\n  {:<5} {hex}", NAMES[r.trapdoor])
            })
            .collect();
        format!("round {}, the contributions on record:{lines}", self.round)
    }
}

impl ProvingKey {
    /// A key as a completed ceremony [wrote](State::finish) it. The Lagrange
    /// basis in G2 is held to the curve and not to the subgroup: it is the
    /// transcript's, verified when the key was made.
    pub fn read(path: &Path) -> Result<ProvingKey, String> {
        let mut input = open(path, KEY)?;
        let constraints = get_u64(&mut input)? as usize;
        let bound = get_u32s(&mut input)?;
        let g1 = get_g1(&mut input)?;
        let g2 = get_g2(&mut input, true)?;
        let lagrange = (get_g1(&mut input)?, get_g2(&mut input, false)?);
        let (l, h) = (get_g1(&mut input)?, get_g1(&mut input)?);
        match (&g1[..], &g2[..]) {
            ([alpha, ic @ ..], [beta, gamma, delta, eta]) if ic.len() == PUBLIC => Ok(ProvingKey {
                vk: VerifyingKey {
                    alpha: *alpha,
                    beta: *beta,
                    gamma: *gamma,
                    delta: *delta,
                    eta: *eta,
                    ic: [ic[0], ic[1], ic[2]],
                },
                constraints,
                lagrange,
                l,
                h,
                bound,
            }),
            _ => Err("the file is not a key".into()),
        }
    }
}

// ---------------------------------------------------------------------------
// The two files: little-endian, a list its length and then its items, a point
// as `curve` writes it.
// ---------------------------------------------------------------------------

const STATE: &[u8; 16] = b"apogee phase 2\0\0";
const KEY: &[u8; 16] = b"apogee groth16\0\0";

fn open(path: &Path, magic: &[u8; 16]) -> Result<BufReader<File>, String> {
    let mut input =
        BufReader::new(File::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
    let mut found = [0u8; 16];
    input.read_exact(&mut found).map_err(|e| e.to_string())?;
    match &found == magic {
        true => Ok(input),
        false => Err(format!("{} is another kind of file", path.display())),
    }
}

fn get_u64(input: &mut impl Read) -> Result<u64, String> {
    let mut bytes = [0u8; 8];
    input.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_vec<T: Sync>(
    out: &mut impl Write,
    items: &[T],
    width: usize,
    encode: impl Fn(&T, &mut [u8]) + Sync,
) -> std::io::Result<()> {
    out.write_all(&(items.len() as u64).to_le_bytes())?;
    for chunk in items.chunks(1 << 16) {
        let mut bytes = vec![0u8; chunk.len() * width];
        bytes
            .par_chunks_mut(width)
            .zip(chunk)
            .for_each(|(b, item)| encode(item, b));
        out.write_all(&bytes)?;
    }
    Ok(())
}

fn read_vec<T: Send>(
    input: &mut impl Read,
    width: usize,
    decode: impl Fn(&[u8]) -> Option<T> + Sync,
) -> Result<Vec<T>, String> {
    let count = get_u64(input)? as usize;
    let mut items = Vec::new();
    let mut bytes = vec![0u8; (1 << 16) * width];
    while items.len() < count {
        let take = (1 << 16).min(count - items.len()) * width;
        input
            .read_exact(&mut bytes[..take])
            .map_err(|e| e.to_string())?;
        let decoded: Option<Vec<T>> = bytes[..take].par_chunks(width).map(&decode).collect();
        items.extend(decoded.ok_or("a file holds something that does not decode")?);
    }
    Ok(items)
}

fn put_u32s(out: &mut impl Write, items: &[u32]) -> std::io::Result<()> {
    write_vec(out, items, 4, |x, b| b.copy_from_slice(&x.to_le_bytes()))
}

fn get_u32s(input: &mut impl Read) -> Result<Vec<u32>, String> {
    read_vec(input, 4, |b| Some(u32::from_le_bytes(b.try_into().ok()?)))
}

fn put_g1(out: &mut impl Write, points: &[G1Affine]) -> std::io::Result<()> {
    write_vec(out, points, 64, |p, b| b.copy_from_slice(&p.to_bytes()))
}

fn get_g1(input: &mut impl Read) -> Result<Vec<G1Affine>, String> {
    read_vec(input, 64, |b| G1Affine::from_bytes(b.try_into().ok()?))
}

fn put_g2(out: &mut impl Write, points: &[G2Affine]) -> std::io::Result<()> {
    write_vec(out, points, 128, |p, b| b.copy_from_slice(&p.to_bytes()))
}

/// G2 points, held to the subgroup — a scalar multiplication each — or, for a
/// list too long for that, to the curve.
fn get_g2(input: &mut impl Read, subgroup: bool) -> Result<Vec<G2Affine>, String> {
    read_vec(input, 128, |b| {
        if subgroup || b.iter().all(|x| *x == 0) {
            return G2Affine::from_bytes(b.try_into().ok()?);
        }
        let point = G2Affine {
            x: Fq2::from_bytes(b[..64].try_into().ok()?)?,
            y: Fq2::from_bytes(b[64..].try_into().ok()?)?,
            infinity: false,
        };
        point.is_on_curve().then_some(point)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive, domain, prove, root, tests::cubic, verify};

    /// A ceremony over a transcript whose `τ` the test knows: two
    /// contributions to round 1, a seal, one to round 2. The state verifies
    /// at every step and reads back from its file; a moved element, a
    /// trapdoor nobody contributed and a second-hand record are refused; an
    /// unfinished ceremony gives no key; and the key it gives at the end is,
    /// element for element, the one its six trapdoors derive — and proves.
    #[test]
    fn a_ceremony_makes_the_key_its_trapdoors_derive() {
        let f = Fr::from_u64;
        let tau = f(0x0123_4567_89ab_cdef);
        let n = domain(&mut cubic(3));
        let z = (0..n.trailing_zeros()).fold(tau, |x, _| x.square()) - Fr::ONE;
        let over_n = inverse(f(n as u64));
        let omega = root(n);
        let mut basis = Vec::new();
        let mut w = Fr::ONE;
        for _ in 0..n {
            basis.push(w * z * over_n * inverse(tau - w));
            w *= omega;
        }
        let g1 = |x: &Fr| G1Projective::GENERATOR.mul(x).to_affine();
        let lagrange: (Vec<G1Affine>, Vec<G2Affine>) = (
            basis.iter().map(g1).collect(),
            basis.iter().map(|x| G2Affine::GENERATOR.mul(x)).collect(),
        );
        let mut powers = vec![Fr::ONE];
        for k in 1..2 * n - 1 {
            powers.push(powers[k - 1] * tau);
        }
        let powers: Vec<G1Affine> = powers.iter().map(g1).collect();

        let first = init(&mut cubic(3), &lagrange.0, &powers);
        let coin = f(0xc01);
        let mut state = first.clone();
        assert!(state.seal().is_err(), "alpha and beta first");
        let mut trapdoors = [tau, Fr::ONE, Fr::ONE, Fr::ONE, Fr::ONE, Fr::ONE];
        let mut contribute = |state: &mut State, seed: u64| {
            for t in state.round() {
                trapdoors[1 + t] *= f(seed + *t as u64);
            }
            state.apply(&|t| (f(seed + t as u64), f(7 * seed + t as u64)));
            assert_eq!(state.verify(&first, coin), Ok(()));
        };
        contribute(&mut state, 1000);
        contribute(&mut state, 2000);
        assert!(state.clone().key(&first, coin, lagrange.clone()).is_err());
        state.seal().expect("it seals");
        assert_eq!(state.verify(&first, coin), Ok(()));
        assert!(state.clone().key(&first, coin, lagrange.clone()).is_err());
        contribute(&mut state, 3000);
        state.contribute(b"and one from entropy");
        assert_eq!(state.verify(&first, coin), Ok(()));

        let path = std::env::temp_dir().join(format!("apogee-phase2-{}", std::process::id()));
        state.write(&path).expect("it writes");
        assert_eq!(State::read(&path).as_ref(), Ok(&state));

        let mut moved = state.clone();
        moved.terms[0].swap(4, 5);
        assert!(moved.verify(&first, coin).is_err());
        let mut uncontributed = state.clone();
        uncontributed.trapdoors[DELTA] = G2Affine::GENERATOR;
        assert!(uncontributed.verify(&first, coin).is_err());
        let mut replayed = state.clone();
        replayed.records.swap(0, 2);
        assert!(replayed.verify(&first, coin).is_err());

        // Without the last contribution, whose factors the test does not
        // know, the key is the trapdoors'.
        let mut known = state.clone();
        known.records.truncate(known.records.len() - 3);
        let mut again = first.clone();
        for seed in [1000, 2000] {
            again.apply(&|t| (f(seed + t as u64), f(7 * seed + t as u64)));
        }
        again.seal().expect("it seals");
        again.apply(&|t| (f(3000 + t as u64), f(21000 + t as u64)));
        assert_eq!(again.records, known.records);
        let key = again.key(&first, coin, lagrange.clone()).expect("a key");
        assert_eq!(key, derive(&mut cubic(3), trapdoors));

        let key = state.finish(&first, coin, lagrange, &path).expect("a key");
        assert_eq!(ProvingKey::read(&path).as_ref(), Ok(&key));
        std::fs::remove_file(&path).expect("the file is the test's");
        let (proof, data) = prove(&key, &mut cubic(3)).expect("it proves");
        assert!(verify(&key.vk, &proof, &data));
    }
}
