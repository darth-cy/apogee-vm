# S07 — Pippenger MSM + ptau Ingestion + KZG

Branch `s07-msm-srs-kzg`. Status: complete. The performance gate passes at
**1.49x** against arkworks, where the bar is 2x.

The normative document is **`docs/spec/srs.md`**, written this stage: the frozen
`.ptau` ingestion statement, the point encoding, the archive layout, the
`SrsVerifier` contract and the KZG rewrite. This note is the frozen API, the
artifacts, the numbers and the deviations.

---

## The one thing to read before anything else

**The SRS digest was dropped. SRS integrity is presumed.**

S07 specified a Poseidon2 digest over every SRS point — cached on `Srs`, carried
in `SrsVerifier`, absorbed in statement binding, and re-verified by
`Srs::load`. **On the user's explicit instruction it was not built.** Nothing in
this workspace hashes an SRS.

What that costs, stated so no later stage has to rediscover it:

- **The master prompt's frozen statement-binding order lists `SRS digest` as its
  third absorbed item, before the `VmConfig` descriptor. That item has no
  implementation.** A stage that builds statement binding must either reinstate
  it or record the same deviation.
- **Nothing binds a proof to a particular SRS.** A prover who swaps in a
  different valid ceremony produces a proof that a verifier holding the matching
  `SrsVerifier` accepts. The protocol is not sound against SRS substitution.
- `SrsVerifier` therefore has **three** fields, not the four S07 specified. There
  is no `digest: [u8; 32]`.
- Must-be-exact 5 (digest determinism), the digest half of must-be-exact 6, and
  the digest half of acceptance 6 are consequently not delivered. Everything else
  in those items is.

What survives is structural and does not identify anything: every point is
validated at decode with S05's `from_bytes`, and `Srs::validate` checks the
powers really are consecutive powers of one `tau` under the two G2 points.
`docs/spec/srs.md` §4 is the long form.

---

## Frozen public API, as built

```rust
// crates/curve/src/msm.rs   (new module, re-exported as `curve::msm`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsmError {
    LengthMismatch { bases: usize, scalars: usize },
}

pub fn msm(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Projective, MsmError>;
pub fn msm_small_u32(bases: &[G1Affine], scalars: &[u32]) -> Result<G1Projective, MsmError>;
```

No separate `u16` entry: the stage made it optional, and the cost is the window
count, which is already 2 or 3 for anything that fits in 32 bits.

```rust
// crates/srs/src/lib.rs
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SrsError {
    Io(String),
    BadMagic,
    BadVersion(u32),
    BadSection(&'static str),
    WrongCurve,
    Truncated,
    PowerTooLarge { requested: u32, available: u32 },
    InvalidPoint { index: usize },
    DegreeTooLarge { degree: usize, max: usize },
    NotGenerator,
    TauMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srs { /* private: g1: Vec<G1Affine>, g2_gen, g2_tau */ }

impl Srs {
    pub fn from_ptau(path: &Path, power: u32) -> Result<Srs, SrsError>;
    pub fn validate(&self) -> Result<(), SrsError>;
    pub fn max_degree(&self) -> usize;
    pub fn save(&self, path: &Path) -> Result<(), SrsError>;
    pub fn load(path: &Path) -> Result<Srs, SrsError>;
    pub fn g1(&self) -> &[G1Affine];
    pub fn g2_gen(&self) -> G2Affine;
    pub fn g2_tau(&self) -> G2Affine;
    pub fn verifier(&self) -> SrsVerifier;
}

/// The ONLY SRS material any verifier path may require. Three points, 320
/// bytes on the wire, canonical little-endian, hand-written serde that decodes
/// through the validating `from_bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]   // + hand-written Serialize/Deserialize
pub struct SrsVerifier {
    pub g1_gen: G1Affine,
    pub g2_gen: G2Affine,
    pub g2_tau: G2Affine,
}
```

```rust
// crates/srs/src/kzg.rs
pub fn kzg_commit(srs: &Srs, coeffs: &[Fr]) -> Result<G1Affine, SrsError>;
pub fn kzg_open(srs: &Srs, coeffs: &[Fr], z: Fr) -> Result<(Fr, G1Affine), SrsError>;
pub fn kzg_verify(srs: &Srs, cm: &G1Affine, z: Fr, v: Fr, w: &G1Affine) -> bool;
```

`kzg_verify` reads only `g1[0]`, `g2_gen` and `g2_tau` — exactly `SrsVerifier`.
It takes `&Srs` because S07 pins the signature that way, not because it needs
one.

`PartialEq`/`Eq` on `Srs` is the one addition beyond the stage's list, so
`save`/`load` can be stated as a round trip.

---

## The MSM, in one paragraph

Windowed Pippenger. Window width is **arkworks' heuristic verbatim** — `3` below
32 points, `log2(n) * 69 / 100 + 2` above — so the gate compares implementations
rather than window choices. Scalars are recoded into signed digits in
`[-2^(w-1), 2^(w-1)]`, halving the buckets; negating an affine base is one `Fq`
negation, so the sign is free. Buckets are reduced by a running sum and the
windows combined by doublings.

Two details worth keeping:

- **The window count is `ceil((bits + 1) / w)`, not `ceil(bits / w)`.** The
  recoding carries a 1 out of any window reaching `2^(w-1)`, so the top window
  must have room to swallow the carry rather than emit one — the top window's raw
  value has to stay below `2^(w-1)`, which needs `d*w >= bits + 1`. For every
  width the heuristic can pick this is the same number, because no `w` in
  `3..=29` divides 254 or 32; the `+1` is what makes it provable rather than
  lucky.
- **Work is split over (window, input chunk), not windows alone.** Windows alone
  leave cores idle exactly where it hurts most: the small-scalar path has two of
  them. Splitting the input is exact — bucket sums are group elements — so the
  answer does not depend on the core count, which `tests/msm.rs` pins across 39
  sizes and 10 thread counts against a naive sum.

`msm` never inspects scalar magnitude; `msm_small_u32` is the only door to the
small path (must-be-exact 9). That is a source-level fact, not something a test
can observe — the two agree on every value and differ only in cost.

---

## Acceptance

| # | Item | Result |
| --- | --- | --- |
| 1 | MSM differential fixtures at 1, 2, 100, 2^10, 2^16 + must-be-exact-1 cases | 13 committed cases, all match |
| 2 | 100 live random MSMs at sizes <= 2^12 vs arkworks | 100 runs, 26 of them the exact window-width boundaries |
| 3 | `msm_small_u32` == `msm` on u16/u32/zero/single-bit sets to 2^14 | 10 sizes x 5 scalar kinds |
| 4 | Real ceremony file at power 24 | PSE `ppot_0080_24.ptau`: 2^24 powers, both generators, both G2 points subgroup-valid, `validate()` passes |
| 5 | Ingestion negative controls, every error class | 11 controls, each the real power-12 ceremony file with exactly one edit |
| 6 | Digest + archive | archive round trip, byte stability, pinned header layout, 8 tamper twins. **Digest dropped — see above** |
| 7 | KZG round trip + arkworks differential at 1, 100, 2^10, 2^16 | committed fixtures, all match |
| 8 | KZG tamper twins (a) witness (b) v+1 (c) proof point (d) z+1 | all four reject, plus two infinity substitutions |
| 9 | **Performance gate: within 2x of arkworks at 2^22** | **1.49x — passes** |
| 10 | Small path beats the general path at 2^22 | **0.36x — passes** |
| 11 | One corrupted fixture byte fails | three, one per committed corpus |

Beyond the list: 20,000 malformed `.ptau` containers and 20,000 damaged archives
through both readers with no panic (`crates/srs/tests/totality.rs`), and a
point-for-point differential of our `.ptau` decoder against a second,
independent one written in `kat-gen` over arkworks.

---

## Acceptance 9 and 10 — the numbers

Machine: **Apple M5 Pro, 18 cores, 48 GB, macOS 26.6.2**, rustc 1.96.1,
`--release`, best of 3, one process.

Configuration: `n = 2^22`, **window width 17**, **15 windows** for a 254-bit
`Fr` scalar and **2 windows** for a `u32`. Bases are the first 2^22 powers of
the real ceremony file; both sides get the same bases and the same scalars, and
both agree on the answer before either is timed.

| measurement | ours (ms) | reference (ms) | ratio |
| --- | --- | --- | --- |
| general `msm`, random `Fr` | 1342 | 900 | **1.49x** |
| small path, `u32` scalars | 172 | 474 | **0.36x** |

A second run gave 1305 / 853 (1.53x) and 163 / 456 (0.36x).

Row one's reference is `ark_ec::VariableBaseMSM`; row two's is our own general
path on the same `u32` values lifted into `Fr`. **`ark-ec` and `ark-ff` carry
their `parallel` feature** in the workspace manifest so row one compares two
rayon implementations — against a single-threaded arkworks this would be a gate
passed by not being compared.

`cargo run --release -p bench -- msm`. Setup (reading and validating 2^22
ceremony points) is 145 ms and outside every timed region.

**No precomputed base tables.** The gate passes without them and 2^24 affine
bases would already cost about a gigabyte; the stage said to add them only if
the gate needed them, and it did not.

---

## The ceremony — PSE, not Hermez

**This project uses PSE's perpetual powers of tau, contribution 80.** That is
frozen in `docs/spec/srs.md` §2.0 and it is the decision a later stage most
needs to know about, because the two candidate ceremonies produce entirely
different SRSs.

The stage prompt named "perpetual-powers-of-tau / Hermez", i.e. either. PSE was
chosen because **its mirror is the one that is still up**, and it is the best
behaved: plain S3, no redirects, stable ETags, honest HTTP `Range` so a 19 GB
fetch resumes. Hermez's two published mirrors —
`storage.googleapis.com/zkevm/ptau/*` and `hermez.s3-eu-west-1.amazonaws.com/*`,
both named in the snarkjs README — return `403 AccessDenied` for **every** power.

Hermez's `powersOfTau28_hez_final_*.ptau` is a *different ceremony with a
different `tau`*. Its points and every commitment over them differ, so the two
are not interchangeable: dropping a Hermez file into `assets/ptau/` under a PSE
name would give a structurally valid SRS whose committed fixtures do not match.
Both fixture files carry a `# ceremony <[x]_1>` header line and the tests check
it first, which turns exactly that mistake into one clear message.

Nothing in the code depends on which ceremony it is — the reader would ingest
Hermez's just as happily. The choice is frozen because the fixtures come from
it, and because with the digest dropped nothing else would notice a swap.

### The files

Both gitignored; `/assets` is in `.gitignore`, so nothing under it can reach git
history. Both are contribution 80, so power 12 is a genuine prefix of power 24
and the two agree point for point — verified, not assumed.

| | `ppot_0080_24.ptau` | `ppot_0080_12.ptau` |
| --- | --- | --- |
| size | 19,327,446,162 | 4,811,922 |
| sha256 | `d21a509863a643b8fd15af9b2f6f8af9b5928b3138af591edc2b7a731b8c2938` | `35e163120e724a60853d0dd76ec54037f7c7b00584392255f71a4341d5a05c50` |
| header | `power = 24`, `ceremonyPower = 28` | `power = 12`, `ceremonyPower = 28` |
| used by | the fixtures, the perf gate, every prefix test | the ingestion negative controls, which read a whole file into memory to damage one byte |

`[x]_1` is `9bbb31be...a2f39506` for both — the `# ceremony` line in
`ptau_kats.txt` and `kzg_kats.txt`.

```bash
mkdir -p assets/ptau && cd assets/ptau
for p in 12 24; do
  curl -L -C - -o ppot_0080_$p.ptau \
    "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_$p.ptau"
done
```

The bucket serves powers 08 through 28. Power 24 is the required capability:
the master's trace-height ceiling is 2^22, plus Mercury quotient headroom.

### Other mirrors, for the record

All verified to serve real `ptau`-magic bytes and honour `Range`, in case the
PSE bucket ever goes the way of the other two:

| what | URL |
| --- | --- |
| Hermez 24 / 25 / 26 / 27 | `https://www.dropbox.com/sh/mn47gnepqu88mzl/AAAi2DHbiB5LhGGFRJ_M2DwVa/powersOfTau28_hez_final_24.ptau?dl=1` and siblings |
| Hermez 23 | `https://risc0-artifacts.s3.us-west-2.amazonaws.com/tsc/2024-04-04/powersOfTau28_hez_final_23.ptau` |
| Hermez 08–18 | `https://fastfourier.nyc3.cdn.digitaloceanspaces.com/powers-of-tau/` |

Switching to any of those is a ceremony change: regenerate both fixture files
with `cargo run -p kat-gen -- srs` and update `docs/spec/srs.md` §2.0.

---

## Artifacts

| Path | What |
| --- | --- |
| `crates/curve/tests/vectors/msm_kats.txt` | 13 MSM answers from `ark_ec::VariableBaseMSM` |
| `crates/srs/tests/vectors/ptau_kats.txt` | 8 G1 and 2 G2 ceremony points at pinned indices, from kat-gen's own `.ptau` reader |
| `crates/srs/tests/vectors/kzg_kats.txt` | commitment, evaluation and witness at degrees 1, 100, 2^10, 2^16 |

`cargo run -p kat-gen -- msm` and `cargo run -p kat-gen -- srs` regenerate them
and print each digest; the pins live in `crates/curve/tests/msm.rs` and
`crates/srs/tests/{ptau,kzg}.rs`.

`msm_kats.txt` is the one fixture in the repository that encodes its **inputs as
a seed and a pattern name** rather than writing them out — the 2^16-point case
would otherwise be 12 MB of hex. Both sides expand the same seed independently,
arkworks in `tools/kat-gen/src/msm.rs` and `curve` in `crates/curve/tests/msm.rs`,
so a drift in either expansion changes the expected point and fails. The four
patterns (`random`, `zeros`, `identical`, `infinity`) are how must-be-exact 1's
degenerate cases got into a fixed-arity line format.

---

## What CI does and does not run

CI has no `assets/`, so **every test in `crates/srs` except `totality.rs`
returns quietly**, and so does kat-gen's `srs` group — which is why the
regenerate-and-diff line can include `crates/srs/tests/vectors/` and still be
clean. `cargo test -p srs -- --nocapture` prints one `skipped ...` line per test
that did not run.

That is the direct consequence of the ceremony file being 19 GB.
`cargo test --workspace` reports **251 passing either way** — 205 from S06, 10
new in `crates/curve`, 36 in `crates/srs` — because a test that returns early
still passes. What changes is that **33 of them do nothing**: every `crates/srs`
test except `totality.rs`'s three. Acceptance 4, 5, 6, 7 and 8 are only
demonstrated on a machine with the assets, and a green CI run is not evidence
for them. `cargo test -p srs -- --nocapture` prints one `skipped ...` line per
test that did not run, which is the only way to tell the two situations apart.

`crates/srs` is a **std** crate and is absent from the guest-target build line,
for the same reason `curve` is: no guest reads an SRS.

---

## Two bugs the adversarial pass found, and their fixes

Both were in `crates/srs`, both are fixed, and both have a regression test that
was **run against the unfixed code first** to prove it can fail.

### 1. `validate()` accepted a degenerate `tau = 0` SRS, which made KZG forgeable

`curve::pairing::pairing_check` contributes the identity for a pair at infinity
rather than failing on it — S05 froze that deliberately. So an SRS with
`g2_tau = O` and the tail of `g1` at infinity satisfied the RLC pairing check
**vacuously**: the first pair vanished, the second vanished, and the empty
product is 1. `validate()` returned `Ok`.

`kzg_verify` over such an SRS then accepts an arbitrary commitment opened to an
arbitrary value at an arbitrary point, because every pairing *it* forms is
skipped too. The regression test builds exactly that forgery — commit
`f(X) = 7 + 11X`, open it at `z = 3` to `99999` instead of `40` — and asserts it
is accepted, so the rejection is demonstrated to be load-bearing rather than
tidy.

Fix: `validate()` rejects any SRS containing the point at infinity. `[x^i]_1`
and `[x]_2` are the identity only when `x = 0`, so this is a structural fact,
not a heuristic. **With the digest gone, `validate()` is the only structural
gate there is, so it does not get to be vacuous.**

### 2. `Srs::load` panicked on a 280-byte crafted archive

`power` was bounded only by `usize::BITS`, so `count = 1 << power` could reach
`2^63` and `count * 64` wrapped `u64` to zero for every power at or above 58.
The length guard `len != 280 + count * 64` then degenerated to `len != 280`,
which a header-only file satisfies, and the reader went straight to
`Vec::with_capacity(1 << 58)`. Debug builds panicked on the multiply, release
builds on the allocation.

Fix: `power` is capped at 30 before it is shifted — the same cap the `.ptau`
reader already applied to the declared power, now shared by both. The
regression test sweeps all 64 declared powers against a header-only archive.

The `.ptau` reader was already correct here; the archive reader was the one that
had grown its own bound.

The reviewers also raised, and three-lens refutation rejected, the observation
that CI runs none of `crates/srs`'s acceptance tests. That is true, deliberate,
and recorded above rather than a defect.

## Additive extensions (everything beyond the stage's literal list)

1. **`rayon` becomes a workspace runtime dependency.** Master rule 2 names it;
   `curve` uses it for the MSM fan-out and `srs` for point decoding at
   ingestion. It is the first crate in the workspace to take it.
2. **`ark-ec` and `ark-ff` gain their `parallel` feature.** Dev- and
   tool-dependencies only. Anti-goal 1 bans cargo features *of ours*, not an
   oracle's build configuration, and without it acceptance 9 is not a comparison.
3. **`PartialEq`/`Eq` on `Srs`**, so the archive round trip is one assertion.
4. **`tests/totality.rs`** — 40,000 fuzzed inputs across both readers, plus a
   sweep of all 64 declared archive powers. It is the only `srs` suite CI can
   run, and "returns an error" is a claim about all inputs that the enumerated
   rejection classes cannot make. Worth noting what the fuzz did *not* find: the
   `count * 64` overflow needs `power` and `count` moved together, which random
   bit flips will not do, which is why that case has its own sweep.
5. **`the_answer_does_not_depend_on_the_thread_count`** — 39 sizes x 10 thread
   counts against a naive sum. The chunk count comes from
   `rayon::current_num_threads()`, so the decomposition genuinely differs between
   machines; a proof that verified on the prover's machine and not the
   verifier's would be the worst kind of bug to find later.
6. **A second `.ptau` reader in `kat-gen`.** It decodes by a different route —
   arkworks reads the stored limbs as its own Montgomery representation with
   `Fp::new_unchecked`, while `crates/srs` multiplies by `R^-1` through the
   field — so the point fixtures are a genuine cross-implementation witness that
   the little-endian Montgomery reading is right, not our decoder read back.

## Deviations and notes for the reviewer

1. **The SRS digest.** See the top of this note. This is the deviation that
   matters.
2. **`SrsVerifier` has three fields, not four.** Same cause.
3. **No committed `.ptau` fixture.** The ingestion tests read the real ceremony
   files from the gitignored `assets/ptau/` and skip when absent, per the
   file-discovery decision. CI therefore exercises none of them.
4. **`validate()` also checks `g2_gen == [1]_2` and rejects the point at
   infinity,** neither of which the stage named. Both are load-bearing rather
   than extra; see the two-bugs section above for what the second one costs.
5. **`from_ptau`'s `InvalidPoint { index }` is *a* failing point, not the
   first.** Decoding runs under rayon and collects into a `Result`. Every
   negative control has exactly one bad point, so it is deterministic in
   practice, and reporting the lowest index would mean a serial pass.
6. **The `.ptau` reader enforces that section 2 and 3 sizes are the exact
   function of the declared power.** The stage asked for "wrong section
   structure" rejection and this is the strongest available reading: snarkjs
   rewrites the header on `powersoftau truncate`, so the relation holds for
   every file snarkjs produces.
7. **`MAX_POWER = 30` and `MAX_SECTIONS = 64`** are caps on the declared header
   values, not protocol constants. They exist so a corrupt header cannot make
   the size arithmetic wrap or turn the table walk into a long walk off the end.
   No BN254 ceremony exceeds power 28 and a prepared file has 11 sections.
8. **`tools/bench`'s `msm` routine needs the ceremony file** and says so and
   returns when it is absent. It measures over real SRS bases and deliberately
   does not substitute random ones.
9. **The window heuristic is duplicated in the bench** so the routine can print
   the configuration. It is printed, never used, so a drift misreports a line
   rather than changing a measurement — the same hazard `zerocheck_verify.rs`
   already carries, and noted in `tools/bench/CLAUDE.md`.
