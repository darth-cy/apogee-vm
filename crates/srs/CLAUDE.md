# `crates/srs`

## What this crate owns
The structured reference string: snarkjs `.ptau` ingestion, an archive format for
reloading it, and the univariate KZG core Mercury is built on. Nothing else.

The normative document is `docs/spec/srs.md`. This file is the summary a reader needs
before touching the code.

## Frozen invariants
- **SRS integrity is presumed. There is no digest.** S07 specified a Poseidon2 digest over
  every point, cached on `Srs`, carried in `SrsVerifier`, absorbed in statement binding
  and re-verified by `load`. **It was dropped on the user's explicit instruction.** No code
  in this workspace hashes an SRS. The master prompt's frozen statement-binding order
  still lists `SRS digest` as its third item, and **that item has no implementation**:
  nothing binds a proof to a particular SRS, so the protocol is not sound against SRS
  substitution. A later stage building statement binding must reinstate it or record the
  same deviation. `docs/spec/srs.md` §4 is the long form.
- **One ingestion format.** The snarkjs `.ptau` container from a
  perpetual-powers-of-tau / Hermez ceremony, and no other, in v1.
- **`.ptau` points are little-endian *Montgomery*.** 64 bytes `x || y` for G1, 128 for G2,
  each coordinate `coord * R mod q` with `R = 2^256`. This is the one file format in the
  workspace that is not canonical, and it is the single fact about `.ptau` worth
  remembering. Decoding multiplies by `R^-1` and then hands the canonical bytes to S05's
  `from_bytes`, so there is exactly one validating decoder and this is a translator in
  front of it.
- **Only sections 1, 2 and 3 are read.** A ceremony file's alpha/beta and Lagrange
  sections are Groth16's business. `from_ptau` therefore touches about 2 GB of a 19 GB
  power-24 file.
- **`from_ptau` and `load` never panic.** Every rejection class in `docs/spec/srs.md` §2.4
  is an `SrsError`, and each has a test that is the real ceremony file with exactly one
  edit.
- **`validate()` is structural, not identifying.** Both generators, no point at infinity,
  then one random-linear-combination pairing check. Coefficients come from `/dev/urandom`
  and are deliberately not reproducible: fixed ones would let a file be built to pass.
  All three cheap checks are load-bearing. Without `g2_gen == [1]_2` the pairing identity
  only proves `g2_tau = tau * g2_gen` for *some* `tau`. Without the infinity check it can
  be satisfied **vacuously**: `pairing_check` contributes the identity for a pair at
  infinity rather than failing on it, so a `tau = 0` SRS passes and then makes
  `kzg_verify` accept any opening of any commitment. `tests/archive.rs` builds that
  forgery to show the rejection is not tidiness.
- **A declared power is capped at 30 before it is shifted**, in both readers. It is a cap
  on a value read out of a file, not a protocol constant: without it the archive's
  `count * 64` wraps `u64` above power 57 and a 280-byte header reaches a `2^58`-element
  allocation.
- **`SrsVerifier` is the only SRS material a verifier path may require.** Three points,
  320 bytes on the wire, hand-written serde that decodes through `from_bytes`. The full
  `Srs` stays prover-side.
- **The KZG check is the deferrable shape.** `e(cm - v*[1]_1 + z*w, [1]_2) * e(-w, [x]_2) = 1`,
  one `pairing_check`. Both G2 arguments are SRS constants, which is what lets an
  aggregator batch and defer them — the accumulator's whole reason for existing.
- **Coefficients are little-endian in the degree.** `coeffs[i]` multiplies `X^i`, matching
  `g1[i] = [x^i]_1`.

## Layout
```
src/lib.rs    Srs, SrsError, SrsVerifier, validate, save/load, the archive constants
src/ptau.rs   the .ptau container reader, the Montgomery decode, both point-block readers
src/kzg.rs    kzg_commit, kzg_open, kzg_verify
```

`ptau.rs` holds two nine-line chunk-reader loops rather than one parameterised by which
encoding it is reading. They differ in three lines, and those three lines are the point of
each function.

## The ceremony file
`assets/ptau/powersOfTau28_hez_final_24.ptau`, **gitignored**: it is 19 GB. Every test in
this crate needs it, or one of the smaller powers beside it, and returns quietly when it
is absent — so a clone without the assets still runs a green suite, and **CI runs none of
these tests**. `cargo test -p srs -- --nocapture` prints one `skipped ...` line per test
that did not run.

Provenance and re-download instructions are in `docs/handoff/S07-msm-srs-kzg.md`. Both
mirrors the snarkjs README names are dead; the ones that work are recorded there.

## Artifacts
| Path | What |
| --- | --- |
| `tests/vectors/ptau_kats.txt` | 8 G1 and 2 G2 ceremony points at pinned indices, read by kat-gen's own independent `.ptau` parser |
| `tests/vectors/kzg_kats.txt` | commitment, evaluation and witness at degrees 1, 100, 2^10 and 2^16, all from arkworks arithmetic |

Both are regenerated with `cargo run -p kat-gen -- srs`, which prints each file's SHA-256;
the digests are pinned in `tests/ptau.rs` and `tests/kzg.rs`. **The generator skips and
writes nothing when the ceremony file is absent**, so CI's regenerate-and-diff stays clean
on a machine without the assets.

Both files carry a `# ceremony <[x]_1>` header line. A different power-24 ceremony has a
different `tau`, so every point and every commitment would differ; the tests check that
line first and say so, instead of printing a wall of mismatches.

## Tests
| File | What it pins |
| --- | --- |
| `ptau.rs` | power-24 ingestion end to end, the point-for-point differential against kat-gen's reader, and every rejection class — each one the real power-12 file with exactly one edit |
| `archive.rs` | the round trip, byte stability, the pinned header layout, and eight tamper twins |
| `kzg.rs` | the committed arkworks differential, the round trip at every acceptance degree, the degree bound, and the four tamper twins |
| `verifier.rs` | the 320-byte wire form as bytes, and its rejection classes |
| `common/mod.rs` | asset lookup, scratch files, the one-edit damage helper, the fixture codec. Test-only. |

`srs` is a **std** crate and is absent from CI's guest-target build line, for the same
reason `curve` is: no guest reads an SRS.
