# The structured reference string

The powers of `τ` every commitment is made under: the ceremony they come from, how its file is read
and what is checked, the archive an SRS is cached in, the three points a verifier holds, KZG over
them, and the Groth16 first phase read from the same file. Implementation: `crates/srs`.

## 1. The ceremony

The SRS is PSE's perpetual powers of tau, contribution 80: files `ppot_0080_<p>.ptau`, kept in
`assets/ptau/`, which is gitignored. Hermez's `powersOfTau28_hez_final_*.ptau` is another ceremony
with another `τ`; the reader ingests it as readily, and every commitment, key and identity over it
differs. This ceremony's `[τ]_1`, as the hex of its canonical encoding `x ‖ y`:

```text
9bbb31bedc304e081e2aada4b56c2217e0e94ee16874e3517d14bef5dcec3a16
317ff1589e53513fa333591b318e8f1e55ef7c37d92beb6d9a61d770a2f39506
```

PSE's files are cut from one ceremony: the first `2^k` powers, and the Lagrange bases of domains up
to `2^k`, agree in every file of power `k` or more. One file, `ppot_0080_24.ptau` (19.3 GB), serves
every use. A base key needs as many powers as its tallest family has rows, at most `2^22`, the
menu's top, and at least the generic table's `2^18` ([lookup.md](lookup.md) §9); `bench prove`
reads `2^22`. The recursion format reads `2^24`, its largest stack (`verifier_core::STACK_LOG`,
[recursion.md](recursion.md) §1.3), and the decider its domain's Lagrange bases (§7).

## 2. Ingesting a `.ptau` file

`Srs::from_ptau(path, k)` reads snarkjs's `.ptau` container, the one ingestion format. Integers are
little-endian.

```text
0    4    "ptau"
4    4    version: 1
8    4    section count: at most 64
12   ..   sections: id u32 | size u64 | payload

id 1   header, 44 bytes: n8 = 32 | q (n8 bytes) = BN254's Fq modulus | power p | ceremonyPower
id 2   tauG1: 2^(p+1) − 1 G1 points, [τ^0]_1 first
id 3   tauG2: 2^p G2 points, [1]_2 then [τ]_2
```

Sections 1–3 must each occur once, at the sizes `p` implies; the others (alpha, beta, the
contribution record, the Lagrange bases of §7) are not read here. `from_ptau` takes the first `2^k`
points of section 2 (`k ≤ p`) and the first two of section 3.

A point is uncompressed affine in little-endian Montgomery form: each 32-byte coordinate holds
`coord·R mod q`, `R = 2^256`; G1 is `x ‖ y`, G2 `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`. It is the only
non-canonical point encoding the code reads. A coordinate is read as a canonical `Fq` (refused at
or above `q`), multiplied by `R^−1` and re-encoded, and the canonical bytes go through
`G1Affine::from_bytes` or `G2Affine::from_bytes` ([primitives.md](primitives.md) §3), the one
validating decoder. All-zero bytes are infinity in both forms.

`from_ptau` never panics: every refusal is an `SrsError` — `Io`, `Truncated`, `BadMagic`,
`BadVersion`, `BadSection` (over 64 sections, sections 1–3 not each present once, a header not 44
bytes, a power outside `1..=30`, a section size `p` does not imply), `WrongCurve`, `PowerTooLarge`
(`k > p`), and `InvalidPoint { index }`, a failing point but not necessarily the first.

## 3. What is validated, and what is presumed

Decoding proves every point canonical, on its curve and in the order-`r` subgroup. `Srs::validate`
adds that they are powers of one `τ`:

```text
g1[0] = G1 generator      g2_gen = G2 generator      no point is infinity
e(Σ_i c_i·g1[i], g2_tau) = e(Σ_i c_i·g1[i+1], g2_gen)       i < n − 1
```

with each `c_i` 31 bytes from `/dev/urandom`, so that no file can be built to pass: a power that is
not `τ` times the one before survives with probability at most `2^−248`. The infinity check
excludes `τ = 0`: `pairing_check` skips a pair at infinity ([primitives.md](primitives.md) §4), so
such an SRS would pass vacuously and `kzg_verify` over it accept any opening. `validate` identifies
nothing, and no proving path runs it.

Soundness needs nobody to know `τ`, which this code presumes of the ceremony. A statement binds the
SRS only through the SRS digest ([proof.md](proof.md) §3), which covers the `SrsVerifier` and the
generic table's three commitments, not the powers, which only a prover reads. A key's loader
recomputes the digest from the key's own points, so a key whose `SrsVerifier` has a known `τ`
loads under its own digest: a verifier takes the ceremony's digest from a channel the prover does
not control, or recomputes it from the ceremony. Program identity covers neither the `SrsVerifier`
nor the table; in the recursion tree the digest is a constant of both programs' images, which their
identities bind ([recursion.md](recursion.md) §8.1).

## 4. The SRS archive

`Srs::save` and `Srs::load` keep an ingested SRS in a file of their own, integers little-endian and
points canonical ([primitives.md](primitives.md) §3); `bench recurse` caches its `2^24` powers in
one.

```text
0     8          "APOGESRS"
8     4          version: 1
12    4          power k, at most 30
16    8          G1 count: 2^k
24    128        g2_gen
152   128        g2_tau
280   64·2^k     g1, [τ^0]_1 first
```

`load` requires exactly `280 + 64·2^k` bytes before reading a point (the cap on `k` keeps the
product from wrapping) and decodes every point through `from_bytes`, which catches a corrupted
coordinate, not a substituted archive. It refuses with `Truncated`, `BadMagic`, `BadVersion`,
`BadSection` and `InvalidPoint`.

## 5. `SrsVerifier`

The only SRS material a verifier takes: `g1_gen = [1]_1`, `g2_gen = [1]_2` and `g2_tau = [τ]_2`,
what Mercury's pairings read. A verifier never commits; the generic table's commitments reach it as
given points. The wire form is 320 bytes, `g1_gen ‖ g2_gen ‖ g2_tau`, canonical, unframed — its
postcard form, `VerifyingKey`'s `srs_verifier` and `verifier::encode_srs_verifier` alike — and
every reader decodes it through the validating `from_bytes`.

## 6. KZG

`srs::kzg`, over coefficients little-endian in the degree (`coeffs[i]` multiplies `X^i`, as `g1[i]`
is `[τ^i]_1`):

```text
kzg_commit(f)   = Σ_i f_i·[τ^i]_1                               one MSM
kzg_open(f, z)  = (f(z), [q(τ)]_1), q = (f − f(z))/(X − z)      one Horner pass gives both
kzg_verify(cm, z, v, w):  e(cm − v·[1]_1 + z·w, [1]_2) · e(−w, [τ]_2) = 1
```

More coefficients than powers is an error, never a truncation. The zero polynomial commits to
infinity and opens to `(0, infinity)`, which verifies. A Mercury commitment is exactly `kzg_commit`
of the evaluation table read as coefficients ([mercury.md](mercury.md) §2). Mercury calls neither
`kzg_open` nor `kzg_verify`, but its pairing relations take their shape, `e(A, [1]_2) = e(B, [τ]_2)`
with both G2 arguments SRS constants, which is what lets recursion fold them instead of pairing
([recursion.md](recursion.md) §8.3).

## 7. Phase 1

`srs::Phase1::from_ptau(path, m)`, for `m ≤ p` and `m ≤ 28`, reads what a Groth16 key takes from the
ceremony at a domain of `n = 2^m`: `tau_g1`, `[τ^i]_1` for `i < 2n − 1`, from section 2; and
`lagrange_g1` and `lagrange_g2`, `[L_j(τ)]` in each group, `L_j` the Lagrange polynomial at `ω^j`
and `ω` of order `n` squared down from `constants::FR_TWO_ADIC_ROOT_OF_UNITY`, from sections 12 and
13, which hold the bases of domains `1, 2, 4, …` in turn, domain `n` from point `n − 1`. It refuses
a basis that is not this domain's: `tau_g1[0]` and each basis's sum must be the generator, and
`Σ_j ω^j·[L_j(τ)]_1 = [τ]_1`. The G2 basis is held to the curve, not the subgroup. The decider's key
is made over it ([recursion.md](recursion.md) §9).
