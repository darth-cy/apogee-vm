# The structured reference string

Normative for `crates/srs`. Frozen in S07: the ingestion format, the archive
layout, and the verifier's SRS material. Changing any of them is a
protocol-version change.

Vocabulary is `docs/GLOSSARY.md`'s. `Fr` is the BN254 scalar field the whole
protocol is arithmetized over; `Fq` is the base field curve coordinates live
in; `[a]_1` and `[a]_2` are `a * G1` and `a * G2`.

---

## 1. What an SRS is here

A powers-of-tau SRS is

```text
  g1 = [x^0]_1, [x^1]_1, ..., [x^(n-1)]_1        n = 2^power
  g2_gen = [1]_2
  g2_tau = [x]_2
```

for a `tau = x` nobody knows. `n` is a power of two, and the required
capability is `power = 24`: the master's trace-height ceiling is `2^22`, and
Mercury needs quotient headroom above it.

`alpha`, `beta` and the Lagrange bases that a ceremony file also carries are
Groth16's, not ours. They are never read.

---

## 2. Ingestion format — frozen

**The snarkjs `.ptau` container from a perpetual-powers-of-tau / Hermez
ceremony is the one ingestion format in v1.** There is no second reader, and
adding one is a protocol change.

### 2.1 Container

All integers little-endian.

```text
  offset  size  field
  0       4     magic, the ASCII bytes "ptau"
  4       4     version, u32                 must be 1
  8       4     section count, u32
  12      ..    sections, each:
                  4   section id, u32
                  8   payload size, u64
                  ..  payload
```

Sections are not ordered and not required to be unique by the format; this
reader requires ids 1, 2 and 3 to appear exactly once and ignores every other
id.

### 2.2 Sections read

```text
  id 1  header    4   n8, u32                 must be 32
                  n8  q, the field modulus    must be BN254's Fq modulus
                  4   power, u32
                  4   ceremonyPower, u32      provenance only, not read
                total 44 bytes

  id 2  tauG1     2^(power+1) - 1 G1 points   [x^0]_1, [x^1]_1, ...
  id 3  tauG2     2^power G2 points           [1]_2, [x]_2, ...
```

Both section sizes are a function of the declared `power` and are checked
against it. `from_ptau(path, k)` reads the first `2^k` points of section 2 and
the first two points of section 3, so it touches about 2 GB of a 19 GB
power-24 file.

### 2.3 Point encoding — the one thing worth remembering

`.ptau` points are **uncompressed affine in little-endian Montgomery form**:

```text
  G1   64 bytes    x || y
  G2  128 bytes    x.c0 || x.c1 || y.c0 || y.c1
```

each coordinate 32 little-endian bytes holding `coord * R mod q`, with
`R = 2^256`. That is ffjavascript's in-memory representation written straight
out (`toRprLEM`), and it is **not** the canonical form every other file in this
workspace uses.

Decoding is: read the 32 bytes as a canonical `Fq` — which rejects a stored
value at or above `q` — multiply by `R^-1 mod q`, and re-encode. The point then
goes through S05's `G1Affine::from_bytes` / `G2Affine::from_bytes` unchanged,
so "S05 validation semantics apply to every point" is literally true: one
decoder, with a translator in front of it.

A point whose 64 (or 128) bytes are all zero is the point at infinity in both
encodings, since the Montgomery form of zero is zero.

### 2.4 Rejection classes

`from_ptau` returns an error and never panics, for: a file shorter than the
prologue, a section that runs past the end of the file, wrong magic, a version
other than 1, a missing or duplicated section 1/2/3, a header that is not 44
bytes, `n8 != 32` or a modulus that is not `Fq`'s, a section size that
disagrees with the declared power, a requested power above the file's, and any
point that fails S05's decode.

---

## 3. `validate()` — structure, not identity

```text
  g1[0] == the G1 generator
  g2_gen == the G2 generator
  no point in the SRS is the point at infinity
  e(sum_i c_i [x^i]_1, [x]_2) == e(sum_i c_i [x^(i+1)]_1, [1]_2)   for i < n-1
```

with each `c_i` drawn from `/dev/urandom` as 31 bytes zero-extended to 32 —
below `2^248 < p`, so every draw is canonical without rejection. The
coefficients are deliberately not reproducible: fixed ones would let a file be
built to pass.

All three of the cheap checks are load-bearing, not tidiness.

Without `g2_gen == [1]_2` the pairing identity only proves
`g2_tau = tau * g2_gen` for *some* `tau`, which any consistently scaled pair
satisfies.

Without the infinity check the pairing identity can be satisfied **vacuously**.
`[x^i]_1` and `[x]_2` are the identity only when `x = 0`, so an SRS holding one
is degenerate — but `pairing_check` contributes the identity for a pair at
infinity rather than failing on it. Take `g2_tau = O` and the tail of `g1` at
infinity: the first pair vanishes, the second vanishes, and an empty product is
1. `kzg_verify` over that SRS then accepts an arbitrary commitment opened to an
arbitrary value at an arbitrary point, because every pairing it forms is
skipped too. With the digest gone this is the only structural gate there is, so
it does not get to be vacuous.

The pairing check is a Schwartz–Zippel test on a degree-`(n-1)` polynomial in
the `c_i`: a single wrong power makes it fail except with probability `1/|Fr|`.

---

## 4. SRS integrity is presumed — a dropped requirement

**S07 specified a Poseidon2 digest over every SRS point, cached on `Srs`,
carried in `SrsVerifier`, absorbed in statement binding, and re-verified by
`load`. It was dropped on the user's explicit instruction, and this section is
the unequivocal note that goes with it.**

Consequences, stated plainly:

- `Srs` has no digest, `SrsVerifier` has no `digest` field, and nothing in this
  workspace hashes an SRS.
- The master prompt's frozen statement-binding order lists `SRS digest` as the
  third item absorbed, before the `VmConfig` descriptor. **That item has no
  implementation.** A later stage that builds statement binding must either
  reinstate it or record the same deviation.
- Nothing binds a proof to a particular SRS. A prover who swaps in a different
  valid ceremony produces a proof that a verifier holding the matching
  `SrsVerifier` accepts. **The protocol is not sound against SRS substitution**,
  and that is presumed away rather than checked.
- What survives is structural: every point is validated at decode
  (canonical, on-curve, in-subgroup), and `validate()` relates the powers to
  one `tau`. Neither says *which* SRS you have.

---

## 5. Archive format — frozen

`save` / `load` exist so a prover does not re-read a 19 GB ceremony file for
`2^24` points. All integers little-endian.

```text
  offset  size    field
  0       8       magic, the ASCII bytes "APOGESRS"
  8       4       version, u32                 must be 1
  12      4       power, u32
  16      8       G1 count, u64                must equal 2^power
  24      128     g2_gen, canonical LE
  152     128     g2_tau, canonical LE
  280     n * 64  the G1 powers, canonical LE, [x^0]_1 first
```

The header is 280 bytes and the file is exactly `280 + n * 64`, which `load`
checks before reading a point. `power` rather than the count alone is stored so
a malformed archive cannot claim a length that is not a power of two.

`power` is capped at 30 before it is shifted — the same cap the `.ptau` reader
applies to the declared power, and for the same reason. Without it `n * 64`
wraps `u64` for any power at or above 58, the length check degenerates to
`len != 280`, and a 280-byte header with no point block at all reaches a
`2^58`-element allocation.

Points are the canonical encoding, not the ceremony's Montgomery one: an
archive is a file this workspace writes, so master rule 3 applies to it.

`load` reads the whole file eagerly — no mmap, no lazy loading — and puts every
point through `G1Affine::from_bytes`. With the digest gone, that decode is the
only integrity check the archive has, and it catches a corrupted coordinate but
not a wholesale substitution.

---

## 6. `SrsVerifier` — frozen

```text
  g1_gen: G1Affine     [x^0]_1
  g2_gen: G2Affine     [1]_2
  g2_tau: G2Affine     [x]_2
```

**This is the only SRS material any verifier path may require.** The full `Srs`
stays prover-side; a verifier that wants a power is asking to commit, which is
a design error rather than a missing accessor.

Its wire form is 320 bytes, the three points concatenated in that order, each
in the canonical encoding `curve` writes. Deserialisation goes back through the
validating `from_bytes`, so a wire form carrying an off-curve or
out-of-subgroup point is refused rather than reconstructed.

S07 also specified a `digest: [u8; 32]` field here. See §4.

---

## 7. KZG

Coefficients are little-endian in the degree: `coeffs[i]` multiplies `X^i`,
matching `g1[i] = [x^i]_1`.

```text
  commit(f)     = [f(x)]_1 = sum_i coeffs[i] * g1[i]          one MSM
  open(f, z)    = (f(z), [q(x)]_1),  q(X) = (f(X) - f(z))/(X - z)
  verify        = e(cm - v*[1]_1 + z*w, [1]_2) * e(-w, [x]_2) == 1
```

The quotient comes from one pass of synthetic division: running Horner from the
top coefficient down, the value carried into step `i` is `q`'s coefficient of
`X^i`, and what falls out at the bottom is `f(z)`. The division is exact by
construction, so there is no remainder to check.

The verifier form is the textbook `e(cm - v*[1]_1, [1]_2) = e(w, [x]_2 - z*[1]_2)`
with the `z` term moved into G1. That is one `pairing_check` rather than two
pairings and a G2 scalar multiplication, and — the reason it is written this
way — **both G2 arguments are now SRS constants**, so an aggregator can batch
these across proofs and defer them. That is the shape the accumulator riding
public I/O carries, and the reason base provers and recursion never compute a
pairing.

A polynomial with more coefficients than the SRS has powers is an error at
commit time, never a truncated commitment. The zero polynomial commits to the
point at infinity and opens to `(0, infinity)`, which verifies: both pairing
arguments are infinity, `pairing_check` skips them, and the empty product is 1.
