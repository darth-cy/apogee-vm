# Akita

The polynomial commitment scheme: each group of a shard's committed columns committed once, and
one opening of every group at the GKR pass's point ([proof.md](proof.md) §3, §5). It is Akita, the
lattice scheme of Dao, Bodaghi, Khajehpour, Vitto, Badakhshan, Georghiades, Liu, Zhang and Thaler
(ePrint 2026/1983), over A64-C5 with evaluations in `F_{p^2}`, binding under Module-SIS at 128
bits of quantum Core-SVP security. Section and equation numbers here and in the code are the
paper's.

`crates/pcs-verify` (`#![no_std]`) is the verifier half and every definition both halves read;
`crates/pcs` (`std`, rayon) is the prover half and re-exports it.

The scheme is the paper's analyzed family F1–F3 (Def. 9.2) with four of its tail optimizations: ℓ2
response certificates at the evaluation-trace levels, compression of commitment and opening
payloads to 16 field elements while it pays, a Rice-coded terminal response, and last-block
digests at the terminal. Not built: setup offloading, chunked folds and the planner's search over
schedules. No transcript site grinds a proof of work.

## 1. The ring

`R_d = F_q[X]/(X^d + 1)`, `q = p = 2^64 − 59`, `d` a power of two; an element is its `d`
coefficients, lowest first (`pcs_verify::ring`). `q ≡ 5 (mod 8)`, so `X^d + 1` is the product of
two irreducibles and every nonzero element of ℓ∞ norm below `√q/√2 ≈ 2^31.5` is a unit (§3.1):
every difference of two folding challenges is one.

- **Digits.** A full-field value is `⌈64/b⌉` balanced base-`2^b` digits of its centered lift
  (`full_digits`, `lift`, `digits`).
- **`E` in the ring.** `F_{p^2} = F_p[x]/(x² − 2)` ([primitives.md](primitives.md) §1) embeds as
  `x ↦ e₁ = X^{d/4} − X^{3d/4}`, `e₁² = 2` (`embed_mul`, `embed_eval`).
- **Trace packing** (§3.7): `d` base values pack into one ring element whose product with a
  partial's packing has the `E`-evaluation as its trace (`trace_pack`, `trace_weights`).

## 2. Streams

Every random value is a **stream**: Poseidon2-A64-C5 ([transcript.md](transcript.md) §1) in
counter mode, block `j` of the stream keyed `key ∈ F_p^4` in domain `δ` the rate of one permutation
of `[key, j, δ, 0, …]` (`sample::Stream`).

- **The setup** is the domain-1 stream keyed by `"apogee-vm/akita/v1"`, seven bytes to a lane;
  coefficient `i` is lane `i mod RATE` of block `⌊i/RATE⌋`. Every matrix is a prefix of it (§4.3):
  entry `(i, j)` of `M ∈ R_d^{n×m}` is the `d` coefficients from `(i·m + j)·d`
  (`relation::view`), so the longest view of a schedule, `setup_need`, bounds what it reads. A key
  carries `verifier_core::pcs_setup_len(circuits)`, the longest any of its families needs
  ([proof.md](proof.md) §7.1).
- **Folding challenges** (§3.2, §10.1): coordinate `i` of a fold's challenges is one member of its
  family, drawn from the domain-2 stream keyed `[root.c0, root.c1, nonce, i]`, `root` the fold's
  transcript challenge and `nonce` the prover's (§7). A member has `ones` coefficients `±1` and
  `twos` `±2` on a uniform support, each sign uniform: `FAMILY_128` (in `R_128`, 31 ones,
  `log₂|C| = 129.6`) at the packing levels, `FAMILY_64` (in `R_64`, 31 ones and 10 twos, `128.1`)
  at every trace level and the terminal.

## 3. Commitments

A commitment's source is base-field entries — a group of columns at the root, a fold's successor
witness after it — cut into **blocks** of `m` elements of `R_{d_A}`, at the root within one
column. It is two-tier (§4.5):

```text
s_λ = G⁻¹(f_λ)                      block λ's source digits; a witness is its own
t_λ = A·s_λ ∈ R_{d_A}^{n_A}         the inner image
u_σ = B·t̂_σ ∈ R_64^{n_B}           per outer slice σ of at most 32 blocks, t̂ the images' base-b⋆ digits
payload_σ = F₂·bits(F₁·bits(u_σ))   compressed, in R_16: 16 lanes; uncompressed u_σ, n_B·64
```

`bits` is a coefficient's 64 negative-binary digits in `{−1, 0}`, and `F₁`, `F₂` are Table 10's
rank-one maps over `R_32` and `R_16`. A `Commitment` is the payloads, one per slice, groups in order
(`pcs::commit`); an `Opener` keeps the inner images and each slice's image, quotient and chain. The
shape, the slice count and payload length, is the schedule's (`Schedule::commitment_shape`).

## 4. A fold's relation

A fold reduces a claim on its input to one on a **successor witness** of small digits
(`relation::Layout`): the response `z = Σ_λ c_λ·s_λ` in base-`b⋆` digits, the partial evaluations'
digits, the inner images' digits, the quotient digits of every ring row, and with compression the
chains' bits and quotients. Each ring row — the fold row, the `n_A` inner rows, each slice's `n_B`
outer rows, the `n_D` opening rows and the compression rows — is checked at one random `α` by
**quotient lifting** ((111)–(115)): the unreduced product's high half is witnessed in digits, so the
row holds over the integers modulo `X^d + 1`. `relation::relation` gives every row's terms as
`(row, chunk, pattern, weight)`, a 64-entry chunk of the witness weighed by a scalar times one of a
few fixed patterns; the prover expands them into the fused sumcheck's dense weights, the verifier
contracts them against `eq(r₂, ·)`.

A fold sends, in transcript order (Fig. 4, Fig. 6):

1. at a trace level, the tensor reduction of the incoming `E` claim (§3.7, §5.2): the column
   partials `S₀, S₁`, then a degree-2 sumcheck;
2. the opening payload, `D·ê` over the partial evaluations' digits;
3. at a packing level the batching weights, `ζ^c` over the root's columns; the nonce; then the
   fold challenges;
4. the successor's payloads — at the final fold, the terminal's inner images but the last, and the
   last's digest;
5. `α`, `τ₀`, `τ₁`, then the **range** proof: every witness digit in `b⋆`'s balanced interval, by a
   product tree over `s(s + 1)` (§6.1); on the Euclidean route the response's squared norm, at most
   `S_max` (83), joins the last stage with `z̃_int(r_virt)` (91);
6. the **fused sumcheck** (125), `Σ_x m̃(x)·w̃(x) + κ̃(x)·w̃(x)(w̃(x) + 1)` over the witness, `m`
   the rows' weights at `τ₁` and `κ` the restricted-eq binariness term on the binary segments
   (Remark 6.2); its `w̃(r₂)` is the next fold's claim.

## 5. Schedules

A schedule, `Schedule::new(num_vars, groups)`, is a deterministic integer-only function of the root
shape — the columns' variable count, at least 12, and each group's column count — so the prover,
the verifier and every commitment formed before the opening derive the same one:

- **level 0**, the root: packing at `d_A = 2048` with `FAMILY_128`, source digits base `2^16`, four
  a value, `b⋆ = 2^3`, compressed;
- **level 1**: packing at `d_A = 256` with `FAMILY_128`, `b⋆ ∈ {2^3, 2^4}`;
- **every later level**: evaluation trace at `d_A = 64` with `FAMILY_64`, `b⋆ ∈ {2^4, 2^5, 2^6}`,
  on the Euclidean route, `S_max = ⌈1.1·Σc²·len·src²⌉`;
- a level is compressed while its predecessor was and its input is above `2^19` entries, so
  compression runs from the root and stops at most once;
- another fold is taken while its bytes and the next terminal's are fewer than this terminal's;
- **the terminal** (§8.2): evaluation trace at `d_A = 64`, the response revealed.

At each level the block length `m` and `b⋆` are the candidates' with the shortest successor; every
candidate's ranks are fixed by §6, so the choice trades proof bytes against prover work and never
security.

## 6. Module-SIS ranks

Every rank — `n_A`, `n_B`, `n_D`, the terminal's — is the least whose instance at its ring
dimension, collision bound and width sits at or above 128 bits of quantum Core-SVP (ADPS16,
`0.265·β`) under the LGSA basis shape: coefficient-ℓ∞ for the packing levels' `A`,
`η = 4·‖c‖₁·(b⋆^{δ_f} − 1)`, and every digit map, `η = b⋆ − 1`; Euclidean for the trace levels'
and the terminal's `A`, `η² = 64·‖c‖₁²·S_max` (Cor. 10.35). The ranks are `pcs-verify/src/table.rs`,
generated offline by an estimator of that model, which reproduces the reference implementation's
169-bit table and Table 10's 147.34 and 153.17 bits: per instance, the widest at the floor for each
rank, up to `2^26` columns.

## 7. The opening

`pcs::open(t, setup, groups, point, values)` proves, and `pcs_verify::verify(t, setup, groups,
point, values, proof)` checks, that the groups' columns take `values` at `point`, group-major, in the
caller's live transcript `t`, which has absorbed every commitment and claim. Every fold of the
schedule runs (§4), then the terminal (§8.2):

1. the tensor reduction;
2. every partial but the last, then the last's digest; the nonce; the challenges;
3. the response, Rice-coded with parameter `⌊log₂ σ⌋`, `σ² = S_max/N_z`.

The verifier decodes the response under a unary cap, holds `‖z‖² ≤ S_max`, recovers the last inner
image and the last partial through the last challenge's inverse, holds each to its digest (131),
and checks the evaluation (130).

Every message is absorbed under `PCS_MESSAGE`, every challenge drawn under `PCS_CHALLENGE`, a
digest is the digest of a fresh sponge over its coefficients under `PCS_DIGEST`
([transcript.md](transcript.md) §4), and every round polynomial is sent at `0, 2, …, degree`. A
response's challenges follow a nonce below `NONCES = 256`: the prover takes the first whose response
meets its bounds, and the verifier checks the bounds itself. `proof::Proof` is the messages in
order; its wire form is [proof.md](proof.md) §9's `Opening`.

## 8. The prover's arithmetic

`q ≡ 5 (mod 8)` has no deep roots of unity, so `A·s` is computed exactly: a CRT-NTT over two
62-bit primes `k·2^20 + 1`, whose product, about `2^124`, exceeds every such integer product, lifted
and reduced mod `q` (`pcs::ntt`). The outer and compression maps' products, over digits, are
schoolbook in `i128`, their high halves the quotients of §4. A root column's source digits are
read by its backing, a bit or a byte one digit and a word split by masks, and the inner images and
the root response skip every zero digit plane; a challenge term rotates a plane as two runs, cut
at the negacyclic wrap. The sumcheck prover (`pcs::sumcheck`) keeps a table in small integers
until its first binding and `eq(τ, ·)` as two half tables, and a one-stage range tree's first
round evaluates the leaf product once per class of pair `(s(2p), s(2p+1))`, weighted by the
class's summed `eq`.
