---
title: S15 — LogUp lookup channels + decoder lookup

---

# S15 — LogUp lookup channels + decoder lookup

## Depends on / Inputs
- S13 provides `PolyAddress` (setup and virtual-setup variants included), `GateDef`, `CircuitArtifact`, `gkr` and the checker suite.
- S14 provides the `RangeObligation` format, the obligations the timestamp gap gadget emits, and the memory gate kinds the combined toys need.
- S11 provides `DecodedTables`, the committed decoder/program tables, and `ProgramIdentity`.
- S08/S09 provide `pcs` commit, used only to commit the toy witness and multiplicity columns so "post-commitment" is real. Openings are not required until S16.
- S07 provides `srs`'s `Srs`, a test SRS prefix for toy commitments.
- S01–S04.

## Deliver
- Deliver the LogUp gate kinds in `constraints`, as data: the leaf (num, den) gate, the fraction-pair addition gate that runs up the tree, and per-channel root pairs in the artifact output map.
- Deliver four channels: 16-bit range, timestamp range (19-bit chunks, discharging S14's obligations), generic committed tables, and decoder.
- Deliver the 16-bit range and timestamp range tables as closed-form virtual-setup addresses, evaluated but never materialized and never committed.
- Deliver the committed generic tables zero-padded to a common width, each carrying a `ZeroEntry` neutral row, plus the gated-key convention for conditional lookups.
- Deliver `U16GetSign`, a REQUIRED setup table over the domain u16 high-halfword → sign bit. It is load-bearing in a way it was not over a small field: with a whole word in ONE column, its top bit is no longer a column you already have, so every sign comes from here. Committed or closed-form is the builder's call; state which in the handoff, since S17/S18 consume it by name. The ISA-level table-differential acceptance item covers it.
- Deliver the copower-pairing construction-time assertion: every copower-scaled column also carries its own direct range check. A copower turns the row-varying bound `x < p` into the fixed `x·p' < 2^32`, where `p·p' = 2^32`. That half bounds nothing alone: `p'` is a unit in Fr, so `x = s·p'⁻¹` sweeps a coset of 2^32 elements, almost none of them small integers, and the range check on `s` sees nothing wrong. The scaled bound says x is under this row's width GIVEN x is bounded; only the direct check establishes that. S18/S19 consume it.
- Deliver the decoder lookup binding each cycle row to `DecodedTables`, the packed decoder-mask column and the multiplicity columns.
- Deliver the checker additions: a native fractional-sum recomputation self-check hook, and a per-channel obligation-discharge cross-check against S14's `RangeObligation` list.

## Core algorithm
Follow the master invariant "Lookups (shard-local)".

A lookup is the claim that every witness value appears in some table. With a random g, use the rational identity `Σ_rows 1/(w_i + g) − Σ_table m_j/(t_j + g) = 0`, where m_j counts how often table row j was looked up — committing that multiplicity column is what makes the identity checkable, so every channel carries one. Fractions add pairwise up a binary tree, `a/b + c/d = (ad+cb)/(bd)`, which is why every gate is a (num, den) pair and the root is a single pair.

- Each channel carries LogUp fractional sums, the leaf computing `1/(w+g) − m/(t+g)`. Each shard's root check is `numerator == 0 AND denominator != 0`.
- Challenge g is additive. Challenge β compresses tuples as `VEC = Σ_j β^j·col_j`, with g added by the consuming gate and never inside VEC. Both are drawn from the shard-LOCAL transcript strictly after that shard's witness and multiplicity commitments are absorbed.
- Conditional lookups use gated keys `flag·(key + 1)` with the table's `ZeroEntry` row at key 0. A lookup expression cannot be conditional — it is a linear form evaluated on every row — so without gating, rows whose key is meaningless must still produce a valid table entry and honest rows go unprovable. The flag sends every non-participating row to key 0, where the neutral `ZeroEntry` row answers it. The `+1` is the other half: `flag·key` alone collides, because key 0 is normally a real entry, so a genuine lookup of it and every gated-off row both land there and one neutral entry answers both. The offset reserves key 0 for the neutral row and shifts the real domain up by one.
- The decoder lookup takes the cycle row's key, a pc-derived index per the pc/2 convention. It looks up the decode outputs, including ONE packed mask column whose legal values are exactly the table's domain. One-hotness and mutual exclusivity come from that domain and from nothing else: booleanity permits any subset of bits, all-zero included, and on an all-zero mask every gated constraint goes vacuous and rd is free. Split the mask into independent boolean columns and the property is lost silently. The legal set is declared per family and is not always one-hot. Booleanity of any extracted bit still comes from x²=x constraints.

The decoder table's row layout is S11's frozen `DecodedTables` layout, unchanged. The generic channel's taxonomy stays small: bitwise byte tables survive, since XOR and AND are positional and a wide field says nothing extra about a byte's seventh bit, and so does `U16GetSign`; everything that only existed to work around a small field retires into arithmetic gadgets in later stages. For the toy, the generic channel carries exactly two real tables: an 8×8 AND byte table and `U16GetSign`.

## Must-be-exact
1. The leaf and pair formulas are exactly as above. The whole upper tree is the single aggregate-pair gate shape, with no per-node special cases.
2. S2 ordering, per register D4: g and β are per-shard-local, sampled only after the witness and multiplicity commitments are absorbed. No global lookup challenges exist anywhere in the code.
3. Virtual tables are closed-form (`row i = i` over their domain), typed as virtual-setup `PolyAddress`es, with zero committed columns: that form has a multilinear extension evaluable at any point, so a 2^16-row table per circuit is never materialized. Committed generic tables are zero-padded to one common width — widest wins — the committed setup width equals that width exactly, and the `ZeroEntry` row is mandatory.
4. Conditional lookups happen ONLY via gated keys plus `ZeroEntry`. A lookup expression skipped or branched on a flag is a construction-time error. Padding rows contribute neutral entries, never decoder-gated. One documented exemption from the `ZeroEntry` rule applies to the decoder channel only, defined against S11's frozen no-all-zero-row layout: mask = 0 padding cycle rows contribute the MINUS_ONE padding tuple as their lookup key, which S11's height-padding rule guarantees is in the table, and padding multiplicity is counted on a designated padding row. The general gated-key + `ZeroEntry` rule stays mandatory for every other channel.
5. Each circuit carries exactly one committed multiplicity column per channel, in the witness subtree, positioned last in the committed layout. The artifact docs state the multiplicity convention for `ZeroEntry` and padding contributions.
6. The decoder query appears in the artifact's lookup-expression list like every other lookup. It uses no sentinel indices and no out-of-band queries: a decoder query stored beside the list rather than in it makes the reported lookup count exceed the list length by one wherever a decoder is present, so every tool walking the list silently misses the most important lookup in every family. The artifact's lookup count equals the list length: one count, one truth.
7. Every S14 `RangeObligation` is consumed by exactly one channel expression. An unconsumed or double-consumed obligation is a build error.
8. The root check on the verifier side is both conditions: numerator == 0 AND denominator != 0.
9. Degree ceiling 2 holds for all new gates. The leaf inversion is witnessed, not computed in-gate, so use the witnessed-inverse pattern. The construction-time assertion still applies.
10. One leaf gate kind and one aggregate-pair gate kind serve all four channels. The channels differ only in data: table, lookup expressions and multiplicity column. Leaves form a complete binary tree, padded to a power of two with the neutral fraction (0, 1).
11. Multiplicities are counted inside the deterministic single-pass trace generation. One counter per channel per table row is incremented once per lookup expression on each row, padding neutral entries included. A multiplicity column that disagrees with that recount is a build error.
12. Keys are packed in the lookup expression's declared column order, with j starting at 0 and the gated key first. The artifact records that order, and the verifier recomputes `VEC` from it.

## Acceptance
1. A combined toy circuit exercises all four channels, plus S14's memory gates so the timestamp channel has real gap obligations. It commits witness and multiplicity columns via `pcs`, draws g/β locally, then proves and verifies honestly for `Ok`. The checker self-check reproduces every channel root natively.
2. The range-check tamper twin is the stage gate. One out-of-range value w ∉ [0, 2^16), with a forged multiplicity adjustment chosen to rebalance the sum, must fail verification. The honest twin passes.
3. S2 transcript-order assertion: from the recorded transcript event log, every g/β sample event strictly follows the absorb events of all witness and multiplicity commitments of that shard. A structural test fails if any sample precedes any such absorb.
4. S14's future-read attack (acceptance S14.4), rerun through the timestamp channel, now fails cryptographic verification, not just the native checker.
5. Zero-denominator control: a witness crafting a leaf denominator of 0 propagates that denominator to the root, where the denominator check rejects it. Removing that check in a test-only fork of the assertion demonstrably lets it pass.
6. Gated-key twins cover three cases. Honest flag = 0 rows contribute exactly the neutral entry regardless of key-column garbage. Tampering a flag = 1 row's key fails. A table's real entry 0 and `ZeroEntry` are distinguished, which is the +1 offset test.
7. Decoder twins: honest cycle rows bind to `DecodedTables`. Tampering one decoded output fails, for example the claimed family mask for a pc. A mask value outside the legal domain fails, the all-zero mask included.
8. Multiplicity-only tamper: honest values with one multiplicity cell changed must fail.
9. Virtual-table cross-check: closed-form evaluation and direct multilinear evaluation agree at random points. The negative control perturbs the closed form.
10. Differential oracle: every committed generic table, `U16GetSign` included, is regenerated by an independent ISA-level reference computation and diffed. A poisoned table row is caught.
11. Obligation-discharge cross-check negative controls: an unconsumed `RangeObligation` and a doubly-consumed one each fail the build.
12. Booleanity: every extracted decoder bit carries x²=x, and a non-boolean bit witness fails.

## Handoff
Freeze the LogUp `GateDef` kinds, the channel ids, the root output-map names, the multiplicity conventions, the virtual-table closed forms, and the zero-padding, `ZeroEntry` and gated-key (+1) conventions. Freeze the decoder-lookup binding spec — key derivation, the packed-mask domain rule, and the decoder channel's padding-neutral MINUS_ONE-tuple entry, the documented `ZeroEntry` exemption of Must-be-exact 4. Freeze the obligation-discharge API over S14's `RangeObligation`, the `U16GetSign` table with its committed-or-closed-form answer for S17/S18, and the copower-pairing assertion of Deliver for S18/S19. S16 wires these channels into the real shard transcript flow and the single Mercury opening.