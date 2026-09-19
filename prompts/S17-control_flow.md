---
title: S17 — Jump/Branch/SLT Family

---

# S17 — Jump/Branch/SLT Family

## Depends on / Inputs
- S11 (`isa`/`program`) gives `Instr`, `DecodedTables` with pc/2 indexing and the `-1` padding sentinel, `VmConfig` derivation, and `ProgramIdentity`.
- S12 (`emulator`/`trace`) gives `Emulator`, `MemoryEventLog`, `TraceArchive`, and the QEMU differential harness.
- S13 (`constraints`/`gkr`/`checker`) gives `PolyAddress`, the `CircuitArtifact` schema, the forward/backward engine, and the law validators.
- S14 gives the memory-argument gates, the 19+19 timestamp gadget, the PC address space, the register/x0 convention and the padding-row fill convention. Consume it, never redesign it.
- S15 gives the LogUp channels (16-bit range, generic, decoder lookup), the multiplicity conventions, and U16GetSign with the other tables as frozen.
- S16 gives `ShardProof`, `VerifyingKey`, the verifier entry point, the tamper harness, the packed-decoder-mask and witnessed-inverse is-zero gadgets, add/sub as the worked wiring pattern, and the per-query-kind Δ-slot assignment frozen across S12 and S16 as the per-family frame convention.

## Deliver
- Build the jump_branch_slt circuit family as `CircuitArtifact` data in `constraints`, route its trace buffers in `trace`, and wire prover and verifier so guests using it prove and verify through the existing S16 entry point; add none of your own.
- Cover exactly these instructions, enumerated in the artifact: JAL, JALR, BEQ, BNE, BLT, BGE, BLTU, BGEU, SLT, SLTU, SLTI, SLTIU.
- Register the legal-mask set below in the decoder table domain, rd=x0 variants included.
- Commit per-instruction fixture programs under the S12 harness's conventions — the differential suite of Acceptance 1.
- Expose the comparison-gadget helper and the is-zero gadget as named public signatures, frozen in the Handoff.

## Core algorithm
**Comparison.** One ungated degree-2 equation settles signed and unsigned ordering together:
`0 = rs1 − b − 2^32·sc·sign(rs1) + 2^32·sc·sign(b) + 2^32·lt − gap`
`b` is `rs2 + cmp_imm`, `sc` the decoder's signed-compare flag, both signs from U16GetSign lookups on witnessed high halfwords, `lt` boolean, `gap` range-checked to [0, 2^32) by the 16+16 pattern. That range check carries the soundness: at rs1 ≥ b only `lt` = 0 keeps the gap under 2^32, at rs1 < b only `lt` = 1 keeps it non-negative, so exactly one survives per sign quadrant. The two sign terms take both operands to two's complement first, so mixed signs are never a case split.

`cmp_imm` and the branch displacement are separate decoder outputs, `cmp_imm` zeroed on BRANCH rows; share one column and every branch would compare rs1 against rs2 + offset. `b` needs its own bound below 2^32, supplied by the halfword witnessed for its sign: send `(rs2 + cmp_imm) − 2^16·b_hi` and `b_hi` to the 16-bit channel, leaning on the decoder invariant "if imm ≠ 0 then rs2 = x0" to stop that sum carrying. And no comparison table — the retired Airbender `ConditionalJmpBranchSlt` mis-ordered mixed-sign SLT/BLT/BGE and read SLTI's sign from rs2's high limb alone.

**Equality.** BEQ/BNE use S16's witnessed-inverse is-zero gadget on `diff = rs1 − rs2 − cmp_imm`: `eq·diff = 0` and `diff·inv + eq − 1 = 0`, so `eq` is boolean for free.

**Branching.** The branch decision is a decoder-supplied linear form over (const, eq-weight, lt-weight), weights pinned in Must-be-exact 7. Every non-branch row carries the zero triple, which already gates that column and holds next-pc at degree 2. Re-gate the taken contribution with a committed bit, `taken = family_bit[BRANCH]·should_jump`: the decoder tuple is never queried on a padding row, so an ungated `should_jump` lets padding teleport the pc.

**Next-pc.** The decoder supplies the sequential next-pc and the target-forming immediate. Compute `next_pc = taken·target + (1−taken)·seq` at degree ≤ 2 and write it to the PC address space — no pc-chaining constraints. JAL and JALR reach their targets through their own committed selector bits, not the branch weights. Two parts stay ungated: the mod-2^32 reduction and its wrap bit, applying to whichever target the selectors produced and never sitting inside the JAL bracket, since a sign-extended negative displacement pushes the sum past the word and a gated wrap makes every backward branch unprovable; and the default arm, so a mask-zero row still advances well-formedly, filled per S14's convention.

**JALR and the link.** The JALR target is `(rs1 + imm)` with bit 0 cleared via a witnessed dropped bit, boolean and constrained. Being a different sum from the pc advance it takes its own wrap bit, forced by the range check that stops the target leaving the word. No alignment constraint is needed: the next fetch is a decoder-table lookup at target/2, so an undecoded target address is unprovable. Both write the link `pc_after_instr` to rd, itself reduced mod 2^32 with a wrap bit and range-checked — otherwise a JAL at 0xFFFFFFFC writes 0x100000000 into x1.

**The family mask.** Take S16's packed-decoder-mask gadget unchanged. Bits: 0 = JAL, 1 = JALR, 2 = SLT-family, 3 = BRANCH, 4 = RD_IS_ZERO. Bit 4 is an independent modifier, not part of a one-hot — set on every branch and on JAL, JALR or SLT writing x0 — so the legal set is `{1, 2, 4, 17, 18, 20, 24}`, and the domain lookup `(execute flag, mask) ∈ {(0,0)} ∪ {(1,m) : m legal}` keeps padding legal. Mask 20, SLT writing x0, is the one easily left out. A BRANCH always sets bit 4, so selected-rd is free there and masking forces rd = 0.

Trace buffers route the way S16 routes add/sub; fixtures get one directory per instruction.

## Must-be-exact
1. Use the comparison equation above: `gap` direct-range-checked, `lt` boolean, no comparison lookup table.
2. Signed and unsigned selection happens only via `sc`, and SLTI/SLTIU compare against the sign-handled immediate carried by `cmp_imm`. The SLTI defect above must have no analogue, and you write the test that catches it.
3. Taken-branch and link-write terms are gated by committed bits, never by bare decoder outputs.
4. rd writes follow the S14 register/x0 convention, and the legal-mask set is exactly `{1, 2, 4, 17, 18, 20, 24}`: every instruction with its rd=x0 variant, mask 20 included.
5. The per-row memory frame is a pc read, a next_pc write, and the register reads and writes, all inside the uniform Δ ∈ {0..3} budget of that Δ-slot assignment. Every produced value is range-checked or boolean per master invariant 6: lt, gap, target, link, halfwords, and the dropped bit.
6. SLT-family rows take the decoder-supplied sequential next-pc, and rd gets the same `lt` the branch path consumes — one gadget, two consumers, never two encodings.
7. The branch linear form carries exactly these decoder weight triples (const, eq-weight, lt-weight): BEQ (0, 1, 0), BNE (1, −1, 0), BLT/BLTU (0, 0, 1), BGE/BGEU (1, 0, −1), and (0, 0, 0) on every non-branch row.
8. Comparison intermediates are committed base-layer columns; four gate layers sit above that base plus one output layer, and no value lives at an inner layer.

## Acceptance
1. Per-instruction differential: for each of the 12 instructions, committed fixtures run through the S12 emulator and qemu-riscv32 with identical register traces, then prove and verify as a `ShardProof` through S16's entry point.
2. Exhaustive reduced-width comparison check: at a reduced word width, enumerate all operand pairs × {signed, unsigned} and verify exactly one (lt, gap) satisfies the constraint in every sign quadrant. At full width also pin BLT(0x80000000, 1), BGE(1, 0x80000000), BLTU(0x80000000, 1) and a mixed-sign SLT, each answering correctly.
3. Control-flow matrix: taken and not-taken branches, forward targets, a backward branch of −16 closing a loop, and JAL's link and target. Then JALR with rs1 == rd and a negative immediate setting bit 0 of rs1+imm: the old rs1 forms the target, the link is written after, and the test sees bit 0 cleared.
4. SLTI/SLTIU: run `SLTI x5, -1` and `SLTIU x5, -1` against positive and negative rs1 — regression fixtures for the SLTI defect.
5. rd=x0 coverage: JAL x0 (the plain jump idiom) and SLT/SLTU/SLTI/SLTIU with rd=x0 all prove, and x0 reads back 0.
6. Fetch binding: a branch to an address holding no decoded instruction is unprovable, failing loudly via the `-1` sentinel; demonstrate it on one fixture.
7. Tamper twin: an honest branch-heavy guest verifies Ok. Re-proving with one corrupted `lt` cell — bus-pinned, from a not-taken branch row — fails with the expected error class. Second target: the written next_pc cell, failing via the global memory argument.
8. Padding: the canonical padding row passes all checker validators and advances the pc rather than demanding next_pc = 0; regenerate and diff the artifact in CI.
9. Structural: a checker assertion that the legal-mask set equals exactly the instruction list × its modifier bits, so an extra or missing mask fails CI.

## Handoff
Freeze the family's `CircuitArtifact` — name, column map, legal-mask set — its trace-buffer schema in `trace`, the fixture-suite location, and the comparison-gadget and is-zero APIs as named signatures. S18 consumes those for div/rem magnitude comparisons and the rem≠0 test, S19 for AMO min/max.
