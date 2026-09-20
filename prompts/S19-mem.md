---
title: S19 — Memory-Op Families + Atomics

---

# S19 — Memory-Op Families + Atomics

## Depends on / Inputs
- S11 gives you `DecodedTables`, `VmConfig` derivation (static detachment plus the family-partition check) and `ProgramIdentity`.
- S12 gives you the `Emulator`, the `MemoryEventLog` and the QEMU differential harness. That harness must already execute RV32A; if S12 left A untested, extend its config additively.
- S13 gives you `CircuitArtifact` and the checker. S14 gives you the memory gates, word-addressed address spaces, the 19+19 gap gadget, the register/x0 convention and the uniform Δ ∈ {0..3} budget. S15 gives you the LogUp channels, the 16+16 range checks and the gated keys. S15 also froze the copower-pairing construction-time assertion: every copower-scaled column also carries its own direct range check.
- S16 gives you `ShardProof`, `VerifyingKey`, the verifier entry point and the tamper harness. You also inherit the per-query-kind Δ-slot assignment. S12's `MemoryEventLog` timestamp convention froze it, and S16's handoff re-froze it as the per-family frame convention. S17 supplies the comparison helper for AMOMIN/MAX, and S18 the bitwise gadgets and is-zero/magnitude helpers as frozen.

## Deliver
Deliver three circuit families as `CircuitArtifact` data, with trace routing and S16-entry-point wiring:
- **mem_word_only**: LW, SW. One store bit, masks `{0, 1}`.
- **mem_subword_only**: LB, LBU, LH, LHU, SB, SH. Bits 1 = STORE, 2 = BYTE, 4 = SIGNEXTEND; masks `{0, 1, 2, 3, 4, 6}`, 5 and 7 excluded.
- **atomics**: LR.W, SC.W, AMOSWAP.W, AMOADD.W, AMOXOR.W, AMOAND.W, AMOOR.W, AMOMIN.W, AMOMAX.W, AMOMINU.W, AMOMAXU.W.
- The MemoryOffsetGetBits setup table maps an offset to the splice power 2^(8·offset) and its copower, per S15 table conventions.
- Committed per-instruction fixture programs accompany the families, including an atomics guest and an A-free guest for the detachment tests.

## Core algorithm
**Addressing (both mem families).** The effective address is rs1 + imm with a witnessed wrap bit. Decompose it as `addr = 4·word_index + 2·bit1 + bit0` with both bits boolean. That equation is an alignment check over ℤ and NOTHING over Fr: 4 is a unit there, so `word_index := addr·4⁻¹ mod r` (a huge field element, not a small integer) satisfies it for ANY address, and misaligned LW and SW prove as if aligned. Enforcement is the range check on `word_index`, which makes the split genuinely base-4. Word accesses force bit1 = bit0 = 0; halfword accesses force bit0 = 0 by their own constraint, since nothing else gives bit 0 any effect there. Misaligned accesses are unprovable, which is the machine's contract for well-behaved guests. The S12 emulator must treat misalignment as a fatal guest error, so no trace exists to prove.

**Sub-word splice.** Memory is word-addressed, so sub-word queries name the same `4·word_index` address the word family uses: one memory, not two. A byte-address form there is a broken memory model: LB at one word's four offsets names four DIFFERENT cells, and a byte SB wrote is invisible to a later LW. Extraction is `word = high·(w·p) + sub·p + low`, with the variable power `p = 2^(8·offset)` and width `w` from MemoryOffsetGetBits. Each of high, sub and low carries BOTH its copower-scaled bound and its own direct range check; three such bounds were missing once: `sub < w` VARIES row to row (256 for a byte, 65536 for a halfword), so no fixed-domain table enforces it, and unscaled it let LBU extract a three-byte "byte"; a free `high` leaves the decomposition non-unique; a free store source lets SB store a byte unrelated to rs2, so truncated rs2 is witnessed and bounded too. A store is a single splice, `new_word = old_word + (src_sub − old_sub)·p`, with no clear-then-set tables, which holds only because all three parts are bounded. LB and LH sign-extend from the sub-word's sign. BYTE and SIGNEXTEND are modifier bits in the legal-mask domain, so store+signextend is an illegal mask excluded by the table domain, not by a constraint. Values READ from memory are exempt from range checks (write-side induction); every produced part is checked.

**Atomics.**
- Each row carries four data queries. Each query carries a read_value and a write_value at one address, so a read-modify-write is ONE query: rs1 read, rs2 read, the memory RMW, the rd write. Loads, stores and LR.W fit in three (LR.W is a plain word load), but SC.W and the nine AMOs write memory AND a register in one instruction, which no RV32I instruction does, and one instruction is one row. Rather than break stride uniformity, S14 gave EVERY family the four-slot Δ budget; seven of eight leave one unused, at 25% of the timestamp range.
- SC.W always succeeds: it stores src and writes rd = 0. The spec wants it to fail with no valid reservation, so this is a conformance deviation, not a soundness one (the verifier still knows which program ran), and fidelity would cost a reservation flag in machine state. LLVM never emits an unpaired SC nor relies on spurious failure. Frozen, and whitelisted in the QEMU differential harness. Because SC.W never fails the emulator carries no reservation state, so emulator and circuit share one semantics.
- For the AMOs, rd receives the OLD memory value and the stored value is op(old, rs2). ADD goes via add+wrap, AND/OR/XOR via S18's byte gadgets, MIN/MAX/MINU/MAXU via S17's comparison gadget selecting old or rs2 by `lt`.
- Static detachment: the preprocessor derives the family set from the decoded program, so an A-free guest's `VmConfig` simply lacks this family, which also keeps a guest with a dozen atomics off a full-height trace.

Build every fixture at trace height 2^16, the menu's smallest, because fixture traces are tiny; real assignments are finished later. Organize the fixtures one directory per family.

## Must-be-exact
1. Alignment is enforced solely by the range check on `word_index`, plus booleanity of bit1 and bit0 and the separate halfword bit0 = 0 constraint. No divisibility equation is trusted for anything.
2. Unified word addressing holds: sub-word and atomic queries name `4·word_index`, and byte/halfword position lives only in the splice, never in the memory tuple's address.
3. The splice identity carries the copower plus mandatory direct range checks on all three parts and on the store source, and the copower-pairing construction-time assertion frozen in S15 must cover them.
4. SC.W always succeeds and writes rd = 0. The deviation is documented in the handoff and carried as an explicit whitelist entry in the QEMU harness — never a silently-ignored diff.
5. Atomics use the four-query frame, reading and writing the same word address in one row, ordered by Δ slots per that frozen assignment (S12/S16, see Depends); rd gets the old value for every AMO.
6. rd=x0 legal-mask rows exist for all loads, LR.W, SC.W and the AMOs, per the S14 convention. SB, SH and SW have no rd write.
7. Static detachment is decided by the preprocessor from the decoded program only, never by a flag. An A opcode under a detached-atomics config is a loud family-partition failure, the S11 mechanism exercised here.
8. MemoryOffsetGetBits has exactly seven rows, and the artifact documents them. Row 0 is a ZeroEntry serving gated padding keys. The other six are live rows keyed by `1 + bit0 + 2·bit1 + 4·BYTE`: the four byte offsets, plus the two halfword offsets that bit0 = 0 permits. Byte and halfword never share a row even where `p` coincides, because each row also carries the access width and its copower, and the key must pin the position: a freely chosen position is a freely chosen sub-word.
9. Every column that a lookup key or a memory tuple reads is a committed base-layer column. Inner layers carry only degree-reduction products. Introduce those through a pre-gated decoder flag or a booleanity-constrained helper column wherever a gate would otherwise reach degree 3.

## Acceptance
1. Per-instruction differential for all 19 instructions: run the committed fixtures through the S12 emulator and qemu-riscv32 and require identical register traces, SC.W via the documented whitelist entry. Shard proofs must then verify through the S16 entry point, at least one proof per family.
2. Exhaustive reduced-width splice check: enumerate (word, offset, width) at reduced width and verify that exactly one (high, sub, low) witness satisfies the splice and bound constraints in each case.
3. Load/store matrix: exercise LB/LBU at all four byte offsets and LH/LHU at both halfword offsets, verifying sign- and zero-extension. SB and SH must leave the other bytes of the word intact, checked differentially against the emulator, and LW/SW must round-trip.
4. Misalignment: LW with addr ≡ 2 (mod 4) and LH at an odd address are unprovable. Trace generation and proving fail loudly, and the emulator reports a fatal guest error with no silent wraparound.
5. Atomics semantics matrix: prove an LR/SC loop and assert SC.W rd = 0. Run every AMO with sign-boundary operands, so MIN disagrees with MINU and MAX with MAXU across 0x7FFFFFFF/0x80000000. Run two consecutive AMOs to the same address, which exercises timestamp ordering. Assert rd = old value for each AMO.
6. rd=x0 coverage: LW x0 and AMOADD.W x0 prove, and x0 still reads 0.
7. Static detachment. (a) The fib (A-free) guest's derived `VmConfig` excludes the atomics family, asserted from the derived config, not logs. (b) A hand-built image containing an A opcode fails preprocessing loudly against a detached config. (c) The atomics guest's config includes the family and the family-partition check passes.
8. Tamper twins run one per family, and each must fail. For mem_word_only, corrupt one loaded-value cell: no gate reads it, so only the memory multiset pins it and the failure must surface from the permutation product. For mem_subword_only, corrupt one `low` splice cell; for atomics, the rd old-value cell of one AMO. Honest twins pass, and structural count assertions run.
9. Canonical padding rows pass all checker validators for all three families; artifacts are regenerated and diffed in CI.

## Handoff
Freeze the three `CircuitArtifact`s: their names, column maps and legal-mask sets, including the BYTE and SIGNEXTEND modifier bits. Freeze the MemoryOffsetGetBits schema and its generation path, the trace-buffer schemas and the fixture locations. Freeze the SC-always-succeeds whitelist documentation. Freeze also the atomics family's four-query use of the S12/S16-frozen Δ-slot assignment. S20 and later treat all family frames as final after this stage.