---
title: S18 — Shift/Bitwise + Mul/Div Families

---

# S18 — Shift/Bitwise + Mul/Div Families

## Depends on / Inputs
- From S11–S16 you consume what S17 consumed: `DecodedTables`; the `Emulator` and QEMU harness; `CircuitArtifact` and the checker; S14 memory gates and the register/x0 convention; S15 LogUp channels and table conventions; and S16's `ShardProof`, `VerifyingKey` and tamper harness. The add/sub wiring pattern and the per-query-kind Δ-slot assignment come with them, frozen in S12's MemoryEventLog timestamp convention and re-frozen as S16's per-family frame convention.
- S17 supplies the comparison-gadget helper API for div/rem magnitude comparisons, and the is-zero gadget, both as S17 froze them.

## Deliver
Deliver two circuit families as `CircuitArtifact` data, each with trace routing and S16-entry-point wiring:
- **shift_binop** covers SLL, SLLI, SRL, SRLI, SRA, SRAI, AND, ANDI, OR, ORI, XOR, XORI.
- **mul_div** covers the full signed RV32M set: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU.

Also deliver new setup/virtual tables under S15's conventions: ShiftPowers, 32 rows mapping s ↦ (2^s, 2^(32−s)), and the byte AND table, whose domain supplies the byte bounds; both ship this stage. Commit per-instruction fixture programs for the differential suite.

## Core algorithm
**Shifts.** Truncate the amount with `rs2_or_imm = 32·high + amount`. The ShiftPowers table domain bounds `amount` to [0,32); the table IS the bound. `high` is range-checked. Never leave the shamt free: an `amount` used only as the lookup key is prover-chosen, so SLL with rs2 = 4 shifts by 8. SLL uses `rs1·2^s = rd + 2^32·overflow`, with rd and overflow both range-checked. SRL and SRA use the floor-division identity `(rs1 − 2^32·se) = (rd − 2^32·se)·2^s + residue`. `se` is the sign-extension term: 0 for SRL, sign-weighted for SRA with its sign from U16GetSign, and committed as its own helper `se = is_arithmetic·rs1_sign` to keep that line degree 2. Enforce `2^s·2^(32−s) = 2^32` on the looked-up pair too; it licenses the residue bound. Bound `residue < 2^s` with the copower pattern. A constraint DEFINES `scaled = residue·2^(32−s)`; range-check that column without the definition, and `scaled` = 0 discharges both lookups, leaving `residue` free to absorb `rs1 − rd·2^s` for ANY rd. `scaled` is range-checked, AND `residue` itself is direct-range-checked, because the scaled bound alone bounds nothing over Fr.

**Bitwise.** Decompose rs1 and the second operand `rs2 + imm` into bytes, 4×u8 each, with byte bounds from the table domain — one expression covers XOR and XORI alike, and the immediate never enters the permutation-tied rs2 column. Compute AND through byte-table lookups, then derive per byte `xor = a + b − 2·and` and `or = a + b − and`, and recompose rd by weights. Gate that rd term with the bitwise family bit, not the bracket: the op selectors are zero on a shift row, so a bare rd would force rd = 0 and break every shift.

**Mul.** Adjust each operand by its sign: `rs1_adj = rs1 − 2^32·s1`, likewise for rs2. Witness the signs via U16GetSign and select the adjustment per op. MUL and MULH are signed×signed, MULHSU is signed×unsigned, and MULHU is unsigned×unsigned. Unsigned positions force the sign flag to 0 through decoder-preprocessed flags, keeping selection at degree 2. ONE product identity serves all four: `rs1_adj·rs2_adj = product_low + 2^32·product_high − 2^64·product_sign`. Both halves are range-checked, and product_sign is boolean-constrained. The field identity equals the integer identity because both sides are ≪ r. rd is product_low for MUL and product_high for MULH/MULHSU/MULHU.

**Div/Rem.** The identity `rs2_adj·q_adj + r_adj = rs1_adj` holds unconditionally; on a zero divisor it degenerates to rem = dividend and says nothing about q. Two further constraints pin truncation toward zero:
- (a) `rem ≠ 0 ⇒ sign(rem) = sign(dividend)`, via the witnessed-inverse is-zero gadget. It separates truncated from floored division and is the easiest line to leave out. Without it every inexact division has a floored witness too, so DIV(−7, 2) takes −4 as readily as −3; and on unsigned rows, where that sign is 0, it is the only thing forcing a non-negative remainder, so DIVU(0xDEADBEEF, 0x1234) returns 801702 for 801701.
- (b) `|rem| < |divisor|`, enforced by magnitude gadgets plus a range-checked gap carrying a zero-divisor correction term, so a zero divisor imposes no bound, as it must.

Div-by-zero is pinned to q = 2^32 − 1, rem = dividend. Overflow is pinned so that −2^31 ÷ −1 yields q = −2^31, rem = 0.

**Shape.** Both families carry 15 memory columns. shift_binop commits 46 witness columns, keeps exactly two never-committed inner-layer values — the AND accumulator and the scaled residue — and runs 19 degree-2 and 9 degree-1 constraints over 4 gate layers plus an output layer. mul_div commits 56 witness columns, nothing at inner layers, and runs 41 degree-2 and 15 degree-1 constraints over 5 gate layers plus an output layer. Masks are 2 one-hot family bits for shift_binop, shift and bitwise, and 8 for mul_div, one per opcode. Preprocess every degree-2 helper flag in the decoder: shift-direction and arithmetic, three bitwise selectors, two operand-signedness flags, four result selectors.

## Must-be-exact
1. Shift-amount truncation works exactly as above. ShiftPowers is 32 rows exactly, and its (2^s, 2^(32−s)) pair is what the copower uses.
2. Every copower-scaled column also carries its own direct 16+16 range check, no exceptions: a scaled bound is only the variable-width HALF of a bound. S15 froze it as the copower-pairing assertion.
3. XOR and OR are derived from the single AND accumulator. There are no separate XOR or OR tables.
4. The single product identity covers all four multiplies. The division identity holds unconditionally and is accompanied by constraints (a) and (b). The div-by-zero and overflow pins are present. Each of these is individually testable.
5. All boolean helpers carry booleanity constraints: sign bits and their sign-weighted forms, product_sign, and wrap/overflow bits. Every produced word or half is range-checked. rd=x0 legal-mask rows exist for every instruction per the S14 convention.
6. rd selection between product_low and product_high, and between q and rem, is gated by committed bits, never bare decoder outputs: every selector is a sum of family bits. The decoder tuple is never queried on padding rows, so decoder facts are void there: an ungated selector lets padding write a free word to rd.
7. shift_binop ships as one merged family, never split into shift and bitwise halves. The halves share only 12 witness columns against 16 shift-only and 15 bitwise-only, so split circuits of ~43 and ~42 base columns against 58 merged would save about a quarter of the committed area. Ship it merged anyway: Deliver, Acceptance 8 and the Handoff all freeze a two-family count.
8. The div/rem magnitude gadgets and the `rem ≠ 0` test call S17's frozen comparison-gadget and is-zero helper APIs, not a family-local reimplementation. If a frozen helper proves genuinely inadequate, extend it additively and record the extension in your handoff.

## Acceptance
1. Per-instruction differential for all 20 instructions: run committed fixtures through the S12 emulator and qemu-riscv32, require identical register traces, then produce shard proofs that verify through the S16 entry point (at least one proof per family).
2. Shift edge fixtures cover shamt 0, 1 and 31; rs2 = 32 and 33 for truncation; SRA of negative values; and SRAI versus SRLI on the same negative operand.
3. The signed-multiply matrix runs all four sign quadrants for MUL/MULH/MULHSU/MULHU differentially against the emulator. It includes −2^31 × −2^31, the asymmetric MULHSU case −2^31 × (2^32−1), and MULHU near-2^64 products.
4. The div/rem matrix covers all sign quadrants for DIV/REM; div-by-zero for DIV, DIVU, REM, REMU; and the −2^31/−1 overflow case. It also carries a fixture where the floored, wrong quotient would satisfy the bare division identity. With truncated semantics tampered to floored, that fixture must be unprovable.
5. Exhaustive reduced-width check of the division encoding: at reduced width, enumerate (dividend, divisor) pairs signed and unsigned, and verify that exactly one (q, rem, signs, gap) witness satisfies the constraint set.
6. Table differentials: regenerate ShiftPowers and the AND byte table, and compare them against an independent ISA-level recomputation.
7. Derived-op exhaustive check: XOR and OR as derived from AND match reference bitwise results over the full 8-bit × 8-bit byte domain, all 65,536 pairs. Run it as a unit test against the committed table.
8. Tamper twins run one per family. For shift_binop, corrupt one `residue` cell in an honest trace; it must fail with the expected error class. For mul_div, corrupt one `product_high` cell, which must fail too. Honest twins pass, and structural count assertions run.
9. A rd=x0 coverage test runs per family. Canonical padding rows pass the checker validators. Artifacts are regenerated and diffed in CI.

## Handoff
Freeze both families' `CircuitArtifact`s: names, column maps and legal-mask sets. Freeze the ShiftPowers and AND-table schemas with their generation paths, the trace-buffer schemas and the fixture locations. Freeze the name signatures of the magnitude and is-zero helper APIs S19's AMO ops may reuse.
