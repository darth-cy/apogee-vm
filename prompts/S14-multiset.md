---
title: 'S14 — Memory multiset argument, timestamps, init/teardown'

---

# S14 — Memory multiset argument, timestamps, init/teardown

## Depends on / Inputs
- S13 gives you `PolyAddress`, `GateDef`, `LayerSpec`, `CircuitArtifact`, `gkr` forward/prove/verify, checker validators and the witness-row evaluator.
- S12 gives `MemoryEventLog` and `TraceArchive`, the source of real memory events for tests.
- S11 gives `ProgramIdentity` and `DecodedTables`; S10 gives `ProgramImage` and io_digest, the frozen public I/O digest convention.
- S01–S04.

The LogUp discharge of range obligations arrives in S15: this stage DEFINES range obligations as artifact data and validates them with the checker, but builds no lookup channels.

## Deliver
- `constraints` gains new `GateDef` kinds, all as data: a tuple-compression gate, grand-product tree gates including `MaskIntoIdentity` (out = in·mask + (1−mask)), and init/teardown pair gates.
- The init/teardown circuit family ships as a `CircuitArtifact` with closed-form virtual address enumeration, zero committed address columns and zero row constraints. Correctness lives in the product gates. The artifact shape is deliberate: memory-subtree columns only, no witness columns, no algebraic constraints at all, a base layer pairing tuples and a binary product tree above it up to a two-wide output layer carrying the read and write roots.
- The timestamp gap gadget brings column conventions plus a `RangeObligation` data format of channel id, expression and bound, recorded in the artifact for S15 to discharge.
- Register-file conventions cover the x0 mechanism.
- Two public builders, `build_memory_columns(log: &MemoryEventLog, window, height) -> MemorySubtreeColumns` and `build_init_teardown_columns(log, image: &ProgramImage, ...)`. The first keys its columns by the artifact's memory-subtree `PolyAddress`es. S16/S20 consume both rather than re-deriving the fill. The padding-row fill convention for memory-subtree columns is stated here, closing the S12 deferral: mask = 0 rows carry 0 in every memory-subtree column, meaning addresses, timestamps, Δ, values and AS discriminators. `MaskIntoIdentity` makes their product contribution 1 regardless, and the builders fill them deterministically.
- The checker gains a forward-pass self-check hook that recomputes read/write roots directly from materialized layers, plus a `RangeObligation` evaluator doing a native membership check.

## Core algorithm
Follow the master invariant "Memory argument (global)".

There is no trusted RAM inside a proof: a prover claiming address `a` held `v` at cycle `t` must be pinned to what it last claimed to have written there, or it answers every read however it likes. The device is offline memory checking — two shuffles make a RAM. A read consumes the tuple the last writer produced and produces a fresh one stamped now, so a consistent machine has read multiset equal to write multiset once boundary tuples, initial values in and final values out, are folded in. Compressing each tuple to one field element under random challenges turns that equality into a product comparison.

Each event compresses to `γ_M + AS + α_addr·ADDR + α_ts·(TS+Δ) + α_val·VAL`. Read and write multisets are compared as grand products up a binary tree per family: a base gate multiplies two compressed tuples, an interior gate multiplies two partial products, a copy gate carries an odd remainder up a level unchanged, and `MaskIntoIdentity` sits at the leaves. Their roots are exposed in the artifact output map and reconciled globally. Address spaces are registers, RAM and PC. PC continuity means each cycle reads pc and writes next_pc; there is no per-shard pc chaining.

Init/teardown is a dedicated family with closed-form address enumeration, so uniqueness holds by construction. Non-image addresses take value 0 at ts 0, program-image addresses are bound to `ProgramIdentity`, and teardown tuples carry final value plus final ts. Public-I/O binding of teardown values is exercised end-to-end from S16 on; the mechanism lands here.

Witness generation walks the `MemoryEventLog` in recorded order, the emulator's deterministic single pass, and fills each row's fixed Δ slots 0 through 3. Last-write bookkeeping keeps (value, ts) in a dense array for registers and PC and a hash map for RAM. Toy families carry only the pinned tuple-feeding and mask columns.

## Must-be-exact
1. The tuple takes exactly the shape above: 4 parts, γ_M additive, 3 linearization challenges. Part order and the (address, timestamp, value) → (α_addr, α_ts, α_val) assignment are named indices in `constants` that every builder and gate constructor reads rather than hardcoding a position. Pin the AS encoding for registers, RAM and PC there too.
2. S8's pre-commit partition holds: every column any global challenge touches carries a memory-subtree `PolyAddress`. That set covers addresses, values, timestamps, Δ slots, AS discriminators and the mask/execute column. A construction-time assertion enforces the rule, so violating circuits fail to build.
3. Padding rows contribute exactly 1 to every product via `MaskIntoIdentity`, and padding-sensitive logic is never gated on decoder outputs.
4. Timestamps are 38-bit, STEP = 4, and Δ ∈ {0,1,2,3} uniform for all families. Per read, `gap = (ts + Δ) − read_ts − 1` splits 19+19, and only the high chunk `h` is a witnessed column: because a lookup expression IS a linear form, the low chunk is simply the expression `gap − 2^19·h` and costs no column. One column, two lookups, and nothing left for a constraint to say, so the gadget carries zero row constraints. Both chunks are emitted as `RangeObligation`s on the timestamp channel. That shape is also the general range convention this stage freezes for later families: a 32-bit value is bounded by one witnessed halfword and two lookups, and any `mod 2^32` result carries `<exact expr> = <result> + 2^32·<wrap>` with `wrap` witnessed and booleanity-constrained. `RangeObligation` is the data form of all of it.
5. Every emitted `RangeObligation` survives to the artifact, guarded by an artifact-level count assertion. The defect class is real: a range check correctly built and pushed into a collection its caller already consumed, so it never reaches the artifact and the bound it was meant to establish is enforced by nothing.
6. Init/teardown address enumeration is a closed-form virtual setup polynomial, never materialized or committed, and you state the closed form in the handoff. Init value is 0 at ts 0 for non-image addresses. Image addresses take their init value from `ProgramImage`, with the binding routed through `ProgramIdentity`. The register file inits x1–x31 to 0 at ts 0.
7. reads of x0 always yield 0, and no execution can make x0 nonzero. The argument and constraints enforce that, not convention, by write-redirect through value masking. Every register write emits its event at address rd with value `(1 − rd_is_zero) · selected_rd`. `rd_is_zero` comes from the whole-word is-zero gadget: witness an inverse `i` and a boolean `z`, then constrain `rd·i = 1 − z` and `rd·z = 0`, both degree 2, with `z` booleanity-constrained. The witnessed inverse is load-bearing: over a wide field nothing may be argued from non-negativity, since `c0 = 1, c1 = r − 1` sums to zero as happily as `0, 0`, so a zero test must be algebraic. Init/teardown enumerates x0 alongside x1–x31 at init value 0 and ts 0, since reads of x0 are real events needing a producing tuple. That masking rule binds every present and future family, and so covers rd = x0. Write it up as a ≤ 1-page design note.
8. Read/write roots appear in the output map under stable, named entries. The verifier-side reconciliation check is `read_root == write_root` over the exact family/shard set. The full cross-shard form lands in S20; the two-family form lands here.
9. The gap encoding is strict: gap ∈ [0, 2^38) holds exactly when read_ts < ts + Δ. Verify that strictness exhaustively at reduced width.
10. Every grand-product tree layer multiplies exactly two children, one layer per level, because all gates are capped at degree 2 in the layer below. `MaskIntoIdentity` sits at the leaf layer, and its `out = in·mask + (1−mask)` collapses to `in` at mask = 1 and to 1 at mask = 0. The 1 is the point: multiplication's neutral element, where a 0 would zero the whole product.
11. The closed-form enumeration partitions the row index into contiguous segments in a fixed order: register file, then PC, then RAM ascending. Address is affine in the index, and AS is constant inside a segment. The enumeration is therefore injective by construction and evaluable from the index alone.

## Acceptance
1. A hand-built two-family toy combines one main-ish family, carrying real events from an S12 `MemoryEventLog`, with the init/teardown family. The forward pass runs, and the self-check hook confirms read/write roots reconcile across both families. GKR proves and verifies both trees. The witness-row evaluator and all S13 law validators pass on both artifacts. Honest twin: `Ok`.
2. Tamper twin (the stage gate): change ONE memory event's value → root reconciliation fails or GKR verify fails. Honest twin unchanged passes.
3. Tamper twin: change ONE memory event's timestamp → fails. This is a distinct error from #2's class, where the failure surface differs.
4. S3 negative control, the future-read attack: forge a read/write pair consistently, with read_ts in the future, so multisets balance and roots reconcile. The `RangeObligation` evaluator catches it anyway, because gap falls outside [0, 2^38). The test comment must state that cryptographic discharge of this obligation is S15's gate.
5. S4 program-image binding: flip one byte of the `ProgramImage` used to build init tuples → roots no longer reconcile against the honest trace.
6. S4 uninitialized-memory control: an init tuple claiming a nonzero value at a non-image address is unconstructible via the closed-form path, and a hand-forged one breaks reconciliation.
7. Enumeration uniqueness and coverage: the closed-form enumeration emits each touched address exactly once, cross-checked against the `MemoryEventLog`'s touched-address set. A duplicated-address forgery breaks reconciliation.
8. x0 negative control: a trace attempting to make x0 read as nonzero fails under the pinned mechanism, and a guest-level read of x0 returns 0 in the honest twin.
9. S8 negative control: a test circuit placing a tuple-fed column at a witness-subtree address fails the construction-time assertion.
10. Padding: the toy padded to its menu height verifies, and a structural test shows padding rows contribute exactly 1 to each product.
11. Exhaustive reduced-width gap test (e.g. 5+5 chunks): the encoding accepts exactly the strict-ordering set, nothing else.
12. Obligation-count assertion negative control: a gate whose emitted obligation is dropped before artifact write fails the build.

## Handoff
Freeze the memory gate kinds, as `GateDef` variants plus artifact data, with the tuple part order and AS constants. Freeze the `RangeObligation` format and the gap-gadget column conventions. Freeze the init/teardown `CircuitArtifact` and its closed-form enumeration spec. Freeze the register and x0 conventions, and the output-map names for read/write roots. Freeze the two public builders of Deliver, `build_memory_columns` and `build_init_teardown_columns`, which S16/S20 consume rather than re-deriving the fill, and with them the padding-row fill convention for memory-subtree columns — the values a mask = 0 row carries.

The handoff must state exactly which mechanism binds teardown final values to the public I/O digest, S10's `io_digest`. That mechanism lands here, and S16's teardown-binding tamper acceptance targets it. S15 discharges `RangeObligation`s; S16 draws the real global challenges per the master absorb order.