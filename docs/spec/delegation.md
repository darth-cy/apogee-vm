# Delegation

The delegation ABI: how a guest hands a frame of RAM words to a circuit with an `ecall`, how each
request pairs with exactly one invocation, how a program declares the families it calls, and how
each family is sized. Frame layouts and circuits are
[delegation-circuits.md](delegation-circuits.md)'s, the recursion format's four families
[recursion.md](recursion.md)'s.

## 1. What a delegation family is

A **delegation family** proves a function of guest memory too costly to run as instructions. It is
invoked, never decoded: its number is a run-time value of `a7`, so it claims no pc and has no
decoded table. A row is one **invocation**, which rides the cycle that requested it and owns no
cycle ([execution-trace.md](execution-trace.md) §1); its accesses join the one memory multiset;
it is in a `VmConfig` exactly when the image declares it (§7). Otherwise it is an ordinary family,
an arm in `constraints::family_circuit` and a fill in `prover::family_fill`. A call is one row, the
anchor's two leaves being a row's (§5); an operation wider than a row is several calls on one
frame, chained through RAM ([delegation-circuits.md](delegation-circuits.md) §1, RAM glue).

## 2. The calling convention

A call is an `ecall` ([ecall-abi.md](ecall-abi.md) §1): `a7` the number, `a0` the frame base. It
writes 0 to `a0` and falls through ([execution-trace.md](execution-trace.md) §6); a
recursion-format type writes `a0 + 4·words` instead ([recursion.md](recursion.md) §1.4).

An executor without a family's circuit answers `-ENOSYS`, on which a base-format shim's caller
computes the same function in software, so an executor may implement any subset of the families;
any other nonzero answer is fatal ([ecall-abi.md](ecall-abi.md) §7).

## 3. The registry

`constants::delegation::TYPES`, also `program::DELEGATIONS`, is one table of
`(family, number, anchor space, frame words)`, ascending by family, which the emulator dispatches
on and `constraints::add_sub` builds its request gates from. The first `BASE_TYPES = 6` rows are
the base format's ([recursion.md](recursion.md) §1.2). Why each family has its height is §9's.

| family | id | number | anchor space | frame words |
| --- | --- | --- | --- | --- |
| `KECCAK_F` | 9 | `0x0507` | 4 | 51 |
| `POSEIDON2` | 10 | `0x0500` | 5 | 24 |
| `FR_ARITH` | 11 | `0x0502` | 6 | 25 |
| `MOD_MUL` | 15 | `0x0504` | 7 | 25 |
| `SHA256_COMP` | 16 | `0x0508` | 8 | 25 |
| `EC_ADD` | 17 | `0x0506` | 9 | 97 |
| `FR_OP` | 19 | `0x0509` | 11 | 4 |
| `P2_FIELD` | 20 | `0x050A` | 12 | 5 |
| `FIELD_IO` | 21 | `0x050B` | 13 | 3 |
| `FQ_OP` | 22 | `0x050C` | 14 | 4 |

`constraints::add_sub` asserts at compile time that every number is in the precompile range and not
`EXIT`, and that numbers and spaces are pairwise distinct, so an ecall row is the exit or a request
of one type; a type costs that circuit a selector `is_deleg_<f>`, three gates and a term in five
shared ones ([add-sub.md](add-sub.md) §2, §4). A type's **anchor space** is the type: only its
requests and invocations touch it, so the anchor's address is the frame base alone. A reserved
range of RAM would need an argument that no guest access reaches it.

## 4. The frame

A **frame** is `words` 32-bit words at the base `a0` names, word `j` at `base + 4j`, read and
written in place. Its base is word-aligned and it lies in RAM, `RAM_ORIGIN ≤ base` and
`base + 4·words ≤ 2^31`: the executor refuses any other (`Misaligned`, `OutOfBounds`, the sum taken
in `u64`) and the circuit has no witness for one ([delegation-circuits.md](delegation-circuits.md)
§1, frame chain). So no frame lies in a public window or in advice.

An invocation reads and writes every word, unchanged ones written back, each a RAM query of the
requesting cycle at slot `constants::delegation::FRAME_DELTA = 0`, ahead of the request's own
queries ([execution-trace.md](execution-trace.md) §4, §7).

## 5. The anchor

Requests and invocations pair one to one through the memory multiset, in the requested type's
anchor space `s`. Otherwise N requests could close against one invocation, N − 1 calls going
unexecuted, or an unrequested invocation could rewrite a frame.

### 5.1 The two sides

```text
                       reads                               writes
request (deleg)        T(s, a0, 0, 0)                      T(s, a0, 4c + 3, v)
invocation (anchor)    T(s, base, 4c + 3, anchor_value)    T(s, base, 0, 0)
```

The **request** is the `deleg` query of an `ADD_SUB_LUI_AUIPC` ecall row at cycle `c`
([memory.md](memory.md) §2.1): `deleg_mask_rule` makes its mask `m_pc·Σ_t is_deleg_t` and
`deleg_addr_rule` its address the `a0` the row read. One query serves every type, so its space is
`deleg_space`, an `M` column `deleg_space_rule` pins to `Σ_t tag_t·is_deleg_t`: a memory leaf may
read no `W` column, and the selectors are `W` ([memory.md](memory.md) §8).

The invocation's two leaves are the anchor read ([delegation-circuits.md](delegation-circuits.md)
§1): it writes the **answer**, stamped 0 with value 0, and reads back the request's write at
`4c + 3`, `c` its `cycle` column. `v` and `anchor_value` are free and cancel only when equal; an
honest prover writes 0 on both. Each answer starts a path one request long
([memory.md](memory.md) §9).

### 5.2 The three request-side zeroings

| gate, under the request's mask | forces |
| --- | --- |
| `deleg_writes_no_register` | 0 written to `a0`, so the result is not the prover's choice |
| `deleg_read_ts_zero` | the mirror read stamped 0 |
| `deleg_read_value_zero` | the mirror read's value 0 |

With `deleg_addr_rule` the last two make the mirror read the answer tuple, so every request
consumes an answer of its own; without the timestamp, requests at one base chain, each consuming
the previous one's write. The gates are the request row's, the same for every family, so the
pairing needs nothing from a family's frame, and a call that changes no memory value has nothing
else to expose it. The recursion format's `deleg_a0_rule` replaces the first
([recursion.md](recursion.md) §1.4).

### 5.3 Why the pairing is one to one

In `s` the only tuples are the requests' and the invocations': no instruction reaches it, no window
initializes it, nothing chains there (`trace::AddressSpace::chains`).

1. A live row's `4c + 3` is not 0: the request's pc write and the invocation's frame writes at `4c`
   lie on memory paths, whose timestamps are integers below `2^105` ([memory.md](memory.md) §4.2).
2. So the tuples stamped 0 are the requests' reads and the invocations' answers: as many
   invocations as requests, with the same multiset of bases.
3. The rest are the requests' writes and the invocations' reads. No two requests share a cycle
   ([memory.md](memory.md) §9), so each invocation's read is exactly one request's write: every
   invocation sits at its request's base and cycle, its frame accesses at that point of each word's
   history.

The trace-level check credits each anchor-space query with its invocation's tuples and sees none of
this ([execution-trace.md](execution-trace.md) §9).

## 6. The executor's side

For a registered number, `Machine::ecall` and `Machine::delegate` (`crates/emulator/src/lib.rs`)
read `a7` and `a0`; on the tracing paths refuse a family the `VmConfig` lacks (§7); read the frame,
refusing §4's rules; compute the function natively (`emulator::keccak_round`,
`transcript::poseidon2_permute`, `Fr`'s operators, schoolbook products with long division,
`emulator::sha256_call`) and write the whole frame back, a recursion family leaving it unchanged
and working on field cells; stage the mirror query, reading and writing 0; and write `a0`
(`constants::delegation::a0_after`).

`EmuError::DelegationFrame` refuses a frame the circuit has no witness for, which the arithmetic
would answer — long division is right for an unreduced operand too — leaving a proof that fails
inside the GKR pass with nothing named: a `KECCAK_F` round word above 23, a `SHA256_COMP` group
word above 15, an `FR_ARITH` code other than 1, 2, 3 or operand at or above `p` in memory form, a
`MOD_MUL` or `EC_ADD` selector naming nothing or operand its row reads at or above the modulus,
a `POSEIDON2` lane at or above `p`. The recursion families' refusals are
[recursion.md](recursion.md) §3–§6's.

The tracer records each invocation in its family's `trace::DelegationTrace`
([execution-trace.md](execution-trace.md) §11), which a shard reads as a `trace::FrameSlice`,
`⌈invocations / height⌉` shards a family. The fill (`prover::family_fill`) commits the recorded
words and derives the circuit's intermediates from those read. It never recomputes a written word:
what is committed is what the execution did, and the circuit says that is the function. The
circuit's side — frame chain, anchor read, gap decomposition, RAM glue — is
[delegation-circuits.md](delegation-circuits.md) §1's.

## 7. Static detachment

The instruction sweep cannot see a call, so each shim declares its family with a **declaration
record** (`constants::delegation`):

```text
MARKER_MAGIC = "APOGDEL1" (8 bytes) ‖ ecall number (u32 LE)          MARKER_BYTES = 12
```

`guest_sdk` emits one per family, a `static` whose `#[link_section]` is its own allocated section,
`.rodata.apogee.delegations.<family>`, which `link.ld`'s `*(.rodata*)` absorbs.

- **Its own section**, because the linker's garbage collection keeps or drops whole input
  sections: records sharing one would be kept together, and reaching one shim would declare all.
- **Kept by reachability**, not `#[used]`, which keeps every record in every guest. Only the
  family's shim references its record, reading its own number from it through
  `core::hint::black_box`: a linked shim has a record, calls the number it declares, and the
  optimizer cannot fold the read away.
- **Statically**: a call linked but never executed declares its family, which proves zero shards.

`program::declared_delegations` scans the image's file-backed bytes at every byte offset, a
`static`'s address being the linker's; a duplicate is one declaration, and a number no family
answers is `ProgramError::UnknownDelegation`. Identity binds a record through the image column
([program.md](program.md) §8).

A called number whose family the `VmConfig` lacks is the fatal `DelegationFamilyAbsent` on the
tracing paths; `emulator::run`, having no `VmConfig`, executes it. No proof covers it: the statement
has no shard of that family, so the mirror read has no answer to consume.

## 8. Shards, time windows and the block

A delegation shard's window is [proof.md](proof.md) §8's, taken over its invocations' requesting
cycles, so it lies inside the span of the `ADD_SUB_LUI_AUIPC` windows that made the requests. A
delegation family is not cycle-owning, so the block holds its windows to nothing beyond
`start ≤ end ≤ 2^38`; the anchor, not the window, places an invocation in time (§5.3).

## 9. Heights and channels

A height sets how many calls a shard holds and limits no program. It is a parameter
(`ProgramParams::heights`, defaulting to `constants::family::DEFAULT_HEIGHTS`,
[circuits.md](circuits.md) §1) in identity's `VM_CONFIG`: a program's, not an
execution's ([program.md](program.md) §7).

- **Floor**: `constraints::family_circuit` returns `None` below the most variables any of the
  family's channel tables needs (`constraints::lookup::table_vars`, [lookup.md](lookup.md) §3).
- **Trade**: a shard costs its height, not its occupancy ([streaming.md](streaming.md) §1), but its
  proof grows with the height only by a sumcheck round a variable in each gate list, a height
  changing no gate, only the number of halving lists. For a family with many calls the fatter
  shard is the smaller proof.

| family | channels | floor | unit of work | calls a unit | units a shard |
| --- | --- | --- | --- | --- | --- |
| `KECCAK_F` | `RANGE16`, `XOR8` | `2^16` | keccak-f[1600] | 24 | 10,922 |
| `POSEIDON2` | none | none | width-3 permutation | 1 | 256 |
| `FR_ARITH` | none | none | `Fr` add, multiply or inverse | 1 | 256 |
| `MOD_MUL` | `RANGE16` | `2^16` | `a·b mod m` | 1 | 65,536 |
| `SHA256_COMP` | `RANGE16`, `XOR8` | `2^16` | compression | 16 | 16,384 |
| `EC_ADD` | `RANGE16` | `2^16` | complete point addition | 3 | 21,845 |

- `POSEIDON2` and `FR_ARITH` take `2^8`, the menu's smallest shard, where no table fits: every
  bound is a boolean decomposition. `MOD_MUL` and `EC_ADD` take their floor.
- `KECCAK_F` and `SHA256_COMP` take `2^18`, two variables above it: four times the calls for 2%
  more proof (a `KECCAK_F` shard's is 381,100 bytes, against 373,276 at `2^16`). The price is
  memory: two `2^18` `KECCAK_F` shards in flight set the measured block's peak
  ([streaming.md](streaming.md) §1).
- No base family carries `TIMESTAMP`, whose table needs `2^19` rows. `FR_OP`, `P2_FIELD` and
  `FIELD_IO` carry `RANGE16`, and `FQ_OP` `TIMESTAMP` and `RANGE16`, flooring it at `2^20`.

## 10. Guest-side callers

| delegation | reached from |
| --- | --- |
| `KECCAK_F` | `guest_sdk::keccak256`; in `guests/revm-block` every `alloy-primitives` keccak, through its `native-keccak` hook `native_keccak256` |
| `SHA256_COMP` | `guest_sdk::sha256`; `revm-precompile`'s `Crypto::sha256`, the `0x02` precompile and the stateless guest's SSZ hashing |
| `POSEIDON2` | `transcript::poseidon2_permute`; `guest_sdk::poseidon2_permute` |
| `FR_ARITH` | `field::Fr`'s addition, Montgomery multiplication (`*`, `square`, `pow`, the conversions in `from_u64`, `from_bytes`, `to_bytes`) and nonzero `inverse` |
| `MOD_MUL` | `k256`'s `FieldElement10x26::{mul, square}`, `Scalar::mul`; `ark-ff`'s `MontBackend::{mul_assign, square_in_place}` for BN254's two fields, as the product and then `·R⁻¹` |
| `EC_ADD` | `guest_sdk::{ec_add, ec_mul}`; `k256`'s `ProjectivePoint::{add, add_mixed, double}`; `revm-precompile`'s `Crypto::{bn254_g1_add, bn254_g1_mul}` |

- **The shims** are `guest_sdk::recursion`'s but `KECCAK_F`'s, which only `keccak256` reaches
  ([ecall-abi.md](ecall-abi.md) §7). Their frame types are `#[repr(C, align(4))]`, so §4's
  alignment is the type's and not where the code generator put a local.
- **A multi-call operation's order is the caller's**, and nothing refuses a wrong one: it computes
  something else. So each is one SDK function, `keccak256`'s permutation,
  `guest_sdk::recursion::sha256_comp` and `guest_sdk::recursion::ec_add_complete`.
- **The transparent backends**: `field` and `transcript` call the shims under
  `cfg(target_arch = "riscv32")`, through a target dependency on `guest-sdk` that a host build
  never resolves, not a cargo feature. Cargo refusing the cycle, `guest-sdk` cannot name `Fr`, so
  the shims take frames of bytes. The software path is each crate's own code, one branch below the
  call. A guest declares what its library calls reach: `Fr` arithmetic `FR_ARITH`,
  `poseidon2_permute` both.
- **`FR_ARITH`'s frame carries `Fr`'s memory form** ([primitives.md](primitives.md) §1): canonical
  values would cost a Montgomery multiplication per value, more than the one the call replaces.
  `POSEIDON2`'s carries canonical values, six conversions against the permutation's 240
  multiplications.
- **The vendored crates**, `k256` 0.13.4, `ark-ff` 0.6.0 and `revm-precompile` 43.0.2, are what a
  guest compiles through `guests/Cargo.toml`'s `[patch.crates-io]`, each route under the same `cfg`
  with upstream's code as its software path; the root workspace is unpatched. A `MOD_MUL` or
  `EC_ADD` operand must be below its modulus, so `k256` first reduces its lazily reduced field
  elements. Changed files: [guests/vendor/README.md](../../guests/vendor/README.md).

## 11. Limits

- The EVM's `MULMOD` and `MODEXP`, BLS12-381 and every primitive outside §10's table run as
  instructions. No signature or pairing is delegated: secp256k1 recovery is `k256` code over
  `MOD_MUL` and `EC_ADD`, a BN254 pairing `ark-bn254` code over `MOD_MUL`.
- A delegation is an operation's core: padding, a sponge or block loop, a scalar multiplication's
  ladder and a multi-call operation's order are guest code, proven as instructions.
- A call's result is bound to memory alone: the frame after it is the function of the frame before.
- This executor implements every family, so no proof here runs a base shim's software path.
- Retired numbers are [ecall-abi.md](ecall-abi.md) §4's.
