# Public values and advice

How an execution's public input and public output, the **journal**, are bound to its proof, and
what the prover's **advice** is. All three are regions of guest memory, each initialized by a
window family of its own and carried by the memory argument ([memory.md](memory.md)).

## 1. Three regions, no I/O syscall

| region | contents chosen by | bound by |
| --- | --- | --- |
| public input | the statement | step 10c, to the statement's `input` (§5) |
| journal | the guest's stores | step 10c, to the statement's `output` (§5) |
| advice | the prover | nothing (§6) |

There is no I/O syscall: a guest uses ordinary loads and stores, and a provable guest's only
ecalls are `EXIT` and delegation numbers (the retired POSIX numbers: [ecall-abi.md](ecall-abi.md)
§4). A host supplies `emulator::GuestIo`'s `input` and `advice` and reads the journal from
`emulator::Execution::io`. A byte-moving syscall would need cross-row constraints tying each
transfer row to its buffer and length, which this arithmetization has no place for, while a window
is bound by the multiset and one comparison (§5) and asks nothing of the guest. Nor does the guest
hash its output: nothing rests on its honesty, and a panic loses nothing it committed.

## 2. The memory map

| region | bytes | family | windows |
| --- | --- | --- | --- |
| public input | `[0x8000, 0xC000)` | `PUBLIC_INPUT` | `PUBLIC_INPUT_WINDOW` = 2, at `2^12` |
| journal | `[0xC000, 0x1_0000)` | `PUBLIC_OUTPUT` | `PUBLIC_OUTPUT_WINDOW` = 3, at `2^12` |
| advice | `[0x8000_0000, 2^32)` | `ADVICE_WINDOWS` | from `2^29/h`, at the window height `h` |

The full address map is [ecall-abi.md](ecall-abi.md) §6. The public windows take the upper half
of `[0, RAM_ORIGIN)`, 64 KiB that no RAM window family initializes (`INIT_TEARDOWN` masks window
0's rows below `RAM_ORIGIN` and no `ZERO_WINDOWS` id is 0, [memory.md](memory.md) §3), so they
cost RAM nothing, and `[0, 0x8000)` stays a hole in which a null dereference cannot balance.

A window's first address is `4·height·id`, so the pinned height
`constants::family::PUBLIC_WINDOW_HEIGHT = 2^12` is what makes the origins windows 2 and 3, 16 KiB
each, ending flush against `RAM_ORIGIN`. It is the ceiling: at the next menu height, `2^14`, two
windows need 128 KiB, and the one window in the hole is window 0, which would initialize address
zero. Anything larger means moving `RAM_ORIGIN`, which moves every program's load address and
shortens every decoded table's pc reach ([program.md](program.md) §5).

`program::decode_program` assigns that height whatever its caller asks, and the verifier refuses
any other, and any RAM window height that would let a zero window reach the public windows
([memory.md](memory.md) §3.5).

## 3. Layout and the length word

```text
word 0       the payload's byte length
words 1 …    the payload, little-endian, zero-padded to the end of the window
```

A public window is `2^12` words, so a payload is at most `guest_memory::PUBLIC_PAYLOAD_BYTES` =
16,380 bytes. `verifier_core::public_io_words` is the one spelling: the executor seeds the input
window with it, the prover commits it and the verifier evaluates it. The length word makes the
binding exact: without it `[1, 2, 3]` and `[1, 2, 3, 0]` fill the same window.
`verifier_core::derive_global_phase` refuses an `input` or `output` longer than 16,380 bytes as
`Statement`, and the executor refuses such an input before the first cycle.

## 4. The window families

| family | id | height | shards | init leaf | step 10c holds |
| --- | --- | --- | --- | --- | --- |
| `PUBLIC_INPUT` | 12 | `2^12` | exactly 1 | `M[2] init_value` | `M[2]` to `input` |
| `PUBLIC_OUTPUT` | 13 | `2^12` | exactly 1 | literal 0 | `M[1] teardown_value` to `output` |
| `ADVICE_WINDOWS` | 14 | `h` | `k ≥ 0` | `M[2] init_value` | nothing |

All three are in every `VmConfig` and own no cycles. Each public family proves exactly one shard in
every statement ([memory.md](memory.md) §3.5), so step 10c always runs: an unread input is still
the window's initial contents, and an unwritten journal is empty.

The circuits are [memory.md](memory.md) §3.3's. `PUBLIC_OUTPUT`'s is `ZERO_WINDOWS`' byte for
byte, whose init leaf writes the literal 0, so no column holds an initial journal (§5).
`PUBLIC_INPUT`'s and `ADVICE_WINDOWS`' initial values are `M[2]`, one execution's values,
committed before the memory challenges and bound by no program identity.

All three regions' tuples carry `constants::address_space::RAM`; which family initializes an
address is what makes a word public, advice or heap. A space of their own would need an
address-space column, and a gate pinning it, on the memory path of `MEM_WORD`, `MEM_SUBWORD` and
`ATOMICS`; under `RAM` those circuits need nothing for them, their addressing already covering
every 4-aligned address below `2^32` ([memory-ops.md](memory-ops.md) §2).

## 5. The binding

**`io_digest`** absorbs the statement's two strings in a transcript of its own
(`transcript::io_digest`):

```text
t ← Transcript::new()
t.append_bytes(PUBLIC_INPUT_STREAM,  input)      tag, byte length, 31-byte limbs
t.append_bytes(PUBLIC_OUTPUT_STREAM, output)
io_digest ← t.sample()                           one raw squeeze
```

The framing ([transcript.md](transcript.md) §3) parses back to exactly one ordered pair, and the
squeeze is raw, as every digest's is. The guest never computes it. G7 absorbs it before the memory
commitments (G8) and challenges (G10) ([proof.md](proof.md) §2), so both strings are fixed before
any challenge exists.

**The multiset.** At a window address the init leaf is the only write at timestamp 0, every access
consumes a write and produces a strictly later one, and the teardown balances only against the
last ([memory.md](memory.md) §9). So `PUBLIC_INPUT`'s `M[2]` holds each word's value before its
first access, and `PUBLIC_OUTPUT`'s `M[1]` its value at the end.

**Step 10c** of `verifier_core::verify_shard_local` ([proof.md](proof.md) §6). Of a public shard's
base claims, which share one point `u` and each name a column, the verifier takes the one on
`M[2]` (`PUBLIC_INPUT`) or `M[1]` (`PUBLIC_OUTPUT`), refusing its absence as `Malformed`, and
compares it with its own evaluation at `u` of the multilinear extension of `public_io_words(input)`
or `public_io_words(output)`. A mismatch is `MemoryArgument`; the shard's opening then holds the
claim to the committed column. Column and string are fixed before `u` is drawn, so a column other
than the window passes with probability at most `12/p`.

`PUBLIC_INPUT`'s teardown is free: a guest may overwrite its input. `PUBLIC_OUTPUT` has no init
column, and that is the point: with one, a prover could place the journal there at timestamp 0 and
the teardown would match without the guest storing a byte.

### 5.1 The argument, stated plainly

G7 fixes `input` and `output`, and G8 the window columns, before any challenge. Step 10c says the
columns are those strings' windows; the multiset says they are the execution's first values in the
input window and its last values in the journal window. So the guest found the statement's input
in its input window, and the statement's output is what its stores left in the journal window. That
rests on no cooperation, hash or register convention of the guest's, and says nothing about advice.

Recursion carries the binding unchanged: a node recomputes `io_digest` from the windows' words and
repeats step 10c over them, and the decider binds the contract's `input` and `output` calldata to
`io_digest` ([recursion.md](recursion.md) §8.1, §9).

## 6. Advice

Advice is memory whose initial values the prover chose: `ADVICE_WINDOWS` initializes
`[ADVICE_ORIGIN, ADVICE_ORIGIN + 4hk)` from an `M[2]` that nothing binds, not identity, not the
statement, not a gate. A guest reads it with ordinary loads.

- **Layout.** §3's framing over `1 + ⌈len/4⌉` words (`trace::advice_region_words`), spelled once
  by `trace::advice_word` for the executor and the prover; `guest_sdk::advice` reads it back.
- **Windows.** At the window families' one height `h`, shard `i` is window
  `verifier_core::advice_first_window(h) + i`, and `advice_first_window(h) = 2^29/h` is the first
  window above RAM. Consecutive, they need no list: a statement carries only their count
  `k = ⌈words/h⌉` (`trace::advice_window_count`), which covers what the host supplied, an untouched
  word's tuples cancelling. `check_memory_windows` asks only `2^29/h + k ≤ 2^30/h`, the top of the
  address space, and `ZERO_WINDOWS` ids stay below `2^29/h` ([memory.md](memory.md) §3).
- **No advice, no region.** Then `k = 0` and there is no shard; `guest_sdk::advice` on such a run is
  a fatal `emulator::EmuError::OutOfBounds`.
- **Not read-only.** A store there is an ordinary store. Refusing it would need a space selector and
  a gate on three families' memory path, and would buy nothing: advice is unbound either way.

**What a guest owes.** A proof says that some advice exists under which the program, given the
public input, published the journal; advice that changes the journal unchecked is a value the
prover chose. The check is against something the proof binds: a commitment in the public input
(`guests/public-io`, at toy scale, with a position-weighted checksum standing in for a hash), or
one the journal publishes. `revm-block-stateless` publishes the root of the payload it validated
and holds its witness to that payload by hashes ([ethereum.md](ethereum.md) §4).

## 7. The guest's view

A guest reaches the regions with loads and stores at the `constants::guest_memory` constants,
through `guest_sdk::public_input`, `guest_sdk::commit` and `guest_sdk::advice`, none of which issues
an ecall; [ecall-abi.md](ecall-abi.md) §7 is the API and the
[guest program manual](../guest-program-manual.md) the walkthrough. Nothing is published at exit,
so a guest that panics has published what it committed, and its run is proved like any other.

## 8. Cost

- No address space, transcript message, tag, challenge or statement field; no gate elsewhere.
- Two `2^12`-row shards a statement, five committed columns between them; one `h`-row shard of
  three columns per advice window.
- The native verifier: two 4,096-point multilinear evaluations, 4,095 multiplications each. A
  recursion node's cost follows the payload instead: it evaluates the payload's words alone, times
  `1 − r_j` for each variable above them (`verifier_core::chain::public_value`).
- The guest: nothing at exit; a byte store per journal byte and a word store per `commit`.

## 9. Limits

- **16,380 bytes each, and no larger window** (§2). A journal that grows with the execution has no
  fixed bound: the mini-block binary's, a 13-byte record plus return data per transaction
  ([ethereum.md](ethereum.md) §3), holds at most 1,255 transactions, and one record can exceed it.
  Large outputs belong behind a digest (the stateless binary's journal is 43 bytes), large inputs
  in advice.
- **The journal is the window's whole final contents.** Anything but a length of at most 16,380,
  that many bytes, then zeros, matches no statement: the executor refuses an oversized length
  (`EmuError::JournalTooLong`), and a nonzero byte past it fails step 10c. `commit` keeps that
  form; a guest writing the window directly must.
- **Nothing orders the journal's writes, and nothing forces a guest to read its input.** The proof
  binds a window's contents, not its accesses.
- **Read the exit status first.** It is `x10`'s final value ([memory.md](memory.md) §4): a failed
  run, a panic included, has a verifying proof and a journal too (§7).
- **A deployed contract fixes both lengths**, a decider key being per shape
  ([recursion.md](recursion.md) §9).
