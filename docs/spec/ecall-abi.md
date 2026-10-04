# The guest ecall ABI

Frozen at S10. **This document is the ABI.** It is a document rather than a
program because the maintenance surface of a document is small and the surface
of another abstraction layer is not; the numbers themselves live once, in
`crates/constants`'s `ecall` module, and `crates/constants/tests/ecall_abi.rs`
holds this file to them on every build.

**Numbers are append-only, forever.** Once a program's identity is published its
ABI is frozen. Redefining a number does not fail loudly — it quietly makes an
old program compute something else — so a number here is assigned once and never
reused, exactly as `transcript_tags` are. Append-only forbids *reassigning* a
number, not retiring one: a call may be withdrawn, and its number is then burned
rather than freed (§4).

**An Apogee guest is an Apogee-SDK program, not a Linux one.** It has no file
descriptors, no streams and no I/O syscall, and there is no host whose
conventions it is trying to match. What an execution reads and writes is
*memory* — `docs/spec/public-values.md` is normative for all of it — and what is
left in this document is the small set of calls that cannot be memory: ending
the execution, and handing a frame to a circuit.

## 1. The calling convention

An ecall carries its number in `a7` and its argument and result in `a0`:

| Register | Role |
| --- | --- |
| `a7` | the number |
| `a0`–`a5` | the arguments |
| `a0` | the result, or a negated errno |

**Every call defined today takes exactly one argument**, in `a0`: `EXIT` a
status, and each delegation a frame base pointer. `crates/guest-sdk`'s shim is
therefore one-argument, which is not a narrowing of this table but a use of it —
an unused `in(...)` register is still a constraint on the register allocator, and
`a1`–`a5` stay in the convention for a call that needs them.

**An ecall preserves every register except `a0`.** That is part of the frozen ABI, not an
accident of the current executor: `crates/guest-sdk`'s shims declare no clobbers at all,
and every delegation circuit is written against this table. A precompile that
scratched `t0` would produce silently wrong guest arithmetic with nothing to catch it,
which is the "valid proof of a different computation" failure this whole document exists
to prevent.

Delegation arguments travel as **pointers**, because their operands do not fit
in registers: a Poseidon2 state is 96 bytes and a keccak-f state is 200.
Dispatch is by ecall and never by a CSR write.

## 2. The number ranges

| Constant | Value | What |
| --- | --- | --- |
| `ZKVM_IO_FIRST` | 0x0400 | first zkVM host call |
| `ZKVM_IO_LAST` | 0x04FF | last zkVM host call |
| `PRECOMPILE_FIRST` | 0x0500 | first precompile |
| `PRECOMPILE_LAST` | 0x05FF | last precompile |

Both ranges sit **above 1023**, which is the whole of the Linux number space —
not because anything here is Linux, but because a number below it is a number
some other convention has already spent, and staying clear of all of them costs
nothing. They are disjoint from each other, and the split does real security
work:

* a **zkVM host call** would be nondeterministic prover advice — whatever the
  host returns is a value the prover chose;
* a **precompile** is a deterministic function of guest memory, and the circuit
  that replaces it proves exactly that function.

A reviewer must be able to tell which a number is at a glance. Mixing them is
how a nondeterministic call ends up treated as proven.

**The zkVM host-call range is reserved and empty, and it stays that way.** It
was empty at S10 by accident of scheduling and is empty now by decision:
advice does not need a syscall. It is a region of memory the prover fills and
the guest authenticates, which costs no cycle, no gate and no number
(`docs/spec/public-values.md` §6). A call here would be a second way to do the
same thing, and the worse one — a value arriving in a register with nothing
holding it to anything, where the memory form at least sits inside the multiset
argument. The range is kept reserved so that nothing else claims it.

## 3. Syscall numbers

Every number this VM implements, with its nondeterminism class. The
`Constant` column is the name in `constants::ecall`.

| Number | Constant | Class | What |
| --- | --- | --- | --- |
| 93 | `EXIT` | deterministic | `exit(status)`; nonzero is a failed execution. The one non-delegation call a guest may issue |
| 0x0500 | `PRECOMPILE_POSEIDON2` | deterministic | Poseidon2 over `[Fr; 3]`, `a0` = the 96-byte frame base pointer, permuted in place. A **delegation** call since S23: `docs/spec/delegation.md` §12 is its frame table, `constants::family::POSEIDON2` the circuit that proves it. The three lanes cross the frame as canonical little-endian `Fr`, 8 words each |
| 0x0502 | `PRECOMPILE_FR_ARITH` | deterministic | one `Fr` add, multiply or inverse over the 100-byte frame at `a0`, in place. A **delegation** call: `docs/spec/delegation.md` §13 is its frame table, `constants::family::FR_ARITH` the circuit. The operands cross the frame in `field::Fr`'s **in-memory** representation, which is what makes the call cheaper than the software operation it replaces |
| 0x0504 | `PRECOMPILE_MOD_MUL` | deterministic | `out = a · b mod m` over the 100-byte frame at `a0`, in place: a modulus **selector** word, then three runs of eight little-endian 32-bit limbs. A **delegation** call: `docs/spec/delegation.md` §14 is its frame table, `constants::family::MOD_MUL` the circuit. The modulus is one of **four fixed** Ethereum fields the selector names (`constants::mod_mul::CODES`), not an operand; a selector outside that set, or an operand at or above the selected modulus, is a fatal guest error and not an answer |
| 0x0506 | `PRECOMPILE_EC_ADD` | deterministic | One **third** of a complete elliptic-curve point addition over the 388-byte frame at `a0`, in place: a selector naming a curve **and** a group of three reductions, two points in homogeneous projective coordinates, and six intermediate lanes the three invocations pass between them. A **delegation** call: `docs/spec/delegation.md` §16 is its frame table, `constants::family::EC_ADD` the circuit. The curve is secp256k1 or BN254 G1 and the group is 0, 1 or 2 (`constants::ec_add::CODES`); one addition is the three codes of a curve **in group order**, which `guest_sdk::recursion::ec_add_complete` walks. A selector outside the set, or any of the six values the row's group reads at or above the selected modulus, is a fatal guest error and not an answer |
| 0x0507 | `PRECOMPILE_KECCAK_F` | deterministic | **One round** of keccak-f[1600] over the 204-byte frame at `a0`, in place: the round in `0..24` as word 0, then the 1,600-bit state. A **delegation** call: `docs/spec/delegation.md` §6 is its frame table, `constants::family::KECCAK_F` the circuit that proves it. **A whole permutation is 24 of these calls**, the frame being ordinary RAM and the memory multiset being what proves round `r`'s output is round `r + 1`'s input; `guest_sdk::keccak256` walks the loop. A round word at or above 24 is a fatal guest error and not an answer. An executor with the circuit answers 0; one without answers `-ENOSYS` to the **first** call and the caller runs its software path |
| 0x0508 | `PRECOMPILE_SHA256_COMP` | deterministic | **Four rounds** of SHA-256's compression over the 100-byte frame at `a0`, in place: the round group `r` in `0..16` as word 0, the eight working variables, then the sixteen-word schedule window `W_{4r}..W_{4r+15}`. The call runs rounds `4r..4r + 4`, writes the working variables after them and the window back shifted by four, its last four words the schedule words it derived. A **delegation** call: `docs/spec/delegation.md` §15 is its frame table, `constants::family::SHA256_COMP` the circuit. **A whole compression is 16 of these calls** on one frame; the padding, the block loop and the final `H + V` are the caller's, and `guest_sdk::sha256` is where they live. A group word at or above 16 is a fatal guest error and not an answer |
| 0x0509 | `PRECOMPILE_FR_OP` | deterministic | One field operation over cells of the **field memory**, the recursion format's (S-RECURSION): `a0` is the four-word frame `[op, d, a, b]`, read and written back unchanged, `op` one of `constants::fr_op::OPS` — `DIGIT` the one op that writes two cells, `d` and `b`. Like every recursion type it answers `a0` **advanced past its frame**, not 0 (`docs/spec/recursion.md` §1.4). A **delegation** call: `docs/spec/recursion.md` §3 is its table, `constants::family::FR_OP` the circuit. An op outside the set, or an `EQ` whose cells differ, is a fatal guest error and not an answer; there is no software path, the field memory existing only where its circuits do |
| 0x050A | `PRECOMPILE_P2_FIELD` | deterministic | One step of the transcript's duplex over field cells (S-RECURSION): `a0` is the five-word frame `[n, s, x, y, d]`, read-only; the call absorbs `n` of `x, y` into the state at cells `s..s+3` and writes the permuted state to `d..d+3`. `docs/spec/recursion.md` §4, `constants::family::P2_FIELD`. An `n` above 2 is a fatal guest error |
| 0x050B | `PRECOMPILE_FIELD_IO` | deterministic | One move between RAM and a field cell (S-RECURSION): `a0` is the three-word frame `[op, cell, ptr]`, read-only; `IMPORT` sets the cell to the eight words at `ptr` read as a 256-bit integer mod p, and `EXPORT` writes limbs below `2^32` congruent to the cell into them. `docs/spec/recursion.md` §5, `constants::family::FIELD_IO`. An op outside the set, or eight words that are not addressable, is a fatal guest error |

The classes are:

* **deterministic** — the result is a function of the guest's own state, so
  nothing needs to bind it. Every implemented number is one, and that is the
  point of the table: a call that is not deterministic does not get a number.
* **advice** — the result would be chosen by the prover. No number carries this
  class today, and the range reserved for one is empty (§2); it is named here
  because §5 is about the calls that would have it, and because the column has
  to be able to say something other than "deterministic" for the distinction to
  be worth writing down.

**Every one of these is provable except in the sense that `EXIT` and the four
delegation numbers are the only ecalls any circuit admits.** The
`ADD_SUB_LUI_AUIPC` family commits one boolean selector per delegation type and
holds every ecall row's `a7` to 93 or to that type's number; its fill refuses any
other ecall by name (`docs/spec/shard-proof.md` §8). There is no ecall a guest
can issue that a proof does not cover.

## 4. The retired numbers

Five numbers have been retired. **`read` and `write` are gone, and their
numbers are burned.** They were 63 and
64 — their Linux values, chosen when a guest was expected to run under a host
program loader — and they carried four file descriptors with them: standard
input, standard output, diagnostics, and a private hint stream. None of it
exists. There are no descriptors, no `-EBADF`, and no ecall that moves bytes
between guest memory and anything outside it.

| Number | Was | Why it is not coming back |
| --- | --- | --- |
| 63 | `read(fd, buf, len)` | an execution's input is the public input window and the advice region, both of them memory (`docs/spec/public-values.md`) |
| 64 | `write(fd, buf, len)` | an execution's output is the journal, which is memory, and a proof binds its final contents |
| 0x0501 | `RETIRED_KECCAK_F_WHOLE_PERMUTATION` | it was S21's keccak-f[1600] over a 200-byte frame holding the state and nothing else: **one call, one whole permutation**. S26d made one round one invocation, which needs a 204-byte frame whose word 0 is the round — a different call with different semantics, and redefining `0x0501` would not fail loudly: an old binary calling it would have its first state word read as a round selector and get one round of a permuted state back. The re-shaped call took `0x0507`. The number stays a constant so a test can hold it to being unanswered |
| 0x0503 | `RETIRED_MOD_MUL_WITNESSED_MODULUS` | it was S26's `out = a · b mod m` over a 128-byte frame whose first eight words were a **witnessed** modulus. S26b fixed the modulus to one of four a selector names, which is a different 100-byte frame with different semantics, and redefining `0x0503` would not fail loudly: an old binary calling it would have its modulus read as a selector and the rest of its frame misread word for word. The specialized call took `0x0504`. The number stays a constant so a test can hold it to being unanswered |
| 0x0505 | `RETIRED_SHA256_COMP_WHOLE_COMPRESSION` | it was S26c's SHA-256 over a 96-byte frame holding the chaining state and one block: **one call, one whole compression**. S26e made one call four rounds, which needs a 100-byte frame whose word 0 is the round group — a different call with different semantics, and redefining `0x0505` would not fail loudly: an old binary calling it would have its first chaining word read as a group and get four rounds of a shuffled state back. The re-shaped call took `0x0508`. The number stays a constant so a test can hold it to being unanswered |

The numbers are **burned, not freed**: append-only forbids reassigning 63, 64,
`0x0501`, `0x0503` and `0x0505` to anything else, forever, for the same reason it forbids
redefining 93. A program built against the old ABI that issues one gets
`-ENOSYS` (§5), which is the right answer — that call no longer exists — rather
than a silently different computation. **That last clause is what a burned
number buys and why `0x0503` is here rather than reused**: the alternative was
an old `MOD_MUL` caller getting a plausible answer to a question nobody asked.

The rest of this section is about 63 and 64 alone.

**Why they went rather than getting a circuit.** Making a byte-moving syscall
provable is not a gate or two. The call's buffer traffic reached RAM through
*transfer cycles*, extra cycles carrying a RAM query apiece, and a transfer row
that is permitted but not constrained against its ecall's buffer and length can
write any value to any RAM word. Confining it needs cross-row constraints this
arithmetization has nowhere to put. So the two calls were never provable, which
made every guest that used them a guest no proof covered — and that was the
smaller problem. The larger one is that the shape was wrong: **an execution's
public values are not a syscall's business.** They are a property of the
statement, bound by the memory argument at both ends, and they need no call, no
descriptor, no cursor and no cooperation from the guest.
`docs/spec/public-values.md` §1 is normative, and the transfer cycle went with
the calls that were its only source (`docs/spec/execution-trace.md` §6).

## 5. Every other number

**Unimplemented numbers return `-ENOSYS`.**

| Constant | Value | What |
| --- | --- | --- |
| `ENOSYS` | 38 | returned negated in `a0` for a number this VM does not implement |

The value is Linux's, and it is the one errno that survives the deletion of the
POSIX layer, because it was never really part of it: it is the **delegation
ABI's** "this executor has no circuit for that" answer
(`docs/spec/delegation.md` §2). Every shim checks for exactly `-ENOSYS` and runs
its own software path on it, and treats any other nonzero answer as a hard
failure — the difference between "this VM does not have this yet" and "this call
went wrong" is exactly the difference worth keeping. This VM implements all four
delegations, so its executor never answers `-ENOSYS` to one; what it still
answers `-ENOSYS` to is a number nobody has assigned.

That includes, deliberately, every syscall that would return host data:
`getrandom`, `clock_gettime`, `gettimeofday`, and anything Rust's `HashMap`
reaches for on first use to seed its `RandomState`. Each of those is
nondeterministic prover advice wearing the costume of a library call: unless the
guest checks what came back against something a proof binds, the proof does not
pin down which execution happened, and a malicious prover picks the values. They
are refused rather than answered — a guest that wants such a value takes it from
the advice region, where its provenance is written on it and where the guest is
visibly the one that has to authenticate it.

## 6. The public I/O digest

One `Fr` over the statement's two public byte strings. **Frozen at S10**: later
stages recompute it and never redefine it, and S-IO did not — the recipe below,
its tags, its position in the statement-binding order and its test vectors are
all unchanged.

**S-IO is what makes it worth something.** Absorbing the digest fixes the two
byte strings before any challenge exists; what ties them to an *execution* is
the two public value windows, not this hash. The statement's `input` and
`output` are the payloads of two RAM windows, their memory columns are
committed at G8 — also before the memory challenges are squeezed — and
`verify_shard_local` step 10c holds each committed column to the verifier's own
extension of those bytes (`docs/spec/public-values.md` §5,
`docs/spec/shard-proof.md` §6). The design deferred here until S-IO — the guest
computing the digest itself and leaving its words in `x24`…`x31` at exit — is
withdrawn, and the guest never computes `io_digest`.

The two tags keep their S10 names, `PUBLIC_INPUT_STREAM` and
`PUBLIC_OUTPUT_STREAM`. A tag is part of the absorbed stream, so renaming one is
not free; they domain-separate the statement's two byte strings, which is the
job they always did. They name the **statement's** two strings and have never
named a descriptor.

```rust
transcript::io_digest(public_input: &[u8], public_output: &[u8]) -> Fr
```

**Packing.** Each stream is packed into `Fr` limbs 31 bytes at a time,
little-endian, with the final partial limb zero-extended. 31 bytes is below
`2^248 < p`, so every limb is canonical by construction. This is exactly the
byte encoding `docs/spec/transcript.md` §10 already froze.

**Absorption.** Into a Poseidon2 duplex of its own, in this order:

1. the input domain tag, `transcript_tags::PUBLIC_INPUT_STREAM` = 20;
2. the input's **byte** length, as an `Fr`;
3. the input limbs;
4. the output domain tag, `transcript_tags::PUBLIC_OUTPUT_STREAM` = 21;
5. the output's byte length;
6. the output limbs.

which is precisely two `Transcript::append_bytes` messages — the typed layer's
framing is `tag, length, payload`, and its length for a byte message is the byte
count. The digest is then **lane 1 after the final permutation**, taken through
the squeeze API: a raw `Transcript::sample`, not a `challenge_scalar`, because a
challenge under one of these tags would be one tag in two message kinds, which
`docs/spec/transcript.md` §8 forbids.

**An empty stream** contributes its tag and a zero length and no limbs.

**Why this binds the pair.** The absorbed stream parses back uniquely: the two
tags are distinct constants, and each length says how many limbs follow it. So

* swapping two unequal streams changes the digest, because it swaps their tags;
* appending a zero byte changes the digest, because it changes a length — this
  is what the length is for, since the zero-extended final limb would otherwise
  make `x` and `x ‖ 0x00` absorb identically;
* flipping any bit of either stream changes a limb.

Test vectors: `crates/transcript/tests/vectors/io_digest.txt`, generated by
`tools/transcript-ref`, which transcribes this section over Plonky3's
permutation and never links `crates/transcript`.

## 7. The memory map

`crates/guest-sdk/link.ld`, frozen with the symbol names:

```ld
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x7FFF0000 }
```

Those two numbers also live in `constants::guest_memory` as `RAM_ORIGIN` and
`RAM_LENGTH`, and `crates/constants/tests/ecall_abi.rs` checks this document, that module
and the linker script against each other. `crates/loader` refuses a `PT_LOAD` segment that
does not lie inside the window: a program is linked into RAM and nowhere else, so one that
wants to be elsewhere is not one this VM can run — and enforcing it is also what stops a
hostile `p_memsz` from sizing the loader's slot vector.

**The RAM window is not the whole addressable space, and has not been since S-IO.** Two
**16 KiB** public value windows sit below it at `PUBLIC_INPUT_ORIGIN` = `0x8000` and
`PUBLIC_OUTPUT_ORIGIN` = `0xC000`, and the **advice** region sits above it at
`ADVICE_ORIGIN` = `0x8000_0000`; `trace::addressable` is the executor's rule and everything
else — `[0, 0x8000)`, and nothing above the windows, which end flush against `RAM_ORIGIN`
since S-STREAM raised their height to `2^12` — is a hole, so a null dereference is still
a loud error. They were 1 KiB each at `0x8000` and `0x8400` until then, with a second hole
`[0x8800, RAM_ORIGIN)` above them. None of the three is in the ELF, so no linker symbol names them; a guest
reaches them with ordinary loads and stores at the constants.
`docs/spec/public-values.md` §2 is normative, and this section's `MEMORY` line
stays exactly what `link.ld` says.

| Symbol | What |
| --- | --- |
| `__bss_start` | first byte of `.bss`; crt0 zeroes from here |
| `__bss_end` | one past the last byte of `.bss` |
| `__heap_start` | first byte above `.bss`, 16-aligned; the bump allocator's floor |
| `__stack_top` | `ORIGIN(RAM) + LENGTH(RAM)`; the initial `sp`. The allocator's ceiling sits `STACK_RESERVE` below it (§8) |

`_start` lives in its own `.text._start` input section so the linker places it
at `ORIGIN(RAM)`. It sets `sp`, zeroes `.bss` byte by byte, calls `main`, and
exits 0 if `main` returns. The `.bss` zeroing stays even though VM memory starts
zeroed, because `.bss` being zero is a guarantee the Rust that runs above it
relies on, and crt0 is the one place that can make that true of the *image*
rather than of the executor.

Guests link with `--no-relax`. Linker relaxation rewrites instruction sequences
and shifts every later address, and S11's program identity is a function of
those addresses.

### 7.1 The segment layout, and why it is a normative part of this map

The zkVM executor makes the whole window addressable by construction: it has no
pages and no permissions, and `crates/loader` reads nothing from a program
header but `p_vaddr` and `p_memsz`. So the two rules below buy this executor
nothing at all, and they are still normative, because **an ELF's program headers
are the image's own account of itself** and a reader is entitled to believe them.
`llvm-readobj`, a disassembler, a debugger, `crates/loader/tests/layout.rs` and
any loader that is not this one all read the headers and nothing else. A header
that declares twenty kilobytes while the program writes to two gigabytes is
wrong about the program, whatever today's executor is indifferent to; an image
that is only well formed under an indifferent reader is one whose headers cannot
be trusted for anything. The rules cost three pages of address space:

- **Every writable byte a guest can touch is declared.** The heap and the stack
  grow toward each other between `__heap_start` and `__stack_top`, so the linker
  script reserves that whole span as one writable segment reaching the top of the
  window. Undeclared, the headers say the program's writable memory ends at
  `.bss` and the guest's very first stack push is a write outside every segment
  it declares. The reservation itself must cost nothing on disk: `p_filesz` may
  cover an initialised `.data` — lld folds one into this same segment — but must
  stop at or before `.bss`, or the ELF carries the whole 2 GiB reservation as
  zeroes.
- **No two segments share a page.** A `PT_LOAD` states its permissions over the
  pages it covers, so two segments on one page state two different things about
  the same bytes and the file no longer says which: an unaligned `.rodata` is a
  claim that the tail of `.text` is not executable, and zero fill landing inside
  a read-only segment is a claim that the image writes to memory it declared
  read-only. `.text`, `.rodata`, `.data` and `.bss` are therefore each
  page-aligned.

S10 shipped both violations, and neither was visible from inside this VM — which
is the argument for the rules rather than against them.
`crates/loader/tests/layout.rs` holds the image to both by reading the program
headers, and needs neither a cross-compiler nor an emulator to do it.

## 8. The guest-sdk surface

```rust
guest_sdk::entry!(main);              // gives a function the `main` symbol

pub fn public_input() -> &'static [u8];       // the input window; no ecall
pub fn read_input(buf: &mut [u8]) -> usize;   // the same, copied
pub fn commit(bytes: &[u8]);                  // append to the journal; no ecall
pub fn journal() -> &'static [u8];            // the journal so far
pub fn advice() -> &'static [u8];             // prover-chosen, bound by nothing
pub fn exit(code: i32) -> !;

pub fn keccak256(input: &[u8]) -> [u8; 32];               // delegated, or in software
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS
pub mod recursion { /* the poseidon2, fr_arith and mod_mul frames */ }
```

**The first five issue no ecall at all.** The public windows and the advice
region are ordinary memory, reached with loads and stores, so the whole of an
execution's input and output crosses no ABI boundary and costs no cycle beyond
the loads and stores themselves. `docs/spec/public-values.md` §7 is the full
surface and `docs/guest-program-manual.md` §3 the guest author's version. There
is no second surface and no compatibility path: what is listed above is what a
guest has.

`read_input` copies `min(buf.len(), public_input().len())` bytes and may
therefore return short — a caller that needs an exact length must check the
count, because proceeding on a partly-filled buffer is how a guest ends up
proving something about zeroes. `public_input` and `journal` return slices and
copy nothing, so they cannot. `commit` writes all of its bytes or none: it exits
`EXIT_IO_ERROR` rather than truncating a journal that would not fit its window,
because a caller reads `journal` back and must not see one it did not write.

The allocator bumps upward from `__heap_start` and `dealloc` does nothing. An
allocation that would end above `__stack_top - STACK_RESERVE`
(`constants::guest_memory`, 8 MiB), or above the live `sp`, exits 71 rather than
returning null. The top of RAM therefore belongs to the stack, and no block is
ever handed out over a frame in use.

The ceiling was `__stack_top` until S12. With it, an exhausted heap handed out
blocks over live stack frames, and safe code writing into one rewrote locals and
return addresses. What no allocator check can see is a stack that grows past its
reserve after the heap has filled below it.

**A panic is silent.** The handler is a bare `exit(101)` with no message,
because an Apogee guest has no diagnostic stream: the only bytes leaving an
execution are the journal, which a proof binds, and the exit status. That is
worth more than the message — with no write on the panic path, **a panicking
guest is provable**, and it has published exactly what it committed before it
died.
