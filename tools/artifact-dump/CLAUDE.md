# `tools/artifact-dump`

## What this tool owns
Exporting a guest ELF as the artifact later stages consume, and rendering a
report of that artifact a person can read.

```
cargo run -p artifact-dump -- <guest.elf> [--out <dir>]
```

| File written | What |
| --- | --- |
| `<name>.img` | the artifact: the frozen `postcard` wire form of `ProgramImage` |
| `<name>.img.txt` | the report of that artifact, with the full instruction listing |

`docs/guest-program-manual.md` is the user-facing walkthrough. This file is the
design record.

## The decisions that are not obvious
- **The artifact has no container.** No magic, no version word, no length
  prefix: the file is `postcard` over `entry`, `segments`, `slot_base`, `slots`
  and stops. S10 froze that encoding, and wrapping it here would have made the
  file a *second* format to freeze — one that `crates/loader`'s tests do not
  exercise and that every consumer would have to strip. A reader is
  `postcard::from_bytes::<ProgramImage>(&fs::read(path)?)`, which is the whole
  point.
- **The report is rendered from the artifact, not from the image.** `dump`
  serializes, reads back through the reader that re-checks every invariant,
  compares the result to what `load_elf` produced, and renders from *that*. A
  report rendered from the in-memory image would describe something the file
  might not contain. On disagreement it writes nothing.
- **No mnemonics in the `ProgramImage` report.** The instruction model is
  `crates/isa`'s, and that page describes the artifact, which carries words; it
  points at `llvm-objdump` for text, and `tables` below is where mnemonics are
  printed. The listing carries the address, the length, the encoding in memory and
  the expanded word — which is exactly what `crates/loader/tests/differential.rs`
  already checks against that disassembler.
- **Symbols are read from the ELF and marked as such.** They come from
  `.symtab`, not from the artifact, because a listing of four thousand hex words
  with no names is one nobody can navigate. Every part of the report that names
  them says where they came from, and `symbols.rs` cannot fail a dump: a file
  with no symbol table yields an empty index and a listing with no symbol
  column.
- **`--out` defaults to the working directory, not the ELF's.** The ELF lives
  under a `target/` directory that `cargo clean` deletes.
- **`postcard` with no features**, like everywhere else in this workspace, so
  there is no `to_allocvec`; `wire_form` sizes a buffer from the image and uses
  `to_slice`. It is the same four lines as `crates/loader/tests/common`'s
  helper, deliberately: the bytes this exports are the bytes that suite
  exercises.

## What the tests hold it to
`tests/dump.rs` checks the tool against `crates/loader` rather than against a
recorded expectation, so a change on either side has to agree with the other.

- the artifact equals `wire_form(load_elf(elf))`, and reads back equal;
- two dumps of one ELF agree byte for byte, artifact and report both;
- **the printed listing is parsed back** and compared to the image's
  instruction slots — same addresses, same lengths, same expanded words,
  nothing extra and nothing dropped. That is what makes the report examinable
  rather than decorative;
- every slot is accounted for: instruction lines, the mid-instruction slots
  their lengths imply, and the folded `not code` runs sum to `slots.len()`;
- a refused ELF produces an error and no artifact;
- runs that are not code are folded exactly. Real guests reach that path now —
  `amm`, `orderbook` and `vault` carry 1, 16 and 2 halfwords of LLVM's
  `c.unimp` padding — but only ever one halfword at a time, so the test also
  builds a two-segment ELF whose read-only segment sits below the executable
  one and folds 128 halfwords into a single line.

`tests/manual.rs` holds a different thing: `docs/guest-program-manual.md`. It
runs sections 4, 5 and 7 — build, export, rebuild elsewhere, export again,
compare — over every crate in `guests/Cargo.toml`'s member list, and it reads
that list from the manifest rather than carrying its own, so a guest that exists
is a guest whose walkthrough is checked. It also fails when a guest has no
committed ELF fixture, when the manual stops naming one, and when the `members`
line section 2 prints stops being the manifest's — that last one is the line a
reader copies into `guests/Cargo.toml`, so a stale copy of it deletes guests. Twenty guest builds
— ten guests, each built twice — cost about fifteen seconds, which is why it is not `#[ignore]`d: a walkthrough
nothing runs is a walkthrough that has already stopped working and not been
told.

## `tables`: the decoded tables, printed (S11)
```
cargo run --release -p artifact-dump -- tables <guest.elf> [--ptau <ppot_0080_24.ptau>]
```
Prints to stdout: the `VmConfig` (each family's height, live rows, columns and field
mask), then every instruction's pc, `next_pc`, owning family, mnemonic and decoded
fields, then the extra-mask bits the program uses. With `--ptau` it also computes the
program identity at the frozen default parameters, which needs 2^22 ceremony powers and
about a minute; without, the page says what it needs. Any ELF the loader and decoder
refuse is the loader's or `crates/program`'s named error, and nothing is printed.

- **The listing is read out of the tables**, the columns identity commits to, not
  re-derived from the image — except the mnemonic, which a table stores as a one-hot bit
  and which comes from decoding the slot's word. `tests/tables.rs` parses the listing
  back and holds it to the tables row for row, over every committed guest and a
  hand-built ELF that is no fixture.
- **This is where mnemonics live now.** The `ProgramImage` report above still has none,
  on purpose: that page describes the artifact, and the artifact carries words, not
  instructions.

## Not this tool's job
Defining program identity. That is `crates/program`'s; `tables` only prints it. The
sha256 the `ProgramImage` report prints pins the artifact's bytes so a rebuild can be
compared against them, and that report says in as many words that it is not identity,
because a digest next to the word "program" is exactly what a reader would assume.
