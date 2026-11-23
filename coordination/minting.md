# Minting

From the app a developer defines in the Apogee Deployment Suite to the image a Prover Host runs.

## 1. Who owns what

The developer owns what an app is; Apogee owns how its data moves: layouts, encodings, advice,
lookups, write-back and dispatch, all generated and never edited. A runtime improvement reaches every
app by regenerating from its manifest, and no developer file changes.

| the developer's | Apogee's, generated |
| --- | --- |
| tables: names, key and value fields, whether each holds funds | record layouts and encodings, G's fold |
| roles: names and bits | role constants |
| unit actions: name, kind, authorization, fields, consumption, settlement form | tags, unit layouts, shape digests, dispatch |
| logic bodies, one file a unit action | the names the logic uses, lookups, the advice, write-back |
| app id and name, genesis admins | the guest, the Prover Host binary, its configs and image, the client |
| the frontend and the backend | what they exchange with Apogee ([runtime.md](runtime.md)) |

## 2. The manifest

`apogee/app-manifest/v1` is the Suite's one build output
([app-manifest.v1.schema.json](app-manifest.v1.schema.json);
[examples/exchange.manifest.json](examples/exchange.manifest.json)). It carries only what the build
needs. Everything else stays in the Suite: descriptions, templates, data-availability choices,
claims, keys, webhooks, the mode and fuel.

- **Canonical bytes**: its RFC 8785 (JCS) serialization, UTF-8. Every number is an integer.
- **Digest**: the core's Poseidon2-A64-C5 sponge ([precompiles.md](../docs/spec/precompiles.md)
  §7.7) of `field(1, "apogee/app-manifest/v1")`, `field(2, canonical bytes)`; its first 8 lanes, 64
  bytes little-endian, 128 lowercase hex digits. A digest names one project version.

| member | holds |
| --- | --- |
| `format` | `"apogee/app-manifest/v1"` |
| `app` | `{id, name}`: `id` names the generated crates, `^[a-z][a-z0-9-]{0,63}$`; `name` is display text |
| `tables` | `{id, name, key, value, holds_funds}`, in schema order, the order G folds them in, ids from 3; a key of 1 or more fields, a value of 0 or more |
| `roles` | `{name, bit}`: app roles on bits 1–63. ADMIN, bit 0, is the framework's |
| `actions` | `{name, tag, kind, fields}`, kind `signed`, `settled` or `admin`; a signed action adds `auth`, a settled one `consumption` and `settlement` |
| `retired_tags` | every tag once assigned that no action holds now |
| `logic` | path → Rust source: `signed/<name>.rs`, `settled/<name>.rs` or `admin/<name>.rs`, one a unit action |
| `genesis_admins` | at least one user address, in the core's text form: `0x`, 64 hex digits and an 8-digit checksum, lowercase |

**A field** is `{name, type}`, or `{name, type: "enum", variants}` with two or more variants, from
a closed list:

| type | bytes | encodes |
| --- | --- | --- |
| `bool` | 1 | 0 or 1 |
| `u8`, `u16`, `u32`, `u64`, `u128` | 1, 2, 4, 8, 16 | little-endian; big-endian in a key, so a trie orders numbers |
| `enum` | 4 | its variant's index, a `u32` |
| `UserAddress` | 32 | a user address |
| `Owner` | 32 | a user address or an entity address |
| `L1Address` | 20 | an L1 address |
| `bytes32` | 32 | 32 bytes |

| member | values |
| --- | --- |
| `auth` | `{kind: "user"}`; `{kind: "parties", n}`, 2–4 co-signers of one message; `{kind: "role", role}`, one holder of an app role, by name |
| `consumption` | `{kind: "once"}`; `{kind: "fillable", size}`, `size` naming a `u128` field: the most a request fills across batches |
| `settlement` | `{fields, list?}`: fixed fields, then at most one list `{name, entry}`, a `u32` count and that many entries of `entry`'s fields |

### 2.1 Rules

The generator checks every rule and refuses the manifest at the first that fails, in one line: the
rule's code and the item's JSON Pointer (RFC 6901), such as `record_width /tables/1`.

| code | rule |
| --- | --- |
| `form` | the manifest validates against its schema |
| `order` | actions ascend by tag, roles by bit; retired tags and genesis admins ascend |
| `name` | tables PascalCase, actions and fields snake_case, roles UPPER_SNAKE_CASE, each unique where it is declared; none a Rust keyword, a built-in's, a system table's or `ADMIN`; no two generated names alike (§3) |
| `app_id` | `<id>`, `<id>-guest` and `<id>-host` name no package of the build tree |
| `table_id` | table `i`, from 0, has id `3 + i` |
| `record_width` | a key is 1–64 bytes, and a record, key and value, at most 112 |
| `words` | a record, a unit's fields, a settlement's fixed part and its entry are each whole 4-byte words |
| `size` | a fillable action's `size` names one of its own `u128` fields |
| `auth` | a `role` names a declared role |
| `role_bit` | no two roles share a bit |
| `tag_range` | signed and admin tags are `0x100`–`0x1FF`, settled tags `0x200` and up |
| `tag_unique` | no two actions share a tag, and no action holds a retired one |
| `tag_renumbered` | on an upgrade, against the deployed manifest: each of its actions still here in its range keeps its tag, and each of its tags, assigned or retired, is still assigned or retired |
| `logic_files` | exactly one source a unit action, at `<kind>/<name>.rs`, and no other |
| `logic_lint` | the framework's rules: no float, no container but `Vec` and `BTreeMap`, every loop a `while` |
| `genesis_admins` | each address's checksum holds |

**Tags** are assigned once and stored. The Suite gives a new action the tag above the highest its
range has held, assigned or retired. An action removed, or one whose new kind moves it to the other
range, leaves its tag in `retired_tags`, never to be reused. The framework's built-ins hold 1–5, and
the vault's records have no tag.

## 3. The generator's output

The generator, apogee-host's, writes into a checkout of apogee-host beside the framework. The same
manifest at the same framework commit gives the same bytes.

| path | owner | holds |
| --- | --- | --- |
| `apps/<id>/src/{signed,settled,admin}/<name>.rs` | developer | the manifest's `logic`, verbatim |
| `apps/<id>/src/lib.rs`, `apps/<id>/Cargo.toml` | generated | the declarations under the names below, the encodings, the `App` with its tags and dispatch, and the scope each logic file compiles in |
| `guests/<id>/src/main.rs`, `guests/<id>/Cargo.toml` | generated | `app::guest::run` over the app, and the manifest digest in the image (§5) |
| `apps/<id>-host/src/main.rs`, `apps/<id>-host/Cargo.toml` | generated | the Prover Host over the app (`apogee-host:docs/prover-host.md` §10) |
| `apps/<id>-host/config/*.json` | generated | a config for each mode: the genesis admins in it, the deployment's values left to fill ([runtime.md](runtime.md) §5) |
| `apps/<id>-host/Dockerfile` | generated | the image: the release guest and binary, built at one path, the identity recorded |
| `clients/<id>/` | generated | an ES module: each action's message and signing context, each settled and admin unit's bytes, each table's key and value |
| root `Cargo.toml`, `guests/Cargo.toml` | generated entries | the members, and release profiles keeping overflow checks and debug assertions on `<id>` and `<id>-host` |

Every generated file but a JSON config opens with an `@generated` comment naming the manifest digest.

**Layouts.** The fields of every unit layout, a message's, a settlement's fixed part and its entry,
and an admin unit's, are ordered by width, widest first, ties in manifest order: each field of a
word or more lies on a word, and the narrower ones fill the last. A key keeps manifest order, its
trie order. An action's shape digest is the framework's over its layout
(`apogee-host:docs/app-framework.md` §7), each field's type its manifest type and an enum's
`enum(<variants joined by |>)`, so renaming or reordering a variant changes the shape.

**Names** the logic uses, as the Suite's `schemaRs()` previews them (the Suite's
`docs/operating-model.md` §5); none takes a name of the framework's:

| item | generated |
| --- | --- |
| the app | `struct <App>`, PascalCase of `app.id`, implementing `App` |
| table `T` | `struct T` implementing `Table`, its id `const` in UPPER_SNAKE_CASE (`MARKETS`); key: its one field's type, or a tuple in key order; value: its one field's type, or a row struct, `T` without a final `s` (`Market`), or `TRow` where that is `T` (`ConfigRow`) |
| action `a` | its fields' struct in PascalCase (`CreateMarket`), its tag `const` in UPPER_SNAKE_CASE (`CREATE_MARKET`) |
| a settlement | named for its list (`fills`: `Fills`, entries `Fill`), or `<Action>Settlement` where it has none or the name is taken |
| enum field `f` | `enum F` in PascalCase (`Side`), shared by fields of its name and variants; `<Struct><F>` where `F` is taken (`MarketStatus`) |
| role `R` | `const R: u8`, its bit |
| types | `UserAddress` and `Owner`: `Address`; `bytes32`: `[u8; 32]`; the others as named |

## 4. The build record

`apogee/build-record/v1` ([build-record.v1.schema.json](build-record.v1.schema.json)) is what a
build was made from and what it made. Prime Fleet builds every image a deployment runs: it checks
out apogee-host at `framework` with its `core/` submodule, runs the generator and builds the
generated Dockerfile with the pinned toolchain at the one path the Dockerfile names. An ELF embeds
its source paths, so the record's inputs rebuild the ELF byte for byte at that path alone
(`apogee-host:docs/core-interface.md` §5.3). A local build is for development; its identity is its
own path's.

| member | is |
| --- | --- |
| `manifest` | the manifest's digest |
| `framework` | the apogee-host commit the generator and the build ran at |
| `core` | the apogee-vm commit of its `core/` submodule |
| `toolchain` | the Rust release `rust-toolchain.toml` pins |
| `elf_sha256` | the release guest ELF's SHA-256 |
| `identity` | the ELF's program identity at `heights`, 128 hex digits ([program.md](../docs/spec/program.md) §8) |
| `image` | the Prover Host image's digest, `sha256:` and 64 hex digits |
| `heights` | one height per family number of that core, 0 at a retired one: the standard heights unless the build was given others (`apogee-host:docs/core-interface.md` §5.2) |

## 5. Identity and upgrades

- **The identity** is the core's program identity of the release ELF at the record's heights. The
  guest's image holds the manifest digest, so a change to the manifest, to what the guest compiles
  (the framework, the core's SDK), to the core's circuits, to the toolchain or to the heights gives a
  new identity. A change to the Prover Host alone gives a new image and record under the same
  identity.
- **Staging** applies a new identity at the next batch.
- **Production** goes through the vault's timelock: the admin proposes the identity, and the vault
  activates it after T (proposed: 14 days).
- **A shape change**, to an action's name, authorization, consumption or layout, leaves every request
  signed under the old shape unable to apply.
