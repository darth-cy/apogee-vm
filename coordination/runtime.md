# Run time

The interfaces of a running deployment. Integers are little-endian unless marked BE; a digest is 8
lanes, each below p = 2^64 − 59, in 64 bytes little-endian; `‖` concatenates. The internals stay in
apogee-host: the advice (`apogee-host:docs/app-framework.md` §10), the engine and its config
(`apogee-host:docs/prover-host.md`).

## 1. Backend → Prover Host

### 1.1 Signed messages

A user's frontend signs each request with the core's Falcon-512 (`apogee-vm:tools/falcon512/js`),
the generated client encoding the message and its context ([minting.md](minting.md) §3). The
backend holds each request until a batch takes it.

| item | bytes |
| --- | --- |
| message | tag u32 ‖ expires u64 ‖ nonce u64 × k ‖ fields |
| nonce | lane u16 << 48 \| seq, seq below 2^48 (`apogee-host:docs/app-framework.md` §4) |
| context | `"apogee/app/v2"` ‖ deployment id ‖ shape digest ‖ party address 32 × k, the parties only where k ≥ 2 |
| deployment id | chain id u64 BE ‖ vault address 20: 28 bytes |
| shape digest | the framework's, over the action's name, authorization, consumption and layout (`apogee-host:docs/app-framework.md` §7); a constant of the client |
| key | Falcon-512 v1.2's encoding, 897 bytes, `0x09` ‖ h; its user address is the first 32 bytes of its digest K ([precompiles.md](../docs/spec/precompiles.md) §7.7) |
| signature | 666 bytes, `0x39` ‖ salt ‖ s2, of the message under the context, HashToPoint being the core's Poseidon2 sponge |

`k` is the action's signers: 1, or n for `parties(n)`; a settled request has one. `expires` is ms
since the epoch, and a request applies only while the batch's `now` is at most its `expires`.

### 1.2 The batch bytes

The backend builds every batch on the Prover Host's tip (§2.2): the tip's G as G_prev, a `now` at
or after the tip's and no later than the submission's arrival, how many queued deposits and forced
exits it consumes, and its units in its own order. A unit's tag says its kind.

```text
batch          G_prev 64 ‖ now u64 ‖ deposits u32 ‖ exits u32 ‖ unit …        the units to the end
signed unit    message ‖ signer address 32 × k
settled unit   tag u32 ‖ n u32 ‖ request × n ‖ settlement                     n ≥ 1
request        message ‖ signer address 32 ‖ fill u128                       the fill for a fillable action only
settlement     fixed fields ‖ count u32 ‖ entry × count                      the count and entries where it has a list
admin unit     tag u32 ‖ fields
```

| tag | built-in | kind | fields |
| --- | --- | --- | --- |
| 1 | `withdraw` | signed, user | to L1Address ‖ token L1Address ‖ amount u128 |
| 2 | `transfer` | signed, user | to Address ‖ token L1Address ‖ amount u128 |
| 3 | `revoke` | signed, user | nonce u64 |
| 4, 5 | `grant_role`, `revoke_role` | admin | user Address ‖ roles u64 |

An app's tags are its manifest's and its layouts the generator's, reached through the client
([minting.md](minting.md) §3). Every unit applies, or the batch is refused whole.

### 1.3 The submission

`POST /v1/batches`, with `Authorization: Bearer <key>`, a key of the `backend` scope (§5), and a
JSON body ([batch-submission.v1.schema.json](batch-submission.v1.schema.json)) whose byte strings
are hex, with `0x` or without:

```json
{
  "batch": "<the batch bytes>",
  "keys": ["<a unit signer's key>"],
  "signatures": [["<unit 0's first signature>"], []],
  "authorization": {"key": "<an ADMIN holder's key>", "signature": "<its signature of the batch bytes>"}
}
```

| member | holds |
| --- | --- |
| `batch` | the batch bytes, exactly what the authorization signs |
| `keys` | each unit signer's key once, in any order; the authorizer's only where it also signs a unit |
| `signatures` | one list a unit, in the batch's order: a signed unit's signers' in order, a settled unit's one a request, an admin unit's none |
| `authorization` | an ADMIN holder's key at G_prev, and its signature of the batch bytes under the batch context, `"apogee/app/v2/batch"` ‖ deployment id |

### 1.4 Replies

The Prover Host checks in this order and refuses the batch whole at the first failure. A refusal
changes nothing, is kept nowhere and is the backend's to fix.

| # | check | refuses | status |
| --- | --- | --- | --- |
| 1 | — | a batch holding units while the Prover Host is paused after a divergence | 503 |
| 2 | `batch` | bytes that do not begin with their header, or 2^32 bytes or more | 400 |
| 3 | `clock` | a `now` after the submission's arrival | 409 |
| 4 | `tip` | a G_prev that is not the tip's G | 409 |
| 5 | `clock` | a `now` before the tip's | 409 |
| 6 | `queues` | more deposits or forced exits than are queued | 409 |
| 7 | `authorization` | a key not in its transport form, an authorizer without ADMIN at G_prev, a signature that does not verify | 422 |
| 8 | `keys` | a key not in its transport form, a key twice, a second key of one address | 422 |
| 9 | `vault` | a deposit or forced exit that does not apply | 422 |
| 10 | `signatures`, `unit` | unit by unit: a signature missing, extra, of a signer with no key or not verifying; a unit that does not decode or apply | 422 |
| 11 | `signatures`, `keys` | a signature list for no unit; a key no unit's signer holds | 422 |

| status | body |
| --- | --- |
| 200 | `{status: "accepted", batch, g_new, public_input, journal}`: the batch's number, from 1; G after it, the next batch's G_prev; its statement in hex (§4). The next batch may build on `g_new` before this one is proven |
| 400, 409, 422 | `{status: "refused", check, unit, message}`: `unit` the unit's index in the batch bytes, from 0, where the check is a unit's, else null; `message` the native run's panic message or the Prover Host's own. After a 409 the backend rebuilds on the status (§2.2) |
| 503 | `{status: "paused", message}` |
| other | `{status, error}`: 400 `malformed`, a body that is no submission; 401 `unauthorized`; 403 `forbidden`; 413 `too_large`; 500 `error`; 503 `unavailable`, after a fatal error |

## 2. Prover Host → backend

### 2.1 Webhooks

Each endpoint (§5) takes the event types it lists, or `*` for every one:

```text
POST <url>
Content-Type: application/json
Apogee-Event: <the event's id>
Apogee-Signature: t=<unix seconds>,v1=<hex of HMAC-SHA256(secret, "<t>.<body>")>

<the event>
```

| `type` | sent when | body ([webhook-event.v1.schema.json](webhook-event.v1.schema.json)) |
| --- | --- | --- |
| `batch.proven` | the batch commits: its proof verified, every earlier batch proven | `{format, id, type, batch, root, proof: {identity}}`, `root` its G_new |
| `batch.failed` | the batch diverged, or was accepted after one that did | `{format, id, type, batch, cause, root}`, `root` the G of the tip it rolled back to |
| `host.alert` | a divergence paused the Prover Host | `{format, id, type, alert: "batch_diverged", batch, message}` |
| `batch.executed` | in place of `batch.proven` under the development backend, which proves nothing | `{format, id, type, batch, root, proof: null}` |

`format` is `"apogee/webhook-event/v1"`, `id` is `evt_` and 16 hex digits, and `identity` the
program identity the batch was proven under.

- **Delivery.** A 2xx within 10 s delivers. Otherwise the event is retried after 1 s, doubling to an
  hour, for 3 days, then abandoned. Delivery is at least once: deduplicate on `id`.
- **Order.** Batch events go in batch order and alerts as they happen; a retry can arrive late, so
  order by `batch`.
- **Verifying.** Compute the HMAC over `t`, `.` and the body as received, compare it in constant
  time, and refuse a `t` more than 5 minutes from your clock.
- **A report, not a vote.** The reply changes no batch.

### 2.2 Queries

With a key of the `backend` or `operator` scope:

| route | reply |
| --- | --- |
| `GET /v1/status` | `tip: {g, now, deposits: {cursor, hash}, exits: {cursor, hash}}`, the next batch's G_prev, earliest `now` and queue points; `queued: {deposits, exits}`, the records past them, the most the next batch consumes; `proven_root`; `paused`; `batches: {accepted, proven, failed, unproven}`; and the operator's fields (`apogee-host:docs/prover-host.md` §10.2) |
| `GET /v1/batches/{n}` | `{batch, state, at, accepted_at, g_prev, now, deposits, exits, g_new, …}`, `state` `unproven`, `proven` or `failed` (and its `cause`), `executed` under the development backend; 404 `{status: "unknown", batch}` |
| `GET /v1/state/{table}/{key}` | the tip's record, `{table, key, value}`, the table by id, key and value in hex as the client encodes them; 404 `{status: "absent", table, key}`, or `{status: "unknown", error}` for no such table |

In every reply addresses and digests are `0x` and lowercase hex, other byte strings lowercase hex,
counts, batch numbers, cursors and ms times numbers, and amounts decimal strings.

## 3. Prover Host ↔ core

| | shape | rule |
| --- | --- | --- |
| program | the release guest ELF and its heights (the build record) | `host::setup(&elf, &ProgramParams)` gives the key and its `vk.identity`; the Prover Host starts only where that is the record's identity |
| prove | `GuestIo { input: the public input, advice }` | `host::prove(&setup, &io, max_in_flight)` gives `Proven { block, journal, … }`, and refuses any exit status but 0 before proving |
| verify | a `BlockProof` (`to_bytes`), its statement a `PublicInputs`: input, output (the journal), exit status and the execution's record ([proof.md](../docs/spec/proof.md) §1) | `host::verify(&vk, &block)` checks no identity: its caller holds `vk.identity` to the pinned one, the statement's input to the public input, its output to the native run's journal and its exit status to 0 |
| identity | 64 bytes, 128 lowercase hex digits ([program.md](../docs/spec/program.md) §8) | a verifier takes it from a channel the prover does not control |
| CLI | `verifier block <vk> <identity-hex> <statement> <block>` | exit 0 verified, 1 refused, 2 usage |
| version | the proof's: `PROTOCOL_VERSION`, absorbed first ([proof.md](../docs/spec/proof.md) §2, G1); the key's: `code_version` | a proof of another version verifies under no key of this core |

- **Only exit status 0 is provable or verifiable** ([proof.md](../docs/spec/proof.md) §6, step 0). A
  panic (101), a journal overflow (70), an exhausted heap (71) and any `exit(n)` with n ≠ 0 have no
  proof, so a verifier reads a journal, never a status.
- **A divergence.** Before proving, the Prover Host runs the guest under the emulator: a nonzero exit
  or a journal not the native run's fails the batch (`apogee-host:docs/prover-host.md` §6).
- **Heights** are on the core's menu, one per family number, and each choice is its own identity
  ([program.md](../docs/spec/program.md) §7).

## 4. The statement

```text
public input   deployment id 28 ‖ G_prev 64 ‖ now u64 ‖ deposits: cursor u64 ‖ hash 64
               ‖ exits: cursor u64 ‖ hash 64                                  244 bytes exactly
journal        G_new 64 ‖ deposits: cursor u64 ‖ hash 64 ‖ exits: cursor u64 ‖ hash 64
               ‖ withdrawal × w                                               208 + 56·w bytes
withdrawal     to L1Address 20 ‖ token L1Address 20 ‖ amount u128
deposit        owner Address 32 ‖ token L1Address 20 ‖ amount u128           68 bytes, a vault record
forced exit    owner Address 32 ‖ token L1Address 20 ‖ to L1Address 20       72 bytes, a vault record
```

- **A queue point** is the cursor of its next record and the rolling hash through the one before:
  `H' = node(H ‖ leaf(record, ∅), t)`, t = 2^32 for deposits and 2^32 + 1 for forced exits; an
  empty queue's hash is the zero digest (`apogee-host:docs/app-framework.md` §6).
- **G** folds the tables' roots in id order, the system tables 0–2 first:
  `compress(… compress(compress(R_0, R_1), R_2) …, R_k)`.
- **w** is at most 288, what the journal's 16,380 bytes hold; the backend cuts a batch within it.
- **The claim**: an ADMIN holder at G_prev authorized the batch bytes, whose units, each signed as
  its kind requires, take G_prev to G_new with the vault records between the two queue points, and
  emit these withdrawals. The units, their signatures and the authorization are advice, never public
  input; there is no batch digest.

## 5. Suite ↔ Prover Host

The deployment configuration the Suite hands a Prover Host, which takes it as its config
(`apogee-host:docs/prover-host.md` §10.3):

| item | from | rule |
| --- | --- | --- |
| program | the build record: the ELF in the image, its heights and identity | the Prover Host refuses to start on an ELF of another identity at those heights |
| deployment id | the vault on the mode's network | in every signature's context and in the public input |
| genesis admins | the manifest's, as 32-byte hex | at least one; RoleTable's first ADMIN holders |
| API keys | issued by the Suite: `apg_staging_` or `apg_production_`, then 64 hex digits of 32 random bytes; handed over as the SHA-256 of the key's text, with the `backend` scope | the Prover Host holds digests only; operator and prover keys are the host operator's, Prime Fleet's in managed mode |
| webhooks | the Suite's enabled endpoints, `{id, url, secret, events}` | `id` 1–64 letters, digits, `-` and `_`; `secret` at least 16 bytes; `events` types of §2.1, or `*` |
| mode | `staging` or `production` | Staging: Sepolia and the vault's stand-in routes (§6); Production: Ethereum, no stand-ins, HTTPS webhooks only |
| topology | combined, coordinator or prover processes (`apogee-host:docs/prover-host.md` §10.9) | Prime Fleet's choice in managed mode |

- A new program, deployment id or set of genesis admins is a new deployment, from genesis; keys and
  webhooks change with a restart on the same state.
- The Suite reads `GET /v1/status` and `GET /v1/batches/{n}`, and resumes a paused Prover Host
  (`POST /v1/resume`), with an operator key. A refusal reaches only its submitter.

## 6. Prover Host → vault (not built)

| direction | carries |
| --- | --- |
| Prover Host → vault | each committed batch, in order: a proof the vault verifies (the outer proof for L1 is open) and its statement (§4) |
| the vault's check | the proof under the pinned identity; G_prev its root; both queue points its queues'; `now` at or after the previous batch's, and block time − Δ ≤ `now` ≤ block time. Then G := G_new, the cursors advance and the withdrawals become claims |
| vault → Prover Host | each deposit and forced exit at its queue index (§4). In Staging an operator posts them instead: `POST /v1/vault/deposits` `{index, owner, token, amount}` and `POST /v1/vault/exits` `{index, owner, token, to}`, answered `{status: "queued" \| "known", index}` or 409 `{status: "refused", code, index}` |
| Prover Host → backend | `batch.settled` once the vault accepts the batch: the L1 transaction, the new root and the withdrawals; final |
| admin → vault | a new identity, which activates in Production after T |
