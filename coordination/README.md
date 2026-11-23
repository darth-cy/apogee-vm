# Coordination

How the Apogee Deployment Suite, apogee-host and the Apogee core work as one pipeline. This folder,
in the core's repository, is the single source of truth for every shape that crosses between them:
[minting.md](minting.md) from an app's definition to its image, [runtime.md](runtime.md) for a
running deployment.

## Components

| component | repository | does |
| --- | --- | --- |
| Apogee Deployment Suite | `apogee-deployment-suite` | a developer defines an app (tables, roles, unit actions, logic); exports its manifest; holds its deployment settings |
| app framework, generator | `apogee-host` (`crates/app`, `crates/app-host`) | the framework is the runtime every app shares, in the guest and natively; the generator turns a manifest into an app's crates |
| Prime Fleet | Apogee's | builds each image reproducibly; runs managed Prover Hosts and their provers |
| frontend | the developer's | derives a user's address from a recovery phrase and signs the user's requests |
| backend | the developer's | builds, orders and authorizes every batch with an ADMIN key; receives webhooks |
| Prover Host | `apogee-host` (`crates/prover-host`; an app's `<id>-host`) | proves each batch as sent or refuses it whole; sends webhooks, answers queries |
| Apogee core | `apogee-vm` | proves a guest's execution and verifies the proof |
| vault and admin (not built) | L1 | pin the identity, accept proven batches, run deposits and exits |

## The pipeline

| step | hand-off | shape | owner |
| --- | --- | --- | --- |
| define | developer → Suite | the project, in the Suite's own store | Suite |
| manifest | Suite → Prime Fleet | `apogee/app-manifest/v1`, named by its digest ([minting.md](minting.md) §2) | Suite |
| generate | manifest → source tree | an app crate, a guest crate, a Prover Host crate and a client ([minting.md](minting.md) §3) | generator |
| build | Prime Fleet → Suite | the guest ELF, the Prover Host image and `apogee/build-record/v1` ([minting.md](minting.md) §4) | Prime Fleet |
| deploy | Suite → Prover Host | the image and the deployment configuration ([runtime.md](runtime.md) §5) | Suite, Prime Fleet |
| operate | frontend → backend → Prover Host ⇄ core, webhooks back | signed messages, `POST /v1/batches`, the proof, webhook events ([runtime.md](runtime.md) §1–§4) | backend, Prover Host, core |
| settle | Prover Host → vault | the proof and its statement ([runtime.md](runtime.md) §6) | vault |

## Precedence

- **This folder is canonical** for every shape that crosses a component boundary. Each repository
  implements it and points here; its own docs keep only its internals.
- **A change lands here first**, then in the implementations.
- **Every shape carries a version word**, and a layout change bumps it in the same change.
- **An implementation that deviates** is recorded below and moves to the contract; the contract never
  moves to the implementation.

| shape | version word |
| --- | --- |
| app manifest | `format: "apogee/app-manifest/v1"`, also its digest's domain |
| build record | `format: "apogee/build-record/v1"` |
| the Prover Host's API: submissions, replies, queries | the path prefix `/v1/` |
| webhook event | `format: "apogee/webhook-event/v1"`; its signature, `v1=` in `Apogee-Signature` |
| batch bytes, messages, contexts, the statement | the framework's wire domains `apogee/app/v2` and `apogee/app/v2/batch`, which every signature binds |
| shape digest | `apogee/shape/v2` |
| proof | the core's `PROTOCOL_VERSION`, which the proof's transcript absorbs first |
| program identity, verifying key | the core's `CODE_VERSION` |

## Status

| interface | status | implemented in |
| --- | --- | --- |
| manifest ([minting.md](minting.md) §2) | not built: the Suite exports none; it numbers tags by declaration order when it previews them, stores none and keeps no retired tags; its project ids may start with a digit; its digest is a mock | Suite `src/store.js` (`tags`, `digest`) |
| generator ([minting.md](minting.md) §3) | not built: `apps/exchange`, `guests/exchange` and `apps/exchange-host` are its shape by hand, with layouts in declaration order and enum types by Rust name; the Suite previews the declarations | apogee-host; Suite `schemaRs()` |
| generated client ([minting.md](minting.md) §3) | not built: `app_host::context` and `app::wire`'s writers encode natively, in Rust | apogee-host |
| build and build record ([minting.md](minting.md) §4) | not built: the Suite's Build is its lint and a mock digest, which also covers claims that the manifest does not carry; one hand-written Dockerfile builds the exchange | Suite `src/pages/logic.js`; apogee-host `apps/exchange-host/Dockerfile` |
| identity binding the manifest ([minting.md](minting.md) §5) | not built | — |
| upgrades ([minting.md](minting.md) §5) | not built: a new identity is a new Prover Host deployment from genesis; Production's timelock needs the vault | apogee-host |
| signed messages, batch bytes, submission, refusals ([runtime.md](runtime.md) §1) | built | apogee-host `crates/app/src/wire.rs`, `crates/app-host`, `crates/prover-host` |
| webhooks ([runtime.md](runtime.md) §2.1) | built, but no payload carries `format`; the Suite offers `batch.settled`, which the Prover Host refuses as no event type, and shows example payloads that are not these | apogee-host `crates/prover-host/src/service/render.rs`, `webhook.rs` |
| queries ([runtime.md](runtime.md) §2.2) | built | apogee-host `crates/prover-host/src/service/http.rs` |
| Prover Host ↔ core ([runtime.md](runtime.md) §3) | built; no batch is proven on proving hardware yet | apogee-host `crates/prover-host/src/service/prove.rs`; core `crates/host` |
| statement ([runtime.md](runtime.md) §4) | built | apogee-host `crates/app/src/wire.rs` |
| deployment configuration ([runtime.md](runtime.md) §5) | not built: nothing hands the Suite's settings to a Prover Host; the Prover Host has no project mode, so its vault stand-ins and `http://` webhooks serve any; the Suite's keys are `apg_staging_` or `apg_live_` with 24 hex digits, and `exchange-host api-key` prints `apk_…` | apogee-host `crates/prover-host/src/service/config.rs`; Suite `src/store.js` |
| the Suite reading the Prover Host ([runtime.md](runtime.md) §5) | not built: the Suite's batches, refusals and live figures are mock, its refusals naming checks (`now`, `run`) that [runtime.md](runtime.md) §1.4 does not | Suite `src/store.js` (`CHECKS`) |
| vault ([runtime.md](runtime.md) §6) | not built: in Staging an operator stands in for its queues | apogee-host `POST /v1/vault/deposits`, `/exits` |
| pointers here | built | apogee-vm `docs/architecture.md` §1; apogee-host `CLAUDE.md`, `README.md`, `docs/README.md`, `architecture.md`, `app-framework.md`, `prover-host.md`, `core-interface.md`; Suite `CLAUDE.md`, `README.md`, `docs/README.md`, `operating-model.md`, `core.md`, `suite.md` |

## Files

| file | is |
| --- | --- |
| [minting.md](minting.md) | the ownership split, the manifest and its rules, the generator's output, the build record, identity and upgrades |
| [runtime.md](runtime.md) | the run-time interfaces: submissions, refusals, webhooks, queries, the core, the statement, the deployment configuration, the vault |
| [app-manifest.v1.schema.json](app-manifest.v1.schema.json) | the manifest's form |
| [build-record.v1.schema.json](build-record.v1.schema.json) | the build record |
| [batch-submission.v1.schema.json](batch-submission.v1.schema.json) | `POST /v1/batches` and its replies, the refusal among them |
| [webhook-event.v1.schema.json](webhook-event.v1.schema.json) | a webhook delivery's body |
| [examples/exchange.manifest.json](examples/exchange.manifest.json) | the reference exchange as a manifest, its logic the Suite's Exchange template's |
