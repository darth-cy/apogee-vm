# Coordination

How the Apogee Deployment Suite, apogee-host and the Apogee core hand work to each other. This page is the canonical account, and each repository points here. Concrete formats live with the component that produces them, and evolve there.

## What moves between the repositories

| Object | From → to | Format defined by |
|---|---|---|
| App definition: tables, roles, unit actions, logic | Suite → apogee-host | Suite |
| Guest program and Prover Host build, with the program identity | apogee-host → a deployment (Prime Fleet or self-hosted) | apogee-host, on the core's SDK and toolchain |
| Batch: ordered signed requests, authorized by the app's admin | developer's backend → Prover Host | apogee-host |
| Proof and journal | Prover Host ↔ core | core |
| Results: proven batches, failures, alerts | Prover Host → backend and Suite | apogee-host |

- **The producer owns the format.** The component that produces an object defines its format, versions it and documents it. Consumers follow it.
- **The producer changes first.** A format change lands with the producer, then with its consumers.

## Structure, then specialization

- **One structure.** A guest program is persistent tables, unit actions and each action's logic. That is all a developer writes.
- **Everything else is generated.** Layouts, encodings, advice, lookups, write-back and dispatch are derived from that structure, and no one edits them by hand.
- **The toolchain specializes against the structure.** Because the structure is known, the SDK and the compiler optimize for it. For example, records are found by advised position instead of searched, and edited in place instead of copied, which made amazon's proving 28% faster.
- **Improvements apply everywhere.** A specialization reaches every app by regenerating, with no change to the developer's code.
- **The core stays app-agnostic.** It proves programs and checks statements. The structure lives in apogee-host and the Suite.
