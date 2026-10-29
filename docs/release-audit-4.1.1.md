# Tugboat 4.1.1 Release Audit

## Patch status

Tugboat 4.1.1 is a compatibility patch for protocol 1.1 missions. It preserves the
certified-changeset, composition, rollback, intelligence, proof-runtime, and portable
installation surfaces shipped in 4.1.0.

## Corrected behavior

`status` and `next` now inspect the mission ledger's declared protocol before entering
the protocol 2 event-replay path. When the ledger declares protocol 1.1, both commands:

- return a distinct nonzero result identifying the mission as legacy;
- provide the explicit `tugboat migrate --legacy-dir ... --dir ...` workflow;
- do not report event-log corruption; and
- leave every legacy mission file byte-for-byte unchanged.

Protocol 2 missions retain the existing fail-closed snapshot and event-replay checks.
The patch does not migrate a mission implicitly, rewrite prose proof as structured
evidence, or weaken corruption detection.

## Verification inventory

The release gate includes real-process protocol 1.1 `status` and `next` failures,
byte-preservation checks, legacy migration retention and proof-reset checks, protocol 2
state and continuity regressions, installed-runtime parity, neutral export, standalone
installation, package contents, the complete test suite, and CodeQL.
