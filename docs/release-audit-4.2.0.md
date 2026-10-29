# Tugboat 4.2.0 Release Audit

## Feature status

Tugboat 4.2.0 adds one operator-facing command: `tugboat doctor`. The command is a
read-only preflight for a source checkout, an installed Tugboat payload, an optional
mission, or all three together. It does not repair, migrate, unlock, or rewrite state.

## Diagnostic contract

`tugboat doctor [--dir MISSION] [--json]` checks:

- whether the active Node runtime satisfies Tugboat's Node 20 minimum;
- whether the package version and installed manifest can be read;
- whether an installed payload still matches its recorded content digest;
- whether an optional mission is protocol 2, legacy protocol 1.1, missing, or invalid;
- whether protocol 2 events replay to the recorded snapshot; and
- whether the mission currently has an active mutation lock.

Text output leads with one verdict and concise repair guidance. JSON output uses the
versioned `tugboat.doctor.v1` schema. A healthy report exits 0. Any attention finding
exits 2 so a person, shell, or CI job can stop before attempting a mutation.

An absent install manifest in a source checkout is informational, not a payload
failure. A legacy mission receives an explicit `tugboat migrate` instruction and is
not replayed as protocol 2. A changed installed payload receives reinstall guidance.
Snapshot disagreement and active locks remain visible; the command never clears them.

## Security and integrity boundaries

Doctor calculates integrity from the same package-payload contract used by the
installer. It does not display environment variables, credentials, event bodies, or
the contents of mission evidence. Every diagnostic path is tested for byte preservation
of the source payload and supplied mission.

A healthy doctor report is preflight evidence only. It does not prove requirement
completion, command correctness, deployment readiness, or production behavior, and it
does not replace `tugboat validate`, `tugboat ci`, release gates, or operator proof.

## Verification inventory

The feature gate covers healthy installed payloads, source-checkout behavior, human and
JSON output, unsupported Node versions, payload tampering, legacy migration guidance,
snapshot corruption, active locks, and byte preservation. Release verification also
includes the complete deterministic suite, behavior-evaluation dry run, neutral public
export, exported-repository verification, standalone installation in shared, Claude,
and Codex targets, package-content inspection, GitHub CI, and CodeQL.
