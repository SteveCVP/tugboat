# Tugboat Starter Prompts

## Start A Large Build

```text
Use the Tugboat skill.

Run this mission in [REPO]: [MISSION]. Treat [SPEC/PROMPT PATH] as binding. Use `tugboat init` before implementation and the CLI for evidence, checkpoints, resume, CI validation, and close. Capture every requirement and preservation instruction with observable acceptance and proof target, then run the anti-slop gate before implementation. Record release slices, critical path, canonical deploy path, any explicit deadline/budget, and two-strike retry policy; if no hard cap was supplied, do not invent one. Implement independently provable operator workflows using real/reconciled data, durable writes where required, honest loading/empty/partial/stale/error states, permissions, responsive browser proof, and canonical production deployment. Compile proof impact before selecting affected gates and run adversarial, freshness, and release-simulation gates before deployment. Do not reduce scope, model quality for consequential work, correctness, or proof to save tokens. Do not count compiler plans or scaffolding as completion or hide approved work in follow-ups. Return the requirement-to-production completion map only after `tugboat ci` and `tugboat close` pass.
```

## Resume After Context Compaction

```text
Use the Tugboat skill and run `tugboat resume --dir tugboat` for [MISSION] in [REPO]. Do not trust this wake-up prompt as current state. If resume fails, inspect the reported drift and use a structured reconciliation only for measured, intentional state. Continue only the active slice and checkpoint it with structured evidence.
```

## Fix A Failed Or Partial Build

```text
Use the Tugboat skill.

Audit [BRANCH/DEPLOYMENT] against the original requirements in [SPEC/PROMPT PATH]. Populate the requirement ledger with the exact requested work, preservation instructions, what operators can actually use, and current proof. Downgrade any false completion claim. Then close every in-scope defect and missing material workflow in dependency order. Do not redo proven work or broaden into unrelated cleanup. Deploy and verify only through the canonical path.
```

## Work To A Deadline

```text
Use the Tugboat skill. The hard deadline/credit cap is [TIME/BUDGET]. Build [MISSION] in [REPO]. Record the budget, critical path, gate cadence, and two-strike retry policy. Preserve full proof for the core operator workflow and cut optional improvements, repeated broad reviews, and unrelated cleanup. Reserve time for the full release gate and production verification; do not trade away security, data integrity, or required workflow proof to appear finished.
```

## Pair Sasha With Tugboat

```text
Use Tugboat for execution continuity and Sasha for domain, evidence, and language review.

Execute [MISSION] in [REPO] from [SPEC/PROMPT PATH]. Tugboat owns the requirement ledger, audit log, context handoff, slices, drift control, and completion map. Sasha reviews source truth, claims, labels, operator language, and domain correctness at the relevant release boundaries. Record substantive Sasha findings and dispositions by requirement ID. Do not paste either skill's entire protocol into every cycle.
```

## Mid-Mission Requirement Change

```text
Use Tugboat. Append this approved change to the existing mission without rewriting its baseline: [CHANGE]. Record the author, date, reason, affected requirement IDs, changed acceptance criteria, and release impact. Preserve superseded wording and resume from the earliest affected unproven requirement.
```

## Build A Worker Candidate Bundle

```text
Use the Tugboat skill as a worker, not the canonical coordinator. Build [REQUIREMENT IDS] in an isolated branch and mission from [SOURCE SPEC]. Keep each commit and typed component independently owned by explicit requirement IDs. Run source-side verification, then create an immutable `.tugboat` bundle with complete commit mappings, components, dependencies, provenance, and an Ed25519 signature when a trusted key is supplied. Inspect the finished bundle and report only its path, digest, signature state, requirement coverage, dependencies, commits, components, and honest source evidence status. Do not write to the coordinator's branch or mission, do not claim target completion, and do not paste embedded bundle bodies into chat or logs.
```

## Coordinate Multiple Candidate Bundles

```text
Use the Tugboat skill as the sole writer to [TARGET REPO/BRANCH/MISSION]. Treat candidate bundles [FILES] as untrusted inputs until policy verification passes. Inspect and compare them, identify requirement coverage, dependencies, component conflicts, and mixed-ownership units, then choose only explicitly approved source requirements. Map every selected source requirement to one existing target requirement. Run `tugboat cherry-pick --dry-run` first and show the concise impact plan. If valid, promote with the target's own full validation command. Do not substitute ordinary Git cherry-pick or manual file copying. After promotion, verify that the branch fast-forwarded cleanly, the import and promotion provenance is recorded, every mapped target row is reopened, inherited proof is inactive, and fresh target-context evidence is required before any completion claim.
```

## Connect An Agent Host

```text
Use Tugboat's MCP control plane for [MISSION] at [MISSION DIRECTORY]. Start `scripts/tugboat-mcp.mjs` with the mission directory fixed in the host configuration. Keep it read-only unless this host must coordinate parallel work; only then add `--allow-writes`. Begin with `tugboat_next`, act only on ready requirements, and retain the packet digest in the handoff. If parallel workers are used, claim only independently owned requirement IDs with short leases and isolated worktrees, then release them when stopping. A claim is not proof: complete the normal evidence, checkpoint, review, promotion, and production gates before changing requirement status.
```

## Choose An Implementation Architecture

```text
Use Tugboat's language architecture compiler for [MISSION] in [REPO]. Evaluate the immutable ledger and only Git-tracked repository facts. Create a decision profile only from known team languages, hard allow/forbid constraints, priorities, language-count limit, and explicit requirement-to-signal mappings; do not infer skills, scale, platform, or performance targets. Run `tugboat language recommend --dir [MISSION DIRECTORY] --repo [REPO] --profile [PROFILE] --json`. Treat `insufficient_evidence` as an honest stop, not a prompt to choose a fashionable default. Review contributions, vetoes, uncertainties, why-not alternatives, allocations, and the full polyglot tax. Record the final decision and report digest, and require a measured spike for any latency, throughput, memory, binary-size, or platform claim the ledger cannot prove.
```

## Harden A Release With Mission Intelligence

```text
Use Tugboat 3.0 mission intelligence for [MISSION] in [REPO]. Run `intelligence lint` against the approved contract. Compile `intelligence impact` for the exact Git base/head before selecting gates; block unmapped paths. Feed that report to `intelligence portfolio`, then execute the selected gates rather than calling the plan proof. Compile adversarial acceptance cases, evidence freshness, and counterfactual release journeys before deployment. For delegated work, compile the trust graph before capability-aware routing and require current third-party attestations; routing must not dispatch. If this is a release train, compile the explicit child manifest and block on any unready child, broken compatibility contract, missing rollback action, or graph cycle. Preserve every report digest with its decision, but prove requirements only with fresh typed evidence from actual execution.
```
