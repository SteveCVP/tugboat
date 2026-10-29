---
name: tugboat
description: Use when a development mission is large, multi-step, long-running, resumed across agents or CI, governed by a ledger, vulnerable to scope drift, or expected to reach verified production completion without missing requirements.
---

# Tugboat

Carry the user's complete mission to an operator-usable, honestly proven result. The hash-chained event log and Git are the memory; chat summaries, generated Markdown, and scheduled prompts are not sources of truth.

The approved outcome and required proof outrank token, time, and compute optimization. Tugboat removes repetition, re-reading, duplicate gates, and low-value work; it never reduces scope, model quality, correctness, security, data integrity, or production proof merely to appear economical.

## Required Protocol

1. Read repository instructions and `references/operating-protocol.md`. For long runs, deadlines, loops, or expensive gates, also read `references/efficiency-and-context.md`.
2. Before implementation, create a mission with `tugboat init`. Capture every requirement, preservation instruction, proof target, release slice, deploy path, source digest, and Git baseline. Commit the genesis files before resuming.
3. Before acting and after every handoff, run `tugboat next --dir tugboat --json`. Treat its digest as the exact compiled context: ready work, claims, blockers, acceptance, proof gaps, preservation duties, Git state, and next check. A completed packet means stop.
4. When implementation language or runtime architecture is consequential and not already decided, run `tugboat language recommend --dir tugboat --repo . --json`. Add a bounded profile for explicit team, platform, constraint, priority, and requirement-signal evidence. Treat `insufficient_evidence` as a request for facts, not permission to guess; record the final human/engineering decision and report digest without treating the recommendation as proof.
5. Use mission intelligence before consequential selection: run `intelligence lint` on contracts; `impact` before `portfolio`; `adversary`, `freshness`, and `simulate` before release; `trust` before `route`; and `federation` for multi-mission trains. Use `memory` only from explicit cross-mission files. Every report is read-only planning evidence—portfolio selection, adversarial cases, routing, memory, and simulation are never implementation or passing proof. See the operating protocol and command help for bounded inputs.
6. Use the proof runtime when confidence itself is consequential: mutation-test critical gates; capture or verify evidence capsules before reuse; attach in-toto/SLSA provenance when evidence crosses a trust boundary; use the causal kernel for content-addressed incremental recomputation; inspect and conform external adapters before execution; reconstruct prior mission truth with `history explain`; and compare structured agent reviews with `review compare`. A cache hit, signature, capsule, mutation plan, or reviewer consensus is not passing requirement proof.
7. Use stable requirement IDs. Never silently narrow work to an MVP, schema, endpoint, shell, mockup, foundation, read-only surface, or follow-up.
8. Build independently verifiable operator workflows. Existing source data must be reconciled when the feature depends on it; an empty interface is not complete.
9. Capture typed evidence with `tugboat evidence` or a deployment adapter. At each verified slice boundary, use `checkpoint --evidence-ids ...`; prose is a note and cannot prove a row. A versioned checkpoint completes the satisfied slice and activates the earliest dependency-ready slice; after amendments or promotion, read a fresh packet because affected work can reopen an earlier slice.
10. For concurrent workers, acquire a short `tugboat claim` only for independently owned open requirements, record the expected revision, and release it when stopping. A claim coordinates work; it never changes requirement status, proves work, grants repository access, or replaces an isolated worktree.
11. For parallel or multi-model work, designate one coordinator as the only writer to the canonical target branch and mission. Workers create immutable `.tugboat` bundles with `bundle create`; the coordinator uses `bundle inspect`, `bundle compare`, certified `bundle compose --dry-run`, and then explicit `bundle compose --apply` or target-owned selective promotion. Never use ordinary Git cherry-pick as a substitute for bundle policy, both-order proof, provenance, and final target race checks.
12. Imported bundle proof is provenance, not completion. Promotion or composition must reopen mapped target requirements and invalidate their active proof. Re-capture target-context command, operator/browser, deployment, and production evidence before claiming the row proven.
13. When release policy requires rollback, run `rollback prove` with the exact base, ordered forward commits, rollback operation, a verified boundary-manifest envelope, fail-closed runtime-effect declarations, and policy. Changed files must be owned by the boundary; schema, data, infrastructure, and external obligations are derived from changed paths and interfaces and cannot be relabeled as file recovery. Treat only `equivalent` as admission; `not_equivalent` blocks and `insufficient_evidence` demands runtime proof or a safer plan. Verification requires the exact local repository and recomputes ancestry, observations, boundary descriptors, and effects; integrity-only JSON verification is not proof. For composition policy, require `rollbackAdmission` so the exact canonical range certificate is bound into composition, merge authorization, and mission history. Execute proof only through the explicit CLI; agents and MCP may perform repository-backed verification but never initiate rollback implicitly.
14. Preserve requested workflows and design with regression proof. Record substantive specialist findings and dispositions; reviewer names alone are not gates.
15. Use targeted gates per slice, affected integration gates at boundaries, and full gates before deploy or completion. After two materially identical failures, stop rerunning and diagnose root cause.
16. Use `tugboat resume` after compaction, agent handoff, or wake-up. It fails closed on stale handoff, unrecorded commits, dirty work, source drift, or event tampering. Use `reconcile` only to account for measured state explicitly.
17. Require `tugboat ci --dir tugboat --json` before deployment. Production evidence must independently verify the deployed SHA through GitHub Actions, CloudFormation, or a signed attestation.
18. Use `tugboat close` only when every material row satisfies its proof target. It automatically checks the event chain, append-only baseline, evidence, source, Git, handoff, clean tree, production SHA, live operator proof, and preservation proof.

## Truthful Status

Use only `PENDING`, `IN_PROGRESS`, `BLOCKED`, `PROVEN(local)`, `PROVEN(production)`, and `WAIVED(user)`. A material approved item cannot disappear into follow-ups. If required work remains, the mission is partial or blocked.

## Proof Runtime Boundaries

Run proof mutation only with an operator-supplied argv after `--`; mutation profiles never contain commands. Capture and replay evidence only in disposable clean Git worktrees. Replay always requires a fresh explicit command and compares results—it never executes stored argv by implication. A provenance signature authenticates bytes and signer, not correctness or a SLSA level.

Treat causal-kernel caches as hostile: verify their input key and output digest or recompute. An adapter manifest must pin its entrypoint, declare inputs and environment names, cap time and output, and disclose isolation. `brokered` strips ambient access but is not an OS sandbox; call an adapter sandboxed only when a pinned WASI or container runtime actually enforces it. Differential review must compare identical input digests, preserve minority findings, and state that consensus is not proof.

## Portability

Use the same package, bundle envelope, and state format from Claude Code, Codex, developer shells, and headless CI. Install with `node scripts/install.mjs`; prefer `~/.agents/skills/tugboat` as the shared alias. Never hardcode a runtime home, model name, or actor. Keep updates concise: newly proven IDs, measured evidence, active slice, and one real blocker if present.

Agent hosts may use `scripts/tugboat-mcp.mjs --dir MISSION --repo REPOSITORY`. Keep MCP read-only unless claim/release access is explicitly required; enable that boundary only with the startup flag `--allow-writes`. Mission and repository paths and write policy are process capabilities, never model-controlled tool arguments. Language, intelligence, capsule/provenance/rollback verification, bundle commutativity, adapter inspection, history explanation, and differential review tools are read-only; MCP never exposes mutation, rollback execution, composition application, replay, signing, adapter execution, cache writes, cross-mission memory, or federation files. MCP claim/release calls must carry `expectedRevision` and `expectedHead` from the latest packet.
