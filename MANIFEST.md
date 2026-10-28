# Tugboat Skill Manifest

## Core

- `SKILL.md`: trigger, non-negotiable contract, work rhythm, and completion gate.
- `README.md`: human orientation and quick start.
- `starter-prompts.md`: concise prompts for new, resumed, deadline-bound, and Sasha-paired missions.

## References

- `references/operating-protocol.md`: authority, scope control, execution slices, proof, reviews, deployment, and failure patterns.
- `references/efficiency-and-context.md`: context budget, test cadence, compact handoffs, stale-prompt recovery, and credit/time discipline.

## Templates

- `templates/requirement-ledger.md`: immutable requirement-to-proof contract, scope changes, release slices, reviews, deployment, and completion map.
- `templates/audit-log.md`: append-only decisions and evidence.
- `templates/context-handoff.md`: compact compaction/resume index.
- `templates/completion-report.md`: final requirement and preservation proof.

## Deterministic Tools

- `package.json`: Node 20+ package and portable `tugboat` and `tugboat-mcp` binaries.
- `scripts/tugboat.mjs`: protocol 2 mission, language architecture, compiled execution packets, expiring claims, evidence, scope, continuity, bundle, selective-promotion, CI, migration, recovery, and close commands with 1.1 compatibility.
- `scripts/tugboat-mcp.mjs`: bounded dependency-free MCP stdio adapter with read-only default, fixed mission and repository scope, deterministic discovery, structured tools, and packet resources.
- `scripts/lib/control-plane.mjs`: canonical execution-packet compilation and atomic claim/release mutation layer shared by CLI and MCP.
- `scripts/lib/language-catalog.mjs`: versioned, source-auditable ordinal capability catalog.
- `scripts/lib/language-optimizer.mjs`: deterministic ledger signals, private-safe repository facts, language ranking, decision grades, and costed topology selection shared by CLI and MCP.
- `scripts/install.mjs`: atomic shared/Claude/Codex skill installer.
- `scripts/lib/bundle.mjs`: immutable multimodal bundle creation, validation, signing, redacted inspection, and candidate comparison.
- `scripts/lib/promotion.mjs`: requirement mapping, impact planning, disposable-worktree application, target-owned validation, and atomic fast-forward promotion.
- `scripts/lib/`: hash-chained store, locks, reducers, evidence, provider verification, validation, migration, rendering, security, recovery, bundles, and promotion.
- `scripts/validate-ledger.mjs`: protocol 1.1 compatibility validator.
- `scripts/run-behavior-evals.mjs`: bounded baseline-versus-Tugboat Claude behavior harness.
- `scripts/*.test.mjs`: deterministic contracts for all tools, including failed/dry-run byte preservation and installed-runtime promotion workflows.
- `templates/github/tugboat-validate.yml`: least-privilege CI validation gate.

## Evals

- `evals/evals.json`: seven pressure scenarios for scope preservation, stale resumes, efficient deadlines, honest completion, mid-mission changes, and dirty worktrees.

## Canonical install targets

- `~/.agents/skills/tugboat`: shared cross-runtime alias.
- `~/.claude/skills/tugboat`: Claude Code discovery.
- `~/.codex/skills/tugboat`: Codex discovery.
