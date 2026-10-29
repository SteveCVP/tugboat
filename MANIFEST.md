# Tugboat Skill Manifest

## Core

- `SKILL.md`: trigger, non-negotiable contract, work rhythm, and completion gate.
- `README.md`: human orientation and quick start.
- `starter-prompts.md`: concise prompts for new, resumed, deadline-bound, and Sasha-paired missions.
- `docs/release-audit-4.0.0.md`: public capability, security, portability, and verification inventory for the 4.0 release.
- `docs/release-audit-4.1.0.md`: exact shipped scope, limits, and verification inventory for the current certified-changeset release.

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
- `scripts/tugboat.mjs`: protocol 2 mission, language architecture, ten mission-intelligence compilers, seven proof-runtime workflows, compiled execution packets, expiring claims, evidence, scope, continuity, bundle, selective-promotion, CI, migration, recovery, and close commands with 1.1 compatibility.
- `scripts/tugboat-mcp.mjs`: bounded dependency-free MCP stdio adapter with read-only default, fixed mission and repository scope, deterministic discovery, proof verification and comparison, structured tools, and packet resources.
- `scripts/lib/control-plane.mjs`: canonical execution-packet compilation and atomic claim/release mutation layer shared by CLI and MCP.
- `scripts/lib/language-catalog.mjs`: versioned, source-auditable ordinal capability catalog.
- `scripts/lib/language-optimizer.mjs`: deterministic ledger signals, private-safe repository facts, language ranking, decision grades, and costed topology selection shared by CLI and MCP.
- `scripts/lib/intelligence-core.mjs`: bounded validation, replay-verified mission reads, portable globs, canonical reports, and secret/path rejection shared by every intelligence compiler.
- `scripts/lib/causality-intelligence.mjs`: tracked-change inspection and requirement/proof impact graphs.
- `scripts/lib/quality-intelligence.mjs`: anti-slop findings and adversarial acceptance contracts.
- `scripts/lib/proof-intelligence.mjs`: evidence freshness, failure-journey simulation, and exact proof-portfolio optimization.
- `scripts/lib/trust-intelligence.mjs`: sensitivity and authority propagation with exact violation witnesses.
- `scripts/lib/routing-intelligence.mjs`: capability-, trust-, clearance-, capacity-, cost-, and latency-aware non-dispatch routing.
- `scripts/lib/decision-memory.mjs`: exact-context production decision reuse with assumption half-life and contradiction handling.
- `scripts/lib/federation.mjs`: child readiness, compatibility, deploy waves, and independently derived rollback waves.
- `scripts/lib/proof-runtime.mjs`: portable-path, exact-file, argv, execution-bound, and canonical-digest primitives.
- `scripts/lib/proof-mutation.mjs`: disposable-worktree mutation execution and gate-sensitivity reports.
- `scripts/lib/evidence-capsule.mjs`: declared execution-context capture, verification, and explicit replay comparison.
- `scripts/lib/provenance.mjs`: in-toto/SLSA statement construction and Ed25519 DSSE verification.
- `scripts/lib/causal-kernel.mjs`: verified content-addressed incremental compilation and untrusted cache repair.
- `scripts/lib/adapter-sdk.mjs`: digest-pinned capability broker, direct execution, and deterministic conformance.
- `scripts/lib/history-debugger.mjs`: exact-revision event replay and requirement causal explanations.
- `scripts/lib/differential-review.mjs`: exact-input structured review consensus, divergence, and evidence-gap compilation.
- `scripts/lib/boundary-manifest.mjs`: canonical ownership, interface, invariant, gate, and disclosure boundaries with source-digest verification.
- `scripts/lib/analyzer-protocol.mjs`: bounded, digest-pinned compatibility-analyzer request and report protocol.
- `scripts/analyzers/`: certified language, API, data, workflow, infrastructure, and image-boundary analyzers with conformance fixtures.
- `scripts/lib/effect-footprint.mjs`: deterministic Git and analyzer effect derivation with typed uncertainty.
- `scripts/lib/non-interference.mjs`: path, dependency, interface, schema, infrastructure, and proof-interference witnesses.
- `scripts/lib/certified-changeset.mjs`: candidate, boundary, effect, invalidation, and evidence binding into verifiable certificates.
- `scripts/lib/bundle-algebra.mjs`: pairwise commutativity matrices and deterministic multi-bundle composition order.
- `scripts/lib/hermetic-runner.mjs`: disposable-worktree execution with bounded argv, environment, output, and repository observations.
- `scripts/lib/composition.mjs`: prepared composition, target revalidation, authorization, merge certificates, and immutable mission records.
- `scripts/lib/rollback-equivalence.mjs`: exact or declared rollback execution, semantic obligation accounting, and repository-backed verification.
- `scripts/install.mjs`: atomic shared/Claude/Codex skill installer.
- `scripts/lib/bundle.mjs`: immutable multimodal bundle creation, validation, signing, redacted inspection, and candidate comparison.
- `scripts/lib/promotion.mjs`: requirement mapping, impact planning, disposable-worktree application, target-owned validation, and atomic fast-forward promotion.
- `scripts/lib/`: hash-chained store, locks, reducers, evidence, provider verification, validation, migration, rendering, security, recovery, bundles, and promotion.
- `scripts/validate-ledger.mjs`: protocol 1.1 compatibility validator.
- `scripts/run-behavior-evals.mjs`: bounded baseline-versus-Tugboat Claude behavior harness.
- `scripts/*.test.mjs`: deterministic contracts for all tools, including failed/dry-run byte preservation and installed-runtime promotion workflows.
- `templates/github/tugboat-validate.yml`: least-privilege CI validation gate.
- `templates/github/tugboat-intelligence.yml`: least-privilege impact, anti-slop, adversarial, and freshness pull-request gates with report artifacts.
- `templates/github/tugboat-proof-runtime.yml`: least-privilege mutation and evidence-capsule CI gate with content-addressed artifacts.

## Evals

- `evals/evals.json`: sixteen pressure scenarios covering scope preservation, stale resumes, efficient deadlines, honest completion, change impact, anti-slop rejection, plan/proof separation, weak gates, evidence portability, sandbox honesty, review disagreement, capability routing, federated release blocking, and dirty worktrees.

## Canonical install targets

- `~/.agents/skills/tugboat`: shared cross-runtime alias.
- `~/.claude/skills/tugboat`: Claude Code discovery.
- `~/.codex/skills/tugboat`: Codex discovery.
