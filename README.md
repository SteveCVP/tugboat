# Tugboat

Tugboat is portable mission control for consequential software builds. The same dependency-free Node 20+ package runs from Claude Code, Codex, a developer shell, and CI.

## Truth model

```text
tugboat/
  events.jsonl             append-only, hash-chained authority
  state.json               replayable snapshot
  evidence/*.json          typed evidence projections
  requirement-ledger.md    generated human view
  audit-log.md             generated human view
  context-handoff.md       generated compact resume view
  completion-report.md     generated only from validated state
```

Do not edit the Markdown projections. Mutating commands acquire a filesystem lock, compare the expected revision, append an event, replay it, and regenerate the views.

## Agent control plane

Tugboat 3.0 compiles the ledger into a small, content-addressed execution packet instead of making an agent reread the full mission. The packet names what is ready, blocked, or claimed; the exact acceptance and proof gaps; preservation duties; Git state; the next check; and a canonical SHA-256 digest.

```bash
tugboat next --dir tugboat --json

tugboat claim --dir tugboat --id C-CODEX-R1 --holder codex-a \
  --requirements R1 --ttl-seconds 900 \
  --expected-revision "$PACKET_REVISION" --expected-head "$PACKET_HEAD" --json

tugboat release --dir tugboat --claim C-CODEX-R1 --holder codex-a --json
```

Claims are bounded coordination leases, not permissions or proof. They can cover only open requirements in the active release slice, expire exactly at their boundary, reject overlap atomically, and remain auditable in the event chain. A rejected race does not change mission bytes.
Set `PACKET_REVISION` and `PACKET_HEAD` from the immediately preceding packet's `mission.revision` and `observation.git.head`; Tugboat then rejects a claim made from stale mission or Git context.

New checkpoints deterministically mark completed slices and activate the earliest
dependency-ready slice. Scope amendments and bundle promotions reopen the earliest
affected work. This behavior is versioned in new events, so replay of older missions
does not silently change historical state.

The same control plane is available to Claude, Codex, IDEs, and other agent hosts over dependency-free MCP stdio:

```json
{
  "mcpServers": {
    "tugboat": {
      "command": "node",
      "args": [
        "/absolute/path/to/tugboat/scripts/tugboat-mcp.mjs",
        "--dir",
        "/absolute/path/to/project/tugboat"
      ]
    }
  }
}
```

The MCP server is read-only by default and fixes the mission and repository paths at startup. Add `--allow-writes` to its startup arguments only when that host should be able to claim and release work. Tool arguments cannot change either path or elevate the policy. The server exposes deterministic mission intelligence, language recommendation, status, next-work, capsule/provenance verification, adapter inspection, history explanation, and differential-review tools plus the current execution packet at `tugboat://mission/current`; write-enabled servers also expose `tugboat_claim` and `tugboat_release`. Mutation, command replay, signing, adapter execution, cache writes, cross-mission memory, and federation remain explicit CLI/CI operations.
MCP mutations require both `expectedRevision` and `expectedHead` from a fresh `tugboat_next` result, so the host fails closed if either mission history or Git context moved between reasoning and action.

## Language architecture compiler

Tugboat 3.0 can compile ledger requirements, explicit constraints, team capability,
and Git-tracked repository facts into an auditable language recommendation:

```bash
tugboat language recommend --dir tugboat --repo . --json

tugboat language recommend --dir tugboat --repo . \
  --profile architecture-profile.json
```

An optional profile makes consequential assumptions explicit:

```json
{
  "teamLanguages": ["typescript", "python"],
  "allowedLanguages": ["go", "python", "typescript"],
  "forbiddenLanguages": [],
  "maxLanguages": 2,
  "priorities": {
    "delivery_speed": 4,
    "operational_simplicity": 5,
    "safety": 4
  },
  "requirementSignals": {
    "R1": ["browser_ui", "fast_iteration"],
    "R2": ["data_ai"]
  }
}
```

The output traces each contribution and veto to a requirement, matched ledger excerpt,
profile field, or aggregated tracked-file fact. It reports `insufficient_evidence`
instead of naming a winner when the ledger has not earned a decision. A second language
is allowed only for a distinct platform-bound requirement cluster with a two-level
capability advantage, compatible constraints, and visible integration, staffing,
deployment, observability, and security costs.

The compiler is deterministic, dependency-free, offline, and advisory. It reads only
Git-tracked path names, never source contents, lockfile dependencies, remotes,
environment values, or untracked files. Its ordinal ranks are not performance
benchmarks; measure real latency, throughput, memory, and binary constraints before a
decision that depends on them.

## Why Tugboat is different

Tugboat is not another prompt collection or autonomous coding loop. Its core is an
append-only mission kernel: requirements and preservation duties are executable truth;
work packets and mutations are causally bound to mission and Git state; proof is kept
separate from generation; and signed candidate composition reopens affected proof.
Claude, Codex, human shells, and CI all consume the same state machine.

Tugboat 3.0 ships ten content-addressed mission-intelligence compilers: proof impact,
anti-slop quality, counterfactual release simulation, capability-aware execution
routing, decision memory, proof-portfolio optimization, evidence freshness,
trust-taint analysis, adversarial acceptance, and federated release trains. They share
one dependency-free kernel, strict schemas and bounds, canonical SHA-256 reports, and a
hard distinction between planning and proof.

Tugboat 4.0 adds a proof runtime around those compilers: proof mutation, reproducible
evidence capsules, signed in-toto/SLSA provenance, verified incremental recomputation,
capability-brokered adapters, hash-chain time travel, and cross-agent differential
review. These are not extra dashboards or agent personas. They test whether a gate can
detect a declared defect, preserve the context needed to verify a result, and expose
where independent reviewers or cached conclusions diverge.

## Proof runtime

Test the test, then capture and attest the exact result:

```bash
tugboat proof mutate --repo . --plan critical-mutations.json --json --gate -- npm test

tugboat capsule capture --repo . --inputs package.json,scripts/tugboat.mjs \
  --output proof.capsule.json -- npm test
tugboat capsule verify --file proof.capsule.json --repo . --json

tugboat provenance create --root . --subjects dist/report.json \
  --materials materials.json --builder https://ci.example/builders/release \
  --private-key release-ed25519.pem --output report.provenance.json
tugboat provenance verify --file report.provenance.json --root . \
  --public-key release-ed25519.pub --require-signature --json
```

Capsule replay always requires a new command after `--`; stored argv is never executed
implicitly. A valid signature authenticates the exact statement bytes and signer. It
does not prove correctness, establish a SLSA level, or satisfy a ledger row by itself.

Compile only causally invalidated nodes and inspect extension boundaries:

```bash
tugboat kernel compile --graph causal-graph.json --cache .tugboat-cache --json
tugboat adapter inspect --manifest adapters/reviewer/manifest.json --json
tugboat adapter conform --manifest adapters/reviewer/manifest.json \
  --cases adapters/reviewer/conformance.json --json
tugboat history explain --dir tugboat --revision 12 --requirement R4 --json
tugboat review compare --reviews codex-review.json,claude-review.json --json --gate
```

The causal cache is untrusted and revalidated. Adapter code is digest-pinned, receives
only staged inputs and explicitly supplied environment names, runs without a shell,
and is time/output bounded. `brokered` execution is intentionally not called an OS
sandbox; kernel-enforced isolation requires a pinned WASI or container runtime.
Differential review preserves minority findings and treats consensus without evidence
as a gap—reviewer count is not confidence.

## Mission intelligence

Run contract quality before implementation, impact before choosing proof, and release
intelligence before deployment:

```bash
tugboat intelligence lint --dir tugboat --profile quality.json --json --gate
tugboat intelligence impact --dir tugboat --repo . \
  --base origin/main --head HEAD --profile impact.json --json > impact-report.json
tugboat intelligence portfolio --dir tugboat \
  --impact impact-report.json --catalog proof-gates.json --json
tugboat intelligence adversary --dir tugboat \
  --profile adversarial.json --json --gate
tugboat intelligence freshness --dir tugboat \
  --policy freshness.json --observed-at 2026-10-28T18:00:00.000Z \
  --impact impact-report.json --json --gate
tugboat intelligence simulate --dir tugboat \
  --profile release-controls.json --impact impact-report.json --json --gate
```

Trust analysis constrains routing before cost or latency can rank workers:

```bash
tugboat intelligence trust --graph trust-graph.json --policy trust-policy.json --json
tugboat intelligence route --dir tugboat --workers workers.json \
  --profile routing.json --observed-at 2026-10-28T18:00:00.000Z --json
```

Routing profiles must explicitly name `trustedIssuers`. A matching capability string
is ineligible unless a listed third party issued a current evidence-digest attestation;
when a trust report is supplied, every worker must also bind to a `type: worker` node.

Cross-mission intelligence is deliberately explicit-file only:

```bash
tugboat intelligence memory --records decisions.json --context context.json \
  --observed-at 2026-10-28T18:00:00.000Z --json
tugboat intelligence federation --manifest release-train.json --json --gate
```

Impact reports must map every changed path or return `insufficient_evidence`.
Portfolio output is an exact declared-cost set cover with
`planStatus: not_executed`; adversarial cases are contracts; routing never dispatches;
memory is precedent rather than authority; simulations are failure plans. None of these
reports proves a requirement. Execute the selected work, capture typed evidence, and
checkpoint normally.

The reusable `templates/github/tugboat-intelligence.yml` workflow runs least-privilege
pull-request gates and uploads content-addressed JSON reports without secret access.
Its actions are commit-pinned, and manual dispatch requires an explicit comparison base
instead of silently comparing a commit to itself.

## Install once, use everywhere

```bash
node scripts/install.mjs --source "$PWD" --targets agents,claude,codex
```

This installs the identical version into `~/.agents/skills/tugboat`, `~/.claude/skills/tugboat`, and `~/.codex/skills/tugboat`. Existing installs are moved to timestamped backups. CI can use the package binary directly.

Vendor the same pinned runtime and its least-privilege workflow into a repository:

```bash
node scripts/install.mjs --source "$PWD" --targets repo --repo /path/to/project
```

Actor identity resolves from `--actor`, `TUGBOAT_ACTOR`, CI metadata, Git identity, then the OS user. Tugboat contains no Claude-, Codex-, model-, or home-path assumption.

## Export a clean standalone repository

Create a neutral MIT-licensed repository snapshot without internal mission records,
design files, local paths, or source Git history:

```bash
npm run export:distribution -- --destination ../tugboat-distribution
cd ../tugboat-distribution
npm test
npm run test:behavior
npm pack --dry-run
```

The destination must be absent or empty. The exporter copies an explicit allowlist,
rejects symlinks, private provenance, and secret-shaped text, and publishes the result
atomically only after the complete output passes those checks. It does not initialize
Git or configure a remote; repository ownership and publication remain explicit steps.

## Multimodal candidate bundles

Tugboat lets independent Claude, Codex, human, or CI workers deliver reviewable candidate work without writing to the coordinator's branch or mission. A `.tugboat` bundle is an immutable, content-addressed JSON envelope containing ordered per-commit patches, typed binary-safe components, requirement and preservation snapshots, dependency IDs, evidence summaries, source Git provenance, and an optional Ed25519 signature.

Create a bundle from a worker mission. `commit-map.json` must associate every selected commit with the requirements it implements; `components.json` associates each non-Git artifact with a safe target path and requirement IDs.

```bash
tugboat bundle create \
  --dir tugboat --id candidate-claude-01 --output dist/candidate.tugboat \
  --requirements R1,R2 --commits abc123,def456 \
  --commit-requirements-file commit-map.json \
  --components-file components.json \
  --private-key worker-ed25519.pem

tugboat bundle inspect --file dist/candidate.tugboat \
  --public-key trusted-worker.pub --require-signature --json

tugboat bundle compare \
  --bundles dist/claude.tugboat,dist/codex.tugboat \
  --public-key trusted-worker.pub --require-signature --json
```

Inspection and comparison expose hashes, coverage, dependencies, commits, component metadata, proof provenance, and signature state—never embedded patch or binary bodies. Bundle creation rejects secrets, symlinks, unsafe paths, unsupported types, oversized payloads, nonlinear commits, incomplete commit mappings, and inconsistent requirement ownership.

Only the coordinator promotes work into the canonical target mission. Always review a dry run first, map worker requirement IDs explicitly when they differ, and supply a target-owned validation command for the real promotion:

```bash
tugboat cherry-pick \
  --dir tugboat --bundle dist/candidate.tugboat \
  --requirements WORKER-R1,WORKER-R2 \
  --map WORKER-R1:R1,WORKER-R2:R2 \
  --public-key trusted-worker.pub --require-signature \
  --dry-run --json

tugboat cherry-pick \
  --dir tugboat --bundle dist/candidate.tugboat \
  --requirements WORKER-R1,WORKER-R2 \
  --map WORKER-R1:R1,WORKER-R2:R2 \
  --public-key trusted-worker.pub --require-signature \
  -- npm test
```

Promotion happens in a disposable detached worktree. Tugboat applies only independently owned commits and components, runs the coordinator's validation command, records import and mapping provenance, then fast-forwards the original branch only if its branch, HEAD, and cleanliness are unchanged. A conflict, failed test, stale target, dry run, or policy failure leaves the target branch, worktree, and mission untouched.

### Certified rollback equivalence

Before admitting a release that requires rollback, prove the exact forward range and
rollback operation against a content-addressed boundary and policy:

```bash
tugboat rollback prove \
  --manifest rollback-manifest.json \
  --output rollback-certificate.json --json

tugboat certificate verify-rollback \
  --file rollback-certificate.json --repository . --json

tugboat history explain \
  --rollback-certificate rollback-certificate.json --repository . --json
```

The manifest names `repository`, `baseRef`, ordered `forwardCommits`, a rollback
operation (`exact_inverse` or ordered declared commits), a complete
`tugboat.boundary-manifest.v1` envelope, optional fail-closed `runtimeEffects`, and a
policy requiring `equivalent`. Tugboat derives the changed-file footprint from the
union of every parent-to-commit transition in the exact Git range (so transient changes
cannot disappear), rejects paths outside verified component ownership, validates boundary
source and interface digests at the exact base, and derives schema, data,
infrastructure, and external obligations from changed paths and interface kinds. A
caller may classify a derived runtime obligation only as `unknown` or `irreversible`;
omission defaults to `unknown`, and relabeling it as file recovery is rejected.

Tugboat executes the forward and rollback paths only in a disposable worktree, compares
the resulting Git objects with the exact base, stages the certificate, rechecks the
observed target snapshot immediately before atomic publication, and emits one of
`equivalent`, `not_equivalent`, or `insufficient_evidence`. The snapshot claim is
deliberately narrow; it is not a repository lock. Schema, data, infrastructure, and
external effects are never inferred to be restored merely because repository bytes
match; without runtime proof they remain indeterminate, while declared irreversible
effects block admission.

The certificate binds the exact commit range, rollback operation, verified boundary,
policy, derived effect footprint, observations, mismatches, and assessments. Verification
requires the exact local repository and recomputes commit ancestry, observations,
boundary descriptors, and effects from native Git objects with replace refs and grafts
disabled and rejected; a self-consistent JSON envelope is
not admission evidence. Its output must be outside the target repository so proof cannot
create an untracked target mutation. CLI proof is the only execution surface; MCP exposes
repository-backed verification only and never executes rollback.

For certified multi-candidate composition, set `rollbackAdmission.required` in the
composition manifest and provide `boundaryManifest`, `policy`, and `runtimeEffects`.
Tugboat proves the exact canonical prepared range before authorizing it, embeds the
verified rollback certificate in the composition certificate, and records its digest,
status, base, tip, and change digest in the immutable `COMPOSITION_MERGED` mission event.
Composition and merge verification then require the same repository whenever rollback
admission is present.

Imported evidence remains provenance, not target proof. Every promoted target requirement is reopened, its active proof is invalidated, and target-context operator, browser, deployment, and production checks must be captured again. Exact-content source command evidence is merely identified as reusable context; the coordinator decides what to rerun and records new canonical proof.

Use one coordinator as the sole writer to the target mission and branch. Workers may create bundles concurrently, but must never share a writable worktree or append to the coordinator's event log. Bundle dependencies (`--depends-on`) are enforced against prior canonical promotions.

## Start a mission

Create a JSON contract containing `requirements`, `preservations`, and optional `slices`, then run:

```bash
tugboat init \
  --dir tugboat --mission example-app --title "Build Example App" --owner Alex \
  --source docs/spec.md --requirements-file requirements.json \
  --target production --critical-path R1,R2 \
  --deploy-path .github/workflows/deploy.yml

git add tugboat && git commit -m "chore: initialize Tugboat mission"
```

Protocol 2 is the default. Use `--legacy` only to create a 1.1 compatibility mission.

## Daily operation

```bash
tugboat status --dir tugboat
tugboat resume --dir tugboat
tugboat next --dir tugboat

tugboat evidence --dir tugboat --id E-TEST --requirements R1 -- npm test
tugboat evidence --dir tugboat --kind operator --id E-OPERATOR --requirements R1 \
  --url https://app.example.test/workflow --result 'Alex completed the live workflow'
tugboat checkpoint --dir tugboat --requirements R1 \
  --status 'PROVEN(local)' --evidence-ids E-TEST,E-OPERATOR \
  --result 'Operator completes the workflow' \
  --action 'proved workflow' --next 'deploy staging'

tugboat amend --dir tugboat --id A1 --requirements R1 \
  --reason 'User expanded acceptance' \
  --requirement-text 'Expanded workflow' --acceptance 'Operator completes expanded workflow'
```

`resume` fails closed when the handoff is stale, the source changed, the worktree is dirty, commits bypassed the latest mission event, or the event chain was altered. Account for intentional state explicitly:

```bash
tugboat reconcile --dir tugboat --issues dirty_worktree \
  --reason 'Resume the exact reviewed patch' --allow-current-patch
```

## Production proof

```bash
tugboat deployment --dir tugboat --id E-DEPLOY --requirements R1 \
  --provider github-actions --external-id 123456 --repository example/project \
  --environment production

tugboat checkpoint --dir tugboat --requirements R1 \
  --status 'PROVEN(production)' \
  --evidence-ids E-TEST,E-OPERATOR,E-DEPLOY \
  --result 'Live operator workflow succeeds' --action 'proved production' --next 'close'

tugboat ci --dir tugboat --json
tugboat close --dir tugboat
```

Production proof requires a clean implementation tree, deterministic evidence, live operator/browser evidence, and a provider-verified deployed SHA equal to the implementation SHA. A local `HEAD`, green CI badge, endpoint, migration, or screenshot alone is not proof.

Use `tugboat validate --dir tugboat --json` for integrity checks on intermediate pull requests. Use `tugboat ci` or `tugboat validate --release` as the full completion gate immediately before deployment.

## Migration and recovery

```bash
tugboat migrate --legacy-dir tugboat-v1 --dir tugboat
tugboat backup --dir tugboat --destination .tugboat-backups
tugboat rebuild --dir tugboat
```

Migration preserves every legacy requirement, preservation, and audit row but resets prose proof to `PENDING`. Rebuild recreates snapshots and projections only after the full event chain verifies.

## Verification

```bash
npm test
npm run test:behavior
npm pack --dry-run
```
