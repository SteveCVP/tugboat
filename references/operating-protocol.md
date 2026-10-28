# Tugboat Operating Protocol

## Contents

1. Authority and change control
2. Requirement capture
3. Compiled execution and claims
4. Architecture decision compilation
5. Slicing and execution
6. Multi-worker candidate promotion
7. Proof model
8. Reviews and defects
9. Deployment and completion
10. Failure patterns

## 1. Authority And Change Control

Use this precedence order:

1. current system/developer/repository instructions;
2. the user's newest explicit direction;
3. approved source specification and preservation instructions;
4. Tugboat requirement ledger and recorded scope changes;
5. implementation plan and scheduled prompts;
6. old chat summaries.

Never rewrite an original requirement to make implementation easier. Append a scope
change with date, author, exact change, reason, and affected requirement IDs. A new
instruction may supersede an old one; preserve both and mark the relationship.

Persist any chat-only mission brief verbatim in `tugboat/sources/mission-source.md`
and record its SHA-256 digest. For an existing durable specification, record its path
and digest. Redact tokens, passwords, cookies, private keys, and one-time links rather
than turning the mission record into a secret store.

Classify new findings as:

- `in_scope_defect`: prevents an approved requirement from working;
- `required_dependency`: necessary for the approved workflow;
- `optional_improvement`: useful but not required for completion;
- `out_of_scope`: unrelated and preserved for a separate decision.

Fix in-scope defects and required dependencies. Do not let optional improvements
consume the critical path. Do not use `out_of_scope` to evade a requirement.

## 2. Requirement Capture

Prefer the deterministic CLI for mission state:

```bash
tugboat init ...
tugboat evidence --dir tugboat --id E1 --requirements R1 -- <verification command>
tugboat checkpoint --dir tugboat --requirements R1 --evidence-ids E1 ...
tugboat resume --dir tugboat
tugboat ci --dir tugboat --json
tugboat close --dir tugboat
```

Protocol 2 stores authority in `events.jsonl` and rejects manual edits. `state.json` and
Markdown files are generated projections. Use `migrate` for a 1.1 mission; imported
prose proof remains historical context and does not satisfy structured proof.

Each requirement row must state:

- stable ID;
- exact requirement;
- source or user quote;
- whether it is material;
- observable acceptance criteria;
- proof target (`local`, `production`, or `documentation`);
- implementation locations;
- deterministic tests;
- browser/operator proof;
- production proof and deployed SHA;
- current status.

Capture negative requirements too: do not remove a design, do not alter a workflow,
do not deploy yet, do not fabricate data, do not add a new tab. These are preservation
requirements and need regression proof.

Resolve ambiguity by reading the repo, source materials, prior decisions, and live
behavior first. Ask the user only when a consequential choice remains unknowable.
Record the question once. Do not ask low-value questions at the end of each cycle.

## 3. Compiled Execution And Claims

Run `tugboat next --dir tugboat --json` before choosing work and after any handoff,
compaction, claim, release, checkpoint, or scope amendment. It compiles the active
dependency closure into a content-addressed execution packet. Use the packet rather
than copying the full ledger into an agent prompt. Record its digest when another
system must identify the exact context it acted on.

Ready work must be open, inside the active slice and its requirement dependencies,
unblocked, and free of a live claim. The packet must state exact acceptance, literal
proof gaps, preservation duties, Git head and dirty state, next action, and next check.
It must not contain command output, environment values, embedded bundle bodies, or
evidence narratives. A complete mission advertises no work and says to stop.

Use claims only when concurrent workers own independent requirement units:

```bash
tugboat claim --dir tugboat --id C-WORKER-R1 --holder worker-a \
  --requirements R1 --ttl-seconds 900 --expected-revision 3 \
  --expected-head "$PACKET_HEAD"
tugboat release --dir tugboat --claim C-WORKER-R1 --holder worker-a
```

Keep leases short. An overlapping, stale-revision, out-of-slice, closed, duplicate, or
impersonated claim must fail atomically. Expiration immediately restores readiness but
does not erase history. Claims do not prove requirements, mutate their status, grant
Git access, or make shared worktrees safe.

An agent host may connect through the dependency-free MCP stdio server. The mission
directory and write policy are fixed at process startup. Read-only is the default;
`--allow-writes` adds claim and release tools but never arbitrary command execution.
Do not accept model-provided mission paths, write-policy overrides, wall-clock values,
or evidence bodies through the protocol.

## 4. Architecture Decision Compilation

When a mission has not already fixed its implementation language, use the ledger as
the decision input rather than asking a model for a preference:

```bash
tugboat language recommend --dir tugboat --repo . \
  --profile architecture-profile.json --json
```

Map material requirement IDs to concrete workload signals. Declare team languages,
allow/forbid constraints, priorities, and `maxLanguages` only when they are known. An
empty profile permits conservative literal inference and tracked-stack affinity, but a
result of `insufficient_evidence` is intentionally not a recommendation.

Read the candidate contributions, vetoes, uncertainties, rejected alternatives, and
topology gates before deciding. Ordinal scores order the built-in catalog; they do not
predict latency, throughput, reliability, staffing, or cost. Run a measured spike when
a decision depends on those values. Record the chosen architecture and report digest as
a decision, not as implementation or proof.

Default to one language. A second language must be limited to the requirement IDs that
earn it and must expose integration, staffing, deployment, observability, and security
costs. Do not add a language merely because it is locally fashionable or scores well on
an unallocated requirement. The compiler never mutates mission or repository state.

## 5. Slicing And Execution

Order slices by user-visible critical path and dependency, not by file type. A useful
slice crosses schema, API, UI, data population, permissions, and tests when that is
what makes one workflow usable.

For each slice:

1. name the requirement IDs it closes;
2. define the operator journey;
3. identify existing patterns and preservation tests;
4. reproduce current behavior or establish a baseline;
5. implement the complete path;
6. verify honest loading, empty, partial, stale, permission, error, and success states;
7. test desktop and mobile where applicable;
8. populate or reconcile authoritative data;
9. commit an independently reversible change;
10. update ledger, audit log, and handoff.

Protocol-2 checkpoints record versioned slice progression. When the active slice's
material requirements are no longer open, Tugboat marks it complete and activates the
earliest dependency-ready slice; when an amendment or governed promotion reopens proof,
the earliest affected slice becomes active again. Always compile a fresh packet after
those events. Events created before this rule retain their original replay semantics.

A migration or endpoint is an increment, not completion, unless the requirement itself
was explicitly only that artifact.

## 6. Multi-Worker Candidate Promotion

Use selective promotion when Claude, Codex, a human developer, or CI builds candidate
work outside the canonical target branch. The coordinator owns the target mission,
requirement mapping, validation command, and final proof. Workers own only their source
missions and immutable `.tugboat` bundle outputs.

The safe operating sequence is:

1. each worker implements and commits independently owned requirement slices;
2. each worker maps every included commit and typed component to source requirement IDs;
3. the worker creates a bundle, optionally signs it, and publishes its digest out of band;
4. the coordinator verifies trust policy, inspects candidates, and compares conflicts;
5. the coordinator dry-runs the exact selection, exclusions, and source-to-target mappings;
6. the coordinator promotes with a target-owned validation command;
7. Tugboat applies the selection in a disposable detached worktree and atomically
   fast-forwards only an unchanged, clean target;
8. the coordinator captures fresh target proof for every reopened requirement.

Never let multiple agents append to one mission event log or write one worktree. Never
copy bundle bodies into prompts, logs, or review comments. Never treat `git cherry-pick`,
patch application, or artifact copying as equivalent to Tugboat promotion: those paths
omit bundle validation, mapping, proof invalidation, provenance, and stale-target checks.

Reject promotion when a commit or component mixes selected and unselected requirements.
Split the source commit or select the complete owned unit; do not infer file-level
ownership. Enforce declared bundle dependencies in canonical promotion order. Require a
trusted public key and `--require-signature` whenever bundles cross a trust boundary.

Inspection and comparison are non-mutating and redact embedded bodies. Dry-run is also
non-mutating. Any malformed bundle, secret, unsafe path, size violation, signature
failure, dependency gap, collision, patch conflict, failed validation, dirty validation
side effect, or target drift must leave the target branch, worktree, and mission exactly
as they were.

Imported source evidence remains immutable provenance. It does not satisfy target
acceptance. Promotion records reusable exact-content command evidence and expired
context-bound evidence separately, reopens mapped target requirements, and requires new
canonical proof before a checkpoint can restore a proven status.

## 7. Proof Model

Use these statuses exactly:

- `PENDING`
- `IN_PROGRESS`
- `BLOCKED`
- `PROVEN(local)`
- `PROVEN(production)`
- `WAIVED(user)`

`PROVEN(local)` requires implementation evidence, deterministic tests, and an
operator/browser check or a reason it is not applicable. `PROVEN(production)` also
requires deployed SHA, live evidence, correct permissions, real data, and regression
proof. `WAIVED(user)` requires the approver, date, and exact waiver.

The proof target controls mission completion:

- `documentation`: `PROVEN(local)` is sufficient;
- `local`: `PROVEN(local)` is sufficient only when the user did not request deploy;
- `production`: only `PROVEN(production)` or `WAIVED(user)` closes the row.

Examples of insufficient proof:

- route exists;
- table exists;
- UI contains the label;
- fixture renders;
- source string appears;
- CI is green;
- one screenshot exists;
- code was merged;
- Lambda was modified;
- reviewer said `looks good`.

## 8. Reviews And Defects

Use appropriate reviewers as real gates. A review record includes reviewer, scope,
finding, severity, disposition, requirement IDs, implementation change, and proof.
Do not ask reviewers to re-audit the whole product after every small increment.

When a defect is found:

1. reproduce it;
2. identify the violated requirement or add an in-scope defect row;
3. find root cause;
4. add a failing regression test;
5. fix without masking errors;
6. verify the wider affected matrix;
7. record the lesson and proof.

Do not celebrate the number of tests or fixes. Explain what operator failure is now
prevented.

## 9. Deployment And Completion

Before deployment, record canonical workflow, migrations, ordering constraints,
rollback anchor, secrets/permissions, data population, and post-deploy journeys.

After deployment verify:

- served SHA/assets;
- authentication and authorization;
- each new operator path with real data;
- existing preserved paths;
- responsive behavior;
- error/partial states;
- queues, schedules, alarms, or workers affected;
- no test artifacts or temporary credentials remain.

If the deployment reports failure after resources changed, measure actual state before
retrying. Fix lying release signals as defects. Do not equate a workflow's green/red
badge with production truth without inspection.

Run strict validation against the immutable baseline before deployment and completion.
This recomputes source digests, verifies Git ancestry and recorded SHAs, rejects stale
handoffs, and detects rewritten requirements, preservation rows, scope changes, or
audit history.

Mission completion requires the validator, full gates, production proof, completion
map, and a clean handoff. Stop scheduled loops when complete.

## 10. Failure Patterns

Reject these common shortcuts:

- `foundation complete` while the UI is empty;
- `frontend complete` while writes are staged or fake;
- `integration complete` because a webhook returns 2xx but drops payloads;
- `analytics complete` without identity, coverage, bot exclusion, or real history;
- `data populated` from invented defaults or fuzzy matches;
- `review complete` with no findings or dispositions;
- `production proven` from anonymous health endpoints only;
- `follow-up` used to hide approved material scope;
- rerunning the entire suite after every line while avoiding the missing workflow;
- continuing a loop after the durable ledger says the mission is complete.
- allowing multiple workers to mutate one canonical branch or mission;
- importing a bundle and preserving its source completion claim as target proof;
- selecting part of a mixed-ownership commit because only some files look relevant;
- bypassing failed bundle policy with manual Git or filesystem operations.
