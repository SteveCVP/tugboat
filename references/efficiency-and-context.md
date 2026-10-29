# Efficiency And Context Control

## Objective

The approved outcome and required proof come first. Spend context and compute on
decisions, implementation, and proof. Make resumption cheap by keeping durable state
concise and current.

Efficiency means reaching the complete result with less waste. Reduce repetition,
re-reading, duplicate model judgment, unnecessary gates, and unrelated work; do not
reduce approved scope, engineering quality, source rigor, security, data integrity,
usability, deployment, or required proof.

## Context Budget

Do not reread the whole repository each cycle. Maintain a working set:

- repo instructions;
- requirement ledger;
- latest audit entries;
- context handoff;
- files for active requirement IDs;
- relevant tests and source data;
- recent commits/diff.

Use targeted search (`rg`, file lists, source IDs) before broad reads. Read schema or
structured data with a parser. Parallelize independent reads and tests when safe.

Do not paste the original prompt into each update or subtask. Refer to stable
requirement IDs and load the canonical source file when exact wording is needed.

## Test Cadence

Use three levels:

1. `slice`: focused unit/contract/browser tests for the active workflow;
2. `integration`: affected package and cross-module tests at a slice/release boundary;
3. `release`: full gates, production checks, and preservation matrix before deploy or
   completion.

Do not run a 15-minute database suite after every copy change. Do not skip it before
a release that changes its contract. Record why each gate is run.

Use the mission's recorded cadence:

- `slice`: targeted contract and operator-path evidence;
- `integration`: affected packages and cross-module contracts;
- `release`: complete regression, preservation, deploy, and production proof.

Compile change impact before choosing affected gates. Then use the proof portfolio to
find the cheapest complete declared set; do not call its unexecuted plan evidence. Use
freshness to avoid rerunning proof that is still valid and to force reruns when change,
age, volatility, amendments, or deployed-SHA drift invalidates it. This is causal gate
selection, not test-count minimization.

After two materially identical failures, do not run the same command a third time.
Classify the failure, inspect the smallest useful logs/state, record the diagnosis,
and change the test, implementation, environment, or plan before retrying. A timeout
and a deterministic assertion failure are not identical failure classes.

If a gate is slow, profile setup, caching, repeated migrations, serialization, and
test scope. Improve the gate only when that work reduces recurring mission cost or
removes unreliable signals; do not detour into a testing-platform rebuild.

## Compact Handoff

At every verified slice boundary update one short handoff containing:

- mission and current status;
- repo/worktree/branch/current SHA;
- active requirement IDs;
- requirements newly proven and exact evidence;
- unresolved blocker or decision;
- changed files/commits;
- next command and next acceptance test;
- processes/sessions still running;
- stale prompts that must be ignored.

Keep detailed history in the append-only audit log, not the handoff. The handoff is a
resume index, not a narrative.

## Compaction Resume Protocol

After context compaction or a scheduled continuation:

1. read repo instructions;
2. read mission metadata and incomplete ledger rows;
3. read the last audit entries and current handoff;
4. inspect `git status`, branch, recent log, and running sessions;
5. compare actual state with the incoming wake-up text;
6. continue only the first unmet critical-path item.

If the wake-up asks for already-proven work, log it as stale and stop or proceed to
the next incomplete requirement. Never redo production work merely because the old
prompt says `continue`.

## Credit And Time Discipline

Use this priority order:

1. complete the approved material requirements;
2. preserve correctness, security, data integrity, and operator usability;
3. produce the required local and production proof;
4. optimize context, model calls, gate cadence, and elapsed time;
5. pursue optional improvements only when they do not threaten the critical path.

When the user provides no explicit hard token, credit, or dollar cap, do not invent
one. Continue required work until the completion contract is met. Do not stop core or
required work merely because it consumes tokens, takes multiple contexts, or costs
more than an arbitrary internal estimate. If an explicit hard cap conflicts with the
approved outcome, surface that conflict early and preserve an honest incomplete
status; never silently narrow the task or lower the proof standard.

- Favor deterministic scripts over repeated model judgment for structural checks.
- Reuse decision memory only when context matches exactly, production outcomes agree,
  and time-decayed assumptions remain live; stale precedent is more expensive than a
  fresh decision.
- Batch related source reads and independent tests.
- Keep reviewer scopes precise; require findings and dispositions.
- Make one source-reconciliation pass reusable across features.
- Do not produce speculative options after direction is approved.
- Do not add low-value polish, metadata churn, or unrelated cleanup.
- Do not ask questions whose answers can be measured from the repo or live system.
- Do not spend time making progress reports ornate.
- Stop when the completion contract is met.

Route work by consequence, not by price. Use adequate model quality for each task.
Architecture, difficult debugging, security, data-model decisions, source-sensitive
analysis, final review, and ambiguous product judgment require the strongest suitable
reasoning available. Deterministic scripts and lower-cost calls are appropriate for
mechanical classification, formatting, structural validation, and other bounded work
only when their outputs are automatically checked. Never downgrade consequential work
solely to conserve tokens.

## Certainty-Preserving Alternatives

When the projected token, time, or external-service cost is high, first look for a
certainty-preserving alternative rather than either spending blindly or weakening the
task. Hold the same acceptance criteria, preservation contract, security properties,
real-data requirement, and proof target constant. Compare alternatives on estimated
cost, time, and proof risk.

Prefer, in order:

1. deterministic parsers, scripts, queries, compilers, and validators instead of
   repeated model interpretation;
2. targeted retrieval and diff-based review instead of rereading or re-reviewing the
   full repository and unchanged artifacts;
3. cached normalized source evidence and reusable reconciliation outputs instead of
   extracting the same facts for each feature;
4. targeted slice gates during implementation and one complete release gate instead
   of repeated full-suite runs;
5. bounded lower-cost model work for mechanical tasks whose output has deterministic
   validation, with escalation on ambiguity or failure;
6. a simpler architecture or existing proven component when it provides deterministic
   equivalence: the same operator workflow, acceptance criteria, reliability, security,
   maintainability, and production proof;
7. staged releases that each leave a usable, reversible product while preserving every
   material requirement in the active mission.

The agent may choose an alternative without interruption only when deterministic
equivalence is demonstrated and the operator-visible outcome is unchanged. Record the
substitution and evidence in the audit log. If an alternative changes material scope,
behavior, source quality, model judgment, permissions, design intent, or proof, obtain
user approval and append a scope change before using it. A cheaper uncertain answer is
not an alternative. If no certainty-preserving path exists, use the resources required
to complete the task correctly.

Record any explicit deadline or credit cap in the ledger; otherwise record that no
hard cap was supplied and completion governs. For optional model-based evaluation
harnesses, set a per-call ceiling and total worst-case ceiling before the first call.
Those evaluation ceilings control the optional evaluation run, not the quality or
scope of the development mission. Start with a dry run or one scenario, inspect the
result, and expand only when the harness is behaving correctly.

When the user gives a deadline, cut optional improvements, not proof of the core
workflow. Report the critical path and reserve time for deployment and production
verification.
