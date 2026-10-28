# Tugboat Requirement Ledger

## Mission Metadata

- Mission ID: `[stable-name]`
- Mission title: `[exact outcome]`
- Owner: `[user]`
- Repository: `[absolute path]`
- Worktree: `[absolute path]`
- Branch: `[branch]`
- Baseline SHA: `[sha]`
- Current SHA: `[sha]`
- Mission status: `ACTIVE`
- Protocol version: `1.1`
- Source specification(s): `[paths or durable prompt]`
- Source specification digest: `sha256:[64 lowercase hex characters]`
- Audit log: `./audit-log.md`
- Context handoff: `./context-handoff.md`
- Canonical deploy path: `[workflow/command]`
- Rollback anchor: `[sha or not-yet-deployed]`
- Deadline / budget: `[explicit deadline/cap, or "none supplied — completion and proof govern"]`
- Critical path: `[ordered requirement IDs]`
- Gate cadence: `slice=targeted; integration=affected; release=full`
- Retry policy: `two-strike: diagnose before a third identical rerun`

Allowed mission statuses: `ACTIVE`, `PARTIAL`, `BLOCKED`, `COMPLETE`.

## Baseline And Preservation Contract

Describe the current operator behavior, authoritative data sources, permissions,
visual elements, and workflows that must remain intact.

| ID | Preservation instruction | Source | Regression proof | Status |
|---|---|---|---|---|
| P1 | `[exact do-not-change requirement]` | `[quote/path]` | `[test/journey]` | PENDING |

If there is genuinely nothing to preserve, add `P1` with a specific `N/A:` reason
and prove the clean baseline. Do not leave this table empty.

## Requirement-To-Proof Ledger

Use one row per observable requirement. Do not combine independent workflows in one
row merely to reduce row count.

| ID | Requirement | Source | Material | Acceptance | Proof target | Implementation | Tests | Browser proof | Production proof | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| R1 | `[exact requirement]` | `[quote/path]` | yes | `[operator-observable result]` | production | `[files or pending]` | `[tests or pending]` | `[journey or pending]` | `[SHA/live evidence or pending]` | PENDING |

Allowed values:

- `Material`: `yes` or `no`
- `Proof target`: `documentation`, `local`, or `production`
- `Status`: `PENDING`, `IN_PROGRESS`, `BLOCKED`, `PROVEN(local)`,
  `PROVEN(production)`, or `WAIVED(user)`

Use `N/A: [reason]` where a proof category genuinely does not apply. `TBD`, `later`,
`follow-up`, or an empty interface is not proof.

Escape a literal pipe in table text as `\|`.

## Release Slices

| Slice | Requirement IDs | Operator journey | Dependencies | Target gate | Status |
|---|---|---|---|---|---|
| S1 | R1 | `[journey]` | `[dependencies]` | `[slice/integration/release]` | PENDING |

## Scope Changes

Append; never rewrite the original requirement.

| Timestamp | Author | Change | Requirement IDs | Reason | Approval evidence |
|---|---|---|---|---|---|

## Decisions And Assumptions

| Timestamp | Requirement IDs | Decision or bounded assumption | Evidence | Reversal condition |
|---|---|---|---|---|

## Review Findings And Dispositions

| Timestamp | Reviewer | Scope | Finding | Severity | Requirement IDs | Disposition | Proof |
|---|---|---|---|---|---|---|---|

## Deployment Record

| Timestamp | Environment | Deployed SHA | Migration/order notes | Rollback anchor | Result | Production evidence |
|---|---|---|---|---|---|---|

## Completion Map

Populate this from the requirement ledger; do not substitute a prose summary.

| Requirement ID | User-visible result | Implementation | Tests | Browser evidence | Deployed SHA | Production result |
|---|---|---|---|---|---|---|
