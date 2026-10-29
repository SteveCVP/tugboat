# Tugboat 5.0.0-alpha.1 Release Audit

## Release status

This prerelease ships the certified-changeset core from the Tugboat 5 design. It is
usable for boundary verification, candidate certification, commutativity analysis,
composition admission, merge authorization, and rollback-equivalence proof. It does
not claim the remaining Tugboat 5 roadmap is complete.

## Shipped contract

| Capability | Operator surface | Fail-closed boundary |
|---|---|---|
| Component boundaries | `boundary verify` | canonical ownership, interface, invariant, gate, disclosure, and source digests |
| Certified analyzers | analyzer manifests and conformance runner | pinned executable/assets, bounded input/output/time, exact spans, typed insufficiency |
| Effect footprints | certification and composition internals | Git transitions plus semantic analyzer results; unknown effects stay unknown |
| Non-interference | `bundle commute` and certification | paths, dependencies, interfaces, schema, infrastructure, and invalidated proof |
| Certified changesets | `bundle certify` and `certificate verify` | candidate, boundary, effects, evidence, policy, and digest binding |
| Composition planning | `bundle compose --dry-run` | complete pairwise matrix, dependency order, uncertainty, and counterexamples |
| Composition admission | `bundle compose --apply` | disposable worktree, target revalidation, final race check, and immutable mission event |
| Merge authorization | `certificate verify-composition` and `certificate verify-merge` | exact prepared tree, target base, policy, composition proof, and transitive rollback evidence |
| Rollback equivalence | `rollback prove` and `certificate verify-rollback` | real Git objects, exact/declared rollback, semantic obligations, drift and tamper rejection |

## Honest limits

- `equivalent` applies only to the verified repository range, boundary, rollback
  operation, and declared policy. It is not a universal disaster-recovery guarantee.
- File restoration cannot silently satisfy schema, data, infrastructure, or external
  effects. Missing runtime evidence produces `insufficient_evidence`; irreversible
  effects produce `not_equivalent`.
- Certified analyzers are deterministic compatibility evidence, not replacements for
  target-owned tests, deployment checks, or production observation.
- Composition certificates authorize an exact prepared result. Any base, candidate,
  policy, boundary, evidence, or repository drift requires recomputation.
- MCP can verify repository-backed certificates but cannot execute rollback, apply
  composition, sign artifacts, or widen its startup authority.

## Explicitly not in this prerelease

The final Tugboat 5 roadmap still includes a new selective-disclosure trust layer,
transparency publication, a mission model checker, agent flight recording, an MCP chaos
laboratory, a compiled merge-policy language, a rendered blast-radius proof graph, and
a proof-quality benchmark. Existing Tugboat 4 signing, provenance, intelligence, and
history features remain available; they are not represented as completion of those new
Tugboat 5 workstreams.

## Security and portability

- Runtime code remains dependency-free Node 20+ ESM with no implicit hosted service.
- Execution uses literal argv without a shell, bounded output and time, stripped or
  explicitly declared environment, and disposable Git worktrees.
- Verification rejects replacement refs, grafts, unsafe paths, symlink-dependent
  ownership, forged object identities, stale observations, unknown fields, and digest
  substitution.
- Certificate publication is no-clobber and revalidates staged bytes and file identity
  before the final link.
- The neutral public export uses an explicit allowlist and scans current content,
  references, commit metadata, object paths, and historical text blobs.

## Verification inventory

The release gate covers exact and declared rollback, no-op and transient commits,
schema/data/infrastructure/external obligations, missing evidence, drift, tampering,
replace refs, grafts, output races, unowned paths, composition admission, immutable
history, CLI journeys, read-only MCP parity, neutral export, standalone install, package
contents, complete regression, and CodeQL. Passing tests prove those checked contracts;
they do not upgrade a prerelease or an unimplemented roadmap item into a shipped claim.
