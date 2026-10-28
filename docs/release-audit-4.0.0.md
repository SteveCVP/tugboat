# Tugboat 4.0.0 Release Audit

## Release contract

Tugboat 4.0.0 adds seven dependency-free proof-runtime workflows while preserving the
protocol-2 event format and Tugboat 3 mission-intelligence behavior.

| Capability | Operator surface | Security boundary |
|---|---|---|
| Proof mutation | `proof mutate` | exact declared text changes in disposable Git worktrees; explicit argv; no shell |
| Evidence capsules | `capsule capture/verify/replay` | clean detached worktrees; digest verification; replay requires fresh argv |
| Signed provenance | `provenance create/verify` | in-toto Statement v1; SLSA v1 predicate; optional Ed25519 DSSE |
| Incremental causal kernel | `kernel compile` | content-addressed pure compilers; cache treated as untrusted |
| Adapter SDK | `adapter inspect/run/conform` | digest pin; staged inputs; stripped environment; timeout/output caps |
| Mission time travel | `history explain` | read-only hash-chain replay to an exact revision |
| Differential review | `review compare` | identical input digests; minority findings preserved; consensus is not proof |

## Honest claims

- Brokered adapter execution is not an OS sandbox. A pinned external WASI or container
  runtime is required before claiming kernel-enforced filesystem or network isolation.
- A provenance signature proves which key signed which canonical statement bytes. It
  does not prove correctness, satisfy acceptance, or establish a SLSA level.
- An evidence capsule is `declared`, not hermetic, unless the host kernel and executable
  image are independently content-addressed.
- A cache hit, killed mutation, or reviewer consensus is decision evidence, not an
  automatic mission checkpoint.

## Security and portability

- Runtime code remains Node 20+ ESM with no production dependency or implicit network.
- Commands are literal argv arrays invoked without a shell. Profiles cannot carry a
  command. Mutation, capsule execution, and replay require a clean Git repository and
  use disposable detached worktrees.
- Portable paths reject absolute paths, traversal, empty segments, and symlinks.
- Adapter manifests pin entrypoint bytes and allow only explicitly staged files and
  explicitly supplied environment names. Ambient process environment is not inherited.
- Every execution has a timeout, output cap, and secret scan. Reports use canonical
  SHA-256 digests and bounded structures.
- MCP exposes only read-only adapter inspection, capsule/provenance verification,
  history explanation, and review comparison. It cannot mutate, replay, sign, execute
  adapters, or write caches.
- Neutral export still uses an explicit allowlist, symlink and secret scan, forbidden
  provenance scan, atomic staging, and full-history public-repository verification.

## Verification inventory

Focused tests cover path traversal, symlinks, command bounds, killed/surviving/invalid
mutations, source byte preservation, capsule tampering and replay divergence, DSSE key
and payload failure, subject drift, verified/cache-corrupt incremental compilation,
adapter digest and ambient-environment denial, hash-chain tampering, review input and
evidence conflicts, real CLI operator journeys, and read-only MCP parity. Release is
governed by the fresh complete regression, behavior, package, install, neutral export,
and public-history verification results—not by this document.

## Adversarial review dispositions

| Finding | Severity | Disposition |
|---|---|---|
| A no-op replacement could be reported as a surviving mutation | major | Reject identical find/replace before workspace creation; regression added |
| Binary bytes decoded as UTF-8 could create meaningless mutations | major | Require byte-valid UTF-8 text and reject binary targets; regression added |
| Stripping all environment made ordinary explicit `npm` argv fail outside `/usr/bin` | major | Use a recorded, deterministic launcher policy containing the Node sibling and fixed system bins; capsule binds its digest |
| A digest-valid capsule with unknown or malformed fields could verify | blocker | Validate exact top-level and nested schemas, bounds, unique portable paths, command digest, and result digests |
| A signed envelope without a supplied verification key returned the same readiness as verified proof | blocker | Return `insufficient_evidence` with `signature_unverified`; `--require-signature` still fails without a key |
| DSSE accepted extra fields and permissive base64 encodings | major | Enforce exact envelope/signature/statement subjects and strict base64 and digest shapes |
| A forged cache entry could carry its own matching unkeyed output digest | blocker | Run the compiler's independent output verifier before accepting a hit; forged self-hashes recompute |
| A manifest could claim `container` or `wasi` while the built-in runner still used Node | blocker | Built-in run accepts only `brokered`; external isolation labels require a separately pinned runtime |
| Adapter input and output schema claims were not constructed | blocker | Require bounded explicit schemas and enforce both sides of every invocation |
| Adapter result provenance omitted the supplied environment context | major | Bind only environment names and value digests into the request digest; never emit values |
| Review and key CLI paths bypassed the generic input-size bound | major | Limit review JSON to 1 MiB each, keys to 64 KiB, and CSV inputs to 256 unique entries |
| Time travel omitted evidence, deployment, amendment, and claim inventories promised by the design | major | Include their revision-specific IDs and bounded claim projections in both selected and current snapshots |
| Public-export fixtures contained a secret-shaped literal and failed the actual publication scanner | major | Construct the runtime negative fixture without embedding the token-shaped source string; scanner remained unchanged |
| Four new behavior scenarios exceeded the old declared total evaluation ceiling | minor | Raise the explicit dry-run ceiling from 2.00 to 3.00 USD; calculated maximum is 2.40 USD and still fail-closed |
| GitHub pull-request checkout verified the synthetic merge commit, whose platform-generated author could violate the neutral-history policy | major | Pin CI checkout to the pull request head SHA (or event SHA outside pull requests) before full-history verification; regression and live-CI proof required |
| CodeQL found a potentially super-linear regular expression in a workflow-template test | major | Replace the nested quantified expression with deterministic line indexing; preserve the same required-input assertion and require a clean CodeQL rerun |
