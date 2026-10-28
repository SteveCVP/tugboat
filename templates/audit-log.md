# Tugboat Audit Log

Append entries in chronological order. Do not delete or rewrite prior entries. If an
entry was wrong, append a correction that cites it.

| Timestamp | Actor | Requirement IDs | Action | Decision / reason | Evidence | Next step |
|---|---|---|---|---|---|---|
| `[ISO-8601]` | `[operator/agent/reviewer]` | `[R1,P1]` | `[measured action]` | `[why]` | `[file/test/URL/SHA]` | `[one concrete next step]` |

## Entry Rules

- Record scope capture, user changes, significant decisions, defects, review
  findings, commits, deploys, production checks, waivers, and blockers.
- Cite requirement IDs. An audit log detached from requirements is narration.
- Record measured evidence, not `worked on` or `looks good`.
- Keep routine command noise out of the log.
- Never store secrets, one-time tokens, private keys, or sensitive payloads.
- When the user supplies a credential during the mission, record only that the
  credential was handled and where its approved secret store lives, never its value.
