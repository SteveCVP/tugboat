import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { validateLedger } from "./validate-ledger.mjs";

function setup({ complete = true, proof = "Live /workflow at abc1234", duplicate = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-ledger-"));
  const spec = path.join(dir, "spec.md");
  fs.writeFileSync(spec, "# Approved source\n\nBuild the workflow.\n");
  const digest = createHash("sha256").update(fs.readFileSync(spec)).digest("hex");
  const status = complete ? "COMPLETE" : "ACTIVE";
  fs.writeFileSync(path.join(dir, "audit-log.md"), "# Audit\n\n| Timestamp | Actor | Requirement IDs | Action | Decision / reason | Evidence | Next step |\n|---|---|---|---|---|---|---|\n| 2026-08-28T12:00:00Z | Codex | R1 | verified | operator path works | test | stop |\n");
  fs.writeFileSync(path.join(dir, "context-handoff.md"), `# Handoff\n\n- Updated: 2026-08-28T12:00:00Z\n- Mission: test\n- Mission status: ${status}\n- Branch / current SHA: main / abc1234\n- Exact next action: stop\n`);
  const second = duplicate ? "\n| R1 | Duplicate | user | no | duplicate rejected | local | src/b.js | b.test.js | N/A: no UI | N/A: local target | PROVEN(local) |" : "";
  const rowStatus = complete ? "PROVEN(production)" : "IN_PROGRESS";
  const ledger = `# Ledger

## Mission Metadata

- Mission status: ${status}
- Mission ID: test-mission
- Mission title: Test mission
- Owner: Alex
- Repository: /tmp/project
- Worktree: /tmp/project-worktree
- Branch: feat/test
- Baseline SHA: def5678
- Current SHA: abc1234
- Source specification(s): ./spec.md
- Source specification digest: sha256:${digest}
- Audit log: ./audit-log.md
- Context handoff: ./context-handoff.md
- Canonical deploy path: deploy.yml
- Rollback anchor: def5678

## Baseline And Preservation Contract

| ID | Preservation instruction | Source | Regression proof | Status |
|---|---|---|---|---|
| P1 | Preserve login | user | live login at abc1234 | ${complete ? "PROVEN(production)" : "IN_PROGRESS"} |

## Requirement-To-Proof Ledger

| ID | Requirement | Source | Material | Acceptance | Proof target | Implementation | Tests | Browser proof | Production proof | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| R1 | Working workflow | user | yes | operator completes workflow | production | src/a.js | a.test.js | Chromium 390 and 1440 | ${proof} | ${rowStatus} |${second}

## Completion Map

| Requirement ID | User-visible result | Implementation | Tests | Browser evidence | Deployed SHA | Production result |
|---|---|---|---|---|---|---|
| R1 | works | src/a.js | a.test.js | browser | abc1234 | live |
`;
  const ledgerPath = path.join(dir, "requirement-ledger.md");
  fs.writeFileSync(ledgerPath, ledger);
  return ledgerPath;
}

test("accepts a complete, fully proven production ledger", () => {
  assert.deepEqual(validateLedger(setup()), []);
});

test("rejects a production claim without production evidence", () => {
  const errors = validateLedger(setup({ proof: "pending" }));
  assert.ok(errors.some((error) => error.includes("Production proof is required")));
});

test("rejects duplicate requirement IDs", () => {
  const errors = validateLedger(setup({ complete: false, duplicate: true }));
  assert.ok(errors.some((error) => error.includes("duplicate requirement ID")));
});

test("does not require completion proof while a mission is active", () => {
  assert.deepEqual(validateLedger(setup({ complete: false })), []);
});

test("rejects a complete mission with unproven preservation", () => {
  const ledger = setup();
  fs.writeFileSync(ledger, fs.readFileSync(ledger, "utf8").replace("| P1 | Preserve login | user | live login at abc1234 | PROVEN(production) |", "| P1 | Preserve login | user | pending | PENDING |"));
  const errors = validateLedger(ledger);
  assert.ok(errors.some((error) => error.includes("unclosed preservation requirement P1")));
});

test("rejects an unresolved source specification digest", () => {
  const ledger = setup({ complete: false });
  fs.writeFileSync(ledger, fs.readFileSync(ledger, "utf8").replace(/sha256:[0-9a-f]{64}/, "[digest]"));
  const errors = validateLedger(ledger);
  assert.ok(errors.some((error) => error.includes("Source specification digest")));
});

test("recomputes the local source digest and rejects changed source", () => {
  const ledger = setup({ complete: false });
  fs.appendFileSync(path.join(path.dirname(ledger), "spec.md"), "Scope changed.\n");
  const errors = validateLedger(ledger, { strictSource: true });
  assert.ok(errors.some((error) => error.includes("digest does not match")));
});

test("rejects stale active handoffs when a maximum age is requested", () => {
  const ledger = setup({ complete: false });
  const errors = validateLedger(ledger, {
    maxHandoffAgeHours: 2,
    now: new Date("2026-08-29T00:00:00Z"),
  });
  assert.ok(errors.some((error) => error.includes("Context handoff is stale")));
});

test("checks recorded branch and SHA ancestry against Git truth", () => {
  const ledger = setup({ complete: false });
  const dir = path.dirname(ledger);
  execFileSync("git", ["init", "-b", "main"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "tugboat@example.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: dir });
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "baseline"], { cwd: dir });
  const sha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
  let text = fs.readFileSync(ledger, "utf8")
    .replace("- Repository: /tmp/project", `- Repository: ${dir}`)
    .replace("- Worktree: /tmp/project-worktree", `- Worktree: ${dir}`)
    .replace("- Branch: feat/test", "- Branch: wrong-branch")
    .replace("- Baseline SHA: def5678", `- Baseline SHA: ${sha}`)
    .replace("- Current SHA: abc1234", `- Current SHA: ${sha}`);
  fs.writeFileSync(ledger, text);
  const errors = validateLedger(ledger, { strictGit: true });
  assert.ok(errors.some((error) => error.includes("Recorded branch wrong-branch")));
});

test("rejects rewritten requirement meaning and audit history against a Git baseline", () => {
  const ledger = setup({ complete: false });
  const dir = path.dirname(ledger);
  execFileSync("git", ["init", "-b", "main"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "tugboat@example.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: dir });
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "baseline"], { cwd: dir });
  fs.writeFileSync(ledger, fs.readFileSync(ledger, "utf8").replace("Working workflow", "Narrower workflow"));
  const audit = path.join(dir, "audit-log.md");
  fs.writeFileSync(audit, fs.readFileSync(audit, "utf8").replace("operator path works", "rewritten history"));
  const errors = validateLedger(ledger, { baseRef: "HEAD", gitCwd: dir });
  assert.ok(errors.some((error) => error.includes("Requirement R1 meaning changed")), errors.join("\n"));
  assert.ok(errors.some((error) => error.includes("Audit history was rewritten")), errors.join("\n"));
});

test("rejects a stale or incomplete context handoff", () => {
  const ledger = setup({ complete: false });
  const handoff = path.join(path.dirname(ledger), "context-handoff.md");
  fs.writeFileSync(handoff, "# Handoff\n\n- Updated: [later]\n");
  const errors = validateLedger(ledger);
  assert.ok(errors.some((error) => error.includes("Context handoff field Mission")));
});

test("accepts escaped literal pipes inside requirement text", () => {
  const ledger = setup({ complete: false });
  fs.writeFileSync(ledger, fs.readFileSync(ledger, "utf8").replace("Working workflow", "Working A\\|B workflow"));
  assert.deepEqual(validateLedger(ledger), []);
});

test("protocol 1.1 requires explicit critical-path and efficiency controls", () => {
  const ledger = setup({ complete: false });
  fs.writeFileSync(ledger, fs.readFileSync(ledger, "utf8").replace("- Mission status: ACTIVE", "- Mission status: ACTIVE\n- Protocol version: 1.1"));
  const errors = validateLedger(ledger);
  for (const label of ["Deadline / budget", "Critical path", "Gate cadence", "Retry policy"]) {
    assert.ok(errors.some((error) => error.includes(label)), `${label}: ${errors.join("\n")}`);
  }
});
