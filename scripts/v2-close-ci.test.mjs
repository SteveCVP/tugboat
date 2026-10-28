import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { sha256 } from "./lib/canonical.mjs";
import { closeMission, validateAppendOnlyBaseline, validateMission } from "./lib/mission-validator.mjs";
import { captureCommandEvidence, checkpointMission, gitSnapshot, recordEvidence } from "./lib/evidence.mjs";
import { createMission } from "./lib/reducer.mjs";
import { readState } from "./lib/store.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, "tugboat.mjs");

function setup({ target = "local" } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-close-"));
  const run = (args) => execFileSync("git", args, { cwd: dir, encoding: "utf8" }).trim();
  run(["init", "-b", "main"]); run(["config", "user.email", "test@example.com"]); run(["config", "user.name", "Tugboat Test"]);
  fs.writeFileSync(path.join(dir, "spec.md"), "# Approved\n");
  run(["add", "."]); run(["commit", "-m", "baseline"]);
  const baseline = run(["rev-parse", "HEAD"]);
  const missionDir = path.join(dir, "tugboat");
  createMission({
    dir: missionDir, actor: { name: "Alex", kind: "human" },
    metadata: { id: "m", title: "M", owner: "Alex", target, repository: dir, worktree: dir, branch: "main", baselineGitSha: baseline, source: { path: "spec.md", digest: `sha256:${sha256(fs.readFileSync(path.join(dir, "spec.md")))}` }, criticalPath: ["R1"], deployPath: ".github/workflows/deploy.yml" },
    requirements: [{ id: "R1", requirement: "Run", source: "spec", material: true, acceptance: "Operator runs", proofTarget: target }],
    preservations: [{ id: "P1", instruction: "Keep login", source: "spec" }],
  });
  run(["add", "tugboat"]); run(["commit", "-m", "initialize mission"]);
  return { dir, missionDir, run };
}

function proveLocal(context) {
  const evidence = captureCommandEvidence({ id: "E1", requirementIds: ["R1"], cwd: context.dir, command: [process.execPath, "-e", "process.exit(0)"], excludePaths: [context.missionDir] });
  const operator = { schemaVersion: 1, id: "E-OP", kind: "operator", requirementIds: ["R1"], capturedAt: new Date().toISOString(), origin: { actor: { name: "Alex", kind: "human" }, cwd: context.dir }, git: evidence.git, verification: { status: "passed", verifier: "human:Alex", url: "https://app.example.test/workflow", result: "Operator completed the workflow" }, artifacts: [] };
  recordEvidence(context.missionDir, evidence);
  recordEvidence(context.missionDir, operator);
  checkpointMission(context.missionDir, {
    actor: { name: "Codex", kind: "agent" }, requirementIds: ["R1"], preservationIds: ["P1"], status: "PROVEN(local)", evidenceRefs: ["E1", "E-OP"], result: "Operator runs", action: "proved local workflow", nextAction: "close",
  });
  context.run(["add", "tugboat"]); context.run(["commit", "-m", "prove mission"]);
}

test("strict validator rejects incomplete missions and close automatically invokes it", () => {
  const context = setup();
  const report = validateMission(context.missionDir);
  assert.equal(report.valid, false);
  assert.ok(report.errors.some((error) => error.code === "unclosed_requirement"));
  assert.throws(() => closeMission(context.missionDir, { actor: { name: "Alex", kind: "human" } }), /unclosed_requirement/i);
});

test("close succeeds only from a clean, committed, fully proven mission", () => {
  const context = setup();
  proveLocal(context);
  assert.equal(readState(context.missionDir).activeSliceId, null);
  assert.equal(readState(context.missionDir).slices.S1.status, "COMPLETE");
  assert.equal(validateMission(context.missionDir).valid, true);
  const closed = closeMission(context.missionDir, { actor: { name: "Alex", kind: "human" } });
  assert.equal(closed.status, "COMPLETE");
  assert.match(fs.readFileSync(path.join(context.missionDir, "completion-report.md"), "utf8"), /Status: `COMPLETE`/);
});

test("strict validation rejects dirty implementation state and source drift", () => {
  const context = setup();
  proveLocal(context);
  fs.writeFileSync(path.join(context.dir, "dirty.txt"), "dirty\n");
  assert.ok(validateMission(context.missionDir).errors.some((error) => error.code === "dirty_worktree"));
  fs.rmSync(path.join(context.dir, "dirty.txt"));
  fs.appendFileSync(path.join(context.dir, "spec.md"), "changed\n");
  assert.ok(validateMission(context.missionDir).errors.some((error) => error.code === "source_drift"));
});

test("append-only baseline validation rejects rewritten event history", () => {
  const context = setup();
  const base = context.run(["rev-parse", "HEAD"]);
  const eventFile = path.join(context.missionDir, "events.jsonl");
  fs.writeFileSync(eventFile, fs.readFileSync(eventFile, "utf8").replace('"type":"GENESIS"', '"type":"REWRITTEN"'));
  assert.ok(validateAppendOnlyBaseline(context.missionDir, base).some((error) => error.code === "baseline_rewritten"));
});

test("CI command emits stable JSON and policy exit code", () => {
  const context = setup();
  const result = spawnSync(process.execPath, [CLI, "ci", "--dir", context.missionDir, "--json"], { cwd: context.dir, encoding: "utf8" });
  assert.equal(result.status, 3);
  const report = JSON.parse(result.stdout);
  assert.equal(report.valid, false);
  assert.ok(report.errors.some((error) => error.code === "unclosed_requirement"));
  assert.doesNotMatch(result.stdout, /"requirements"|"metadata"|Operator runs/);
});

test("development validation accepts an incomplete but internally consistent mission", () => {
  const context = setup();
  const result = spawnSync(process.execPath, [CLI, "validate", "--dir", context.missionDir, "--json"], { cwd: context.dir, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).valid, true);
});

test("usage errors have a stable exit code 2", () => {
  const result = spawnSync(process.execPath, [CLI, "not-a-command"], { encoding: "utf8" });
  assert.equal(result.status, 2);
});

test("validator compares the complete snapshot with event replay", () => {
  const context = setup();
  const file = path.join(context.missionDir, "state.json");
  const state = JSON.parse(fs.readFileSync(file, "utf8"));
  state.requirements.R1.status = "PROVEN(local)";
  fs.writeFileSync(file, JSON.stringify(state, null, 2));
  assert.ok(validateMission(context.missionDir).errors.some((error) => error.code === "snapshot_mismatch"));
});

test("local proof requires deterministic and operator evidence", () => {
  const context = setup();
  const command = captureCommandEvidence({ id: "E-ONLY", requirementIds: ["R1"], cwd: context.dir, command: [process.execPath, "-e", ""], excludePaths: [context.missionDir] });
  recordEvidence(context.missionDir, command);
  assert.throws(() => checkpointMission(context.missionDir, {
    actor: { name: "Codex", kind: "agent" }, requirementIds: ["R1"], status: "PROVEN(local)", evidenceRefs: ["E-ONLY"], result: "claimed", action: "claim", nextAction: "close",
  }), /operator or browser evidence/i);
});

test("CLI captures operator evidence without hand-authored JSON", () => {
  const context = setup();
  const result = spawnSync(process.execPath, [CLI, "evidence", "--dir", context.missionDir, "--kind", "operator", "--id", "E-OP-CLI", "--requirements", "R1", "--url", "https://app.example.test/workflow", "--result", "Alex completed the workflow", "--actor", "Alex"], { cwd: context.dir, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readState(context.missionDir).evidence["E-OP-CLI"].verification.result, "Alex completed the workflow");
});

test("production checkpoints require clean state, live operator proof, and matching provider-verified deployed SHA", () => {
  const context = setup({ target: "production" });
  const snapshot = gitSnapshot(context.dir, { excludePaths: [context.missionDir] });
  const command = captureCommandEvidence({ id: "E-CMD", requirementIds: ["R1"], cwd: context.dir, command: [process.execPath, "-e", ""], excludePaths: [context.missionDir] });
  const operator = { schemaVersion: 1, id: "E-OP", kind: "operator", requirementIds: ["R1"], capturedAt: new Date().toISOString(), origin: { actor: { name: "Alex", kind: "human" }, cwd: context.dir }, git: snapshot, verification: { status: "passed", verifier: "human:Alex", url: "https://app.example.test/workflow", result: "Operator completed the workflow" }, artifacts: [] };
  const deployment = { schemaVersion: 1, id: "E-DEPLOY", kind: "deployment", requirementIds: ["R1"], capturedAt: new Date().toISOString(), origin: { actor: { name: "release", kind: "ci" }, cwd: context.dir }, git: snapshot, verification: { status: "passed", verifier: "github-actions:123" }, deployment: { provider: "github-actions", deployedSha: "b".repeat(40), environment: "production", source: "github-actions:123" }, artifacts: [] };
  for (const item of [command, operator, deployment]) recordEvidence(context.missionDir, item);
  assert.throws(() => checkpointMission(context.missionDir, { actor: { name: "Codex", kind: "agent" }, requirementIds: ["R1"], status: "PROVEN(production)", evidenceRefs: ["E-CMD", "E-OP", "E-DEPLOY"], result: "live", action: "prove", nextAction: "close" }), /deployed SHA.*does not match/i);
});
