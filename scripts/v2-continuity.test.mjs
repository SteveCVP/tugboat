import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { inspectContinuity, reconcileMission } from "./lib/continuity.mjs";
import { sha256 } from "./lib/canonical.mjs";
import { createMission } from "./lib/reducer.mjs";

function setup({ commitMission = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-continuity-"));
  execFileSync("git", ["init", "-b", "main"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: dir });
  fs.writeFileSync(path.join(dir, "spec.md"), "# Approved\n");
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "baseline"], { cwd: dir });
  const baseline = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();
  const missionDir = path.join(dir, "tugboat");
  createMission({
    dir: missionDir, actor: { name: "Alex", kind: "human" },
    metadata: { id: "m", title: "M", owner: "Alex", target: "local", repository: dir, worktree: dir, branch: "main", baselineGitSha: baseline, source: { path: "spec.md", digest: `sha256:${sha256(fs.readFileSync(path.join(dir, "spec.md")))}` }, criticalPath: ["R1"], deployPath: "not requested" },
    requirements: [{ id: "R1", requirement: "Run", source: "spec", material: true, acceptance: "passes", proofTarget: "local" }],
    preservations: [{ id: "P1", instruction: "keep", source: "spec" }],
  });
  if (commitMission) {
    execFileSync("git", ["add", "tugboat"], { cwd: dir });
    execFileSync("git", ["commit", "-m", "initialize mission"], { cwd: dir });
  }
  return { dir, missionDir };
}

function codes(report) {
  return report.issues.map((issue) => issue.code);
}

test("a committed genesis is current even though it could not record its own containing SHA", () => {
  const { missionDir } = setup();
  assert.deepEqual(inspectContinuity(missionDir, { maxHandoffAgeHours: 24 }).issues, []);
});

test("committed mission continuity resolves a fresh checkout instead of the creator's absolute path", () => {
  const { dir } = setup();
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-clone-"));
  const clone = path.join(parent, "checkout");
  execFileSync("git", ["clone", "--branch", "main", dir, clone]);
  fs.rmSync(dir, { recursive: true, force: true });

  assert.deepEqual(inspectContinuity(path.join(clone, "tugboat"), { maxHandoffAgeHours: 24 }).issues, []);
});

test("resume rejects a genesis that has not been committed", () => {
  const { missionDir } = setup({ commitMission: false });
  assert.ok(codes(inspectContinuity(missionDir)).includes("mission_uncommitted"));
});

test("resume continuity detects commits after the latest mission event, dirty work, source drift, and stale handoff", () => {
  const { dir, missionDir } = setup();
  fs.writeFileSync(path.join(dir, "code.mjs"), "export const value = 1;\n");
  execFileSync("git", ["add", "code.mjs"], { cwd: dir });
  execFileSync("git", ["commit", "-m", "unrecorded work"], { cwd: dir });
  assert.ok(codes(inspectContinuity(missionDir)).includes("unrecorded_commits"));

  fs.writeFileSync(path.join(dir, "dirty.txt"), "dirty\n");
  assert.ok(codes(inspectContinuity(missionDir)).includes("dirty_worktree"));

  fs.appendFileSync(path.join(dir, "spec.md"), "changed\n");
  assert.ok(codes(inspectContinuity(missionDir)).includes("source_drift"));

  const future = new Date(Date.now() + 48 * 60 * 60 * 1000);
  assert.ok(codes(inspectContinuity(missionDir, { now: future, maxHandoffAgeHours: 1 })).includes("stale_handoff"));
});

test("structured reconciliation accounts for an exact dirty patch but fails when that patch changes", () => {
  const { dir, missionDir } = setup();
  fs.writeFileSync(path.join(dir, "work.txt"), "accounted\n");
  const reconciled = reconcileMission(missionDir, {
    actor: { name: "Alex", kind: "human" }, reason: "Resume approved work", issueCodes: ["dirty_worktree"], allowCurrentPatch: true,
  });
  assert.equal(reconciled.reconciliations.length, 1);
  assert.ok(!codes(inspectContinuity(missionDir)).includes("dirty_worktree"));

  fs.writeFileSync(path.join(dir, "work.txt"), "different\n");
  assert.ok(codes(inspectContinuity(missionDir)).includes("dirty_worktree"));
});

test("reconciliation flags cannot account for issues that were not explicitly named", () => {
  const { dir, missionDir } = setup();
  fs.writeFileSync(path.join(dir, "work.txt"), "dirty\n");
  assert.throws(() => reconcileMission(missionDir, {
    actor: { name: "Alex", kind: "human" }, reason: "unnamed dirty state", issueCodes: [], allowCurrentPatch: true,
  }), /dirty_worktree.*explicit/i);
});
