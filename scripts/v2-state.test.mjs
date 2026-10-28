import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { activeRequirementIds, createMission, missionReducer } from "./lib/reducer.mjs";
import { renderMission } from "./lib/render.mjs";
import { appendEvent, readState, replayEvents } from "./lib/store.mjs";

function missionInput(dir) {
  return {
    dir,
    actor: { name: "Alex", kind: "human", runtime: "test" },
    metadata: {
      id: "portable-mission", title: "Portable mission", owner: "Alex", target: "production",
      repository: "/repo", worktree: "/repo-wt", branch: "feat/test", baselineGitSha: "a".repeat(40),
      source: { path: "spec.md", digest: `sha256:${"b".repeat(64)}` }, criticalPath: ["R1", "R2"], deployPath: ".github/workflows/deploy.yml",
    },
    requirements: [
      { id: "R1", requirement: "First workflow", source: "spec 1", material: true, acceptance: "Operator completes first", proofTarget: "production" },
      { id: "R2", requirement: "Second workflow", source: "spec 2", material: true, acceptance: "Operator completes second", proofTarget: "production" },
      { id: "R3", requirement: "Later workflow", source: "spec 3", material: true, acceptance: "Operator completes later", proofTarget: "local" },
    ],
    preservations: [{ id: "P1", instruction: "Preserve login", source: "spec", regressionProofTarget: "browser" }],
    slices: [
      { id: "S1", name: "First release", requirementIds: ["R1", "R2"], dependencies: [], status: "ACTIVE", operatorJourney: "First two workflows" },
      { id: "S2", name: "Later release", requirementIds: ["R3"], dependencies: ["S1"], status: "PENDING", operatorJourney: "Later workflow" },
    ],
  };
}

test("v2 initialization creates a replayable genesis anchor and generated Markdown views", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-v2-state-"));
  const state = createMission(missionInput(dir));
  assert.equal(state.schemaVersion, 2);
  assert.equal(state.revision, 1);
  assert.equal(state.genesisEventHash, state.lastEventHash);
  assert.equal(replayEvents(dir, { reducer: missionReducer }).state.genesisEventHash, state.genesisEventHash);
  for (const file of ["state.json", "events.jsonl", "requirement-ledger.md", "audit-log.md", "context-handoff.md", "completion-report.md"]) {
    assert.ok(fs.existsSync(path.join(dir, file)), file);
  }
  assert.match(fs.readFileSync(path.join(dir, "requirement-ledger.md"), "utf8"), /Protocol version: `2\.0`/);
  assert.match(fs.readFileSync(path.join(dir, "requirement-ledger.md"), "utf8"), new RegExp(`Genesis event hash: \`${state.genesisEventHash}\``));
});

test("active requirements include only the current slice and its unmet requirement dependencies", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-v2-slice-"));
  const state = createMission(missionInput(dir));
  assert.deepEqual(activeRequirementIds(state), ["R1", "R2"]);
  assert.doesNotMatch(fs.readFileSync(path.join(dir, "context-handoff.md"), "utf8"), /R3/);
});

test("versioned checkpoints advance completed slices without reinterpreting legacy events", () => {
  const legacyDir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-v2-legacy-slice-"));
  createMission(missionInput(legacyDir));
  const legacy = appendEvent(legacyDir, {
    type: "CHECKPOINT_RECORDED",
    actor: { name: "Legacy", kind: "agent" },
    payload: {
      requirementIds: ["R1", "R2"], preservationIds: [], status: "PROVEN(local)", evidenceRefs: ["E1"],
      result: "legacy proof", action: "prove", nextAction: "next", nextCheck: "next", blocker: null,
    },
  }, { reducer: missionReducer }).state;
  assert.equal(legacy.activeSliceId, "S1");
  assert.equal(legacy.slices.S1.status, "ACTIVE");

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-v2-progress-slice-"));
  createMission(missionInput(dir));
  const advanced = appendEvent(dir, {
    type: "CHECKPOINT_RECORDED",
    actor: { name: "Codex", kind: "agent" },
    payload: {
      requirementIds: ["R1", "R2"], preservationIds: [], status: "PROVEN(local)", evidenceRefs: ["E1"],
      result: "first slice proven", action: "prove", nextAction: "next", nextCheck: "next", blocker: null,
      sliceProgressionVersion: 1,
    },
  }, { reducer: missionReducer }).state;
  assert.equal(advanced.slices.S1.status, "COMPLETE");
  assert.equal(advanced.slices.S2.status, "ACTIVE");
  assert.equal(advanced.activeSliceId, "S2");
  assert.deepEqual(activeRequirementIds(advanced), ["R3"]);

  const complete = appendEvent(dir, {
    type: "CHECKPOINT_RECORDED",
    actor: { name: "Codex", kind: "agent" },
    payload: {
      requirementIds: ["R3"], preservationIds: [], status: "PROVEN(local)", evidenceRefs: ["E2"],
      result: "second slice proven", action: "prove", nextAction: "close", nextCheck: "close", blocker: null,
      sliceProgressionVersion: 1,
    },
  }, { reducer: missionReducer }).state;
  assert.equal(complete.slices.S2.status, "COMPLETE");
  assert.equal(complete.activeSliceId, null);
  assert.deepEqual(activeRequirementIds(complete), []);

  assert.throws(() => appendEvent(dir, {
    type: "CHECKPOINT_RECORDED",
    actor: { name: "Future", kind: "agent" },
    payload: {
      requirementIds: [], preservationIds: ["P1"], status: "PROVEN(local)", evidenceRefs: ["E3"],
      action: "prove", nextAction: "close", sliceProgressionVersion: 2,
    },
  }, { reducer: missionReducer }), /slice progression version 2/i);
});

test("a versioned amendment reopens the earliest affected slice", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-v2-reopen-slice-"));
  createMission(missionInput(dir));
  appendEvent(dir, {
    type: "CHECKPOINT_RECORDED", actor: { name: "Codex", kind: "agent" },
    payload: { requirementIds: ["R1", "R2", "R3"], preservationIds: [], status: "PROVEN(local)", evidenceRefs: ["E1"], action: "prove", nextAction: "close", sliceProgressionVersion: 1 },
  }, { reducer: missionReducer });
  const reopened = appendEvent(dir, {
    type: "SCOPE_AMENDED", actor: { name: "Alex", kind: "human" },
    payload: { id: "A1", reason: "new evidence", affectedIds: ["R1"], supersedes: [], replacements: {}, sliceProgressionVersion: 1 },
  }, { reducer: missionReducer }).state;
  assert.equal(reopened.requirements.R1.status, "PENDING");
  assert.equal(reopened.slices.S1.status, "ACTIVE");
  assert.equal(reopened.slices.S2.status, "COMPLETE");
  assert.equal(reopened.activeSliceId, "S1");
  assert.deepEqual(activeRequirementIds(reopened), ["R1"]);
});

test("structured amendments supersede prior meaning and invalidate stale proof", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-v2-amend-"));
  createMission(missionInput(dir));
  appendEvent(dir, {
    type: "REQUIREMENT_PROVEN",
    actor: { name: "Codex", kind: "agent", runtime: "codex" },
    payload: { requirementId: "R1", status: "PROVEN(local)", evidenceRefs: ["E1"], result: "old result" },
  }, { reducer: missionReducer, expectedRevision: 1 });
  const amended = appendEvent(dir, {
    type: "SCOPE_AMENDED",
    actor: { name: "Alex", kind: "human", runtime: "shell" },
    payload: {
      id: "A1", reason: "User expanded the workflow", affectedIds: ["R1"], supersedes: [],
      replacements: { R1: { requirement: "Expanded first workflow", acceptance: "Operator completes expanded first" } },
    },
  }, { reducer: missionReducer, expectedRevision: 2 }).state;
  renderMission(dir, amended);
  assert.equal(amended.requirements.R1.status, "PENDING");
  assert.deepEqual(amended.requirements.R1.evidenceRefs, []);
  assert.equal(amended.requirements.R1.requirement, "Expanded first workflow");
  assert.equal(amended.amendments.A1.invalidatedProof.R1.previousStatus, "PROVEN(local)");
});

test("overlapping amendments are flagged until the newer amendment explicitly supersedes the older", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-v2-conflict-"));
  createMission(missionInput(dir));
  appendEvent(dir, { type: "SCOPE_AMENDED", actor: { name: "Alex", kind: "human" }, payload: { id: "A1", reason: "first", affectedIds: ["R1"], supersedes: [], replacements: {} } }, { reducer: missionReducer });
  const conflicted = appendEvent(dir, { type: "SCOPE_AMENDED", actor: { name: "Alex", kind: "human" }, payload: { id: "A2", reason: "second", affectedIds: ["R1"], supersedes: [], replacements: {} } }, { reducer: missionReducer }).state;
  assert.deepEqual(conflicted.amendments.A2.conflictsWith, ["A1"]);

  const resolved = appendEvent(dir, { type: "SCOPE_AMENDED", actor: { name: "Alex", kind: "human" }, payload: { id: "A3", reason: "resolution", affectedIds: ["R1"], supersedes: ["A1", "A2"], replacements: {} } }, { reducer: missionReducer }).state;
  assert.deepEqual(resolved.amendments.A3.conflictsWith, []);
  assert.equal(readState(dir).revision, 4);
});
