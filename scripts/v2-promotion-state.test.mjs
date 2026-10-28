import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createMission, missionReducer } from "./lib/reducer.mjs";
import { renderMission } from "./lib/render.mjs";
import { appendEvent, replayEvents } from "./lib/store.mjs";

function mission() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-promotion-state-"));
  createMission({
    dir,
    actor: { name: "Alex", kind: "human" },
    metadata: {
      id: "target", title: "Target", owner: "Alex", target: "local", repository: "/repo", worktree: "/repo",
      branch: "main", baselineGitSha: "a".repeat(40), source: { path: "spec.md", digest: `sha256:${"b".repeat(64)}` },
      criticalPath: ["R1"], deployPath: "not requested",
    },
    requirements: [
      { id: "R1", requirement: "Target interface", source: "spec 1", material: true, acceptance: "works", proofTarget: "local" },
      { id: "R2", requirement: "Unaffected worker", source: "spec 2", material: true, acceptance: "works", proofTarget: "local" },
    ],
    preservations: [{ id: "P1", instruction: "Preserve login", source: "spec", regressionProofTarget: "test" }],
  });
  appendEvent(dir, {
    type: "REQUIREMENT_PROVEN", actor: { name: "Codex", kind: "agent" },
    payload: { requirementId: "R1", status: "PROVEN(local)", evidenceRefs: ["E-OLD-COMMAND", "E-OLD-OPERATOR"], result: "old result" },
  }, { reducer: missionReducer, expectedRevision: 1, currentHead: "c".repeat(40) });
  appendEvent(dir, {
    type: "REQUIREMENT_PROVEN", actor: { name: "Codex", kind: "agent" },
    payload: { requirementId: "R2", status: "PROVEN(local)", evidenceRefs: ["E-R2"], result: "unaffected result" },
  }, { reducer: missionReducer, expectedRevision: 2, currentHead: "c".repeat(40) });
  return dir;
}

function importPayload() {
  return {
    bundleId: "B-ALPHA",
    digest: `sha256:${"d".repeat(64)}`,
    source: { missionId: "source", protocolVersion: "2.0", missionRevision: 9, branch: "feat/ui", baseSha: "1".repeat(40), tipSha: "2".repeat(40), contentDigest: `sha256:${"3".repeat(64)}` },
    signature: { status: "verified", keyFingerprint: `sha256:${"4".repeat(64)}` },
    requirementIds: ["SRC-1", "SRC-2"],
    dependencies: ["B-FOUNDATION"],
    commits: [{ sha: "2".repeat(40), subject: "build UI" }],
    components: [{ type: "image", targetPath: "assets/ui.bin", digest: `sha256:${"5".repeat(64)}` }],
    evidence: [
      { id: "E-SRC-COMMAND", kind: "command", requirementIds: ["SRC-1"], digest: `sha256:${"6".repeat(64)}` },
      { id: "E-SRC-OPERATOR", kind: "operator", requirementIds: ["SRC-1"], digest: `sha256:${"7".repeat(64)}` },
      { id: "E-SRC-DEPLOY", kind: "deployment", requirementIds: ["SRC-1"], digest: `sha256:${"8".repeat(64)}` },
    ],
  };
}

function promotionPayload() {
  return {
    bundleId: "B-ALPHA",
    digest: `sha256:${"d".repeat(64)}`,
    sourceRequirementIds: ["SRC-1"],
    targetRequirementIds: ["R1"],
    excludedSourceIds: ["SRC-2"],
    mappings: { "SRC-1": "R1" },
    appliedCommits: [{ sourceSha: "2".repeat(40), targetSha: "9".repeat(40) }],
    components: [{ type: "image", targetPath: "assets/ui.bin", digest: `sha256:${"5".repeat(64)}` }],
    reusableEvidence: [{ sourceEvidenceId: "E-SRC-COMMAND", kind: "command", reason: "exact tracked content digest" }],
    expiredEvidence: [
      { sourceEvidenceId: "E-SRC-OPERATOR", kind: "operator", reason: "target context requires a new observation" },
      { sourceEvidenceId: "E-SRC-DEPLOY", kind: "deployment", reason: "target requires a new deployment" },
    ],
    validation: { command: ["npm", "test"], exitCode: 0, stdoutDigest: `sha256:${"a".repeat(64)}`, stderrDigest: `sha256:${"b".repeat(64)}` },
  };
}

test("retains imported bundle provenance without activating source evidence", () => {
  const dir = mission();
  const imported = appendEvent(dir, {
    type: "BUNDLE_IMPORTED", actor: { name: "Alex", kind: "human" }, payload: importPayload(),
  }, { reducer: missionReducer, expectedRevision: 3, currentHead: "9".repeat(40) }).state;
  assert.equal(imported.bundleImports["B-ALPHA"].digest, `sha256:${"d".repeat(64)}`);
  assert.equal(imported.bundleImports["B-ALPHA"].evidence.length, 3);
  assert.deepEqual(imported.evidence, {});
  assert.equal(imported.requirements.R1.status, "PROVEN(local)");
});

test("promotion reopens selected requirements, records invalidated proof, and leaves unselected state unchanged", () => {
  const dir = mission();
  appendEvent(dir, { type: "BUNDLE_IMPORTED", actor: { name: "Alex", kind: "human" }, payload: importPayload() }, { reducer: missionReducer, expectedRevision: 3, currentHead: "9".repeat(40) });
  const promoted = appendEvent(dir, {
    type: "BUNDLE_PROMOTED", actor: { name: "Alex", kind: "human" }, payload: promotionPayload(),
  }, { reducer: missionReducer, expectedRevision: 4, currentHead: "9".repeat(40) }).state;
  renderMission(dir, promoted);

  assert.equal(promoted.requirements.R1.status, "IN_PROGRESS");
  assert.deepEqual(promoted.requirements.R1.evidenceRefs, []);
  assert.equal(promoted.requirements.R1.result, null);
  assert.deepEqual(promoted.requirements.R1.promotedBy, ["B-ALPHA"]);
  assert.equal(promoted.requirements.R2.status, "PROVEN(local)");
  assert.deepEqual(promoted.requirements.R2.evidenceRefs, ["E-R2"]);
  assert.deepEqual(promoted.promotions[0].invalidatedProof.R1, {
    previousStatus: "PROVEN(local)", evidenceRefs: ["E-OLD-COMMAND", "E-OLD-OPERATOR"], result: "old result",
  });
  assert.equal(promoted.promotions[0].reusableEvidence[0].sourceEvidenceId, "E-SRC-COMMAND");
  assert.equal(promoted.promotions[0].expiredEvidence.length, 2);
  assert.match(fs.readFileSync(path.join(dir, "requirement-ledger.md"), "utf8"), /Bundle Promotions[\s\S]*B-ALPHA[\s\S]*R1/);
  assert.equal(replayEvents(dir, { reducer: missionReducer }).state.promotions.length, 1);
});

test("rejects duplicate imports, digest mismatches, duplicate promotions, and unknown target requirements", () => {
  const dir = mission();
  appendEvent(dir, { type: "BUNDLE_IMPORTED", actor: { name: "Alex", kind: "human" }, payload: importPayload() }, { reducer: missionReducer, currentHead: "9".repeat(40) });
  assert.throws(() => appendEvent(dir, { type: "BUNDLE_IMPORTED", actor: { name: "Alex", kind: "human" }, payload: importPayload() }, { reducer: missionReducer }), /already imported/i);
  assert.throws(() => appendEvent(dir, { type: "BUNDLE_PROMOTED", actor: { name: "Alex", kind: "human" }, payload: { ...promotionPayload(), digest: `sha256:${"0".repeat(64)}` } }, { reducer: missionReducer }), /digest/i);
  appendEvent(dir, { type: "BUNDLE_PROMOTED", actor: { name: "Alex", kind: "human" }, payload: promotionPayload() }, { reducer: missionReducer, currentHead: "9".repeat(40) });
  assert.throws(() => appendEvent(dir, { type: "BUNDLE_PROMOTED", actor: { name: "Alex", kind: "human" }, payload: promotionPayload() }, { reducer: missionReducer }), /already promoted/i);

  const other = mission();
  appendEvent(other, { type: "BUNDLE_IMPORTED", actor: { name: "Alex", kind: "human" }, payload: importPayload() }, { reducer: missionReducer });
  const unknown = promotionPayload();
  unknown.targetRequirementIds = ["R404"];
  unknown.mappings = { "SRC-1": "R404" };
  assert.throws(() => appendEvent(other, { type: "BUNDLE_PROMOTED", actor: { name: "Alex", kind: "human" }, payload: unknown }, { reducer: missionReducer }), /unknown target requirement/i);
});
