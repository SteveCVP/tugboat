import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendEvent, writeStateSnapshot } from "./lib/store.mjs";
import { missionReducer } from "./lib/reducer.mjs";
import { explainMissionHistory } from "./lib/history-debugger.mjs";

function mission() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-history-"));
  const genesis = appendEvent(dir, { actor: { name: "test" }, type: "GENESIS", timestamp: "2026-10-28T10:00:00.000Z", payload: { metadata: { id: "m", baselineGitSha: "a".repeat(40), criticalPath: ["R1"] }, requirements: [{ id: "R1", requirement: "x" }], preservations: [], slices: [{ id: "S1", requirementIds: ["R1"], dependencies: [], status: "ACTIVE" }] } }, { reducer: missionReducer });
  const next = appendEvent(dir, { actor: { name: "test" }, type: "REQUIREMENT_UPDATED", timestamp: "2026-10-28T11:00:00.000Z", payload: { requirementId: "R1", status: "IN_PROGRESS", result: "started", evidenceRefs: [] } }, { reducer: missionReducer });
  writeStateSnapshot(dir, next.state);
  return dir;
}

test("time travel reconstructs exact revisions and requirement causality without mutation", () => {
  const dir = mission();
  const before = fs.readFileSync(path.join(dir, "events.jsonl"), "utf8");
  const report = explainMissionHistory(dir, { revision: 1, requirementId: "R1" });
  assert.equal(report.selected.revision, 1);
  assert.equal(report.selected.requirement.status, "PENDING");
  assert.equal(report.current.requirement.status, "IN_PROGRESS");
  assert.deepEqual(report.causalPath.map((item) => item.sequence), [1]);
  assert.equal(fs.readFileSync(path.join(dir, "events.jsonl"), "utf8"), before);
  assert.throws(() => explainMissionHistory(dir, { revision: 99 }), /revision/);
});

test("time travel rejects a tampered event chain", () => {
  const dir = mission();
  const file = path.join(dir, "events.jsonl");
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("started", "rewritten"));
  assert.throws(() => explainMissionHistory(dir, { revision: 1 }), /hash mismatch/);
});

