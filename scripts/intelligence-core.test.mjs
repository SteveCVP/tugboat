import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  INTELLIGENCE_STATUS,
  boundedList,
  canonicalReport,
  missionSummary,
  normalizeObservedAt,
  portableGlobMatch,
  readMissionState,
  validateObject,
} from "./lib/intelligence-core.mjs";
import { createMission } from "./lib/reducer.mjs";

function createFixtureMission() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-intelligence-core-"));
  const missionDir = path.join(root, "mission");
  createMission({
    dir: missionDir,
    actor: { name: "Intelligence Test", kind: "human", runtime: "test" },
    metadata: {
      id: "intelligence-core",
      title: "Intelligence Core",
      owner: "Test",
      target: "local",
      repository: root,
      worktree: root,
      branch: "main",
      baselineGitSha: "a".repeat(40),
      source: { path: "spec.md", digest: `sha256:${"b".repeat(64)}` },
      criticalPath: ["R1"],
      deployPath: "none",
    },
    requirements: [{
      id: "R1",
      requirement: "Compile intelligence",
      source: "spec",
      material: true,
      acceptance: "The report has a canonical digest.",
      proofTarget: "local",
    }],
    preservations: [{
      id: "P1",
      instruction: "Preserve replay",
      source: "spec",
      regressionProofTarget: "state test",
    }],
    slices: [{
      id: "S1",
      name: "Intelligence",
      requirementIds: ["R1"],
      dependencies: [],
      status: "ACTIVE",
      operatorJourney: "Compile intelligence",
    }],
  });
  return { root, missionDir };
}

function directoryBytes(dir) {
  return Object.fromEntries(fs.readdirSync(dir).sort().map((name) => [name, fs.readFileSync(path.join(dir, name))]));
}

test("canonical reports are stable, content-addressed, bounded-status documents", () => {
  const first = canonicalReport("tugboat.example.v1", {
    status: "ready",
    nested: { z: 2, a: 1 },
    items: ["R2", "R1"],
  });
  const second = canonicalReport("tugboat.example.v1", {
    items: ["R2", "R1"],
    nested: { a: 1, z: 2 },
    status: "ready",
  });

  assert.deepEqual(first, second);
  assert.equal(first.schemaVersion, "tugboat.example.v1");
  assert.match(first.digest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(INTELLIGENCE_STATUS, ["blocked", "insufficient_evidence", "ready"]);
  assert.throws(() => canonicalReport("tugboat.example.v1", { status: "complete" }), /status must be one of/i);
  assert.throws(
    () => canonicalReport("tugboat.example.v1", { status: "ready", token: ["github", "_pat_", "abcdefghijklmnopqrstuvwxyz123456"].join("") }),
    /secret material/i,
  );
});

test("bounded profile primitives reject unknown, missing, duplicate, oversized, and unsafe values", () => {
  assert.deepEqual(
    validateObject({ id: "R1", enabled: true }, { label: "rule", allowed: ["enabled", "id"], required: ["id"] }),
    { id: "R1", enabled: true },
  );
  assert.throws(() => validateObject([], { label: "rule", allowed: [] }), /rule must be an object/i);
  assert.throws(() => validateObject({ surprise: true }, { label: "rule", allowed: ["id"] }), /unknown rule field surprise/i);
  assert.throws(() => validateObject({}, { label: "rule", allowed: ["id"], required: ["id"] }), /rule is missing id/i);
  assert.throws(() => validateObject({ id: "/private/tmp/data" }, { label: "rule", allowed: ["id"], required: ["id"] }), /absolute path/i);
  assert.throws(() => validateObject({ id: "x".repeat(4097) }, { label: "rule", allowed: ["id"] }), /4096 bytes/i);

  assert.deepEqual(boundedList([{ id: "A" }, { id: "B" }], "rules", 2, { uniqueBy: "id" }), [{ id: "A" }, { id: "B" }]);
  assert.throws(() => boundedList("A", "rules", 2), /rules must be an array/i);
  assert.throws(() => boundedList([1, 2, 3], "rules", 2), /at most 2/i);
  assert.throws(() => boundedList([{ id: "A" }, { id: "A" }], "rules", 2, { uniqueBy: "id" }), /duplicate rules id A/i);
});

test("observation time and portable globs are strict and platform-neutral", () => {
  assert.equal(normalizeObservedAt("2026-10-28T18:00:00.000Z"), "2026-10-28T18:00:00.000Z");
  assert.throws(() => normalizeObservedAt("2026-10-28"), /ISO-8601 UTC timestamp/i);
  assert.throws(() => normalizeObservedAt("2026-10-28T14:00:00-04:00"), /ISO-8601 UTC timestamp/i);
  assert.throws(() => normalizeObservedAt("not-a-date"), /ISO-8601 UTC timestamp/i);

  assert.equal(portableGlobMatch("scripts/**", "scripts/lib/core.mjs"), true);
  assert.equal(portableGlobMatch("scripts/*.mjs", "scripts/lib/core.mjs"), false);
  assert.equal(portableGlobMatch("src/*/test?.js", "src/unit/test1.js"), true);
  assert.equal(portableGlobMatch("*.md", "README.md"), true);
  assert.equal(portableGlobMatch("*.md", "docs/README.md"), false);
  assert.throws(() => portableGlobMatch("/scripts/**", "scripts/core.mjs"), /portable relative/i);
  assert.throws(() => portableGlobMatch("../**", "scripts/core.mjs"), /portable relative/i);
  assert.throws(() => portableGlobMatch("scripts/**", "../secret"), /portable relative/i);
});

test("verified mission reads expose only bounded identity and preserve every mission byte", () => {
  const { missionDir } = createFixtureMission();
  const before = directoryBytes(missionDir);

  const state = readMissionState(missionDir);
  const summary = missionSummary(state);

  assert.deepEqual(summary, {
    activeSliceId: "S1",
    id: "intelligence-core",
    protocolVersion: "2.0",
    revision: 1,
    status: "ACTIVE",
  });
  assert.deepEqual(directoryBytes(missionDir), before);

  const statePath = path.join(missionDir, "state.json");
  const corrupted = JSON.parse(fs.readFileSync(statePath, "utf8"));
  corrupted.status = "COMPLETE";
  fs.writeFileSync(statePath, `${JSON.stringify(corrupted, null, 2)}\n`);
  assert.throws(() => readMissionState(missionDir), /state\.json does not match event replay/i);
});
