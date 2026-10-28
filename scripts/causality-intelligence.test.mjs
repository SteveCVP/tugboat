import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { compileImpactGraph, inspectTrackedChanges } from "./lib/causality-intelligence.mjs";

function stateFixture() {
  return {
    schemaVersion: 2,
    protocolVersion: "2.0",
    status: "ACTIVE",
    revision: 4,
    activeSliceId: "S1",
    metadata: { id: "impact-test" },
    slices: { S1: { id: "S1", requirementIds: ["R1", "R2", "R3", "R4"], dependencies: [], status: "ACTIVE" } },
    requirements: {
      R1: { id: "R1", requirement: "Runtime", acceptance: "Runtime passes", material: true, status: "PROVEN(local)", evidenceRefs: ["E1"] },
      R2: { id: "R2", requirement: "CLI", acceptance: "CLI passes", material: true, status: "PROVEN(local)", evidenceRefs: ["E2"] },
      R3: { id: "R3", requirement: "Package", acceptance: "Package passes", material: true, status: "PROVEN(local)", evidenceRefs: ["E3"] },
      R4: { id: "R4", requirement: "Distribution", acceptance: "Distribution passes", material: true, status: "PENDING", evidenceRefs: [] },
    },
    evidence: {
      E1: { id: "E1", kind: "command", requirementIds: ["R1"], verification: { status: "passed" } },
      E2: { id: "E2", kind: "operator", requirementIds: ["R2"], verification: { status: "passed" } },
      E3: { id: "E3", kind: "command", requirementIds: ["R3"], verification: { status: "passed" } },
      E9: { id: "E9", kind: "command", requirementIds: ["R9"], verification: { status: "passed" } },
    },
  };
}

function profileFixture() {
  return {
    rules: [
      {
        id: "runtime-owner",
        pattern: "scripts/lib/**",
        requirementIds: ["R1"],
        evidenceIds: ["E1"],
        tests: ["node --test scripts/runtime.test.mjs"],
        risks: ["runtime"],
      },
      {
        id: "cli-owner",
        pattern: "scripts/**",
        requirementIds: ["R2"],
        tests: ["node --test scripts/cli.test.mjs"],
        risks: ["operator-surface"],
      },
    ],
    requirementDependencies: {
      R3: ["R1"],
      R4: ["R3"],
    },
  };
}

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

test("impact graph maps overlapping path ownership through transitive requirements and proof", () => {
  const state = stateFixture();
  const before = JSON.stringify(state);
  const report = compileImpactGraph(state, [
    { path: "scripts/lib/runtime.mjs", status: "modified" },
  ], profileFixture());

  assert.equal(report.status, "ready");
  assert.deepEqual(report.impact.directRequirementIds, ["R1", "R2"]);
  assert.deepEqual(report.impact.transitiveRequirementIds, ["R3", "R4"]);
  assert.deepEqual(report.impact.allRequirementIds, ["R1", "R2", "R3", "R4"]);
  assert.deepEqual(report.impact.invalidatedEvidenceIds, ["E1", "E2", "E3"]);
  assert.deepEqual(report.impact.requiredTests, [
    "node --test scripts/cli.test.mjs",
    "node --test scripts/runtime.test.mjs",
  ]);
  assert.deepEqual(report.impact.riskTags, ["operator-surface", "runtime"]);
  assert.deepEqual(report.unmappedChanges, []);
  assert.ok(report.edges.some((edge) => edge.from === "change:scripts/lib/runtime.mjs" && edge.to === "requirement:R1" && edge.kind === "direct"));
  assert.ok(report.edges.some((edge) => edge.from === "requirement:R1" && edge.to === "requirement:R3" && edge.kind === "dependency"));
  assert.ok(report.edges.some((edge) => edge.from === "requirement:R3" && edge.to === "requirement:R4" && edge.kind === "dependency"));
  assert.ok(report.edges.some((edge) => edge.from === "requirement:R3" && edge.to === "evidence:E3" && edge.kind === "invalidates"));
  assert.match(report.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(state), before);
});

test("impact graph is canonical across change and rule order and never loses unmapped work", () => {
  const changes = [
    { path: "docs/unknown.md", status: "added" },
    { path: "scripts/lib/runtime.mjs", status: "modified" },
  ];
  const profile = profileFixture();
  const left = compileImpactGraph(stateFixture(), changes, profile);
  const right = compileImpactGraph(stateFixture(), [...changes].reverse(), {
    requirementDependencies: { R4: ["R3"], R3: ["R1"] },
    rules: [...profile.rules].reverse(),
  });

  assert.equal(left.status, "insufficient_evidence");
  assert.deepEqual(left.unmappedChanges, [{ path: "docs/unknown.md", status: "added" }]);
  assert.deepEqual(left, right);
  assert.equal(left.gaps[0].code, "unmapped_change");
});

test("impact reports support more than 256 canonical edges while staying bounded", () => {
  const requirementIds = Array.from({ length: 100 }, (_, index) => `R${String(index + 1).padStart(3, "0")}`);
  const state = {
    schemaVersion: 2,
    protocolVersion: "2.0",
    status: "ACTIVE",
    revision: 1,
    activeSliceId: "S1",
    metadata: { id: "large-impact-test" },
    slices: { S1: { id: "S1", requirementIds, dependencies: [], status: "ACTIVE" } },
    requirements: Object.fromEntries(requirementIds.map((id) => [id, {
      id,
      requirement: `Requirement ${id}`,
      acceptance: `${id} returns an observable result.`,
      material: true,
      status: "PENDING",
      evidenceRefs: [],
    }])),
    evidence: {},
  };
  const profile = {
    rules: requirementIds.map((requirementId, index) => ({
      id: `rule-${String(index).padStart(3, "0")}`,
      pattern: "src/**",
      requirementIds: [requirementId],
      evidenceIds: [],
      tests: [],
      risks: [],
    })),
  };
  const report = compileImpactGraph(state, ["src/a.mjs", "src/b.mjs", "src/c.mjs"], profile);
  assert.equal(report.status, "ready");
  assert.ok(report.edges.length > 256);
  assert.match(report.digest, /^sha256:[0-9a-f]{64}$/);
});

test("impact profiles fail closed on malformed, unknown, duplicate, excessive, and secret-bearing input", () => {
  const state = stateFixture();
  const baseRule = { id: "owner", pattern: "scripts/**", requirementIds: ["R1"] };

  assert.throws(() => compileImpactGraph(state, ["scripts/a.mjs"], { rules: [baseRule], surprise: true }), /unknown impact profile field surprise/i);
  assert.throws(() => compileImpactGraph(state, ["scripts/a.mjs"], { rules: [{ ...baseRule, surprise: true }] }), /unknown impact rule field surprise/i);
  assert.throws(() => compileImpactGraph(state, ["scripts/a.mjs"], { rules: [{ ...baseRule, requirementIds: ["R9"] }] }), /unknown requirement R9/i);
  assert.throws(() => compileImpactGraph(state, ["scripts/a.mjs"], { rules: [baseRule, baseRule] }), /duplicate impact rules id owner/i);
  assert.throws(() => compileImpactGraph(state, ["scripts/a.mjs"], { rules: [{ ...baseRule, pattern: "../**" }] }), /portable relative/i);
  assert.throws(() => compileImpactGraph(state, ["scripts/a.mjs"], { rules: Array.from({ length: 129 }, (_, index) => ({ ...baseRule, id: `R${index}` })) }), /at most 128/i);
  assert.throws(
    () => compileImpactGraph(state, ["scripts/a.mjs"], { rules: [{ ...baseRule, tests: [["github", "_pat_", "abcdefghijklmnopqrstuvwxyz123456"].join("")] }] }),
    /secret material/i,
  );
  assert.throws(() => compileImpactGraph(state, ["scripts/a.mjs"], { rules: [baseRule], requirementDependencies: { R2: ["R9"] } }), /unknown requirement R9/i);
});

test("tracked change inspection uses one bounded read-only Git diff and parses modifications, deletion, and renames", () => {
  const calls = [];
  const result = inspectTrackedChanges(".", "base-ref", "head-ref", (_cwd, args) => {
    calls.push(args);
    return "M\0scripts/a.mjs\0D\0scripts/old.mjs\0R100\0scripts/from.mjs\0scripts/to.mjs\0";
  });

  assert.deepEqual(calls, [["diff", "--name-status", "-z", "--find-renames=50%", "base-ref", "head-ref", "--"]]);
  assert.deepEqual(result.changes, [
    { path: "scripts/a.mjs", status: "modified" },
    { path: "scripts/old.mjs", status: "deleted" },
    { path: "scripts/to.mjs", previousPath: "scripts/from.mjs", status: "renamed" },
  ]);
  assert.match(result.digest, /^sha256:[0-9a-f]{64}$/);
  assert.throws(() => inspectTrackedChanges(".", "--output=/tmp/x", "HEAD", () => ""), /unsafe Git ref/i);
});

test("real tracked inspection is byte-preserving and includes deleted and renamed paths", () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-impact-git-"));
  git(repo, ["init", "-b", "main"]);
  git(repo, ["config", "user.name", "Impact Test"]);
  git(repo, ["config", "user.email", "impact@example.invalid"]);
  fs.mkdirSync(path.join(repo, "scripts"));
  fs.writeFileSync(path.join(repo, "scripts", "keep.mjs"), "export const keep = true;\n");
  fs.writeFileSync(path.join(repo, "scripts", "remove.mjs"), "export const remove = true;\n");
  git(repo, ["add", "."]);
  git(repo, ["commit", "-m", "base"]);
  const base = git(repo, ["rev-parse", "HEAD"]);
  fs.renameSync(path.join(repo, "scripts", "keep.mjs"), path.join(repo, "scripts", "renamed.mjs"));
  fs.rmSync(path.join(repo, "scripts", "remove.mjs"));
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-m", "change"]);
  const head = git(repo, ["rev-parse", "HEAD"]);
  const statusBefore = git(repo, ["status", "--porcelain=v1"]);

  const result = inspectTrackedChanges(repo, base, head);

  assert.deepEqual(result.changes, [
    { path: "scripts/remove.mjs", status: "deleted" },
    { path: "scripts/renamed.mjs", previousPath: "scripts/keep.mjs", status: "renamed" },
  ]);
  assert.equal(git(repo, ["status", "--porcelain=v1"]), statusBefore);
});
