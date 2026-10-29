import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalDigest } from "./lib/proof-runtime.mjs";
import { compileProofInvalidation, createNonInterferencePreservation } from "./lib/proof-invalidation.mjs";
import { createMission, missionReducer } from "./lib/reducer.mjs";
import { appendEvent } from "./lib/store.mjs";

const bundleDigest = `sha256:${"a".repeat(64)}`;
const manifestDigest = `sha256:${"b".repeat(64)}`;
const witnessDigest = `sha256:${"c".repeat(64)}`;

function graph() {
  return {
    schemaVersion: "tugboat.proof-invalidation-graph.v1",
    bundleDigest,
    boundaryManifestDigest: manifestDigest,
    nodes: [
      { id: "effect:e1", kind: "effect", mandatory: false },
      { id: "component:core", kind: "boundary", mandatory: false },
      { id: "requirement:R1", kind: "requirement", mandatory: false },
      { id: "gate:core", kind: "gate", mandatory: false },
      { id: "evidence:E1", kind: "evidence", mandatory: false },
      { id: "deployment:production", kind: "deployment", mandatory: false },
      { id: "component:docs", kind: "boundary", mandatory: false },
      { id: "requirement:R2", kind: "requirement", mandatory: false },
      { id: "gate:docs", kind: "gate", mandatory: false },
      { id: "evidence:E2", kind: "evidence", mandatory: false },
      { id: "gate:release", kind: "gate", mandatory: true },
      { id: "evidence:E-UNRELATED", kind: "evidence", mandatory: false },
    ],
    edges: [
      { from: "effect:e1", to: "component:core", kind: "affects" },
      { from: "effect:e1", to: "component:docs", kind: "conservative_affects" },
      { from: "component:core", to: "requirement:R1", kind: "governs" },
      { from: "requirement:R1", to: "gate:core", kind: "requires" },
      { from: "gate:core", to: "evidence:E1", kind: "invalidates" },
      { from: "evidence:E1", to: "deployment:production", kind: "supports" },
      { from: "component:docs", to: "requirement:R2", kind: "governs" },
      { from: "requirement:R2", to: "gate:docs", kind: "requires" },
      { from: "gate:docs", to: "evidence:E2", kind: "invalidates" },
    ],
  };
}

function witness(overrides = {}) {
  return {
    semanticProof: true,
    verdict: "ready",
    digest: witnessDigest,
    payload: {
      body: {
        bundleDigest,
        boundaryManifestDigest: manifestDigest,
        effects: [{ id: "effect:e1" }],
        provenUnaffectedComponentIds: ["component:docs"],
        ...overrides,
      },
    },
  };
}

test("invalidates direct and transitive proof with shortest witness paths while mandatory gates always rerun", () => {
  const report = compileProofInvalidation(graph(), { witness: witness() });
  assert.equal(report.status, "ready");
  assert.deepEqual(report.invalidated.map((item) => item.id), [
    "component:core", "deployment:production", "effect:e1", "evidence:E1", "gate:core", "gate:release", "requirement:R1",
  ]);
  assert.deepEqual(report.invalidated.find((item) => item.id === "evidence:E1").witnessPath, [
    "effect:e1", "component:core", "requirement:R1", "gate:core", "evidence:E1",
  ]);
  assert.deepEqual(report.invalidated.find((item) => item.id === "gate:release"), {
    id: "gate:release", kind: "gate", reason: "mandatory_gate", witnessPath: ["gate:release"],
  });
  assert.deepEqual(report.invalidatedEvidenceIds, ["evidence:E1"]);
  assert.deepEqual(report.invalidatedDeploymentIds, ["deployment:production"]);
});

test("a verified non-interference boundary cuts propagation and returns explicit retained reasons", () => {
  const report = compileProofInvalidation(graph(), { witness: witness() });
  assert.deepEqual(report.retained.find((item) => item.id === "component:docs"), {
    id: "component:docs",
    kind: "boundary",
    reason: "verified_non_interference",
    witnessPath: ["effect:e1", "component:docs"],
    witnessDigest,
  });
  assert.deepEqual(report.retained.find((item) => item.id === "evidence:E2").reason, "verified_non_interference");
  assert.deepEqual(report.retained.find((item) => item.id === "evidence:E-UNRELATED").reason, "not_reachable_from_changed_effect");
  assert.deepEqual(report.retainedEvidenceIds, ["evidence:E-UNRELATED", "evidence:E2"]);
});

test("stale, mismatched, or integrity-only witnesses cannot prune proof", () => {
  assert.throws(() => compileProofInvalidation(graph(), { witness: { ...witness(), semanticProof: false } }), /semantic verification/);
  assert.throws(() => compileProofInvalidation(graph(), { witness: witness({ bundleDigest: `sha256:${"d".repeat(64)}` }) }), /bundle digest mismatch/);
  assert.throws(() => compileProofInvalidation(graph(), { witness: witness({ boundaryManifestDigest: `sha256:${"e".repeat(64)}` }) }), /boundary manifest digest mismatch/);
  assert.throws(() => compileProofInvalidation(graph(), { witness: witness({ effects: [{ id: "effect:missing" }] }) }), /unknown changed effect/);
  assert.throws(() => compileProofInvalidation(graph(), { witness: { ...witness(), verdict: "blocked" } }), /ready witness/);
});

test("rejects cycles, missing nodes, unknown fields, and invalid mandatory node types", () => {
  const cyclic = graph();
  cyclic.edges.push({ from: "evidence:E1", to: "component:core", kind: "cycle" });
  assert.throws(() => compileProofInvalidation(cyclic, { witness: witness() }), /cycle.*component:core.*requirement:R1.*gate:core.*evidence:E1.*component:core/i);
  const missing = graph();
  missing.edges[0].to = "component:missing";
  assert.throws(() => compileProofInvalidation(missing, { witness: witness() }), /unknown node component:missing/);
  const extra = graph();
  extra.nodes[0].confidence = 0.9;
  assert.throws(() => compileProofInvalidation(extra, { witness: witness() }), /Unknown proof node field confidence/);
  const mandatory = graph();
  mandatory.nodes.find((item) => item.id === "evidence:E1").mandatory = true;
  assert.throws(() => compileProofInvalidation(mandatory, { witness: witness() }), /only gate nodes may be mandatory/i);
});

test("result is canonical across node and edge order", () => {
  const left = compileProofInvalidation(graph(), { witness: witness() });
  const reordered = graph();
  reordered.nodes.reverse();
  reordered.edges.reverse();
  assert.deepEqual(compileProofInvalidation(reordered, { witness: witness() }), left);
  assert.match(left.digest, /^sha256:[0-9a-f]{64}$/);
});

test("non-interference is stored as preservation proof but promotion still reopens functional target proof", () => {
  const invalidation = compileProofInvalidation(graph(), { witness: witness() });
  const preservation = createNonInterferencePreservation(witness(), invalidation);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-invalidation-state-"));
  createMission({
    dir,
    actor: { name: "Test", kind: "human", runtime: "test" },
    metadata: {
      id: "target", title: "Target", owner: "Test", target: "local", repository: "/repo", worktree: "/repo",
      branch: "main", baselineGitSha: "1".repeat(40), source: { path: "spec.md", digest: `sha256:${"2".repeat(64)}` },
      criticalPath: ["R1"], deployPath: "not requested",
    },
    requirements: [
      { id: "R1", requirement: "Changed target", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
      { id: "R2", requirement: "Unaffected target", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
    ],
    preservations: [{ id: "P1", instruction: "Preserve docs", source: "spec", regressionProofTarget: "witness" }],
  });
  appendEvent(dir, { type: "REQUIREMENT_PROVEN", actor: { name: "Test" }, payload: { requirementId: "R1", status: "PROVEN(local)", evidenceRefs: ["E1"], result: "old" } }, { reducer: missionReducer });
  appendEvent(dir, { type: "REQUIREMENT_PROVEN", actor: { name: "Test" }, payload: { requirementId: "R2", status: "PROVEN(local)", evidenceRefs: ["E2"], result: "retained" } }, { reducer: missionReducer });
  appendEvent(dir, {
    type: "BUNDLE_IMPORTED", actor: { name: "Test" },
    payload: { bundleId: "B1", digest: bundleDigest, source: { missionId: "source" }, requirementIds: ["SRC1"], dependencies: [], commits: [], components: [], evidence: [] },
  }, { reducer: missionReducer });
  const promotionPayload = {
    bundleId: "B1", digest: bundleDigest, sourceRequirementIds: ["SRC1"], targetRequirementIds: ["R1"], mappings: { SRC1: "R1" },
    preservationProofs: [preservation], reusableEvidence: [], expiredEvidence: [], appliedCommits: [], components: [],
  };
  assert.throws(() => appendEvent(dir, {
    type: "BUNDLE_PROMOTED", actor: { name: "Test" },
    payload: { ...promotionPayload, preservationProofs: [{ ...preservation, authority: "functional_acceptance" }] },
  }, { reducer: missionReducer }), /invalidation_only/);
  const promoted = appendEvent(dir, {
    type: "BUNDLE_PROMOTED", actor: { name: "Test" }, payload: promotionPayload,
  }, { reducer: missionReducer }).state;

  assert.equal(promoted.requirements.R1.status, "IN_PROGRESS");
  assert.deepEqual(promoted.requirements.R1.evidenceRefs, []);
  assert.equal(promoted.requirements.R1.result, null);
  assert.equal(promoted.requirements.R2.status, "PROVEN(local)");
  assert.deepEqual(promoted.requirements.R2.evidenceRefs, ["E2"]);
  assert.deepEqual(promoted.promotions[0].preservationProofs, [preservation]);
  assert.equal(preservation.kind, "non_interference");
  assert.equal(preservation.authority, "invalidation_only");
  assert.equal(preservation.digest, canonicalDigest({
    kind: preservation.kind,
    authority: preservation.authority,
    witnessDigest: preservation.witnessDigest,
    invalidationDigest: preservation.invalidationDigest,
    bundleDigest: preservation.bundleDigest,
    boundaryManifestDigest: preservation.boundaryManifestDigest,
    retainedNodeIds: preservation.retainedNodeIds,
    invalidatedNodeIds: preservation.invalidatedNodeIds,
  }));
});
