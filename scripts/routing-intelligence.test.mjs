import assert from "node:assert/strict";
import test from "node:test";

import { canonicalReport } from "./lib/intelligence-core.mjs";
import { compileExecutionRouting } from "./lib/routing-intelligence.mjs";

const OBSERVED_AT = "2026-10-28T18:00:00.000Z";
const DIGEST = `sha256:${"a".repeat(64)}`;

function routingState(ids = ["R1"]) {
  return {
    protocolVersion: "2.0",
    status: "ACTIVE",
    revision: 5,
    activeSliceId: "S1",
    metadata: { id: "routing-test", criticalPath: ids },
    slices: { S1: { id: "S1", name: "Route", requirementIds: ids, dependencies: [], status: "ACTIVE", operatorJourney: "Route work" } },
    requirements: Object.fromEntries(ids.map((id) => [id, { id, requirement: `Implement ${id}`, acceptance: `${id} returns a result.`, material: true, proofTarget: "local", status: "PENDING", evidenceRefs: [] }])),
    preservations: {},
    evidence: {},
    claims: {},
    handoff: { nextAction: "route work", nextCheck: "verify assignment", blocker: null },
  };
}

function attestation(capability, overrides = {}) {
  return {
    capability,
    evidenceDigest: DIGEST,
    issuer: "trusted-ci",
    issuedAt: "2026-10-28T16:00:00.000Z",
    expiresAt: "2026-10-28T20:00:00.000Z",
    ...overrides,
  };
}

function worker(id, overrides = {}) {
  return {
    id,
    trustNodeId: id,
    trustLevel: "standard",
    maxClassification: "confidential",
    costUnits: 2,
    latencyUnits: 2,
    capacity: 1,
    activeAssignments: 0,
    attestations: [attestation("node-runtime")],
    ...overrides,
  };
}

function profile(ids = ["R1"]) {
  return {
    trustLevels: ["untrusted", "standard", "privileged"],
    classifications: ["public", "internal", "confidential", "restricted"],
    trustedIssuers: ["trusted-ci"],
    packets: Object.fromEntries(ids.map((id) => [id, {
      capabilities: ["node-runtime"],
      minTrust: "standard",
      classification: "confidential",
    }])),
  };
}

test("router assigns only a current third-party-attested, trusted, cleared, available worker", () => {
  const state = routingState();
  const workers = {
    workers: [
      worker("eligible", { costUnits: 3, latencyUnits: 1 }),
      worker("self", { attestations: [attestation("node-runtime", { issuer: "self" })] }),
      worker("expired", { attestations: [attestation("node-runtime", { expiresAt: OBSERVED_AT })] }),
      worker("under-trusted", { trustLevel: "untrusted" }),
      worker("under-cleared", { maxClassification: "internal" }),
      worker("full", { capacity: 1, activeAssignments: 1 }),
      worker("node-runtime-expert", { attestations: [] }),
      worker("untrusted-issuer", { attestations: [attestation("node-runtime", { issuer: "unknown-ci" })] }),
    ],
  };
  workers.workers.find(({ id }) => id === "self").attestations[0].issuer = "self";
  const before = JSON.stringify({ state, workers });
  const report = compileExecutionRouting(state, workers, profile(), OBSERVED_AT);
  const evaluations = Object.fromEntries(report.evaluations.map((item) => [item.workerId, item]));

  assert.equal(report.status, "ready");
  assert.deepEqual(report.assignments.map(({ requirementId, workerId }) => ({ requirementId, workerId })), [{ requirementId: "R1", workerId: "eligible" }]);
  assert.deepEqual(report.unassigned, []);
  assert.ok(evaluations.self.failedConstraints.includes("capability:node-runtime:self_attested"));
  assert.ok(evaluations.expired.failedConstraints.includes("capability:node-runtime:expired"));
  assert.ok(evaluations["under-trusted"].failedConstraints.includes("trust_level"));
  assert.ok(evaluations["under-cleared"].failedConstraints.includes("classification_clearance"));
  assert.ok(evaluations.full.failedConstraints.includes("capacity"));
  assert.ok(evaluations["node-runtime-expert"].failedConstraints.includes("capability:node-runtime:not_attested"));
  assert.ok(evaluations["untrusted-issuer"].failedConstraints.includes("capability:node-runtime:untrusted_issuer"));
  assert.equal(report.dispatchPerformed, false);
  assert.equal(JSON.stringify({ state, workers }), before);
});

test("router ranks cost then latency then ID and consumes declared capacity across multiple packets", () => {
  const state = routingState(["R1", "R2"]);
  const workers = { workers: [
    worker("b-worker", { costUnits: 1, latencyUnits: 1, capacity: 2, attestations: [attestation("node-runtime")] }),
    worker("a-worker", { costUnits: 1, latencyUnits: 1, capacity: 1, attestations: [attestation("node-runtime")] }),
    worker("cheap-slow", { costUnits: 1, latencyUnits: 5, capacity: 2, attestations: [attestation("node-runtime")] }),
    worker("fast-expensive", { costUnits: 2, latencyUnits: 0, capacity: 2, attestations: [attestation("node-runtime")] }),
  ] };
  const report = compileExecutionRouting(state, workers, profile(["R1", "R2"]), OBSERVED_AT);

  assert.equal(report.status, "ready");
  assert.deepEqual(report.assignments.map(({ requirementId, workerId }) => [requirementId, workerId]), [["R1", "a-worker"], ["R2", "b-worker"]]);
  assert.deepEqual(report.assignments[0].rank, { costUnits: 1, latencyUnits: 1, tieBreak: "a-worker" });
});

test("trust-taint violations are hard routing constraints, not score penalties", () => {
  const state = routingState();
  const trust = canonicalReport("tugboat.trust-taint.v1", {
    status: "blocked",
    classifications: ["public", "internal", "confidential"],
    edges: [],
    nodes: [
      { id: "cheap", type: "worker", classification: "internal", authorities: [], effectiveClassification: "internal", effectiveAuthorities: [] },
      { id: "safe", type: "worker", classification: "internal", authorities: [], effectiveClassification: "internal", effectiveAuthorities: [] },
    ],
    violations: [{ code: "authority_overflow", nodeId: "cheap", edgeId: null, message: "cheap can deploy", witnessPath: ["cheap", "prod"] }],
  });
  const workers = { workers: [
    worker("cheap", { costUnits: 1, latencyUnits: 1 }),
    worker("safe", { costUnits: 5, latencyUnits: 5 }),
  ] };
  const report = compileExecutionRouting(state, workers, profile(), OBSERVED_AT, trust);

  assert.deepEqual(report.assignments.map(({ workerId }) => workerId), ["safe"]);
  assert.ok(report.evaluations.find(({ workerId }) => workerId === "cheap").failedConstraints.includes("trust_policy_violation"));

  const absent = { workers: [worker("absent")] };
  const absentReport = compileExecutionRouting(state, absent, profile(), OBSERVED_AT, trust);
  assert.ok(absentReport.evaluations[0].failedConstraints.includes("trust_node_missing"));

  trust.violations.push({ code: "flow_cycle", nodeId: "safe", edgeId: null, message: "cycle", witnessPath: ["safe", "prod", "safe"] });
  assert.throws(() => compileExecutionRouting(state, workers, profile(), OBSERVED_AT, trust), /trust report digest/i);
});

test("router leaves impossible and underspecified packets unassigned with literal reasons", () => {
  const state = routingState(["R1", "R2"]);
  const workers = { workers: [worker("python-only", { attestations: [attestation("python-runtime")] })] };
  const routingProfile = profile(["R1"]);
  const report = compileExecutionRouting(state, workers, routingProfile, OBSERVED_AT);

  assert.equal(report.status, "insufficient_evidence");
  assert.deepEqual(report.assignments, []);
  assert.deepEqual(report.unassigned, [
    { requirementId: "R1", reasons: ["no_eligible_worker"] },
    { requirementId: "R2", reasons: ["profile_missing"] },
  ]);
});

test("routing input rejects malformed profiles, workers, attestations, timestamps, and forged trust reports", () => {
  const state = routingState();
  const workers = { workers: [worker("valid")] };
  assert.throws(() => compileExecutionRouting(state, workers, { ...profile(), surprise: true }, OBSERVED_AT), /unknown routing profile field surprise/i);
  assert.throws(() => compileExecutionRouting(state, workers, { ...profile(), trustedIssuers: [] }, OBSERVED_AT), /trustedIssuers needs at least one issuer/i);
  assert.throws(() => compileExecutionRouting(state, { workers: [worker("A"), worker("A")] }, profile(), OBSERVED_AT), /duplicate workers id A/i);
  assert.throws(() => compileExecutionRouting(state, { workers: [worker("A", { capacity: 0 })] }, profile(), OBSERVED_AT), /capacity must be a positive integer/i);
  assert.throws(() => compileExecutionRouting(state, { workers: [worker("A", { attestations: [attestation("node-runtime", { evidenceDigest: "bad" })] })] }, profile(), OBSERVED_AT), /evidenceDigest must be a SHA-256 digest/i);
  assert.throws(() => compileExecutionRouting(state, workers, profile(), "2026-10-28"), /ISO-8601 UTC timestamp/i);
  assert.throws(() => compileExecutionRouting(state, workers, { ...profile(), packets: { R9: profile().packets.R1 } }, OBSERVED_AT), /unknown requirement R9/i);
});
