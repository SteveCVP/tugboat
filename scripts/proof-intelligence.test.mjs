import assert from "node:assert/strict";
import test from "node:test";

import { canonicalReport } from "./lib/intelligence-core.mjs";
import {
  compileEvidenceFreshness,
  compileProofPortfolio,
  compileReleaseSimulation,
} from "./lib/proof-intelligence.mjs";

const OBSERVED_AT = "2026-10-28T18:00:00.000Z";

function freshnessState() {
  const requirement = (id, amendedBy = []) => ({
    id,
    requirement: `Requirement ${id}`,
    acceptance: `${id} returns an observable result.`,
    material: true,
    proofTarget: "local",
    status: "PROVEN(local)",
    evidenceRefs: [],
    amendedBy,
  });
  const evidence = (id, kind, capturedAt, requirementIds, extra = {}) => ({
    id,
    kind,
    capturedAt,
    requirementIds,
    git: { sha: "a".repeat(40), clean: true },
    verification: { status: "passed", verifier: "test" },
    ...extra,
  });
  const state = {
    protocolVersion: "2.0",
    status: "ACTIVE",
    revision: 8,
    activeSliceId: "S1",
    metadata: { id: "freshness-test" },
    slices: { S1: { id: "S1", requirementIds: ["R1", "R2", "R3"], dependencies: [], status: "ACTIVE" } },
    requirements: {
      R1: requirement("R1"),
      R2: requirement("R2"),
      R3: requirement("R3", ["A1"]),
    },
    evidence: {
      "E-FRESH": evidence("E-FRESH", "command", "2026-10-28T17:30:00.000Z", ["R1"]),
      "E-EXP": evidence("E-EXP", "command", "2026-10-28T16:30:00.000Z", ["R1"]),
      "E-BOUND": evidence("E-BOUND", "command", "2026-10-28T16:00:00.000Z", ["R1"]),
      "E-VOL": evidence("E-VOL", "operator", "2026-10-28T17:15:00.000Z", ["R2"]),
      "E-IMPACT": evidence("E-IMPACT", "operator", "2026-10-28T17:50:00.000Z", ["R1"]),
      "E-DEPLOY": evidence("E-DEPLOY", "deployment", "2026-10-28T17:50:00.000Z", ["R1"], { deployment: { deployedSha: "c".repeat(40) } }),
      "E-SUP": evidence("E-SUP", "command", "2026-10-28T17:50:00.000Z", ["R3"]),
      "E-UNKNOWN": evidence("E-UNKNOWN", "browser", "2026-10-28T17:50:00.000Z", ["R1"]),
    },
    amendments: {
      A1: { id: "A1", affectedIds: ["R3"], invalidatedProof: { R3: { evidenceRefs: ["E-SUP"] } }, supersededBy: null },
    },
  };
  for (const item of Object.values(state.evidence)) {
    for (const requirementId of item.requirementIds) state.requirements[requirementId].evidenceRefs.push(item.id);
  }
  return state;
}

function impactReport() {
  return canonicalReport("tugboat.proof-impact.v1", {
    status: "ready",
    mission: { id: "freshness-test", revision: 8 },
    changes: [{ path: "scripts/core.mjs", status: "modified" }],
    edges: [],
    impact: {
      allRequirementIds: ["R1"],
      directRequirementIds: ["R1"],
      invalidatedEvidenceIds: ["E-IMPACT"],
      requiredTests: [],
      riskTags: [],
      transitiveRequirementIds: [],
    },
    gaps: [],
    unmappedChanges: [],
  });
}

function freshnessPolicy() {
  return {
    expiringWithinHours: 1,
    expectedDeploymentSha: "b".repeat(40),
    ttlHoursByKind: { command: 2, deployment: 48, operator: 24 },
    volatilityHoursByRequirement: { R2: 0.5 },
  };
}

test("freshness classifies age boundaries, volatility, impact, deployment, supersession, and unknown policy literally", () => {
  const state = freshnessState();
  const before = JSON.stringify(state);
  const report = compileEvidenceFreshness(state, freshnessPolicy(), OBSERVED_AT, impactReport());
  const byId = Object.fromEntries(report.evidence.map((item) => [item.id, item]));

  assert.equal(report.status, "insufficient_evidence");
  assert.equal(byId["E-FRESH"].freshness, "fresh");
  assert.equal(byId["E-EXP"].freshness, "expiring");
  assert.equal(byId["E-EXP"].expiresAt, "2026-10-28T18:30:00.000Z");
  assert.equal(byId["E-BOUND"].freshness, "stale");
  assert.ok(byId["E-BOUND"].reasons.some(({ code }) => code === "age_exceeded"));
  assert.ok(byId["E-VOL"].reasons.some(({ code }) => code === "age_exceeded" && /volatility/i.test(code + byId["E-VOL"].reasons.map(({ message }) => message).join(" "))));
  assert.ok(byId["E-IMPACT"].reasons.some(({ code }) => code === "impact_invalidated"));
  assert.ok(byId["E-DEPLOY"].reasons.some(({ code }) => code === "deployment_sha_mismatch"));
  assert.ok(byId["E-SUP"].reasons.some(({ code }) => code === "superseded_requirement"));
  assert.equal(byId["E-UNKNOWN"].freshness, "unknown_policy");
  assert.ok(byId["E-UNKNOWN"].reasons.some(({ code }) => code === "policy_missing"));
  assert.deepEqual(report.summary, { expiring: 1, fresh: 1, stale: 5, unknownPolicy: 1 });
  assert.match(report.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(state), before);
});

test("freshness is reproducible at exact boundaries and stale evidence blocks when policy is complete", () => {
  const state = freshnessState();
  delete state.evidence["E-UNKNOWN"];
  state.requirements.R1.evidenceRefs = state.requirements.R1.evidenceRefs.filter((id) => id !== "E-UNKNOWN");
  const report = compileEvidenceFreshness(state, freshnessPolicy(), OBSERVED_AT, impactReport());

  assert.equal(report.status, "blocked");
  assert.equal(report.observedAt, OBSERVED_AT);
  assert.deepEqual(report, compileEvidenceFreshness(state, freshnessPolicy(), OBSERVED_AT, impactReport()));
});

test("freshness returns ready for live evidence and rejects unknown policy fields, bad timestamps, and forged impact digests", () => {
  const state = freshnessState();
  state.evidence = { "E-FRESH": state.evidence["E-FRESH"] };
  state.requirements.R1.evidenceRefs = ["E-FRESH"];
  state.requirements.R2.evidenceRefs = [];
  state.requirements.R3.evidenceRefs = [];
  state.requirements.R3.amendedBy = [];
  state.amendments = {};
  const policy = freshnessPolicy();
  const ready = compileEvidenceFreshness(state, policy, OBSERVED_AT);
  assert.equal(ready.status, "ready");
  assert.equal(ready.evidence[0].freshness, "fresh");

  assert.throws(() => compileEvidenceFreshness(state, { ...policy, surprise: true }, OBSERVED_AT), /unknown freshness policy field surprise/i);
  assert.throws(() => compileEvidenceFreshness(state, policy, "2026-10-28"), /ISO-8601 UTC timestamp/i);
  const forged = impactReport();
  forged.impact.invalidatedEvidenceIds.push("E-FRESH");
  assert.throws(() => compileEvidenceFreshness(state, policy, OBSERVED_AT, forged), /impact report digest/i);
  const anonymous = canonicalReport("tugboat.proof-impact.v1", {
    status: "ready", changes: [], edges: [], impact: { allRequirementIds: [], directRequirementIds: [], invalidatedEvidenceIds: [], requiredTests: [], riskTags: [], transitiveRequirementIds: [] }, gaps: [], unmappedChanges: [],
  });
  assert.throws(() => compileEvidenceFreshness(state, policy, OBSERVED_AT, anonymous), /impact report mission id is required/i);
  assert.throws(() => compileEvidenceFreshness(state, { ...policy, volatilityHoursByRequirement: { R9: 1 } }, OBSERVED_AT), /unknown requirement R9/i);
});

function releaseState() {
  return {
    protocolVersion: "2.0",
    status: "ACTIVE",
    revision: 12,
    activeSliceId: "S2",
    metadata: {
      id: "release-test",
      baselineGitSha: "a".repeat(40),
      deployPath: "GitHub Actions",
      rollbackAnchor: "release-previous",
    },
    slices: {
      S1: { id: "S1", requirementIds: ["R1"], dependencies: [], status: "COMPLETE" },
      S2: { id: "S2", requirementIds: ["R2"], dependencies: ["S1"], status: "ACTIVE" },
    },
    requirements: {
      R1: { id: "R1", material: true, requirement: "Runtime", acceptance: "Runtime returns 200.", proofTarget: "local", status: "PROVEN(local)", evidenceRefs: ["EC", "EO"] },
      R2: { id: "R2", material: true, requirement: "Production release", acceptance: "Production returns 200 and rollback restores the prior version.", proofTarget: "production", status: "PROVEN(production)", evidenceRefs: ["EC", "EO", "ED"] },
    },
    evidence: {
      EC: { id: "EC", kind: "command", requirementIds: ["R1", "R2"], verification: { status: "passed" } },
      EO: { id: "EO", kind: "operator", requirementIds: ["R1", "R2"], verification: { status: "passed" } },
      ED: { id: "ED", kind: "deployment", requirementIds: ["R2"], verification: { status: "passed" }, deployment: { deployedSha: "b".repeat(40) } },
    },
  };
}

const BUILT_IN_FAILURES = [
  "dependency_unavailable",
  "deployment_failed",
  "operator_denied",
  "rollback_anchor_missing",
  "stale_proof",
  "target_drift",
];

function readySimulationProfile() {
  return {
    controls: Object.fromEntries(BUILT_IN_FAILURES.map((id) => [id, {
      containment: `Contain ${id} before continuing the release.`,
      detectionEvidenceKinds: ["command"],
      recoveryGates: [`recover-${id}`],
      rollbackAction: `Restore the recorded anchor for ${id}.`,
    }])),
    failureModes: [{
      id: "queue_poisoned",
      trigger: "The work queue accepts messages but no worker can acknowledge them.",
      affectedRequirementIds: ["R2"],
      detectionEvidenceKinds: ["operator"],
      containment: "Pause producers and retain the dead-letter payload digest.",
      recoveryGates: ["queue-drain-proof"],
      rollbackAction: "Restore the prior worker release.",
    }],
  };
}

test("release simulation compiles all built-ins and blocks undetected or unrecoverable failure journeys", () => {
  const state = releaseState();
  const before = JSON.stringify(state);
  const blocked = compileReleaseSimulation(state);

  assert.equal(blocked.status, "blocked");
  assert.deepEqual(blocked.journeys.map(({ id }) => id), BUILT_IN_FAILURES);
  assert.ok(blocked.journeys.every(({ verdict }) => verdict === "blocked"));
  assert.ok(blocked.journeys.every(({ gaps }) => gaps.includes("detection_missing") && gaps.includes("recovery_missing")));
  assert.equal(JSON.stringify(state), before);

  const ready = compileReleaseSimulation(state, readySimulationProfile());
  assert.equal(ready.status, "ready");
  assert.deepEqual(ready.journeys.map(({ id }) => id), [...BUILT_IN_FAILURES, "queue_poisoned"].sort());
  assert.ok(ready.journeys.every(({ verdict }) => verdict === "ready"));
  assert.ok(ready.journeys.every(({ detection, recovery }) => detection.covered && recovery.covered));
  assert.match(ready.digest, /^sha256:[0-9a-f]{64}$/);
});

test("release simulation validates explicit failures, references, reports, and recovery controls", () => {
  const state = releaseState();
  const profile = readySimulationProfile();
  assert.throws(() => compileReleaseSimulation(state, { ...profile, surprise: true }), /unknown release simulation profile field surprise/i);
  assert.throws(() => compileReleaseSimulation(state, { controls: {}, failureModes: [{ ...profile.failureModes[0], affectedRequirementIds: ["R9"] }] }), /unknown requirement R9/i);
  assert.throws(() => compileReleaseSimulation(state, { controls: { stale_proof: { surprise: true } } }), /unknown failure control field surprise/i);
  assert.throws(() => compileReleaseSimulation(state, { controls: {}, failureModes: [{ ...profile.failureModes[0], id: "stale_proof" }] }), /duplicates built-in failure stale_proof/i);

  const forgedImpact = impactReport();
  forgedImpact.impact.allRequirementIds.push("R2");
  assert.throws(() => compileReleaseSimulation(state, profile, forgedImpact), /impact report digest/i);
  const forgedAdversarial = canonicalReport("tugboat.adversarial-acceptance.v1", {
    status: "ready", mission: { id: "release-test" }, cases: [], oracleGaps: [],
  });
  forgedAdversarial.cases.push({ class: "empty" });
  assert.throws(() => compileReleaseSimulation(state, profile, undefined, forgedAdversarial), /adversarial report digest/i);

  const anonymousImpact = canonicalReport("tugboat.proof-impact.v1", {
    status: "ready", changes: [], edges: [], impact: { allRequirementIds: [], directRequirementIds: [], invalidatedEvidenceIds: [], requiredTests: [], riskTags: [], transitiveRequirementIds: [] }, gaps: [], unmappedChanges: [],
  });
  assert.throws(() => compileReleaseSimulation(state, profile, anonymousImpact), /impact report mission id is required/i);
});

test("release simulation treats unresolved adversarial oracles as insufficient evidence", () => {
  const adversarial = canonicalReport("tugboat.adversarial-acceptance.v1", {
    status: "insufficient_evidence",
    mission: { id: "release-test" },
    cases: [],
    oracleGaps: [{ requirementId: "R2", class: "rollback" }],
  });
  const report = compileReleaseSimulation(releaseState(), readySimulationProfile(), undefined, adversarial);
  assert.equal(report.status, "insufficient_evidence");
  assert.equal(report.adversarialCoverage.oracleGapCount, 1);
  assert.ok(report.journeys.every(({ verdict }) => verdict === "ready"));
});

function portfolioImpact(requirementIds = ["R1", "R2"], riskTags = ["runtime"]) {
  return canonicalReport("tugboat.proof-impact.v1", {
    status: "ready",
    mission: { id: "release-test", revision: 12 },
    changes: [{ path: "scripts/core.mjs", status: "modified" }],
    edges: [],
    impact: {
      allRequirementIds: requirementIds,
      directRequirementIds: requirementIds,
      invalidatedEvidenceIds: [],
      requiredTests: [],
      riskTags,
      transitiveRequirementIds: [],
    },
    gaps: [],
    unmappedChanges: [],
  });
}

function gate(id, cost, requirementIds, proofKinds, riskTags = []) {
  return { id, cost, requirementIds, proofKinds, riskTags };
}

test("proof portfolio finds the exact lowest declared-cost complete gate set without calling it proof", () => {
  const report = compileProofPortfolio(releaseState(), portfolioImpact(), {
    gates: [
      gate("r1-proof", 2, ["R1"], ["command", "operator"], ["runtime"]),
      gate("r2-proof", 2, ["R2"], ["command", "deployment", "operator"]),
      gate("broad-proof", 5, ["R1", "R2"], ["command", "deployment", "operator"], ["runtime"]),
      gate("noise", 1, ["R1"], ["command"]),
    ],
  });

  assert.equal(report.status, "ready");
  assert.equal(report.planStatus, "not_executed");
  assert.deepEqual(report.selectedGates.map(({ id }) => id), ["r1-proof", "r2-proof"]);
  assert.equal(report.totalCost, 4);
  assert.deepEqual(report.uncoveredObligations, []);
  assert.ok(report.obligations.includes("proof:R2:deployment"));
  assert.ok(report.obligations.includes("risk:runtime"));
  assert.doesNotMatch(JSON.stringify(report), /passed|proven/);
});

test("proof portfolio uses fewer gates then canonical IDs to break equal-cost ties", () => {
  const impact = portfolioImpact(["R1"], []);
  const state = releaseState();
  state.requirements.R1.proofTarget = "local";
  const report = compileProofPortfolio(state, impact, {
    gates: [
      gate("z-broad", 4, ["R1"], ["command", "operator"]),
      gate("a-broad", 4, ["R1"], ["command", "operator"]),
      gate("command-only", 2, ["R1"], ["command"]),
      gate("operator-only", 2, ["R1"], ["operator"]),
    ],
  });
  assert.deepEqual(report.selectedGates.map(({ id }) => id), ["a-broad"]);
});

test("proof portfolio compares fixed-point declared costs rather than binary floating point", () => {
  const impact = portfolioImpact(["R1", "R2"], []);
  const state = releaseState();
  state.requirements.R1.proofTarget = "local";
  state.requirements.R2.proofTarget = "local";
  const report = compileProofPortfolio(state, impact, {
    gates: [
      gate("a-r1", 0.1, ["R1"], ["command", "operator"]),
      gate("a-r2", 0.2, ["R2"], ["command", "operator"]),
      gate("b-command", 0.15, ["R1", "R2"], ["command"]),
      gate("b-operator", 0.15, ["R1", "R2"], ["operator"]),
    ],
  });
  assert.deepEqual(report.selectedGates.map(({ id }) => id), ["a-r1", "a-r2"]);
  assert.equal(report.totalCost, 0.3);
});

test("proof portfolio blocks uncovered obligations and rejects malformed or unbounded catalogs", () => {
  const state = releaseState();
  const impact = portfolioImpact(["R2"], ["security"]);
  const blocked = compileProofPortfolio(state, impact, {
    gates: [gate("partial", 1, ["R2"], ["command", "operator"])],
  });
  assert.equal(blocked.status, "blocked");
  assert.deepEqual(blocked.selectedGates, []);
  assert.ok(blocked.uncoveredObligations.includes("proof:R2:deployment"));
  assert.ok(blocked.uncoveredObligations.includes("risk:security"));

  assert.throws(() => compileProofPortfolio(state, impact, { gates: [gate("A", 1, ["R2"], ["command"]), gate("A", 2, ["R2"], ["operator"])] }), /duplicate proof gates id A/i);
  assert.throws(() => compileProofPortfolio(state, impact, { gates: Array.from({ length: 21 }, (_, index) => gate(`G${index}`, 1, ["R2"], ["command"])) }), /at most 20/i);
  assert.throws(() => compileProofPortfolio(state, impact, { gates: [gate("bad", 0, ["R2"], ["command"])] }), /cost must be a positive number/i);
  assert.throws(() => compileProofPortfolio(state, impact, { gates: [gate("bad", 1, ["R9"], ["command"])] }), /unknown requirement R9/i);
});
