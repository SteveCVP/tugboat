import assert from "node:assert/strict";
import test from "node:test";

import { compileAdversarialAcceptance, compileAntiSlopReport } from "./lib/quality-intelligence.mjs";

function lintState() {
  return {
    protocolVersion: "2.0",
    status: "ACTIVE",
    revision: 2,
    activeSliceId: "S1",
    metadata: { id: "slop-test" },
    slices: {
      S1: { id: "S1", requirementIds: ["R1", "R2", "R3"], dependencies: [], status: "ACTIVE" },
    },
    requirements: {
      R1: { id: "R1", requirement: "Build a scalable world-class platform", source: "user", material: true, acceptance: "Make it intuitive and robust.", proofTarget: "local", status: "PENDING", evidenceRefs: [] },
      R2: { id: "R2", requirement: "Add audit history later", source: "follow-up", material: true, acceptance: "TBD in phase 2", proofTarget: "local", status: "PENDING", evidenceRefs: [] },
      R3: { id: "R3", requirement: "Ship verification", source: "spec", material: true, acceptance: "The CLI exits zero and emits a sha256 digest.", proofTarget: "pending", status: "PENDING", evidenceRefs: [] },
      R4: { id: "R4", requirement: "Preserve operator workflow", source: "spec", material: true, acceptance: "The existing command returns exit code 0 and preserves every mission byte.", proofTarget: "local", status: "PENDING", evidenceRefs: [] },
    },
    evidence: {
      EPASS: { id: "EPASS", kind: "command", requirementIds: ["R4"], verification: { status: "passed" } },
      EFAIL: { id: "EFAIL", kind: "command", requirementIds: ["R1"], verification: { status: "failed" } },
    },
  };
}

function lintProfile() {
  return {
    architecture: [
      { id: "ornament", capability: "event-bus", requirementIds: [], consumers: [] },
      { id: "queue-a", capability: "job-queue", requirementIds: ["R1"], consumers: ["worker"] },
      { id: "queue-b", capability: "job-queue", requirementIds: ["R1"], consumers: ["worker"] },
    ],
    gates: [
      { id: "green-ci", requirementIds: [], proofKinds: [] },
    ],
    claims: [
      { id: "done", text: "The platform is certainly complete.", confidence: "certain", requirementIds: ["R1"], evidenceIds: ["EFAIL"] },
    ],
  };
}

test("anti-slop linter names every deterministic contract defect with stable rule IDs", () => {
  const state = lintState();
  const before = JSON.stringify(state);
  const report = compileAntiSlopReport(state, lintProfile());
  const ruleIds = new Set(report.findings.map(({ ruleId }) => ruleId));

  assert.equal(report.status, "blocked");
  assert.deepEqual([...ruleIds].sort(), [
    "acceptance.vague_oracle",
    "architecture.duplicate_abstraction",
    "architecture.ornamental",
    "claim.unsupported_confidence",
    "gate.fake",
    "proof.placeholder",
    "scope.follow_up_laundering",
    "scope.unsliced_material",
  ]);
  for (const finding of report.findings) {
    assert.match(finding.subject, /\S/);
    assert.match(finding.remediation, /\S/);
    assert.ok(["error", "warning"].includes(finding.severity));
  }
  assert.ok(report.findings.some((item) => item.ruleId === "scope.unsliced_material" && item.requirementIds.includes("R4")));
  assert.ok(report.findings.some((item) => item.ruleId === "claim.unsupported_confidence" && item.subject === "claim:done"));
  assert.match(report.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(state), before);
});

test("concrete ledgers and necessary architecture pass without generic style findings", () => {
  const state = lintState();
  state.requirements = {
    R1: { id: "R1", requirement: "Return a deterministic impact report", source: "spec", material: true, acceptance: "For an unmapped path the CLI exits 2 and emits unmapped_change with that path.", proofTarget: "local", status: "PENDING", evidenceRefs: [] },
  };
  state.slices.S1.requirementIds = ["R1"];
  state.evidence = {};
  const report = compileAntiSlopReport(state, {
    architecture: [{ id: "compiler", capability: "impact-compiler", requirementIds: ["R1"], consumers: ["cli"] }],
    gates: [{ id: "impact-test", requirementIds: ["R1"], proofKinds: ["command", "operator"] }],
    claims: [],
  });

  assert.equal(report.status, "ready");
  assert.deepEqual(report.findings, []);
});

test("anti-slop rejects vague can-language, incomplete proof gates, and partial claim evidence", () => {
  const state = lintState();
  state.requirements = {
    R1: { id: "R1", requirement: "Ship an interface", source: "spec", material: true, acceptance: "Users can have an intuitive and scalable workflow.", proofTarget: "production", status: "PENDING", evidenceRefs: [] },
    R4: state.requirements.R4,
  };
  state.slices.S1.requirementIds = ["R1", "R4"];
  const report = compileAntiSlopReport(state, {
    gates: [{ id: "command-only", requirementIds: ["R1"], proofKinds: ["command"] }],
    claims: [{ id: "partial", text: "Both workflows are proven.", confidence: "certain", requirementIds: ["R1", "R4"], evidenceIds: ["EPASS"] }],
  });
  assert.equal(report.status, "blocked");
  assert.ok(report.findings.some(({ ruleId, subject }) => ruleId === "acceptance.vague_oracle" && subject === "requirement:R1"));
  assert.ok(report.findings.some(({ ruleId, subject }) => ruleId === "gate.fake" && subject === "gate:command-only"));
  assert.ok(report.findings.some(({ ruleId, subject }) => ruleId === "claim.unsupported_confidence" && subject === "claim:partial"));
});

test("anti-slop profile rejects unknown, duplicate, secret-bearing, and dangling references", () => {
  const state = lintState();
  assert.throws(() => compileAntiSlopReport(state, { surprise: [] }), /unknown anti-slop profile field surprise/i);
  assert.throws(() => compileAntiSlopReport(state, { architecture: [{ id: "A", capability: "one", requirementIds: [], consumers: [] }, { id: "A", capability: "two", requirementIds: [], consumers: [] }] }), /duplicate architecture components id A/i);
  assert.throws(() => compileAntiSlopReport(state, { gates: [{ id: "G", requirementIds: ["R9"], proofKinds: ["command"] }] }), /unknown requirement R9/i);
  assert.throws(() => compileAntiSlopReport(state, { claims: [{ id: "C", text: ["github", "_pat_", "abcdefghijklmnopqrstuvwxyz123456"].join(""), confidence: "certain", requirementIds: ["R1"], evidenceIds: [] }] }), /secret material/i);
});

function adversarialState() {
  return {
    protocolVersion: "2.0",
    status: "ACTIVE",
    revision: 3,
    activeSliceId: "S1",
    metadata: { id: "adversary-test" },
    slices: { S1: { id: "S1", requirementIds: ["R1", "R2", "R3"], dependencies: [], status: "ACTIVE" } },
    requirements: {
      R1: {
        id: "R1",
        material: true,
        requirement: "Process record updates safely",
        acceptance: "An empty or malformed update is rejected with 400; partial and stale records are labeled; unauthorized users get 403; concurrent updates get 409; duplicate events do not create a second record; dependency failure returns 503; rollback restores the prior version.",
        proofTarget: "local",
        status: "PENDING",
        evidenceRefs: [],
      },
      R2: { id: "R2", material: true, requirement: "Process ordered events", acceptance: "Events are processed correctly.", proofTarget: "local", status: "PENDING", evidenceRefs: [] },
      R3: { id: "R3", material: true, requirement: "Make the experience world class", acceptance: "It should work well.", proofTarget: "local", status: "PENDING", evidenceRefs: [] },
    },
    evidence: {},
  };
}

test("adversarial compiler grounds negative journeys in literal acceptance or explicit contracts", () => {
  const state = adversarialState();
  const before = JSON.stringify(state);
  const report = compileAdversarialAcceptance(state, {
    contracts: {
      R2: [{
        class: "out_of_order",
        mutation: "Deliver sequence 4 after sequence 5.",
        setup: "Persist sequence 5 as the latest accepted event.",
        oracle: "Earlier sequence numbers are ignored and the stored version remains 5.",
        evidenceKind: "command",
      }],
    },
  });
  const r1Classes = report.cases.filter(({ requirementId }) => requirementId === "R1").map(({ class: caseClass }) => caseClass);

  assert.equal(report.status, "insufficient_evidence");
  assert.deepEqual(r1Classes, ["concurrent", "dependency_error", "duplicate", "empty", "malformed", "partial", "rollback", "stale", "unauthorized"]);
  assert.deepEqual(report.cases.find((item) => item.requirementId === "R2"), {
    class: "out_of_order",
    evidenceKind: "command",
    mutation: "Deliver sequence 4 after sequence 5.",
    oracle: "Earlier sequence numbers are ignored and the stored version remains 5.",
    requirementId: "R2",
    setup: "Persist sequence 5 as the latest accepted event.",
    source: "profile",
  });
  assert.deepEqual(report.oracleGaps, [{
    code: "oracle_missing",
    requirementId: "R3",
    message: "No literal negative-state oracle is grounded for R3.",
  }]);
  assert.ok(report.cases.every((item) => item.mutation && item.setup && item.oracle && item.evidenceKind));
  assert.equal(JSON.stringify(state), before);
});

test("explicit contracts override inferred duplicates and reports are canonical across input order", () => {
  const state = adversarialState();
  delete state.requirements.R3;
  state.slices.S1.requirementIds = ["R1", "R2"];
  const contract = {
    class: "duplicate",
    mutation: "Replay the same event identifier twice.",
    setup: "Persist the event identifier after the first delivery.",
    oracle: "The second delivery returns duplicate and record count remains one.",
    evidenceKind: "operator",
  };
  const left = compileAdversarialAcceptance(state, { contracts: { R2: [{ ...contract, class: "out_of_order" }], R1: [contract] } });
  const rightState = { ...state, requirements: { R2: state.requirements.R2, R1: state.requirements.R1 } };
  const right = compileAdversarialAcceptance(rightState, { contracts: { R1: [contract], R2: [{ ...contract, class: "out_of_order" }] } });

  assert.equal(left.status, "ready");
  assert.deepEqual(left, right);
  const duplicate = left.cases.filter((item) => item.requirementId === "R1" && item.class === "duplicate");
  assert.equal(duplicate.length, 1);
  assert.equal(duplicate[0].source, "profile");
  assert.equal(duplicate[0].evidenceKind, "operator");
});

test("adversarial profiles fail closed on unknown classes, fields, requirements, and invented oracles", () => {
  const state = adversarialState();
  const valid = { class: "empty", mutation: "Empty input", setup: "Valid actor", oracle: "Returns 400", evidenceKind: "command" };
  assert.throws(() => compileAdversarialAcceptance(state, { surprise: true }), /unknown adversarial profile field surprise/i);
  assert.throws(() => compileAdversarialAcceptance(state, { contracts: { R9: [valid] } }), /unknown requirement R9/i);
  assert.throws(() => compileAdversarialAcceptance(state, { contracts: { R2: [{ ...valid, class: "quantum" }] } }), /unknown adversarial class quantum/i);
  assert.throws(() => compileAdversarialAcceptance(state, { contracts: { R2: [{ ...valid, surprise: true }] } }), /unknown adversarial contract field surprise/i);
  assert.throws(() => compileAdversarialAcceptance(state, { contracts: { R2: [{ ...valid, oracle: "works" }] } }), /oracle must state an observable result/i);
});
