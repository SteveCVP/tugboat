import assert from "node:assert/strict";
import test from "node:test";

import { compileDecisionMemory } from "./lib/decision-memory.mjs";

const OBSERVED_AT = "2026-10-28T18:00:00.000Z";
const DIGEST = `sha256:${"a".repeat(64)}`;

function record(id, overrides = {}) {
  return {
    id,
    decidedAt: "2026-10-18T18:00:00.000Z",
    contextTags: ["aws", "internal-tool", "postgres"],
    constraints: { dataResidency: "us", teamSize: 4 },
    decision: "Use Aurora PostgreSQL with the Data API.",
    rejectedAlternatives: [{ decision: "Self-managed PostgreSQL", reason: "Operational burden exceeds the team constraint." }],
    assumptions: [{ id: "traffic", text: "Traffic remains below the declared serverless envelope.", halfLifeDays: 30 }],
    evidence: { kind: "production", digest: DIGEST },
    outcome: { status: "success", observedAt: "2026-10-20T18:00:00.000Z" },
    supersedes: [],
    ...overrides,
  };
}

function context(overrides = {}) {
  return {
    tags: ["aws", "internal-tool", "postgres"],
    constraints: { dataResidency: "us", teamSize: 4 },
    minAssumptionRetention: 0.5,
    ...overrides,
  };
}

test("decision memory reuses only exact production-evidenced decisions with live assumptions", () => {
  const records = [
    record("reusable"),
    record("local-only", { decision: "Use RDS PostgreSQL.", evidence: { kind: "local", digest: DIGEST } }),
    record("wrong-context", { decision: "Use DynamoDB.", contextTags: ["aws", "high-scale", "key-value"] }),
  ];
  const before = JSON.stringify(records);
  const report = compileDecisionMemory(records, context(), OBSERVED_AT);
  const byId = Object.fromEntries(report.matches.map((item) => [item.id, item]));

  assert.equal(report.status, "ready");
  assert.equal(report.recommendation.recordId, "reusable");
  assert.equal(byId.reusable.disposition, "reusable");
  assert.deepEqual(byId.reusable.reasons, []);
  assert.ok(byId.reusable.assumptions[0].retention > 0.79 && byId.reusable.assumptions[0].retention < 0.80);
  assert.equal(byId["local-only"].disposition, "conditional");
  assert.ok(byId["local-only"].reasons.includes("production_evidence_missing"));
  assert.equal(byId["wrong-context"].disposition, "conditional");
  assert.ok(byId["wrong-context"].reasons.includes("context_mismatch"));
  assert.deepEqual(byId.reusable.rejectedAlternatives, records[0].rejectedAlternatives);
  assert.match(report.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(records), before);
});

test("assumption retention is deterministic at the half-life boundary", () => {
  const boundary = record("boundary", {
    decidedAt: "2026-09-28T18:00:00.000Z",
    assumptions: [{ id: "traffic", text: "Traffic shape remains stable.", halfLifeDays: 30 }],
  });
  const live = compileDecisionMemory([boundary], context({ minAssumptionRetention: 0.5 }), OBSERVED_AT);
  assert.equal(live.matches[0].assumptions[0].retention, 0.5);
  assert.equal(live.matches[0].disposition, "reusable");

  const stale = compileDecisionMemory([boundary], context({ minAssumptionRetention: 0.500001 }), OBSERVED_AT);
  assert.equal(stale.status, "insufficient_evidence");
  assert.equal(stale.matches[0].disposition, "conditional");
  assert.ok(stale.matches[0].reasons.includes("assumption_stale"));
});

test("supersession and contradictory production outcomes prevent stale decision reuse", () => {
  const superseded = record("old");
  const replacement = record("new", { decision: "Use Aurora PostgreSQL with provisioned readers.", supersedes: ["old"] });
  const success = record("same-success", { decision: "Use a shared event bus." });
  const failure = record("same-failure", { decision: "Use a shared event bus.", outcome: { status: "failure", observedAt: "2026-10-22T18:00:00.000Z" } });
  const report = compileDecisionMemory([failure, superseded, replacement, success], context(), OBSERVED_AT);
  const byId = Object.fromEntries(report.matches.map((item) => [item.id, item]));

  assert.equal(byId.old.disposition, "rejected");
  assert.ok(byId.old.reasons.includes("superseded"));
  assert.equal(byId.new.disposition, "reusable");
  assert.equal(byId["same-success"].disposition, "rejected");
  assert.ok(byId["same-success"].reasons.includes("contradictory_outcome"));
  assert.equal(byId["same-failure"].disposition, "rejected");
  assert.ok(byId["same-failure"].reasons.includes("outcome_not_success"));
});

test("a successful replacement is not poisoned by the superseded record's old failure", () => {
  const failed = record("failed", { outcome: { status: "failure", observedAt: "2026-10-20T18:00:00.000Z" } });
  const replacement = record("replacement", { supersedes: ["failed"] });
  const report = compileDecisionMemory([failed, replacement], context(), OBSERVED_AT);
  const byId = Object.fromEntries(report.matches.map((item) => [item.id, item]));
  assert.equal(byId.failed.disposition, "rejected");
  assert.equal(byId.replacement.disposition, "reusable");
  assert.equal(report.recommendation.recordId, "replacement");
});

test("decision memory is canonical across record, tag, constraint, and alternative order", () => {
  const first = record("A");
  const second = record("B", { decision: "Use RDS PostgreSQL." });
  const left = compileDecisionMemory([second, first], context(), OBSERVED_AT);
  const right = compileDecisionMemory([
    { ...first, contextTags: [...first.contextTags].reverse(), constraints: { teamSize: 4, dataResidency: "us" }, rejectedAlternatives: [...first.rejectedAlternatives].reverse() },
    second,
  ], { ...context(), tags: [...context().tags].reverse(), constraints: { teamSize: 4, dataResidency: "us" } }, OBSERVED_AT);
  assert.deepEqual(left, right);
});

test("decision records reject unknown fields, paths, secrets, bad references, and invalid time or retention", () => {
  assert.throws(() => compileDecisionMemory([{ ...record("A"), surprise: true }], context(), OBSERVED_AT), /unknown decision record field surprise/i);
  assert.throws(() => compileDecisionMemory([record("A"), record("A")], context(), OBSERVED_AT), /duplicate decision records id A/i);
  assert.throws(() => compileDecisionMemory([record("A", { supersedes: ["missing"] })], context(), OBSERVED_AT), /supersedes unknown record missing/i);
  assert.throws(() => compileDecisionMemory([record("A", { missionPath: "/private/mission" })], context(), OBSERVED_AT), /unknown decision record field missionPath|absolute path/i);
  assert.throws(() => compileDecisionMemory([record("A", { decision: ["github", "_pat_", "abcdefghijklmnopqrstuvwxyz123456"].join("") })], context(), OBSERVED_AT), /secret material/i);
  assert.throws(() => compileDecisionMemory([record("A")], { ...context(), surprise: true }, OBSERVED_AT), /unknown decision context field surprise/i);
  assert.throws(() => compileDecisionMemory([record("A")], context({ minAssumptionRetention: 1.1 }), OBSERVED_AT), /from 0 to 1/i);
  assert.throws(() => compileDecisionMemory([record("A")], context(), "2026-10-28"), /ISO-8601 UTC timestamp/i);
});
