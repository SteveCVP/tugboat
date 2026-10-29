import assert from "node:assert/strict";
import test from "node:test";

import { compileDifferentialReview } from "./lib/differential-review.mjs";

const review = (reviewer, findings, inputDigest = `sha256:${"a".repeat(64)}`) => ({
  schemaVersion: "tugboat.agent-review.v1", reviewer, inputDigest, findings,
});
const finding = (id, severity, claim, evidenceDigests = [`sha256:${"b".repeat(64)}`], recommendation = "fix", disposition = "open") => ({ id, severity, claim, subjects: ["src/a.mjs"], evidenceDigests, recommendation, disposition });

test("differential review exposes consensus, unique findings, and conflicts without voting", () => {
  const report = compileDifferentialReview([
    review("agent-a", [finding("A1", "high", "Cache accepts corrupt entry"), finding("A2", "low", "Name is unclear")]),
    review("agent-b", [finding("B1", "medium", "Cache accepts corrupt entry", [`sha256:${"c".repeat(64)}`], "reject cache")]),
  ]);
  assert.equal(report.status, "blocked");
  assert.equal(report.consensus.length, 1);
  assert.equal(report.unique.length, 1);
  assert.equal(report.conflicts.some((item) => item.kind === "severity"), true);
  assert.equal(report.policy, "Reviewer count is not confidence and consensus is not proof.");
});

test("differential review flags input mismatch and unsupported agreement deterministically", () => {
  const unsupported = finding("A", "medium", "Unknown issue", []);
  const report = compileDifferentialReview([review("b", [unsupported]), review("a", [{ ...unsupported, id: "B" }], `sha256:${"d".repeat(64)}`)]);
  assert.equal(report.status, "insufficient_evidence");
  assert.equal(report.conflicts.some((item) => item.kind === "input"), true);
  assert.equal(report.evidenceGaps.length, 1);
});

