import assert from "node:assert/strict";
import test from "node:test";

import { compileTrustGraph } from "./lib/trust-intelligence.mjs";

const PROOF = `sha256:${"a".repeat(64)}`;

function graphFixture({ sanitizer } = {}) {
  return {
    nodes: [
      { id: "source", type: "artifact", classification: "confidential", authorities: ["read"] },
      { id: "service", type: "service", classification: "internal", authorities: ["read"] },
      { id: "prod", type: "environment", classification: "internal", authorities: ["read"] },
    ],
    edges: [
      { id: "source-service", from: "source", to: "service", ...(sanitizer ? { sanitizer } : {}) },
      { id: "service-prod", from: "service", to: "prod" },
    ],
  };
}

function policyFixture() {
  return {
    classifications: ["public", "internal", "confidential", "restricted"],
    sinks: [
      { nodeId: "prod", maxClassification: "internal", allowedAuthorities: ["read"] },
    ],
    approvedSanitizers: [
      { id: "redact-confidential", fromClassification: "confidential", toClassification: "internal", proofDigest: PROOF },
    ],
  };
}

test("trust graph propagates sensitivity and returns an exact witness path for an illegal sink", () => {
  const graph = graphFixture();
  const before = JSON.stringify(graph);
  const report = compileTrustGraph(graph, policyFixture());

  assert.equal(report.status, "blocked");
  assert.deepEqual(report.violations, [{
    code: "sensitivity_overflow",
    edgeId: null,
    message: "prod receives confidential data above its internal ceiling.",
    nodeId: "prod",
    witnessPath: ["source", "service", "prod"],
  }]);
  assert.equal(report.nodes.find(({ id }) => id === "prod").effectiveClassification, "confidential");
  assert.equal(JSON.stringify(graph), before);
  assert.match(report.digest, /^sha256:[0-9a-f]{64}$/);
});

test("only a policy-approved sanitizer with the exact proof digest may lower taint", () => {
  const approved = compileTrustGraph(graphFixture({ sanitizer: { id: "redact-confidential", proofDigest: PROOF } }), policyFixture());
  assert.equal(approved.status, "ready");
  assert.deepEqual(approved.violations, []);
  assert.equal(approved.nodes.find(({ id }) => id === "prod").effectiveClassification, "internal");

  const unproved = compileTrustGraph(graphFixture({ sanitizer: { id: "redact-confidential", proofDigest: `sha256:${"b".repeat(64)}` } }), policyFixture());
  assert.equal(unproved.status, "blocked");
  assert.deepEqual(unproved.violations.map(({ code }) => code), ["sensitivity_overflow", "unproved_sanitizer"]);
  assert.ok(unproved.violations.find(({ code }) => code === "unproved_sanitizer").witnessPath.includes("source-service"));

  const overClassified = graphFixture({ sanitizer: { id: "redact-confidential", proofDigest: PROOF } });
  overClassified.nodes.find(({ id }) => id === "source").classification = "restricted";
  const unsafe = compileTrustGraph(overClassified, policyFixture());
  assert.equal(unsafe.status, "blocked");
  assert.ok(unsafe.violations.some(({ code }) => code === "sensitivity_overflow"));
  assert.equal(unsafe.nodes.find(({ id }) => id === "prod").effectiveClassification, "restricted");
});

test("trust graph blocks authority overflow and directed flow cycles with witness paths", () => {
  const graph = {
    nodes: [
      { id: "worker", type: "worker", classification: "internal", authorities: ["read"] },
      { id: "prod", type: "environment", classification: "internal", authorities: ["deploy"] },
    ],
    edges: [
      { id: "worker-prod", from: "worker", to: "prod" },
      { id: "prod-worker", from: "prod", to: "worker" },
    ],
  };
  const policy = {
    classifications: ["public", "internal", "confidential"],
    sinks: [{ nodeId: "prod", maxClassification: "internal", allowedAuthorities: ["read"] }],
    approvedSanitizers: [],
  };
  const report = compileTrustGraph(graph, policy);
  const byCode = Object.fromEntries(report.violations.map((item) => [item.code, item]));

  assert.equal(report.status, "blocked");
  assert.deepEqual(byCode.authority_overflow.witnessPath, ["prod"]);
  assert.deepEqual(byCode.authority_overflow.authorities, ["deploy"]);
  assert.equal(byCode.flow_cycle.witnessPath[0], byCode.flow_cycle.witnessPath.at(-1));
  assert.ok(byCode.flow_cycle.witnessPath.includes("worker"));
  assert.ok(byCode.flow_cycle.witnessPath.includes("prod"));
});

test("trust reports are canonical across node, edge, sink, and sanitizer input order", () => {
  const graph = graphFixture({ sanitizer: { id: "redact-confidential", proofDigest: PROOF } });
  const policy = policyFixture();
  const left = compileTrustGraph(graph, policy);
  const right = compileTrustGraph({ nodes: [...graph.nodes].reverse(), edges: [...graph.edges].reverse() }, {
    classifications: policy.classifications,
    sinks: [...policy.sinks].reverse(),
    approvedSanitizers: [...policy.approvedSanitizers].reverse(),
  });
  assert.deepEqual(left, right);
});

test("trust graph fails closed on unknown nodes, duplicate edges, invalid policy, and secrets", () => {
  const graph = graphFixture();
  const policy = policyFixture();
  assert.throws(() => compileTrustGraph({ ...graph, edges: [{ id: "bad", from: "source", to: "missing" }] }, policy), /unknown node missing/i);
  assert.throws(() => compileTrustGraph({ ...graph, edges: [graph.edges[0], graph.edges[0]] }, policy), /duplicate trust edges id source-service/i);
  assert.throws(() => compileTrustGraph(graph, { ...policy, classifications: ["public", "internal", "public"] }), /duplicate classification public/i);
  assert.throws(() => compileTrustGraph(graph, { ...policy, sinks: [{ nodeId: "missing", maxClassification: "internal", allowedAuthorities: [] }] }), /unknown sink node missing/i);
  assert.throws(() => compileTrustGraph(graph, { ...policy, surprise: true }), /unknown trust policy field surprise/i);
  assert.throws(() => compileTrustGraph({ ...graph, nodes: [{ ...graph.nodes[0], id: ["github", "_pat_", "abcdefghijklmnopqrstuvwxyz123456"].join("") }] }, policy), /secret material/i);
});
