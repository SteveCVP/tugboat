import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";

import { canonicalDigest } from "./lib/proof-runtime.mjs";
import { compileBundleAlgebra } from "./lib/bundle-algebra.mjs";
import { dispatch } from "./tugboat-mcp.mjs";
import { effectFixture } from "./fixtures/certified-changesets/effect-fixture.mjs";

function digest(label) { return canonicalDigest({ label }); }
function effect(id, domain, subject, access = "write", operation = "modify", extra = {}) {
  return { id, domain, subject, access, operation, sourceDigest: digest(id), ...extra };
}
function candidate(id, effects, { dependencies = [], uncertainty = [], bundleDigest = digest(`bundle:${id}`), boundaryDigest = digest("boundary") } = {}) {
  return {
    bundle: { digest: bundleDigest, payload: { id, selection: { bundleDependencies: [...dependencies] } } },
    witness: {
      semanticProof: true,
      verdict: uncertainty.length ? "insufficient_evidence" : "ready",
      digest: digest(`witness:${id}`),
      payload: { body: { bundleId: id, bundleDigest, boundaryManifestDigest: boundaryDigest, effects, uncertainty } },
    },
  };
}

test("path-disjoint verified bundles commute with a complete deterministic matrix", () => {
  const a = candidate("A", [effect("a1", "path", "src/a.mjs")]);
  const b = candidate("B", [effect("b1", "path", "src/b.mjs")]);
  const report = compileBundleAlgebra({ candidates: [b, a] });
  assert.equal(report.status, "ready");
  assert.equal(report.verdict, "commute");
  assert.deepEqual(report.canonicalOrder, ["A", "B"]);
  assert.deepEqual(report.pairwiseMatrix.map((item) => [item.leftBundleId, item.rightBundleId, item.commutes]), [["A", "B", true]]);
  assert.equal(report.proofBasis.coveredPairCount, 1);
  assert.equal(report.proofBasis.exactEffectComparison, true);
});

test("overlapping writes and read/write interactions return exact subjects", () => {
  const writeA = candidate("A", [effect("a", "path", "src/shared.mjs")]);
  const writeB = candidate("B", [effect("b", "path", "src/shared.mjs")]);
  const overlap = compileBundleAlgebra({ candidates: [writeA, writeB] });
  assert.equal(overlap.status, "blocked");
  assert.equal(overlap.hazards[0].code, "overlapping_write");
  assert.deepEqual(overlap.hazards[0].subjectIds, ["path:src/shared.mjs"]);
  const reader = candidate("C", [effect("c", "path", "src/shared.mjs", "read", "observe")]);
  const readWrite = compileBundleAlgebra({ candidates: [writeA, reader] });
  assert.equal(readWrite.hazards[0].code, "read_write_hazard");
});

test("dependency order composes, inversion and cycles block with shortest paths", () => {
  const a = candidate("A", [effect("a", "path", "src/a")]);
  const b = candidate("B", [effect("b", "path", "src/b")], { dependencies: ["A"] });
  const ordered = compileBundleAlgebra({ candidates: [b, a] });
  assert.equal(ordered.status, "ready");
  assert.equal(ordered.verdict, "ordered");
  assert.deepEqual(ordered.canonicalOrder, ["A", "B"]);
  assert.equal(ordered.pairwiseMatrix[0].requiredOrder.join("->"), "A->B");
  const inverted = compileBundleAlgebra({ candidates: [a, b], proposedOrder: ["B", "A"] });
  assert.equal(inverted.status, "blocked");
  assert.ok(inverted.hazards.some((item) => item.code === "dependency_inversion"));
  const cyclicA = candidate("A", [], { dependencies: ["B"] });
  const cyclicB = candidate("B", [], { dependencies: ["A"] });
  const cycle = compileBundleAlgebra({ candidates: [cyclicA, cyclicB] });
  assert.equal(cycle.status, "blocked");
  assert.deepEqual(cycle.hazards.find((item) => item.code === "dependency_cycle").witnessPath, ["bundle:A", "bundle:B", "bundle:A"]);
});

test("interface, schema, and infrastructure collisions stay typed", () => {
  const domains = [
    ["interface", "api:GET /deals", "interface_conflict"],
    ["schema", "table:deals", "schema_order_conflict"],
    ["infrastructure", "resource:DealsTable", "infrastructure_collision"],
  ];
  for (const [domain, subject, code] of domains) {
    const report = compileBundleAlgebra({ candidates: [candidate("A", [effect("a", domain, subject)]), candidate("B", [effect("b", domain, subject)])] });
    assert.equal(report.status, "blocked");
    assert.equal(report.hazards[0].code, code);
  }
});

test("uncertainty and stale witnesses return insufficiency instead of optimistic admission", () => {
  const uncertain = candidate("A", [], { uncertainty: [{ code: "unknown_effect", sourceId: "patch:1", message: "unclassified" }] });
  const uncertainty = compileBundleAlgebra({ candidates: [uncertain, candidate("B", [])] });
  assert.equal(uncertainty.status, "insufficient_evidence");
  assert.equal(uncertainty.hazards[0].code, "unknown_effect");
  const stale = candidate("A", []);
  stale.witness.payload.body.bundleDigest = digest("old");
  const staleReport = compileBundleAlgebra({ candidates: [stale, candidate("B", [])] });
  assert.equal(staleReport.status, "insufficient_evidence");
  assert.equal(staleReport.hazards[0].code, "stale_witness");
  const otherBoundary = candidate("B", [], { boundaryDigest: digest("other-boundary") });
  const mismatch = compileBundleAlgebra({ candidates: [candidate("A", []), otherBoundary] });
  assert.equal(mismatch.status, "insufficient_evidence");
  assert.ok(mismatch.hazards.some((item) => item.code === "boundary_mismatch"));
});

test("three-bundle dependency chains identify transitive hazards and canonical order", () => {
  const a = candidate("A", [effect("a", "path", "src/state", "write")]);
  const b = candidate("B", [effect("b", "path", "src/middle")], { dependencies: ["A"] });
  const c = candidate("C", [effect("c", "path", "src/state", "read", "observe")], { dependencies: ["B"] });
  const report = compileBundleAlgebra({ candidates: [c, a, b] });
  assert.equal(report.status, "blocked");
  assert.deepEqual(report.canonicalOrder, ["A", "B", "C"]);
  const hazard = report.hazards.find((item) => item.code === "transitive_read_write_hazard");
  assert.deepEqual(hazard.witnessPath, ["bundle:A", "bundle:B", "bundle:C", "path:src/state"]);
});

test("candidate and effect order cannot change the report digest", () => {
  const a = candidate("A", [effect("a2", "path", "src/z"), effect("a1", "path", "src/a")]);
  const b = candidate("B", [effect("b1", "path", "src/b")]);
  const first = compileBundleAlgebra({ candidates: [a, b] });
  const reversedA = structuredClone(a);
  reversedA.witness.payload.body.effects.reverse();
  const second = compileBundleAlgebra({ candidates: [b, reversedA] });
  assert.equal(first.digest, second.digest);
  assert.deepEqual(first.pairwiseMatrix, second.pairwiseMatrix);
});

test("CLI commute/compose planning and read-only MCP produce the same bounded report", () => {
  const fixture = effectFixture();
  const input = [candidate("A", [effect("a", "path", "src/a")]), candidate("B", [effect("b", "path", "src/b")])];
  const file = path.join(fixture.repo, "algebra.json");
  fs.writeFileSync(file, JSON.stringify({ candidates: input }));
  const commute = JSON.parse(execFileSync(process.execPath, [path.resolve("scripts/tugboat.mjs"), "bundle", "commute", "--candidates", file, "--json"], { encoding: "utf8" }));
  assert.throws(
    () => execFileSync(process.execPath, [path.resolve("scripts/tugboat.mjs"), "bundle", "compose", "--candidates", file, "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }),
    /planning-only|dry-run/,
  );
  const compose = JSON.parse(execFileSync(process.execPath, [path.resolve("scripts/tugboat.mjs"), "bundle", "compose", "--candidates", file, "--dry-run", "--json"], { encoding: "utf8" }));
  const mcp = dispatch(
    { dir: fixture.missionDir, repo: fixture.repo, allowWrites: false, actor: { name: "Test", kind: "human", runtime: "test" } },
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "tugboat_bundle_commute", arguments: { candidates: input } } },
  );
  assert.equal(commute.digest, compose.digest);
  assert.equal(commute.digest, mcp.structuredContent.digest);
  assert.equal(compose.executionAuthorized, false);
  assert.equal(mcp.structuredContent.verdict, "commute");
});
