import assert from "node:assert/strict";
import test from "node:test";

import { compileFederation } from "./lib/federation.mjs";

const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;

function child(id, overrides = {}) {
  return {
    id,
    status: "ready",
    stateDigest: DIGEST_A,
    reportDigest: DIGEST_B,
    dependencies: [],
    rollbackAfter: [],
    deployAction: `deploy-${id}`,
    rollbackAction: `rollback-${id}`,
    provides: [],
    requires: [],
    ...overrides,
  };
}

function readyManifest() {
  return {
    id: "platform-release",
    children: [
      child("db", { provides: [{ name: "database-schema", version: "1" }] }),
      child("api", {
        dependencies: ["db"],
        provides: [{ name: "deal-api", version: "2" }],
        requires: [{ name: "database-schema", version: "1" }],
      }),
      child("web", {
        dependencies: ["api"],
        requires: [{ name: "deal-api", version: "2" }],
      }),
    ],
  };
}

test("federation compiles canonical deploy waves and reverse-safe rollback waves", () => {
  const manifest = readyManifest();
  const before = JSON.stringify(manifest);
  const report = compileFederation(manifest);

  assert.equal(report.status, "ready");
  assert.deepEqual(report.deployWaves, [["db"], ["api"], ["web"]]);
  assert.deepEqual(report.rollbackWaves, [["web"], ["api"], ["db"]]);
  assert.deepEqual(report.compatibility, [
    { consumerId: "api", contract: "database-schema", providerId: "db", version: "1" },
    { consumerId: "web", contract: "deal-api", providerId: "api", version: "2" },
  ]);
  assert.deepEqual(report.gaps, []);
  assert.match(report.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(manifest), before);
});

test("one unready or unattested child and one broken compatibility contract block the train", () => {
  const manifest = readyManifest();
  const api = manifest.children.find(({ id }) => id === "api");
  api.status = "blocked";
  api.reportDigest = null;
  const web = manifest.children.find(({ id }) => id === "web");
  web.requires[0].version = "3";
  delete web.rollbackAction;
  const report = compileFederation(manifest);
  const codes = report.gaps.map(({ code }) => code);

  assert.equal(report.status, "blocked");
  assert.ok(codes.includes("child_not_ready"));
  assert.ok(codes.includes("child_digest_invalid"));
  assert.ok(codes.includes("compatibility_unsatisfied"));
  assert.ok(codes.includes("rollback_action_missing"));
});

test("dependency and rollback cycles block release with literal witnesses", () => {
  const dependencyCycle = readyManifest();
  dependencyCycle.children.find(({ id }) => id === "db").dependencies = ["web"];
  const deployReport = compileFederation(dependencyCycle);
  assert.equal(deployReport.status, "blocked");
  assert.deepEqual(deployReport.deployWaves, []);
  const deployGap = deployReport.gaps.find(({ code }) => code === "dependency_cycle");
  assert.equal(deployGap.witness[0], deployGap.witness.at(-1));

  const rollbackCycle = readyManifest();
  rollbackCycle.children.find(({ id }) => id === "web").rollbackAfter = ["api"];
  const rollbackReport = compileFederation(rollbackCycle);
  assert.equal(rollbackReport.status, "blocked");
  assert.deepEqual(rollbackReport.rollbackWaves, []);
  const rollbackGap = rollbackReport.gaps.find(({ code }) => code === "rollback_cycle");
  assert.equal(rollbackGap.witness[0], rollbackGap.witness.at(-1));
});

test("federation is canonical across child, dependency, provider, and requirement order", () => {
  const manifest = readyManifest();
  const left = compileFederation(manifest);
  const right = compileFederation({
    id: manifest.id,
    children: [...manifest.children].reverse().map((item) => ({
      ...item,
      dependencies: [...item.dependencies].reverse(),
      rollbackAfter: [...item.rollbackAfter].reverse(),
      provides: [...item.provides].reverse(),
      requires: [...item.requires].reverse(),
    })),
  });
  assert.deepEqual(left, right);
});

test("federation rejects duplicate children, unknown references, unknown fields, paths, and secrets", () => {
  const manifest = readyManifest();
  assert.throws(() => compileFederation({ id: "x", children: [child("A"), child("A")] }), /duplicate federation children id A/i);
  assert.throws(() => compileFederation({ id: "x", children: [child("A", { dependencies: ["missing"] })] }), /unknown dependency missing/i);
  assert.throws(() => compileFederation({ ...manifest, surprise: true }), /unknown federation manifest field surprise/i);
  assert.throws(() => compileFederation({ id: "x", children: [child("A", { deployAction: "/private/deploy.sh" })] }), /absolute path/i);
  assert.throws(() => compileFederation({ id: "x", children: [child("A", { rollbackAction: ["github", "_pat_", "abcdefghijklmnopqrstuvwxyz123456"].join("") })] }), /secret material/i);
});
