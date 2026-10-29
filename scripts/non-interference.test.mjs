import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { createCertifiedEnvelope } from "./lib/certified-changeset.mjs";
import {
  certifyBundleNonInterference,
  verifyBundleNonInterference,
  writeNonInterferenceWitness,
} from "./lib/non-interference.mjs";
import { dispatch } from "./tugboat-mcp.mjs";
import { effectFixture } from "./fixtures/certified-changesets/effect-fixture.mjs";

const producer = { name: "Codex", kind: "agent", runtime: "codex" };
const generatedAt = "2026-10-29T18:00:00.000Z";

function certify(context, bundle = context.coreBundle) {
  return certifyBundleNonInterference({ bundle, boundary: context.boundary, rootDir: context.repo, producer, generatedAt });
}

test("certifies confined changes and identifies direct, dependent, and proven-unaffected boundaries", () => {
  const context = effectFixture();
  const witness = certify(context);
  const verified = verifyBundleNonInterference(witness, {
    bundle: context.coreBundle, boundary: context.boundary, rootDir: context.repo,
  });
  assert.equal(verified.verdict, "ready");
  assert.equal(verified.semanticProof, true);
  assert.deepEqual(witness.payload.body.directlyAffectedComponentIds, ["component:core"]);
  assert.deepEqual(witness.payload.body.transitivelyAffectedComponentIds, ["component:api"]);
  assert.deepEqual(witness.payload.body.provenUnaffectedComponentIds, ["component:docs"]);
  assert.deepEqual(witness.payload.counterexamples, []);
});

test("blocks cross-boundary and secret-path writes with exact reproducible counterexamples", () => {
  const context = effectFixture();
  const cross = certify(context, context.crossBundle);
  assert.equal(cross.payload.verdict, "blocked");
  assert.equal(cross.payload.counterexamples[0].code, "cross_boundary_write");
  assert.equal(cross.payload.counterexamples[0].invariantId, "invariant:declared-boundary");
  assert.match(cross.payload.counterexamples[0].actual, /R1.*component:api.*R2/);
  assert.ok(cross.payload.counterexamples[0].subjectIds.includes("component:api"));
  assert.ok(cross.payload.counterexamples[0].subjectIds.some((item) => item.startsWith("file:src/api/cross.mjs")));

  const secret = certify(context, context.secretBundle);
  assert.equal(secret.payload.verdict, "blocked");
  assert.equal(secret.payload.counterexamples[0].code, "sensitive_path_write");
  assert.match(secret.payload.counterexamples[0].actual, /config\/secrets\.env/);
});

test("verification recomputes semantics and rejects both ordinary and rehashed witness tampering", () => {
  const context = effectFixture();
  const witness = certify(context);
  const ordinary = structuredClone(witness);
  ordinary.payload.body.provenUnaffectedComponentIds = ["component:api", "component:docs"];
  assert.throws(() => verifyBundleNonInterference(ordinary, { bundle: context.coreBundle, boundary: context.boundary, rootDir: context.repo }), /digest mismatch/);

  const rehashed = createCertifiedEnvelope({
    format: witness.format,
    payload: { ...witness.payload, body: { ...witness.payload.body, provenUnaffectedComponentIds: ["component:api", "component:docs"] } },
  });
  assert.throws(
    () => verifyBundleNonInterference(rehashed, { bundle: context.coreBundle, boundary: context.boundary, rootDir: context.repo }),
    /semantic mismatch/,
  );
});

test("CLI certification and CLI/MCP verification are deterministic, concise, and byte preserving", () => {
  const context = effectFixture();
  const witnessFile = path.join(context.repo, "core.witness.json");
  const bundleBefore = fs.readFileSync(context.coreBundlePath);
  const boundaryBefore = fs.readFileSync(context.boundaryPath);
  const cliCreated = JSON.parse(execFileSync(process.execPath, [
    path.resolve("scripts/tugboat.mjs"), "bundle", "certify",
    "--bundle", context.coreBundlePath,
    "--boundary-manifest", context.boundaryPath,
    "--root", context.repo,
    "--output", witnessFile,
    "--generated-at", generatedAt,
    "--actor", "Codex",
    "--json",
  ], { encoding: "utf8" }));
  const cliVerified = JSON.parse(execFileSync(process.execPath, [
    path.resolve("scripts/tugboat.mjs"), "certificate", "verify",
    "--file", witnessFile,
    "--bundle", context.coreBundlePath,
    "--boundary-manifest", context.boundaryPath,
    "--root", context.repo,
    "--json",
  ], { encoding: "utf8" }));
  const text = execFileSync(process.execPath, [
    path.resolve("scripts/tugboat.mjs"), "certificate", "verify",
    "--file", witnessFile,
    "--bundle", context.coreBundlePath,
    "--boundary-manifest", context.boundaryPath,
    "--root", context.repo,
  ], { encoding: "utf8" });
  const witness = JSON.parse(fs.readFileSync(witnessFile, "utf8"));
  const mcp = dispatch(
    { dir: context.missionDir, repo: context.repo, allowWrites: false, actor: { name: "Test", kind: "human", runtime: "test" } },
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "tugboat_certificate_verify", arguments: { witness, bundle: context.coreBundle.envelope, boundaryManifest: context.boundary } } },
  );

  assert.equal(cliCreated.verdict, "ready");
  assert.equal(cliVerified.digest, cliCreated.digest);
  assert.equal(mcp.structuredContent.digest, cliCreated.digest);
  assert.match(text, /Certified changeset B-CORE: ready; direct 1; dependent 1; unaffected 1/);
  assert.deepEqual(fs.readFileSync(context.coreBundlePath), bundleBefore);
  assert.deepEqual(fs.readFileSync(context.boundaryPath), boundaryBefore);
});

test("writing a witness is atomic and semantic verification binds the exact bundle and boundary digests", () => {
  const context = effectFixture();
  const witness = certify(context);
  const file = path.join(context.repo, "witness.json");
  writeNonInterferenceWitness(file, witness);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), witness);

  const wrongBundle = { ...context.coreBundle, digest: `sha256:${"f".repeat(64)}` };
  assert.throws(() => verifyBundleNonInterference(witness, { bundle: wrongBundle, boundary: context.boundary, rootDir: context.repo }), /semantic mismatch/);
  const wrongBoundary = structuredClone(context.boundary);
  wrongBoundary.digest = `sha256:${"e".repeat(64)}`;
  assert.throws(() => verifyBundleNonInterference(witness, { bundle: context.coreBundle, boundary: wrongBoundary, rootDir: context.repo }), /digest mismatch/);
});
