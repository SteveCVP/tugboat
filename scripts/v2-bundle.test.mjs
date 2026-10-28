import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BundleValidationError,
  compareBundles,
  createBundle,
  inspectBundle,
  readBundle,
  trackedContentDigest,
} from "./lib/bundle.mjs";
import { captureCommandEvidence, recordEvidence } from "./lib/evidence.mjs";
import { createMission } from "./lib/reducer.mjs";
import { canonicalJson, sha256 } from "./lib/canonical.mjs";

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function commit(cwd, message) {
  git(cwd, ["add", "-A"]);
  git(cwd, ["commit", "-m", message]);
  return git(cwd, ["rev-parse", "HEAD"]);
}

function fixture() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-bundle-"));
  git(repo, ["init", "-b", "main"]);
  git(repo, ["config", "user.email", "test@example.com"]);
  git(repo, ["config", "user.name", "Tugboat Test"]);
  fs.writeFileSync(path.join(repo, "spec.md"), "# Approved bundle mission\n");
  const baseline = commit(repo, "baseline");
  const missionDir = path.join(repo, "tugboat");
  createMission({
    dir: missionDir,
    actor: { name: "Codex", kind: "agent", runtime: "codex" },
    metadata: {
      id: "source-mission", title: "Source mission", owner: "Alex", target: "local",
      repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline,
      source: { path: "spec.md", digest: `sha256:${sha256(fs.readFileSync(path.join(repo, "spec.md")))}` },
      criticalPath: ["R1"], deployPath: "not requested",
    },
    requirements: [
      { id: "R1", requirement: "Build the interface", source: "spec 1", material: true, acceptance: "Interface works", proofTarget: "local" },
      { id: "R2", requirement: "Build the worker", source: "spec 2", material: true, acceptance: "Worker works", proofTarget: "local" },
    ],
    preservations: [{ id: "P1", instruction: "Preserve login", source: "spec", regressionProofTarget: "test" }],
    slices: [
      { id: "S1", name: "Interface", requirementIds: ["R1"], dependencies: [], status: "ACTIVE", operatorJourney: "Use interface" },
      { id: "S2", name: "Worker", requirementIds: ["R2"], dependencies: ["S1"], status: "PENDING", operatorJourney: "Run worker" },
    ],
  });
  const evidence = captureCommandEvidence({
    id: "E-SOURCE", requirementIds: ["R1"], cwd: repo,
    command: [process.execPath, "-e", "process.exit(0)"], actor: { name: "Codex", kind: "agent", runtime: "codex" },
    excludePaths: [missionDir],
  });
  recordEvidence(missionDir, evidence);
  const missionCommit = commit(repo, "initialize source mission");
  fs.writeFileSync(path.join(repo, "app.mjs"), "export const answer = 41;\n");
  const first = commit(repo, "add application");
  fs.writeFileSync(path.join(repo, "app.mjs"), "export const answer = 42;\n");
  fs.writeFileSync(path.join(repo, "worker.mjs"), "export const run = () => 'ready';\n");
  const second = commit(repo, "complete application");
  const componentPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-component-")), "candidate-image.bin");
  fs.writeFileSync(componentPath, Buffer.from([0, 255, 17, 42, 128, 64]));
  return { repo, missionDir, baseline, missionCommit, first, second, componentPath };
}

function bundleOptions(context, overrides = {}) {
  return {
    missionDir: context.missionDir,
    id: "B-CANDIDATE",
    requirementIds: ["R1"],
    commitShas: [context.first, context.second],
    components: [{
      type: "image", sourcePath: context.componentPath, targetPath: "assets/candidate-image.bin",
      label: "Candidate UI image", requirementIds: ["R1"],
    }],
    dependsOn: ["B-FOUNDATION"],
    actor: { name: "Codex", kind: "agent", runtime: "codex" },
    createdAt: "2026-10-28T12:00:00.000Z",
    ...overrides,
  };
}

test("creates a signed canonical bundle with binary components and complete redacted provenance", () => {
  const context = fixture();
  const outputPath = path.join(context.repo, "candidate.tugboat");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const envelope = createBundle(bundleOptions(context, {
    outputPath,
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
  }));

  assert.equal(envelope.schemaVersion, 1);
  assert.equal(envelope.format, "tugboat.bundle");
  assert.match(envelope.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(envelope.payload.source.missionId, "source-mission");
  assert.equal(envelope.payload.source.baseSha, context.missionCommit);
  assert.equal(envelope.payload.source.tipSha, context.second);
  assert.deepEqual(envelope.payload.commits.map((item) => item.sha), [context.first, context.second]);
  assert.equal(envelope.payload.selection.requirements[0].id, "R1");
  assert.equal(envelope.payload.selection.preservations[0].id, "P1");
  assert.deepEqual(envelope.payload.selection.bundleDependencies, ["B-FOUNDATION"]);
  assert.equal(envelope.payload.evidence[0].id, "E-SOURCE");
  assert.deepEqual(Buffer.from(envelope.payload.components[0].content, "base64"), fs.readFileSync(context.componentPath));
  assert.ok(envelope.signature);

  const verified = readBundle(outputPath, {
    publicKey: publicKey.export({ type: "spki", format: "pem" }), requireSignature: true,
  });
  assert.equal(verified.signatureStatus, "verified");
  const summary = inspectBundle(verified);
  assert.equal(summary.id, "B-CANDIDATE");
  assert.deepEqual(summary.requirementIds, ["R1"]);
  assert.deepEqual(summary.componentTypes, { image: 1 });
  assert.equal(summary.components[0].targetPath, "assets/candidate-image.bin");
  assert.equal(summary.signature.status, "verified");
  assert.equal(summary.evidence[0].verification.status, "passed");
  assert.deepEqual(summary.sliceDependencies, []);
  assert.doesNotMatch(JSON.stringify(summary), new RegExp(envelope.payload.patches[0].content.slice(0, 20)));
  assert.doesNotMatch(JSON.stringify(summary), new RegExp(envelope.payload.components[0].content));
});

test("detects payload, component, and signature tampering", () => {
  const context = fixture();
  const outputPath = path.join(context.repo, "candidate.tugboat");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  createBundle(bundleOptions(context, { outputPath, privateKey: privateKey.export({ type: "pkcs8", format: "pem" }) }));

  const payloadTampered = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  payloadTampered.payload.selection.requirements[0].requirement = "silently changed";
  fs.writeFileSync(outputPath, JSON.stringify(payloadTampered));
  assert.throws(() => readBundle(outputPath), BundleValidationError);

  createBundle(bundleOptions(context, { outputPath, privateKey: privateKey.export({ type: "pkcs8", format: "pem" }) }));
  const componentTampered = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  componentTampered.payload.components[0].content = Buffer.from("different").toString("base64");
  componentTampered.digest = `sha256:${createHash("sha256").update(canonicalJson(componentTampered.payload)).digest("hex")}`;
  assert.throws(() => readBundle(writeJson(path.join(context.repo, "component-tampered.tugboat"), componentTampered)), BundleValidationError);

  createBundle(bundleOptions(context, { outputPath, privateKey: privateKey.export({ type: "pkcs8", format: "pem" }) }));
  const wrongKey = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
  assert.throws(() => readBundle(outputPath, { publicKey: wrongKey, requireSignature: true }), /signature/i);
  assert.equal(readBundle(outputPath, { publicKey: publicKey.export({ type: "spki", format: "pem" }) }).signatureStatus, "verified");
});

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
  return file;
}

function rehash(envelope) {
  envelope.digest = `sha256:${sha256(canonicalJson(envelope.payload))}`;
  delete envelope.signature;
  return envelope;
}

test("rejects malformed imported schemas, unsafe ownership, duplicate targets, and secret metadata", () => {
  const context = fixture();
  const outputPath = path.join(context.repo, "candidate.tugboat");
  createBundle(bundleOptions(context, { outputPath }));
  const original = JSON.parse(fs.readFileSync(outputPath, "utf8"));

  const malformedSelection = structuredClone(original);
  malformedSelection.payload.selection.requirements = {};
  assert.throws(() => readBundle(writeJson(path.join(context.repo, "malformed-selection.tugboat"), rehash(malformedSelection))), /selection|requirements|schema/i);

  const unknownOwnership = structuredClone(original);
  unknownOwnership.payload.components[0].requirementIds = ["R404"];
  assert.throws(() => readBundle(writeJson(path.join(context.repo, "unknown-ownership.tugboat"), rehash(unknownOwnership))), /component.*R404|unselected requirement/i);

  const duplicateTarget = structuredClone(original);
  duplicateTarget.payload.components.push(structuredClone(duplicateTarget.payload.components[0]));
  assert.throws(() => readBundle(writeJson(path.join(context.repo, "duplicate-target.tugboat"), rehash(duplicateTarget))), /duplicate.*target|target.*unique/i);

  const secretMetadata = structuredClone(original);
  secretMetadata.payload.actor.name = ["api", "_key=abcdefghijklmnop"].join("");
  assert.throws(() => readBundle(writeJson(path.join(context.repo, "secret-metadata.tugboat"), rehash(secretMetadata))), /secret material/i);
});

test("requires a linear ordered commit selection and known requirements", () => {
  const context = fixture();
  assert.throws(() => createBundle(bundleOptions(context, { commitShas: [context.second, context.first] })), /ordered|linear|parent/i);
  assert.throws(() => createBundle(bundleOptions(context, { requirementIds: ["R404"] })), /unknown requirement/i);
});

test("associates each independently applicable commit patch with explicit requirement IDs", () => {
  const context = fixture();
  const envelope = createBundle(bundleOptions(context, {
    requirementIds: ["R1", "R2"],
    commitRequirements: { [context.first]: ["R1"], [context.second]: ["R2"] },
    components: [],
  }));
  assert.deepEqual(envelope.payload.commits.map((item) => item.requirementIds), [["R1"], ["R2"]]);
  assert.deepEqual(envelope.payload.patches.map((item) => item.sourceSha), [context.first, context.second]);
  assert.deepEqual(envelope.payload.patches.map((item) => item.requirementIds), [["R1"], ["R2"]]);
  assert.throws(() => createBundle(bundleOptions(context, {
    requirementIds: ["R1", "R2"], commitRequirements: { [context.first]: ["R1"] }, components: [],
  })), /map every commit/i);
});

test("rejects secrets in textual patches and components", () => {
  const componentContext = fixture();
  fs.writeFileSync(componentContext.componentPath, ["api", "_key=abcdefghijklmnop\n"].join(""));
  assert.throws(() => createBundle(bundleOptions(componentContext)), /secret material/i);

  const patchContext = fixture();
  fs.writeFileSync(path.join(patchContext.repo, "leak.txt"), ["github", "_pat_abcdefghijklmnopqrstuvwxyz123456\n"].join(""));
  const leakCommit = commit(patchContext.repo, "accidental secret");
  assert.throws(() => createBundle(bundleOptions(patchContext, { commitShas: [leakCommit], components: [] })), /secret material/i);
});

test("rejects absolute, traversal, git-internal, and symlink component paths", () => {
  const context = fixture();
  for (const targetPath of ["/tmp/escape", "../escape", ".git/config", "nested/../../escape"]) {
    assert.throws(() => createBundle(bundleOptions(context, { components: [{ type: "image", sourcePath: context.componentPath, targetPath, requirementIds: ["R1"] }] })), /component path|unsafe|relative/i);
  }
  const link = path.join(context.repo, "linked-component");
  fs.symlinkSync(context.componentPath, link);
  assert.throws(() => createBundle(bundleOptions(context, { components: [{ type: "image", sourcePath: link, targetPath: "assets/link.bin", requirementIds: ["R1"] }] })), /symbolic link/i);
});

test("enforces per-component and aggregate decoded size ceilings", () => {
  const context = fixture();
  fs.writeFileSync(context.componentPath, Buffer.alloc(101));
  assert.throws(() => createBundle(bundleOptions(context, { limits: { maxComponentBytes: 100, maxBundleBytes: 1000 } })), /component.*100 bytes/i);
  const second = path.join(context.repo, "second.bin");
  fs.writeFileSync(context.componentPath, Buffer.alloc(60));
  fs.writeFileSync(second, Buffer.alloc(60));
  assert.throws(() => createBundle(bundleOptions(context, {
    limits: { maxComponentBytes: 100, maxBundleBytes: 100 },
    components: [
      { type: "image", sourcePath: context.componentPath, targetPath: "assets/one.bin", requirementIds: ["R1"] },
      { type: "image", sourcePath: second, targetPath: "assets/two.bin", requirementIds: ["R1"] },
    ],
  })), /bundle.*100 bytes/i);
});

test("tracked content digest changes for product files but ignores the mission directory", () => {
  const context = fixture();
  const atSecond = trackedContentDigest(context.repo, context.second, "tugboat");
  fs.appendFileSync(path.join(context.missionDir, "context-handoff.md"), "ignored generated change\n");
  const missionOnly = commit(context.repo, "update mission view");
  assert.equal(trackedContentDigest(context.repo, missionOnly, "tugboat"), atSecond);
  fs.appendFileSync(path.join(context.repo, "app.mjs"), "// product change\n");
  const productChange = commit(context.repo, "change product");
  assert.notEqual(trackedContentDigest(context.repo, productChange, "tugboat"), atSecond);
});

test("compares candidate coverage, components, dependencies, and signatures deterministically without bodies", () => {
  const context = fixture();
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const firstFile = path.join(context.repo, "first.tugboat");
  createBundle(bundleOptions(context, {
    id: "B-ALPHA", outputPath: firstFile,
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
  }));
  fs.writeFileSync(context.componentPath, Buffer.from([9, 8, 7, 6]));
  const secondFile = path.join(context.repo, "second.tugboat");
  createBundle(bundleOptions(context, {
    id: "B-BETA", outputPath: secondFile, requirementIds: ["R2"], dependsOn: ["B-OTHER"],
    components: [{ type: "document", sourcePath: context.componentPath, targetPath: "assets/candidate-image.bin", requirementIds: ["R2"] }],
  }));
  const alpha = readBundle(firstFile, { publicKey: publicKey.export({ type: "spki", format: "pem" }) });
  const beta = readBundle(secondFile);

  const forward = compareBundles([alpha, beta]);
  const reverse = compareBundles([beta, alpha]);
  assert.deepEqual(reverse, forward);
  assert.equal(forward.candidateCount, 2);
  assert.deepEqual(forward.requirements, [
    { id: "R1", candidates: ["B-ALPHA"] },
    { id: "R2", candidates: ["B-BETA"] },
  ]);
  assert.deepEqual(forward.dependencies, [
    { id: "B-FOUNDATION", requiredBy: ["B-ALPHA"] },
    { id: "B-OTHER", requiredBy: ["B-BETA"] },
  ]);
  assert.deepEqual(forward.candidates.find((item) => item.id === "B-BETA").sliceDependencies, ["S1"]);
  assert.equal(forward.candidates.find((item) => item.id === "B-ALPHA").evidence[0].verification.status, "passed");
  assert.equal(forward.components[0].targetPath, "assets/candidate-image.bin");
  assert.equal(forward.components[0].conflict, true);
  assert.deepEqual(forward.signatures.map((item) => [item.id, item.status]), [["B-ALPHA", "verified"], ["B-BETA", "unsigned"]]);
  assert.doesNotMatch(JSON.stringify(forward), /"content"|"patch"/);
});
