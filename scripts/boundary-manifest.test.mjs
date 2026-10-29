import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BOUNDARY_MANIFEST_LIMITS,
  BoundaryManifestError,
  createBoundaryManifest,
  readBoundaryManifest,
  verifyBoundaryManifest,
  writeBoundaryManifest,
} from "./lib/boundary-manifest.mjs";
import { sha256 } from "./lib/canonical.mjs";
import { dispatch } from "./tugboat-mcp.mjs";

const fixtureFile = path.resolve("scripts/fixtures/certified-changesets/boundary-manifest.input.json");

function write(root, relative, contents) {
  const file = path.join(root, ...relative.split("/"));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  return `sha256:${sha256(Buffer.from(contents))}`;
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-boundary-"));
  const input = JSON.parse(fs.readFileSync(fixtureFile, "utf8"));
  input.sources[0].digest = write(root, input.sources[0].path, "# Architecture\n");
  input.components[0].interfaces[0].digest = write(root, input.components[0].interfaces[0].path, "export const stable = true;\n");
  input.components[1].interfaces[0].digest = write(root, input.components[1].interfaces[0].path, '{"openapi":"3.1.0"}\n');
  return { root, input };
}

function clone(value) {
  return structuredClone(value);
}

test("verifies a canonical multi-component boundary manifest and indexes ownership, invariants, and gates", () => {
  const { root, input } = fixture();
  const envelope = createBoundaryManifest(input);
  const result = verifyBoundaryManifest(envelope, { rootDir: root });

  assert.equal(result.status, "ready");
  assert.match(result.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.componentCount, 2);
  assert.deepEqual(result.components.map((item) => item.id), ["component:api", "component:core"]);
  assert.deepEqual(result.components.map((item) => [item.id, item.requirementIds]), [
    ["component:api", ["R2"]],
    ["component:core", ["R1"]],
  ]);
  assert.deepEqual(result.ownership, [
    { path: "src/api/**", componentId: "component:api", owner: "team:api" },
    { path: "src/core/**", componentId: "component:core", owner: "team:platform" },
  ]);
  assert.deepEqual(result.invariants["invariant:public-api-compatible"].gateIds, ["gate:api-compat"]);
  assert.equal(result.gates["gate:api-compat"].mandatory, true);
  assert.deepEqual(result.sourceVerification.map((item) => item.status), ["verified", "verified", "verified"]);
});

test("canonical digest is independent of declaration ordering", () => {
  const { input } = fixture();
  const reordered = clone(input);
  reordered.components.reverse();
  reordered.components[0].paths.reverse();
  reordered.invariants.reverse();
  reordered.gates.reverse();
  reordered.components[0].dependencies.reverse();
  assert.deepEqual(createBoundaryManifest(reordered), createBoundaryManifest(input));
});

test("rejects overlapping ownership and unsafe path scopes", () => {
  const { input } = fixture();
  const overlap = clone(input);
  overlap.components[0].paths = ["src/**"];
  assert.throws(() => createBoundaryManifest(overlap), /ownership overlap.*src\/api\/\*\*.*src\/\*\*/i);

  for (const unsafe of ["../outside/**", "/absolute/**", "src/../outside/**", "src\\windows\\**", ".git/**", "src/*/wildcard"] ) {
    const changed = clone(input);
    changed.components[0].paths = [unsafe];
    assert.throws(() => createBoundaryManifest(changed), /portable path scope|unsafe Git-internal path/);
  }
});

test("rejects symlink-dependent scopes and source files", () => {
  const { root, input } = fixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-boundary-outside-"));
  fs.symlinkSync(outside, path.join(root, "linked"));
  const scope = clone(input);
  scope.components[0].paths = ["linked/**"];
  scope.components[0].interfaces[0].path = "linked/index.mjs";
  scope.components[0].interfaces[0].digest = write(outside, "index.mjs", "export const linked = true;\n");
  const scopeEnvelope = createBoundaryManifest(scope);
  assert.throws(() => verifyBoundaryManifest(scopeEnvelope, { rootDir: root }), /symbolic link/);

  fs.symlinkSync(path.join(root, "docs", "architecture.md"), path.join(root, "source-link.md"));
  const source = clone(input);
  source.sources[0].path = "source-link.md";
  const sourceEnvelope = createBoundaryManifest(source);
  assert.throws(() => verifyBoundaryManifest(sourceEnvelope, { rootDir: root }), /symbolic link/);
});

test("rejects duplicate IDs, dependency cycles, and unknown references", () => {
  const { input } = fixture();
  const duplicate = clone(input);
  duplicate.gates.push(clone(duplicate.gates[0]));
  assert.throws(() => createBoundaryManifest(duplicate), /duplicate gate ID/);

  const cycle = clone(input);
  cycle.components[0].dependencies = ["component:api"];
  assert.throws(() => createBoundaryManifest(cycle), /dependency cycle.*component:api.*component:core.*component:api/i);

  const dependency = clone(input);
  dependency.components[1].dependencies = ["component:missing"];
  assert.throws(() => createBoundaryManifest(dependency), /unknown dependency component:missing/);

  const invariant = clone(input);
  invariant.components[0].invariantIds = ["invariant:missing"];
  assert.throws(() => createBoundaryManifest(invariant), /unknown invariant invariant:missing/);

  const subject = clone(input);
  subject.gates[0].subjectIds = ["interface:missing"];
  assert.throws(() => createBoundaryManifest(subject), /unknown subject interface:missing/);
});

test("rejects unknown fields, invalid disclosure, and interface contracts outside ownership", () => {
  const { input } = fixture();
  assert.throws(() => createBoundaryManifest({ ...input, trusted: true }), /Unknown boundary manifest field trusted/);
  assert.throws(() => createBoundaryManifest({ ...input, disclosure: "secret-ish" }), /disclosure/);
  const escaped = clone(input);
  escaped.components[0].interfaces[0].path = "src/api/not-owned.mjs";
  assert.throws(() => createBoundaryManifest(escaped), /is not owned by component:core/);
});

test("detects stale or tampered digests and enforces the manifest byte bound", () => {
  const { root, input } = fixture();
  const envelope = createBoundaryManifest(input);
  write(root, "src/api/openapi.json", '{"openapi":"3.0.0"}\n');
  assert.throws(() => verifyBoundaryManifest(envelope, { rootDir: root }), /stale digest.*interface:public-openapi/);

  const tampered = clone(envelope);
  tampered.manifest.components[0].owner = "team:attacker";
  assert.throws(() => verifyBoundaryManifest(tampered), /digest mismatch/);

  const manifestFile = path.join(root, "oversized.json");
  fs.writeFileSync(manifestFile, Buffer.alloc(BOUNDARY_MANIFEST_LIMITS.maxManifestBytes + 1, 0x20));
  assert.throws(() => readBoundaryManifest(manifestFile), /exceeds/);
});

test("CLI and bounded read-only MCP return the same verified manifest without changing bytes", () => {
  const { root, input } = fixture();
  const manifestFile = path.join(root, "tugboat.boundaries.json");
  const envelope = createBoundaryManifest(input);
  writeBoundaryManifest(manifestFile, envelope);
  const manifestBefore = fs.readFileSync(manifestFile);
  const sourceBefore = fs.readFileSync(path.join(root, "docs", "architecture.md"));

  const cli = JSON.parse(execFileSync(process.execPath, [
    path.resolve("scripts/tugboat.mjs"), "boundary", "verify", "--file", manifestFile, "--root", root, "--json",
  ], { encoding: "utf8" }));
  const text = execFileSync(process.execPath, [
    path.resolve("scripts/tugboat.mjs"), "boundary", "verify", "--file", manifestFile, "--root", root,
  ], { encoding: "utf8" });
  const mcp = dispatch(
    { dir: root, repo: root, allowWrites: false, actor: { name: "Test", kind: "human", runtime: "test" } },
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "tugboat_boundary_verify", arguments: { manifest: envelope } } },
  );

  assert.equal(cli.digest, envelope.digest);
  assert.match(text, /Boundary manifest manifest:example-platform: ready; 2 components/);
  assert.equal(mcp.structuredContent.digest, cli.digest);
  assert.equal(mcp.structuredContent.status, "ready");
  assert.deepEqual(fs.readFileSync(manifestFile), manifestBefore);
  assert.deepEqual(fs.readFileSync(path.join(root, "docs", "architecture.md")), sourceBefore);
});

test("throws a typed boundary error for fail-closed callers", () => {
  const { input } = fixture();
  assert.throws(
    () => createBoundaryManifest({ ...input, components: [] }),
    (error) => error instanceof BoundaryManifestError && error.exitCode === 2,
  );
});
