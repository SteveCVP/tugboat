import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { sha256 } from "./lib/canonical.mjs";
import { inspectAdapter, runAdapter } from "./lib/adapter-sdk.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-adapter-"));
  const source = `import fs from "node:fs";\nlet text="";for await(const c of process.stdin)text+=c;const req=JSON.parse(text);process.stdout.write(JSON.stringify({echo:req.input.value,declared:process.env.DECLARED??"",ambient:process.env.AMBIENT!==undefined,file:fs.readFileSync("inputs/input.txt","utf8").trim()}));\n`;
  fs.writeFileSync(path.join(root, "adapter.mjs"), source);
  fs.writeFileSync(path.join(root, "input.txt"), "declared-file\n");
  const manifest = {
    schemaVersion: "tugboat.adapter-manifest.v1",
    id: "fixture",
    runtime: "node20",
    entrypoint: "adapter.mjs",
    entrypointDigest: `sha256:${sha256(source)}`,
    inputSchema: { type: "object", properties: { value: { type: "number" } }, required: ["value"], additionalProperties: false },
    outputSchema: { type: "object", properties: { echo: { type: "number" }, declared: { type: "string" }, ambient: { type: "boolean" }, file: { type: "string" } }, required: ["echo", "declared", "ambient", "file"], additionalProperties: false },
    capabilities: ["review"],
    allowedInputPaths: ["input.txt"],
    environment: ["DECLARED"],
    timeoutMs: 2000,
    maxOutputBytes: 4096,
    isolation: "brokered",
  };
  return { root, manifest };
}

test("adapter broker pins code, stages only declared files, and strips ambient environment", () => {
  const { root, manifest } = fixture();
  process.env.AMBIENT = "must-not-leak";
  const inspection = inspectAdapter(manifest, { manifestDir: root });
  assert.equal(inspection.status, "ready");
  assert.match(inspection.limitations[0], /not an OS sandbox/);
  const result = runAdapter({ manifest, manifestDir: root, inputRoot: root, inputPaths: ["input.txt"], input: { value: 7 }, environment: { DECLARED: "yes" } });
  assert.equal(result.status, "ready");
  assert.deepEqual(result.output, { echo: 7, declared: "yes", ambient: false, file: "declared-file" });
});

test("adapter broker rejects digest drift, undeclared files, and undeclared environment", () => {
  const { root, manifest } = fixture();
  const input = { value: 1 };
  assert.throws(() => runAdapter({ manifest: { ...manifest, entrypointDigest: `sha256:${"0".repeat(64)}` }, manifestDir: root, inputRoot: root, inputPaths: ["input.txt"], input }), /digest mismatch/);
  fs.writeFileSync(path.join(root, "other.txt"), "no");
  assert.throws(() => runAdapter({ manifest, manifestDir: root, inputRoot: root, inputPaths: ["other.txt"], input }), /not allowed/);
  assert.throws(() => runAdapter({ manifest, manifestDir: root, inputRoot: root, inputPaths: ["input.txt"], input, environment: { AMBIENT: "x" } }), /not declared/);
  assert.throws(() => runAdapter({ manifest: { ...manifest, isolation: "container" }, manifestDir: root, inputRoot: root, inputPaths: ["input.txt"], input }), /external runtime/);
  assert.throws(() => runAdapter({ manifest, manifestDir: root, inputRoot: root, inputPaths: ["input.txt"], input: {} }), /missing value/);
});

test("adapter broker pins and stages declared executable assets", () => {
  const { root, manifest } = fixture();
  const helper = `export const value = "asset-loaded";\n`;
  const source = `import { value } from "./helper.mjs";\nlet text="";for await(const c of process.stdin)text+=c;JSON.parse(text);process.stdout.write(JSON.stringify({echo:1,declared:"",ambient:false,file:value}));\n`;
  fs.writeFileSync(path.join(root, "adapter.mjs"), source);
  fs.writeFileSync(path.join(root, "helper.mjs"), helper);
  const withAsset = {
    ...manifest,
    entrypointDigest: `sha256:${sha256(source)}`,
    assets: [{ path: "helper.mjs", digest: `sha256:${sha256(helper)}` }],
  };
  const result = runAdapter({ manifest: withAsset, manifestDir: root, inputRoot: root, input: { value: 1 } });
  assert.equal(result.output.file, "asset-loaded");
  assert.throws(
    () => runAdapter({ manifest: { ...withAsset, assets: [{ path: "helper.mjs", digest: `sha256:${"0".repeat(64)}` }] }, manifestDir: root, inputRoot: root, input: { value: 1 } }),
    /asset digest mismatch/,
  );
});
