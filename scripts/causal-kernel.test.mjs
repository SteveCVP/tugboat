import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { compileCausalGraph } from "./lib/causal-kernel.mjs";
import { canonicalDigest } from "./lib/proof-runtime.mjs";

const graph = (a = 1) => ({
  schemaVersion: "tugboat.causal-graph.v1",
  nodes: [
    { id: "a", compiler: "canonical", version: "1", dependencies: [], input: { value: a } },
    { id: "b", compiler: "canonical", version: "1", dependencies: [], input: { value: 2 } },
    { id: "c", compiler: "merge", version: "1", dependencies: ["a", "b"], input: { label: "sum" } },
  ],
});

test("causal kernel verifies cache and selectively invalidates dependency closure", () => {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-kernel-"));
  const cold = compileCausalGraph(graph(), { cacheDir });
  assert.deepEqual(cold.execution, { hits: [], misses: ["a", "b", "c"] });
  const warm = compileCausalGraph(graph(), { cacheDir });
  assert.deepEqual(warm.execution, { hits: ["a", "b", "c"], misses: [] });
  assert.equal(warm.graphDigest, cold.graphDigest);
  const changed = compileCausalGraph(graph(9), { cacheDir });
  assert.deepEqual(changed.execution, { hits: ["b"], misses: ["a", "c"] });
  assert.notEqual(changed.graphDigest, cold.graphDigest);
});

test("causal kernel recomputes corrupt cache and rejects cycles and unknown compilers", () => {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-kernel-"));
  compileCausalGraph(graph(), { cacheDir });
  const cacheFile = fs.readdirSync(cacheDir).find((name) => name.endsWith(".json"));
  const original = JSON.parse(fs.readFileSync(path.join(cacheDir, cacheFile), "utf8"));
  const poison = { poisoned: true };
  fs.writeFileSync(path.join(cacheDir, cacheFile), JSON.stringify({ key: original.key, output: poison, outputDigest: canonicalDigest(poison) }));
  const repaired = compileCausalGraph(graph(), { cacheDir });
  assert.ok(repaired.execution.misses.length >= 1);
  const cyclic = graph(); cyclic.nodes[0].dependencies = ["c"];
  assert.throws(() => compileCausalGraph(cyclic, { cacheDir }), /cycle/);
  const unknown = graph(); unknown.nodes[0].compiler = "model";
  assert.throws(() => compileCausalGraph(unknown, { cacheDir }), /Unknown compiler/);
});
