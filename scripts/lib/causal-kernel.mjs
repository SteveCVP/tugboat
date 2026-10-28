import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./canonical.mjs";
import { assertNoSecrets } from "./security.mjs";
import { canonicalDigest, exactObject } from "./proof-runtime.mjs";

const GRAPH_FIELDS = ["schemaVersion", "nodes"];
const NODE_FIELDS = ["id", "compiler", "version", "dependencies", "input"];

const COMPILERS = Object.freeze({
  canonical: ({ input }) => input,
  merge: ({ input, dependencies }) => ({ input, dependencies }),
});

function validateGraph(graph) {
  if (Buffer.byteLength(canonicalJson(graph)) > 1024 * 1024) throw new Error("Causal graph exceeds 1 MiB");
  exactObject(graph, "causal graph", GRAPH_FIELDS, GRAPH_FIELDS);
  if (graph.schemaVersion !== "tugboat.causal-graph.v1") throw new Error("Unsupported causal graph schemaVersion");
  if (!Array.isArray(graph.nodes) || graph.nodes.length < 1 || graph.nodes.length > 256) throw new Error("Causal graph must contain 1 to 256 nodes");
  const byId = new Map();
  for (const [index, node] of graph.nodes.entries()) {
    exactObject(node, `node[${index}]`, NODE_FIELDS, NODE_FIELDS);
    if (!/^[a-zA-Z0-9._-]{1,128}$/.test(node.id)) throw new Error(`Invalid node ID ${node.id}`);
    if (byId.has(node.id)) throw new Error(`Duplicate node ID ${node.id}`);
    if (!Object.hasOwn(COMPILERS, node.compiler)) throw new Error(`Unknown compiler ${node.compiler}`);
    if (typeof node.version !== "string" || !node.version || !Array.isArray(node.dependencies) || node.dependencies.length > 64) throw new Error(`Invalid node ${node.id}`);
    if (new Set(node.dependencies).size !== node.dependencies.length) throw new Error(`Duplicate dependency on node ${node.id}`);
    byId.set(node.id, node);
  }
  for (const node of byId.values()) for (const dependency of node.dependencies) if (!byId.has(dependency)) throw new Error(`Node ${node.id} has unknown dependency ${dependency}`);
  return byId;
}

function orderedNodes(byId) {
  const result = [];
  const visiting = new Set();
  const visited = new Set();
  function visit(id) {
    if (visiting.has(id)) throw new Error(`Causal graph contains a cycle at ${id}`);
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of [...byId.get(id).dependencies].sort()) visit(dependency);
    visiting.delete(id);
    visited.add(id);
    result.push(byId.get(id));
  }
  for (const id of [...byId.keys()].sort()) visit(id);
  return result;
}

function readCache(file, key, expectedOutput) {
  try {
    const entry = JSON.parse(fs.readFileSync(file, "utf8"));
    if (entry.key !== key || entry.outputDigest !== canonicalDigest(entry.output)) return null;
    if (canonicalJson(entry.output) !== canonicalJson(expectedOutput)) return null;
    return entry.output;
  } catch { return null; }
}

function writeCache(file, entry) {
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${canonicalJson(entry)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, file);
}

export function compileCausalGraph(graph, { cacheDir } = {}) {
  const byId = validateGraph(graph);
  if (typeof cacheDir !== "string" || !cacheDir) throw new Error("cacheDir is required");
  fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
  const cache = fs.realpathSync(cacheDir);
  const outputs = {};
  const nodes = [];
  const hits = [];
  const misses = [];
  for (const node of orderedNodes(byId)) {
    const dependencies = Object.fromEntries([...node.dependencies].sort().map((id) => [id, outputs[id]]));
    const key = canonicalDigest({ compiler: node.compiler, version: node.version, input: node.input, dependencies });
    const file = path.join(cache, `${key.slice("sha256:".length)}.json`);
    const verifiedOutput = COMPILERS[node.compiler]({ input: node.input, dependencies });
    let output = readCache(file, key, verifiedOutput);
    if (output === null) {
      output = verifiedOutput;
      assertNoSecrets(output, `Compiler output ${node.id}`);
      writeCache(file, { key, output, outputDigest: canonicalDigest(output) });
      misses.push(node.id);
    } else hits.push(node.id);
    outputs[node.id] = output;
    nodes.push({ id: node.id, key, outputDigest: canonicalDigest(output), dependencies: [...node.dependencies].sort() });
  }
  const graphDigest = canonicalDigest(nodes);
  return {
    schemaVersion: "tugboat.causal-kernel.v1",
    status: "ready",
    graphDigest,
    nodes,
    outputs,
    execution: { hits: hits.sort(), misses: misses.sort() },
    digest: canonicalDigest({ graphDigest, nodes }),
  };
}
