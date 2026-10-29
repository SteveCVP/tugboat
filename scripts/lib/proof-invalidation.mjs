import { canonicalJson } from "./canonical.mjs";
import { portableSubjectId } from "./certified-changeset.mjs";
import { canonicalDigest } from "./proof-runtime.mjs";
import { assertNoSecrets } from "./security.mjs";

const NODE_KINDS = new Set(["requirement", "boundary", "effect", "symbol", "interface", "resource", "gate", "evidence", "deployment"]);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const TOKEN = /^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*$/;
const MAX_NODES = 4096;
const MAX_EDGES = 16384;

export class ProofInvalidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ProofInvalidationError";
    this.exitCode = 2;
  }
}

function fail(message) {
  throw new ProofInvalidationError(message);
}

function exactObject(value, label, allowed, required = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`Unknown ${label} field ${key}`);
  for (const key of required) if (value[key] === undefined || value[key] === null || value[key] === "") fail(`${label} is missing ${key}`);
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail(`${label} must be a sha256 digest`);
  return value;
}

function validateGraph(graph) {
  if (Buffer.byteLength(canonicalJson(graph)) > 4 * 1024 * 1024) fail("Proof invalidation graph exceeds 4 MiB");
  exactObject(graph, "proof invalidation graph", ["schemaVersion", "bundleDigest", "boundaryManifestDigest", "nodes", "edges"], ["schemaVersion", "bundleDigest", "boundaryManifestDigest", "nodes", "edges"]);
  if (graph.schemaVersion !== "tugboat.proof-invalidation-graph.v1") fail("Unsupported proof invalidation graph schemaVersion");
  digest(graph.bundleDigest, "Graph bundleDigest");
  digest(graph.boundaryManifestDigest, "Graph boundaryManifestDigest");
  if (!Array.isArray(graph.nodes) || graph.nodes.length < 1 || graph.nodes.length > MAX_NODES) fail(`Proof invalidation graph must contain 1 to ${MAX_NODES} nodes`);
  if (!Array.isArray(graph.edges) || graph.edges.length > MAX_EDGES) fail(`Proof invalidation graph may contain at most ${MAX_EDGES} edges`);
  const nodes = graph.nodes.map((node, index) => {
    exactObject(node, "proof node", ["id", "kind", "mandatory"], ["id", "kind", "mandatory"]);
    const id = portableSubjectId(node.id, `Proof node ${index} ID`);
    if (!NODE_KINDS.has(node.kind)) fail(`Unknown proof node kind ${node.kind}`);
    if (typeof node.mandatory !== "boolean") fail(`Proof node ${id} mandatory must be a boolean`);
    if (node.mandatory && node.kind !== "gate") fail(`Only gate nodes may be mandatory: ${id}`);
    return { id, kind: node.kind, mandatory: node.mandatory };
  }).sort((left, right) => left.id.localeCompare(right.id));
  if (new Set(nodes.map((item) => item.id)).size !== nodes.length) fail("Proof node IDs must be unique");
  const byId = new Map(nodes.map((item) => [item.id, item]));
  const edges = graph.edges.map((edge, index) => {
    exactObject(edge, "proof edge", ["from", "to", "kind"], ["from", "to", "kind"]);
    const from = portableSubjectId(edge.from, `Proof edge ${index} from`);
    const to = portableSubjectId(edge.to, `Proof edge ${index} to`);
    if (!byId.has(from)) fail(`Proof edge references unknown node ${from}`);
    if (!byId.has(to)) fail(`Proof edge references unknown node ${to}`);
    if (typeof edge.kind !== "string" || !TOKEN.test(edge.kind)) fail(`Proof edge ${from} -> ${to} has invalid kind`);
    return { from, to, kind: edge.kind };
  }).sort((left, right) => left.from.localeCompare(right.from) || left.to.localeCompare(right.to) || left.kind.localeCompare(right.kind));
  if (new Set(edges.map((item) => `${item.from}\0${item.to}\0${item.kind}`)).size !== edges.length) fail("Proof edges must be unique");
  const adjacency = new Map(nodes.map((item) => [item.id, []]));
  for (const edge of edges) adjacency.get(edge.from).push(edge);
  const visiting = new Set();
  const visited = new Set();
  const stack = [];
  function visit(id) {
    if (visiting.has(id)) {
      const start = stack.indexOf(id);
      fail(`Proof invalidation graph contains a cycle: ${[...stack.slice(start), id].join(" -> ")}`);
    }
    if (visited.has(id)) return;
    visiting.add(id);
    stack.push(id);
    for (const edge of adjacency.get(id)) visit(edge.to);
    stack.pop();
    visiting.delete(id);
    visited.add(id);
  }
  for (const node of nodes) visit(node.id);
  try {
    assertNoSecrets({ ...graph, nodes, edges }, "Proof invalidation graph");
  } catch (error) {
    fail(error.message);
  }
  return { nodes, edges, byId, adjacency };
}

function validateWitness(witness, graph, byId) {
  if (!witness?.semanticProof) fail("Proof invalidation requires semantic verification of the non-interference witness");
  if (witness.verdict !== "ready") fail("Proof invalidation requires a ready witness");
  digest(witness.digest, "Witness digest");
  const body = witness.payload?.body;
  if (!body || typeof body !== "object") fail("Verified witness is missing its bound proof body");
  if (body.bundleDigest !== graph.bundleDigest) fail("Witness bundle digest mismatch");
  if (body.boundaryManifestDigest !== graph.boundaryManifestDigest) fail("Witness boundary manifest digest mismatch");
  if (!Array.isArray(body.effects) || !Array.isArray(body.provenUnaffectedComponentIds)) fail("Verified witness is missing effects or unaffected boundaries");
  const changed = [...new Set(body.effects.map((effect) => effect?.id))].sort();
  if (!changed.length || changed.some((id) => typeof id !== "string")) fail("Verified witness contains no changed effects");
  for (const id of changed) {
    const node = byId.get(id);
    if (!node || node.kind !== "effect") fail(`Witness references unknown changed effect ${id}`);
  }
  const cuts = [...new Set(body.provenUnaffectedComponentIds)].sort();
  for (const id of cuts) {
    const node = byId.get(id);
    if (!node || node.kind !== "boundary") fail(`Witness references unknown unaffected boundary ${id}`);
  }
  return { changed, cuts: new Set(cuts) };
}

function choosePath(existing, candidate) {
  if (!existing) return candidate;
  if (candidate.length !== existing.length) return candidate.length < existing.length ? candidate : existing;
  return candidate.join("\0").localeCompare(existing.join("\0")) < 0 ? candidate : existing;
}

function traverse(roots, adjacency, shouldCut) {
  const reached = new Map();
  const cuts = new Map();
  const queue = roots.map((id) => [id]);
  while (queue.length) {
    const path = queue.shift();
    const id = path.at(-1);
    const prior = reached.get(id);
    const selected = choosePath(prior, path);
    if (prior && selected === prior) continue;
    reached.set(id, selected);
    for (const edge of adjacency.get(id) ?? []) {
      const next = [...path, edge.to];
      if (shouldCut(edge.to)) {
        cuts.set(edge.to, choosePath(cuts.get(edge.to), next));
        continue;
      }
      queue.push(next);
    }
  }
  return { reached, cuts };
}

function cutDescendants(cuts, adjacency, invalidated) {
  const retained = new Map(cuts);
  const queue = [...cuts.values()];
  while (queue.length) {
    const path = queue.shift();
    const id = path.at(-1);
    for (const edge of adjacency.get(id) ?? []) {
      if (invalidated.has(edge.to)) continue;
      const next = [...path, edge.to];
      const prior = retained.get(edge.to);
      const selected = choosePath(prior, next);
      if (prior && selected === prior) continue;
      retained.set(edge.to, selected);
      queue.push(next);
    }
  }
  return retained;
}

export function compileProofInvalidation(graph, { witness }) {
  const validated = validateGraph(graph);
  const witnessBinding = validateWitness(witness, graph, validated.byId);
  const effectTraversal = traverse(witnessBinding.changed, validated.adjacency, (id) => witnessBinding.cuts.has(id));
  const mandatoryRoots = validated.nodes.filter((node) => node.mandatory).map((node) => node.id);
  const mandatoryTraversal = traverse(mandatoryRoots, validated.adjacency, () => false);
  const invalidatedPaths = new Map(effectTraversal.reached);
  for (const [id, path] of mandatoryTraversal.reached) invalidatedPaths.set(id, choosePath(invalidatedPaths.get(id), path));
  const retainedByCut = cutDescendants(effectTraversal.cuts, validated.adjacency, invalidatedPaths);

  const invalidated = [...invalidatedPaths.entries()].map(([id, path]) => {
    const node = validated.byId.get(id);
    const mandatory = node.mandatory && path.length === 1;
    return { id, kind: node.kind, reason: mandatory ? "mandatory_gate" : mandatoryTraversal.reached.has(id) && !effectTraversal.reached.has(id) ? "mandatory_gate_dependency" : "effect_path", witnessPath: path };
  }).sort((left, right) => left.id.localeCompare(right.id));
  const retained = validated.nodes.filter((node) => !invalidatedPaths.has(node.id)).map((node) => {
    const cutPath = retainedByCut.get(node.id);
    return cutPath
      ? { id: node.id, kind: node.kind, reason: "verified_non_interference", witnessPath: cutPath, witnessDigest: witness.digest }
      : { id: node.id, kind: node.kind, reason: "not_reachable_from_changed_effect", witnessPath: [] };
  }).sort((left, right) => left.id.localeCompare(right.id));
  const body = {
    schemaVersion: "tugboat.proof-invalidation.v1",
    status: "ready",
    graphDigest: canonicalDigest({
      schemaVersion: graph.schemaVersion,
      bundleDigest: graph.bundleDigest,
      boundaryManifestDigest: graph.boundaryManifestDigest,
      nodes: validated.nodes,
      edges: validated.edges,
    }),
    bundleDigest: graph.bundleDigest,
    boundaryManifestDigest: graph.boundaryManifestDigest,
    witnessDigest: witness.digest,
    invalidated,
    retained,
    invalidatedEvidenceIds: invalidated.filter((item) => item.kind === "evidence").map((item) => item.id),
    retainedEvidenceIds: retained.filter((item) => item.kind === "evidence").map((item) => item.id),
    invalidatedDeploymentIds: invalidated.filter((item) => item.kind === "deployment").map((item) => item.id),
    mandatoryGateIds: validated.nodes.filter((node) => node.mandatory).map((node) => node.id),
    authority: "invalidation_only",
    functionalTargetProof: "reopen",
  };
  return { ...body, digest: canonicalDigest(body) };
}

export function createNonInterferencePreservation(witness, invalidation) {
  if (!witness?.semanticProof || witness.verdict !== "ready") fail("Preservation proof requires a semantically verified ready witness");
  if (invalidation?.status !== "ready" || invalidation.authority !== "invalidation_only") fail("Preservation proof requires a ready invalidation report");
  if (witness.digest !== invalidation.witnessDigest) fail("Preservation witness digest does not match invalidation report");
  const record = {
    kind: "non_interference",
    authority: "invalidation_only",
    witnessDigest: witness.digest,
    invalidationDigest: invalidation.digest,
    bundleDigest: invalidation.bundleDigest,
    boundaryManifestDigest: invalidation.boundaryManifestDigest,
    retainedNodeIds: invalidation.retained.map((item) => item.id),
    invalidatedNodeIds: invalidation.invalidated.map((item) => item.id),
  };
  return validateNonInterferencePreservation({ ...record, digest: canonicalDigest(record) }, { bundleDigest: invalidation.bundleDigest });
}

export function validateNonInterferencePreservation(record, { bundleDigest } = {}) {
  const fields = [
    "kind", "authority", "witnessDigest", "invalidationDigest", "bundleDigest", "boundaryManifestDigest",
    "retainedNodeIds", "invalidatedNodeIds", "digest",
  ];
  exactObject(record, "non-interference preservation", fields, fields);
  if (record.kind !== "non_interference" || record.authority !== "invalidation_only") fail("Non-interference preservation must have invalidation_only authority");
  for (const field of ["witnessDigest", "invalidationDigest", "bundleDigest", "boundaryManifestDigest", "digest"]) digestValue(record[field], `Preservation ${field}`);
  if (bundleDigest !== undefined && record.bundleDigest !== bundleDigest) fail("Non-interference preservation bundle digest mismatch");
  const retainedNodeIds = nodeIds(record.retainedNodeIds, "retainedNodeIds");
  const invalidatedNodeIds = nodeIds(record.invalidatedNodeIds, "invalidatedNodeIds");
  if (retainedNodeIds.some((id) => invalidatedNodeIds.includes(id))) fail("Preservation node cannot be both retained and invalidated");
  const body = {
    kind: record.kind,
    authority: record.authority,
    witnessDigest: record.witnessDigest,
    invalidationDigest: record.invalidationDigest,
    bundleDigest: record.bundleDigest,
    boundaryManifestDigest: record.boundaryManifestDigest,
    retainedNodeIds,
    invalidatedNodeIds,
  };
  if (record.digest !== canonicalDigest(body)) fail("Non-interference preservation digest mismatch");
  return { ...body, digest: record.digest };
}

function digestValue(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail(`${label} must be a sha256 digest`);
  return value;
}

function nodeIds(value, label) {
  if (!Array.isArray(value) || value.length > MAX_NODES) fail(`Preservation ${label} must be a bounded array`);
  const ids = value.map((id) => portableSubjectId(id, `Preservation ${label} item`)).sort();
  if (new Set(ids).size !== ids.length) fail(`Preservation ${label} contains duplicates`);
  return ids;
}
