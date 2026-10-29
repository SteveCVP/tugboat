import {
  boundedList,
  canonicalReport,
  validateObject,
} from "./intelligence-core.mjs";

const GRAPH_FIELDS = ["edges", "nodes"];
const NODE_FIELDS = ["authorities", "classification", "id", "type"];
const EDGE_FIELDS = ["from", "id", "sanitizer", "to"];
const SANITIZER_REF_FIELDS = ["id", "proofDigest"];
const POLICY_FIELDS = ["approvedSanitizers", "classifications", "sinks"];
const SINK_FIELDS = ["allowedAuthorities", "maxClassification", "nodeId"];
const SANITIZER_FIELDS = ["fromClassification", "id", "proofDigest", "toClassification"];
const NODE_TYPES = new Set(["artifact", "bundle", "environment", "service", "worker"]);

function fail(message) {
  throw new Error(message);
}

function strings(value, label, max = 64) {
  const result = boundedList(value ?? [], label, max);
  for (const item of result) if (typeof item !== "string" || item.length === 0) fail(`${label} values must be non-empty strings`);
  return [...new Set(result)].sort((left, right) => left.localeCompare(right));
}

function validateDigest(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? "")) fail(`${label} must be a SHA-256 digest`);
  return value;
}

function validatePolicy(input) {
  validateObject(input, { label: "trust policy", allowed: POLICY_FIELDS, required: POLICY_FIELDS });
  const rawClassifications = boundedList(input.classifications, "classifications", 16);
  for (const item of rawClassifications) if (typeof item !== "string" || item.length === 0) fail("classifications values must be non-empty strings");
  const classifications = [...rawClassifications];
  if (new Set(classifications).size !== rawClassifications.length) {
    const duplicate = rawClassifications.find((item, index) => rawClassifications.indexOf(item) !== index);
    fail(`Duplicate classification ${duplicate}`);
  }
  if (!classifications.length) fail("Trust policy needs at least one classification");
  const classificationSet = new Set(classifications);
  const sinks = boundedList(input.sinks, "trust sinks", 128, { uniqueBy: "nodeId" }).map((sink) => {
    validateObject(sink, { label: "trust sink", allowed: SINK_FIELDS, required: SINK_FIELDS });
    if (!classificationSet.has(sink.maxClassification)) fail(`Sink ${sink.nodeId} has unknown classification ${sink.maxClassification}`);
    return { nodeId: sink.nodeId, maxClassification: sink.maxClassification, allowedAuthorities: strings(sink.allowedAuthorities, `sink ${sink.nodeId} allowedAuthorities`) };
  }).sort((left, right) => left.nodeId.localeCompare(right.nodeId));
  const approvedSanitizers = boundedList(input.approvedSanitizers, "approved sanitizers", 64, { uniqueBy: "id" }).map((sanitizer) => {
    validateObject(sanitizer, { label: "approved sanitizer", allowed: SANITIZER_FIELDS, required: SANITIZER_FIELDS });
    if (!classificationSet.has(sanitizer.fromClassification)) fail(`Sanitizer ${sanitizer.id} has unknown fromClassification ${sanitizer.fromClassification}`);
    if (!classificationSet.has(sanitizer.toClassification)) fail(`Sanitizer ${sanitizer.id} has unknown toClassification ${sanitizer.toClassification}`);
    if (classifications.indexOf(sanitizer.toClassification) >= classifications.indexOf(sanitizer.fromClassification)) {
      fail(`Sanitizer ${sanitizer.id} must lower classification`);
    }
    return { ...sanitizer, proofDigest: validateDigest(sanitizer.proofDigest, `Sanitizer ${sanitizer.id} proofDigest`) };
  }).sort((left, right) => left.id.localeCompare(right.id));
  return { approvedSanitizers, classifications, sinks };
}

function validateGraph(input, policy) {
  validateObject(input, { label: "trust graph", allowed: GRAPH_FIELDS, required: GRAPH_FIELDS });
  const classificationSet = new Set(policy.classifications);
  const nodes = boundedList(input.nodes, "trust nodes", 128, { uniqueBy: "id" }).map((node) => {
    validateObject(node, { label: "trust node", allowed: NODE_FIELDS, required: NODE_FIELDS });
    if (!NODE_TYPES.has(node.type)) fail(`Trust node ${node.id} has unknown type ${node.type}`);
    if (!classificationSet.has(node.classification)) fail(`Trust node ${node.id} has unknown classification ${node.classification}`);
    return { id: node.id, type: node.type, classification: node.classification, authorities: strings(node.authorities, `trust node ${node.id} authorities`) };
  }).sort((left, right) => left.id.localeCompare(right.id));
  const nodeIds = new Set(nodes.map(({ id }) => id));
  for (const sink of policy.sinks) if (!nodeIds.has(sink.nodeId)) fail(`Unknown sink node ${sink.nodeId}`);
  const edges = boundedList(input.edges, "trust edges", 256, { uniqueBy: "id" }).map((edge) => {
    validateObject(edge, { label: "trust edge", allowed: EDGE_FIELDS, required: ["id", "from", "to"] });
    if (!nodeIds.has(edge.from)) fail(`Trust edge ${edge.id} references unknown node ${edge.from}`);
    if (!nodeIds.has(edge.to)) fail(`Trust edge ${edge.id} references unknown node ${edge.to}`);
    let sanitizer;
    if (edge.sanitizer !== undefined) {
      validateObject(edge.sanitizer, { label: "sanitizer reference", allowed: SANITIZER_REF_FIELDS, required: SANITIZER_REF_FIELDS });
      sanitizer = { id: edge.sanitizer.id, proofDigest: validateDigest(edge.sanitizer.proofDigest, `Trust edge ${edge.id} sanitizer proofDigest`) };
    }
    return { id: edge.id, from: edge.from, to: edge.to, ...(sanitizer ? { sanitizer } : {}) };
  }).sort((left, right) => left.id.localeCompare(right.id));
  return { edges, nodes };
}

function cycleWitnesses(nodes, edges) {
  const adjacency = new Map(nodes.map(({ id }) => [id, []]));
  for (const edge of edges) adjacency.get(edge.from).push(edge.to);
  for (const targets of adjacency.values()) targets.sort();
  const color = new Map(nodes.map(({ id }) => [id, 0]));
  const stack = [];
  const cycles = new Map();
  function canonicalCycle(cycle) {
    const ring = cycle.slice(0, -1);
    const variants = ring.map((_, index) => [...ring.slice(index), ...ring.slice(0, index)]);
    variants.sort((left, right) => left.join("\0").localeCompare(right.join("\0")));
    return [...variants[0], variants[0][0]];
  }
  function visit(id) {
    color.set(id, 1);
    stack.push(id);
    for (const target of adjacency.get(id)) {
      if (color.get(target) === 0) visit(target);
      else if (color.get(target) === 1) {
        const index = stack.lastIndexOf(target);
        const cycle = canonicalCycle([...stack.slice(index), target]);
        cycles.set(cycle.join("\0"), cycle);
      }
    }
    stack.pop();
    color.set(id, 2);
  }
  for (const { id } of nodes) if (color.get(id) === 0) visit(id);
  return [...cycles.values()].sort((left, right) => left.join("\0").localeCompare(right.join("\0")));
}

function violationKey(item) {
  return `${item.code}\0${item.nodeId ?? ""}\0${item.edgeId ?? ""}\0${(item.witnessPath ?? []).join("/")}`;
}

export function compileTrustGraph(graphInput, policyInput) {
  const policy = validatePolicy(policyInput);
  const graph = validateGraph(graphInput, policy);
  const classificationRank = new Map(policy.classifications.map((item, index) => [item, index]));
  const sanitizers = new Map(policy.approvedSanitizers.map((item) => [item.id, item]));
  const state = new Map(graph.nodes.map((node) => [node.id, {
    classification: node.classification,
    classificationWitness: [node.id],
    authorities: new Set(node.authorities),
    authorityWitness: new Map(node.authorities.map((authority) => [authority, [node.id]])),
  }]));
  const violations = new Map();

  for (const edge of graph.edges) {
    if (!edge.sanitizer) continue;
    const approved = sanitizers.get(edge.sanitizer.id);
    if (!approved || approved.proofDigest !== edge.sanitizer.proofDigest) {
      const item = {
        code: "unproved_sanitizer",
        edgeId: edge.id,
        message: `${edge.id} attempts to lower taint without the approved sanitizer proof.`,
        nodeId: edge.to,
        witnessPath: [edge.from, edge.id, edge.to],
      };
      violations.set(violationKey(item), item);
    }
  }

  const maxPasses = Math.max(1, graph.nodes.length * Math.max(1, graph.edges.length));
  for (let pass = 0; pass < maxPasses; pass += 1) {
    let changed = false;
    for (const edge of graph.edges) {
      const source = state.get(edge.from);
      const target = state.get(edge.to);
      let candidateClassification = source.classification;
      let candidateWitness = [...source.classificationWitness, edge.to];
      if (edge.sanitizer) {
        const approved = sanitizers.get(edge.sanitizer.id);
        if (approved && approved.proofDigest === edge.sanitizer.proofDigest
          && classificationRank.get(candidateClassification) === classificationRank.get(approved.fromClassification)) {
          candidateClassification = approved.toClassification;
          candidateWitness = [edge.to];
        }
      }
      if (classificationRank.get(candidateClassification) > classificationRank.get(target.classification)) {
        target.classification = candidateClassification;
        target.classificationWitness = candidateWitness;
        changed = true;
      }
      for (const authority of source.authorities) {
        if (target.authorities.has(authority)) continue;
        target.authorities.add(authority);
        target.authorityWitness.set(authority, [...source.authorityWitness.get(authority), edge.to]);
        changed = true;
      }
    }
    if (!changed) break;
    if (pass === maxPasses - 1) fail("Trust propagation did not converge within the graph bound");
  }

  for (const cycle of cycleWitnesses(graph.nodes, graph.edges)) {
    const item = { code: "flow_cycle", edgeId: null, message: "Directed trust flow contains a cycle.", nodeId: cycle[0], witnessPath: cycle };
    violations.set(violationKey(item), item);
  }
  for (const sink of policy.sinks) {
    const effective = state.get(sink.nodeId);
    if (classificationRank.get(effective.classification) > classificationRank.get(sink.maxClassification)) {
      const item = {
        code: "sensitivity_overflow",
        edgeId: null,
        message: `${sink.nodeId} receives ${effective.classification} data above its ${sink.maxClassification} ceiling.`,
        nodeId: sink.nodeId,
        witnessPath: effective.classificationWitness,
      };
      violations.set(violationKey(item), item);
    }
    const allowed = new Set(sink.allowedAuthorities);
    const overflow = [...effective.authorities].filter((authority) => !allowed.has(authority)).sort();
    if (overflow.length) {
      const first = overflow[0];
      const item = {
        authorities: overflow,
        code: "authority_overflow",
        edgeId: null,
        message: `${sink.nodeId} receives authorities above its declared ceiling: ${overflow.join(", ")}.`,
        nodeId: sink.nodeId,
        witnessPath: effective.authorityWitness.get(first),
      };
      violations.set(violationKey(item), item);
    }
  }
  const compiledNodes = graph.nodes.map((node) => ({
    authorities: node.authorities,
    classification: node.classification,
    effectiveAuthorities: [...state.get(node.id).authorities].sort(),
    effectiveClassification: state.get(node.id).classification,
    id: node.id,
    type: node.type,
  }));
  const compiledViolations = [...violations.values()].sort((left, right) => violationKey(left).localeCompare(violationKey(right)));
  return canonicalReport("tugboat.trust-taint.v1", {
    status: compiledViolations.length ? "blocked" : "ready",
    classifications: policy.classifications,
    edges: graph.edges,
    nodes: compiledNodes,
    violations: compiledViolations,
  });
}
