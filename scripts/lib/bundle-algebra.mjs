import { canonicalReport } from "./intelligence-core.mjs";
import { exactObject } from "./proof-runtime.mjs";
import { validateAnalyzerReport } from "./analyzer-protocol.mjs";

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const DOMAINS = new Set(["path", "interface", "schema", "infrastructure", "workflow"]);
const ACCESSES = new Set(["read", "write"]);

function compareText(left, right) { return left.localeCompare(right); }

function shortString(value, label, maximum = 4096) {
  if (typeof value !== "string" || !value || Buffer.byteLength(value) > maximum || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function normalizeEffect(effect, bundleId) {
  if (!effect || typeof effect !== "object" || Array.isArray(effect)) throw new Error(`Bundle ${bundleId} effect must be an object`);
  const id = shortString(effect.id, `Bundle ${bundleId} effect id`);
  if (effect.domain !== undefined) {
    exactObject(effect, `bundle ${bundleId} algebra effect`, ["id", "domain", "subject", "access", "operation", "sourceDigest", "signature", "sequence"], ["id", "domain", "subject", "access", "operation", "sourceDigest"]);
    if (!DOMAINS.has(effect.domain)) throw new Error(`Bundle ${bundleId} effect domain is invalid`);
    if (!ACCESSES.has(effect.access)) throw new Error(`Bundle ${bundleId} effect access is invalid`);
    shortString(effect.subject, `Bundle ${bundleId} effect subject`);
    shortString(effect.operation, `Bundle ${bundleId} effect operation`);
    digest(effect.sourceDigest, `Bundle ${bundleId} effect sourceDigest`);
    if (effect.signature !== undefined) digest(effect.signature, `Bundle ${bundleId} effect signature`);
    if (effect.sequence !== undefined && (!Number.isInteger(effect.sequence) || effect.sequence < 0)) throw new Error(`Bundle ${bundleId} effect sequence is invalid`);
    return { id, domain: effect.domain, subject: effect.subject, access: effect.access, operation: effect.operation, sourceDigest: effect.sourceDigest, ...(effect.signature ? { signature: effect.signature } : {}), ...(effect.sequence !== undefined ? { sequence: effect.sequence } : {}) };
  }
  shortString(effect.path, `Bundle ${bundleId} path effect path`);
  digest(effect.sourceDigest, `Bundle ${bundleId} path effect sourceDigest`);
  return { id, domain: "path", subject: effect.path, access: "write", operation: effect.change ?? "modify", sourceDigest: effect.sourceDigest };
}

function issue(code, bundleId, message, subject = `bundle:${bundleId}`) {
  return { code, leftBundleId: bundleId, rightBundleId: null, subjectIds: [subject], message, witnessPath: [`bundle:${bundleId}`, subject] };
}

function normalizeCandidate(candidate) {
  exactObject(candidate, "bundle algebra candidate", ["bundle", "witness", "analyzerReports"], ["bundle", "witness"]);
  const bundle = candidate.bundle;
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("Bundle algebra candidate bundle is invalid");
  digest(bundle.digest, "Bundle algebra candidate bundle digest");
  const id = shortString(bundle.payload?.id, "Bundle algebra candidate id");
  const dependencies = bundle.payload?.selection?.bundleDependencies ?? [];
  if (!Array.isArray(dependencies) || dependencies.length > 64 || new Set(dependencies).size !== dependencies.length) throw new Error(`Bundle ${id} dependencies are invalid`);
  dependencies.forEach((dependency) => shortString(dependency, `Bundle ${id} dependency`));
  const witness = candidate.witness;
  if (!witness || typeof witness !== "object" || Array.isArray(witness)) throw new Error(`Bundle ${id} witness is invalid`);
  const body = witness.payload?.body ?? {};
  const problems = [];
  digest(witness.digest, `Bundle ${id} witness digest`);
  if (witness.semanticProof !== true) problems.push(issue("unverified_witness", id, "Commutativity requires a semantically recomputed non-interference witness."));
  if (body.bundleId !== id || body.bundleDigest !== bundle.digest) problems.push(issue("stale_witness", id, "The witness is not bound to the current bundle id and digest."));
  if (!DIGEST.test(body.boundaryManifestDigest ?? "")) problems.push(issue("stale_witness", id, "The witness has no current boundary-manifest digest."));
  const uncertainty = Array.isArray(body.uncertainty) ? body.uncertainty : [];
  for (const gap of uncertainty) {
    const code = typeof gap?.code === "string" && gap.code ? gap.code : "unknown_effect";
    const subject = typeof gap?.sourceId === "string" && gap.sourceId ? gap.sourceId : `bundle:${id}`;
    problems.push(issue(code, id, typeof gap?.message === "string" && gap.message ? gap.message : "An unclassified effect prevents commutativity proof.", subject));
  }
  if (witness.verdict !== "ready" && uncertainty.length === 0) problems.push(issue("witness_not_ready", id, "The non-interference witness is not ready."));
  const effects = (Array.isArray(body.effects) ? body.effects : []).map((effect) => normalizeEffect(effect, id));
  const analyzerReports = candidate.analyzerReports ?? [];
  if (!Array.isArray(analyzerReports) || analyzerReports.length > 64) throw new Error(`Bundle ${id} analyzerReports are invalid`);
  const domainForAnalyzer = (analyzerId) => {
    if (["openapi", "graphql", "typescript", "python", "go"].includes(analyzerId)) return "interface";
    if (analyzerId === "sql") return "schema";
    if (analyzerId === "github-actions") return "workflow";
    return "infrastructure";
  };
  for (const analyzerReport of analyzerReports) {
    validateAnalyzerReport(analyzerReport);
    if (analyzerReport.status === "insufficient_evidence") problems.push(issue("analyzer_insufficient_evidence", id, `Analyzer ${analyzerReport.analyzer.id} has unresolved uncertainty.`, `analyzer:${analyzerReport.analyzer.id}`));
    if (analyzerReport.status === "blocked") problems.push(issue("analyzer_breaking_change", id, `Analyzer ${analyzerReport.analyzer.id} reports a breaking change.`, `analyzer:${analyzerReport.analyzer.id}`));
    for (const analyzerEffect of analyzerReport.effects) effects.push({
      id: `analyzer:${analyzerReport.analyzer.id}:${analyzerEffect.id}`,
      domain: domainForAnalyzer(analyzerReport.analyzer.id),
      subject: analyzerEffect.subject,
      access: "write",
      operation: analyzerEffect.change,
      sourceDigest: analyzerReport.digest,
    });
  }
  effects.sort((left, right) => compareText(`${left.domain}:${left.subject}:${left.id}`, `${right.domain}:${right.subject}:${right.id}`));
  if (new Set(effects.map((effect) => effect.id)).size !== effects.length) throw new Error(`Bundle ${id} effect ids must be unique`);
  return { id, bundleDigest: bundle.digest, boundaryDigest: body.boundaryManifestDigest ?? null, dependencies: [...dependencies].sort(compareText), effects, witnessDigest: witness.digest, problems };
}

function dependencyGraph(candidates) {
  const ids = new Set(candidates.map((candidate) => candidate.id));
  const outgoing = new Map(candidates.map((candidate) => [candidate.id, []]));
  const indegree = new Map(candidates.map((candidate) => [candidate.id, 0]));
  const problems = [];
  for (const candidate of candidates) {
    for (const dependency of candidate.dependencies) {
      if (!ids.has(dependency)) {
        problems.push(issue("unknown_dependency", candidate.id, `Bundle ${candidate.id} depends on absent bundle ${dependency}.`, `bundle:${dependency}`));
        continue;
      }
      outgoing.get(dependency).push(candidate.id);
      indegree.set(candidate.id, indegree.get(candidate.id) + 1);
    }
  }
  for (const values of outgoing.values()) values.sort(compareText);
  return { outgoing, indegree, problems };
}

function shortestPath(outgoing, start, target) {
  const queue = [[start]];
  const seen = new Set([start]);
  while (queue.length) {
    const current = queue.shift();
    const last = current.at(-1);
    if (last === target) return current;
    for (const next of outgoing.get(last) ?? []) {
      if (next === target) return [...current, next];
      if (!seen.has(next)) { seen.add(next); queue.push([...current, next]); }
    }
  }
  return null;
}

function findCycle(outgoing, ids) {
  for (const start of ids) {
    const queue = [[start]];
    while (queue.length) {
      const current = queue.shift();
      const last = current.at(-1);
      for (const next of outgoing.get(last) ?? []) {
        if (next === start) return [...current, start];
        if (!current.includes(next) && current.length <= ids.length) queue.push([...current, next]);
      }
    }
  }
  return null;
}

function topologicalOrder(candidates, graph) {
  const indegree = new Map(graph.indegree);
  const ready = candidates.map((candidate) => candidate.id).filter((id) => indegree.get(id) === 0).sort(compareText);
  const order = [];
  while (ready.length) {
    const id = ready.shift();
    order.push(id);
    for (const next of graph.outgoing.get(id) ?? []) {
      indegree.set(next, indegree.get(next) - 1);
      if (indegree.get(next) === 0) { ready.push(next); ready.sort(compareText); }
    }
  }
  for (const id of candidates.map((candidate) => candidate.id).sort(compareText)) if (!order.includes(id)) order.push(id);
  return order;
}

function collisionCode(domain, leftAccess, rightAccess, transitive) {
  if (leftAccess !== rightAccess) return transitive ? "transitive_read_write_hazard" : "read_write_hazard";
  if (leftAccess === "read") return null;
  return { path: "overlapping_write", interface: "interface_conflict", schema: "schema_order_conflict", infrastructure: "infrastructure_collision", workflow: "workflow_collision" }[domain];
}

function pairReport(left, right, graph) {
  const forward = shortestPath(graph.outgoing, left.id, right.id);
  const reverse = shortestPath(graph.outgoing, right.id, left.id);
  const dependencyPath = forward ?? reverse;
  const requiredOrder = dependencyPath ? [dependencyPath[0], dependencyPath.at(-1)] : [];
  const hazards = [];
  const rightByKey = new Map();
  for (const effect of right.effects) {
    const key = `${effect.domain}:${effect.subject}`;
    if (!rightByKey.has(key)) rightByKey.set(key, []);
    rightByKey.get(key).push(effect);
  }
  for (const leftEffect of left.effects) {
    for (const rightEffect of rightByKey.get(`${leftEffect.domain}:${leftEffect.subject}`) ?? []) {
      const transitive = Boolean(dependencyPath && dependencyPath.length > 2 && leftEffect.access !== rightEffect.access);
      const code = collisionCode(leftEffect.domain, leftEffect.access, rightEffect.access, transitive);
      if (!code) continue;
      const subject = `${leftEffect.domain}:${leftEffect.subject}`;
      hazards.push({
        code,
        leftBundleId: left.id,
        rightBundleId: right.id,
        subjectIds: [subject],
        message: `${left.id} ${leftEffect.access}s and ${right.id} ${rightEffect.access}s the same ${leftEffect.domain} subject ${leftEffect.subject}.`,
        witnessPath: transitive ? [...dependencyPath.map((id) => `bundle:${id}`), subject] : [`bundle:${left.id}`, subject, `bundle:${right.id}`],
      });
    }
  }
  hazards.sort((a, b) => compareText(`${a.code}:${a.subjectIds.join(",")}`, `${b.code}:${b.subjectIds.join(",")}`));
  return { leftBundleId: left.id, rightBundleId: right.id, commutes: hazards.length === 0 && !dependencyPath, composable: hazards.length === 0, requiredOrder, hazards };
}

function hazardSort(left, right) {
  return compareText(`${left.leftBundleId}:${left.rightBundleId ?? ""}:${left.code}:${left.subjectIds.join(",")}`, `${right.leftBundleId}:${right.rightBundleId ?? ""}:${right.code}:${right.subjectIds.join(",")}`);
}

export function compileBundleAlgebra({ candidates, proposedOrder } = {}) {
  if (!Array.isArray(candidates) || candidates.length < 1 || candidates.length > 32) throw new Error("Bundle algebra needs 1 to 32 candidates");
  const normalized = candidates.map(normalizeCandidate).sort((left, right) => compareText(left.id, right.id));
  if (new Set(normalized.map((candidate) => candidate.id)).size !== normalized.length) throw new Error("Bundle algebra candidate ids must be unique");
  const graph = dependencyGraph(normalized);
  const canonicalOrder = topologicalOrder(normalized, graph);
  const hazards = [...normalized.flatMap((candidate) => candidate.problems), ...graph.problems];
  const boundaryDigests = [...new Set(normalized.map((candidate) => candidate.boundaryDigest).filter(Boolean))];
  if (boundaryDigests.length > 1) hazards.push({ code: "boundary_mismatch", leftBundleId: normalized[0].id, rightBundleId: normalized.at(-1).id, subjectIds: boundaryDigests.map((value) => `boundary:${value}`), message: "Bundles were certified against different boundary manifests and cannot share a commutativity proof.", witnessPath: normalized.map((candidate) => `bundle:${candidate.id}`) });
  const cycle = findCycle(graph.outgoing, normalized.map((candidate) => candidate.id));
  if (cycle) hazards.push({ code: "dependency_cycle", leftBundleId: cycle[0], rightBundleId: cycle[1] ?? null, subjectIds: cycle.slice(0, -1).map((id) => `bundle:${id}`), message: `Bundle dependencies contain a cycle: ${cycle.join(" -> ")}.`, witnessPath: cycle.map((id) => `bundle:${id}`) });
  if (proposedOrder !== undefined) {
    if (!Array.isArray(proposedOrder) || proposedOrder.length !== normalized.length || new Set(proposedOrder).size !== proposedOrder.length || proposedOrder.some((id) => !normalized.some((candidate) => candidate.id === id))) throw new Error("Proposed bundle order must contain every candidate exactly once");
    const position = new Map(proposedOrder.map((id, index) => [id, index]));
    for (const candidate of normalized) for (const dependency of candidate.dependencies) {
      if (position.has(dependency) && position.get(dependency) > position.get(candidate.id)) hazards.push({ code: "dependency_inversion", leftBundleId: dependency, rightBundleId: candidate.id, subjectIds: [`bundle:${dependency}`, `bundle:${candidate.id}`], message: `Proposed order places ${candidate.id} before dependency ${dependency}.`, witnessPath: [`bundle:${candidate.id}`, `bundle:${dependency}`] });
    }
  }
  const pairwiseMatrix = [];
  for (let leftIndex = 0; leftIndex < normalized.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < normalized.length; rightIndex += 1) {
      const pair = pairReport(normalized[leftIndex], normalized[rightIndex], graph);
      pairwiseMatrix.push(pair);
      hazards.push(...pair.hazards);
    }
  }
  hazards.sort(hazardSort);
  const insufficiencyCodes = new Set(["stale_witness", "unverified_witness", "witness_not_ready", "unknown_dependency", "boundary_mismatch", "analyzer_insufficient_evidence"]);
  const insufficient = hazards.some((hazard) => insufficiencyCodes.has(hazard.code) || normalized.some((candidate) => candidate.problems.includes(hazard) && !["dependency_cycle", "dependency_inversion"].includes(hazard.code)));
  const conflict = hazards.some((hazard) => ["overlapping_write", "read_write_hazard", "transitive_read_write_hazard", "interface_conflict", "schema_order_conflict", "infrastructure_collision", "workflow_collision", "dependency_cycle", "dependency_inversion", "analyzer_breaking_change"].includes(hazard.code));
  const status = insufficient ? "insufficient_evidence" : conflict ? "blocked" : "ready";
  const hasOrdering = normalized.some((candidate) => candidate.dependencies.length > 0);
  const verdict = status === "insufficient_evidence" ? "insufficient_evidence" : status === "blocked" ? "conflict" : hasOrdering ? "ordered" : "commute";
  return canonicalReport("tugboat.bundle-algebra.v1", {
    status,
    verdict,
    executionAuthorized: false,
    candidates: normalized.map((candidate) => ({ id: candidate.id, bundleDigest: candidate.bundleDigest, witnessDigest: candidate.witnessDigest, effectCount: candidate.effects.length, dependencies: candidate.dependencies })),
    canonicalOrder,
    pairwiseMatrix,
    hazards,
    compositionPlan: { dryRun: true, admissible: status === "ready", order: canonicalOrder, reason: status === "ready" ? "Every pair has exact effect comparison and all dependency constraints are satisfied." : "Composition is not admissible until every reported counterexample is resolved." },
    proofBasis: { exactEffectComparison: true, coveredPairCount: pairwiseMatrix.length, expectedPairCount: normalized.length * (normalized.length - 1) / 2, witnessBindingRequired: true, uncertaintyFailsClosed: true },
  });
}
