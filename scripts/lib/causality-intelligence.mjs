import { execFileSync } from "node:child_process";

import { canonicalJson, sha256 } from "./canonical.mjs";
import {
  boundedList,
  canonicalReport,
  missionSummary,
  portableGlobMatch,
  validateObject,
} from "./intelligence-core.mjs";

const PROFILE_FIELDS = ["requirementDependencies", "rules"];
const RULE_FIELDS = ["evidenceIds", "id", "pattern", "requirementIds", "risks", "tests"];
const CHANGE_FIELDS = ["path", "previousPath", "status"];
const CHANGE_STATUSES = new Set(["added", "copied", "deleted", "modified", "renamed", "type_changed", "unmerged", "unknown"]);

function fail(message) {
  throw new Error(message);
}

function sortedUnique(values) {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function strings(value, label, max = 128, { allowEmpty = true } = {}) {
  const result = boundedList(value ?? [], label, max);
  if (!allowEmpty && result.length === 0) fail(`${label} must not be empty`);
  for (const item of result) if (typeof item !== "string" || item.length === 0) fail(`${label} values must be non-empty strings`);
  return sortedUnique(result);
}

function requirementMap(state) {
  const entries = Array.isArray(state?.requirements)
    ? state.requirements.map((item) => [item.id, item])
    : Object.entries(state?.requirements ?? {});
  if (!entries.length) fail("Impact graph needs mission requirements");
  return new Map(entries);
}

function evidenceMap(state) {
  const entries = Array.isArray(state?.evidence)
    ? state.evidence.map((item) => [item.id, item])
    : Object.entries(state?.evidence ?? {});
  return new Map(entries);
}

function validateRule(rule, requirements, evidence, index) {
  validateObject(rule, { label: "impact rule", allowed: RULE_FIELDS, required: ["id", "pattern", "requirementIds"] });
  const requirementIds = strings(rule.requirementIds, `impact rule ${rule.id} requirementIds`, 64, { allowEmpty: false });
  for (const id of requirementIds) if (!requirements.has(id)) fail(`Impact rule ${rule.id} references unknown requirement ${id}`);
  const evidenceIds = strings(rule.evidenceIds, `impact rule ${rule.id} evidenceIds`, 64);
  for (const id of evidenceIds) if (!evidence.has(id)) fail(`Impact rule ${rule.id} references unknown evidence ${id}`);
  const tests = strings(rule.tests, `impact rule ${rule.id} tests`, 64);
  const risks = strings(rule.risks, `impact rule ${rule.id} risks`, 64);
  portableGlobMatch(rule.pattern, "validation/path");
  return { id: rule.id, pattern: rule.pattern, requirementIds, evidenceIds, tests, risks };
}

function validateDependencies(value, requirements) {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("requirementDependencies must be an object");
  const result = {};
  for (const id of Object.keys(value).sort()) {
    if (!requirements.has(id)) fail(`requirementDependencies references unknown requirement ${id}`);
    const dependencies = strings(value[id], `requirementDependencies.${id}`, 64);
    for (const dependency of dependencies) {
      if (!requirements.has(dependency)) fail(`requirementDependencies.${id} references unknown requirement ${dependency}`);
      if (dependency === id) fail(`requirementDependencies.${id} cannot depend on itself`);
    }
    result[id] = dependencies;
  }
  return result;
}

function validateProfile(state, profile) {
  validateObject(profile, { label: "impact profile", allowed: PROFILE_FIELDS, required: ["rules"] });
  const requirements = requirementMap(state);
  const evidence = evidenceMap(state);
  const rules = boundedList(profile.rules, "impact rules", 128, { uniqueBy: "id" })
    .map((rule, index) => validateRule(rule, requirements, evidence, index))
    .sort((left, right) => left.id.localeCompare(right.id));
  if (!rules.length) fail("Impact profile needs at least one rule");
  return { requirementDependencies: validateDependencies(profile.requirementDependencies, requirements), rules };
}

function normalizeChange(change, index) {
  const value = typeof change === "string" ? { path: change, status: "modified" } : change;
  validateObject(value, { label: `change ${index}`, allowed: CHANGE_FIELDS, required: ["path", "status"] });
  if (!CHANGE_STATUSES.has(value.status)) fail(`Change ${value.path} has unsupported status ${value.status}`);
  portableGlobMatch("**", value.path);
  if (value.previousPath !== undefined) portableGlobMatch("**", value.previousPath);
  if (value.status === "renamed" && !value.previousPath) fail(`Renamed change ${value.path} needs previousPath`);
  return { path: value.path, ...(value.previousPath ? { previousPath: value.previousPath } : {}), status: value.status };
}

function normalizeChanges(changes) {
  const normalized = boundedList(changes, "changes", 256).map(normalizeChange);
  const byIdentity = new Map();
  for (const change of normalized) {
    const identity = canonicalJson(change);
    byIdentity.set(identity, change);
  }
  return [...byIdentity.values()].sort((left, right) => left.path.localeCompare(right.path) || left.status.localeCompare(right.status));
}

function transitiveRequirements(directIds, dependencies) {
  const reverse = new Map();
  for (const [dependent, prerequisites] of Object.entries(dependencies)) {
    for (const prerequisite of prerequisites) {
      if (!reverse.has(prerequisite)) reverse.set(prerequisite, []);
      reverse.get(prerequisite).push(dependent);
    }
  }
  for (const values of reverse.values()) values.sort();
  const all = new Set(directIds);
  const queue = [...directIds].sort();
  while (queue.length) {
    const current = queue.shift();
    for (const dependent of reverse.get(current) ?? []) {
      if (all.has(dependent)) continue;
      all.add(dependent);
      queue.push(dependent);
      queue.sort();
    }
  }
  return sortedUnique([...all].filter((id) => !directIds.includes(id)));
}

function edgeKey(edge) {
  return `${edge.from}\0${edge.to}\0${edge.kind}`;
}

const MAX_IMPACT_EDGES = 8192;

export function compileImpactGraph(state, changesInput, profileInput) {
  const profile = validateProfile(state, profileInput);
  const changes = normalizeChanges(changesInput);
  const requirements = requirementMap(state);
  const evidence = evidenceMap(state);
  const direct = new Set();
  const explicitEvidence = new Set();
  const requiredTests = new Set();
  const riskTags = new Set();
  const edges = new Map();
  const unmappedChanges = [];

  function addEdge(edge) {
    const key = edgeKey(edge);
    if (!edges.has(key) && edges.size >= MAX_IMPACT_EDGES) fail(`Impact graph exceeds ${MAX_IMPACT_EDGES} edges`);
    edges.set(key, edge);
  }

  for (const change of changes) {
    const matches = profile.rules.filter((rule) =>
      portableGlobMatch(rule.pattern, change.path)
      || (change.previousPath ? portableGlobMatch(rule.pattern, change.previousPath) : false));
    if (!matches.length) {
      unmappedChanges.push(change);
      continue;
    }
    for (const rule of matches) {
      addEdge({ from: `change:${change.path}`, to: `rule:${rule.id}`, kind: "matches" });
      for (const requirementId of rule.requirementIds) {
        direct.add(requirementId);
        addEdge({ from: `change:${change.path}`, to: `requirement:${requirementId}`, kind: "direct" });
      }
      rule.evidenceIds.forEach((id) => explicitEvidence.add(id));
      rule.tests.forEach((item) => requiredTests.add(item));
      rule.risks.forEach((item) => riskTags.add(item));
    }
  }

  const directRequirementIds = sortedUnique([...direct]);
  const transitiveRequirementIds = transitiveRequirements(directRequirementIds, profile.requirementDependencies);
  const allRequirementIds = sortedUnique([...directRequirementIds, ...transitiveRequirementIds]);
  const impacted = new Set(allRequirementIds);
  for (const [dependent, prerequisites] of Object.entries(profile.requirementDependencies)) {
    for (const prerequisite of prerequisites) {
      if (impacted.has(prerequisite) && impacted.has(dependent)) {
        addEdge({ from: `requirement:${prerequisite}`, to: `requirement:${dependent}`, kind: "dependency" });
      }
    }
  }

  const invalidatedEvidence = new Set(explicitEvidence);
  for (const requirementId of allRequirementIds) {
    for (const id of requirements.get(requirementId)?.evidenceRefs ?? []) invalidatedEvidence.add(id);
  }
  for (const [id, item] of evidence) {
    if ((item.requirementIds ?? []).some((requirementId) => impacted.has(requirementId))) invalidatedEvidence.add(id);
  }
  for (const evidenceId of invalidatedEvidence) {
    const item = evidence.get(evidenceId);
    for (const requirementId of item?.requirementIds ?? []) {
      if (impacted.has(requirementId)) addEdge({ from: `requirement:${requirementId}`, to: `evidence:${evidenceId}`, kind: "invalidates" });
    }
  }

  const gaps = unmappedChanges.map((change) => ({
    code: "unmapped_change",
    path: change.path,
    message: `No ownership rule maps ${change.path} to requirements and proof.`,
  }));
  return canonicalReport("tugboat.proof-impact.v1", {
    status: gaps.length ? "insufficient_evidence" : "ready",
    mission: missionSummary(state),
    inputs: {
      changesDigest: `sha256:${sha256(canonicalJson(changes))}`,
      profileDigest: `sha256:${sha256(canonicalJson(profile))}`,
    },
    changes,
    edges: [...edges.values()].sort((left, right) => edgeKey(left).localeCompare(edgeKey(right))),
    impact: {
      allRequirementIds,
      directRequirementIds,
      invalidatedEvidenceIds: sortedUnique([...invalidatedEvidence]),
      requiredTests: sortedUnique([...requiredTests]),
      riskTags: sortedUnique([...riskTags]),
      transitiveRequirementIds,
    },
    gaps,
    unmappedChanges,
  });
}

function validateRef(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 200 || value.startsWith("-") || !/^[A-Za-z0-9._/~^{}-]+$/.test(value)) {
    fail(`${label} is an unsafe Git ref`);
  }
  return value;
}

function defaultRunGit(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1024 * 1024 });
}

const STATUS_NAMES = {
  A: "added",
  C: "copied",
  D: "deleted",
  M: "modified",
  R: "renamed",
  T: "type_changed",
  U: "unmerged",
};

function parseNameStatus(output) {
  const text = Buffer.isBuffer(output) ? output.toString("utf8") : String(output ?? "");
  if (Buffer.byteLength(text, "utf8") > 1024 * 1024) fail("Git diff output exceeds 1 MiB");
  const tokens = text.split("\0");
  if (tokens.at(-1) === "") tokens.pop();
  const changes = [];
  let index = 0;
  while (index < tokens.length) {
    const rawStatus = tokens[index++];
    if (!rawStatus) fail("Git diff returned an empty status");
    const kind = rawStatus[0];
    const status = STATUS_NAMES[kind] ?? "unknown";
    if (kind === "R" || kind === "C") {
      const previousPath = tokens[index++];
      const currentPath = tokens[index++];
      if (!previousPath || !currentPath) fail(`Git diff ${rawStatus} record is incomplete`);
      changes.push({ path: currentPath, previousPath, status });
    } else {
      const changedPath = tokens[index++];
      if (!changedPath) fail(`Git diff ${rawStatus} record is incomplete`);
      changes.push({ path: changedPath, status });
    }
  }
  return normalizeChanges(changes);
}

export function inspectTrackedChanges(repoDir, base, head, runGit = defaultRunGit) {
  const safeBase = validateRef(base, "base");
  const safeHead = validateRef(head, "head");
  const args = ["diff", "--name-status", "-z", "--find-renames=50%", safeBase, safeHead, "--"];
  const changes = parseNameStatus(runGit(repoDir, args));
  const body = { status: "ready", base: safeBase, head: safeHead, changes };
  return canonicalReport("tugboat.tracked-changes.v1", body);
}
