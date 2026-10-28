import {
  boundedList,
  canonicalReport,
  validateObject,
} from "./intelligence-core.mjs";

const MANIFEST_FIELDS = ["children", "id"];
const CHILD_FIELDS = ["dependencies", "deployAction", "id", "provides", "reportDigest", "requires", "rollbackAction", "rollbackAfter", "stateDigest", "status"];
const CONTRACT_FIELDS = ["name", "version"];
const CHILD_STATUSES = new Set(["blocked", "insufficient_evidence", "ready"]);

function fail(message) {
  throw new Error(message);
}

function strings(value, label, max = 128) {
  const items = boundedList(value ?? [], label, max);
  for (const item of items) if (typeof item !== "string" || item.length === 0) fail(`${label} values must be non-empty strings`);
  return [...new Set(items)].sort((left, right) => left.localeCompare(right));
}

function validDigest(value) {
  return /^sha256:[0-9a-f]{64}$/.test(value ?? "");
}

function contracts(value, label) {
  const items = boundedList(value ?? [], label, 128).map((item) => {
    validateObject(item, { label: "compatibility contract", allowed: CONTRACT_FIELDS, required: CONTRACT_FIELDS });
    return { name: item.name, version: item.version };
  });
  const keys = new Set();
  for (const item of items) {
    const key = `${item.name}\0${item.version}`;
    if (keys.has(key)) fail(`Duplicate ${label} contract ${item.name}@${item.version}`);
    keys.add(key);
  }
  return items.sort((left, right) => left.name.localeCompare(right.name) || left.version.localeCompare(right.version));
}

function validateManifest(input) {
  validateObject(input, { label: "federation manifest", allowed: MANIFEST_FIELDS, required: MANIFEST_FIELDS });
  const children = boundedList(input.children, "federation children", 128, { uniqueBy: "id" }).map((child) => {
    validateObject(child, {
      label: "federation child",
      allowed: CHILD_FIELDS,
      required: ["dependencies", "id", "provides", "requires", "rollbackAfter", "status"],
    });
    if (!CHILD_STATUSES.has(child.status)) fail(`Federation child ${child.id} has unknown status ${child.status}`);
    return {
      dependencies: strings(child.dependencies, `federation child ${child.id} dependencies`),
      deployAction: child.deployAction ?? null,
      id: child.id,
      provides: contracts(child.provides, `federation child ${child.id} provides`),
      reportDigest: child.reportDigest ?? null,
      requires: contracts(child.requires, `federation child ${child.id} requires`),
      rollbackAction: child.rollbackAction ?? null,
      rollbackAfter: strings(child.rollbackAfter, `federation child ${child.id} rollbackAfter`),
      stateDigest: child.stateDigest ?? null,
      status: child.status,
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
  if (!children.length) fail("Federation manifest needs at least one child");
  const ids = new Set(children.map(({ id }) => id));
  for (const child of children) {
    for (const dependency of child.dependencies) {
      if (!ids.has(dependency)) fail(`Federation child ${child.id} references unknown dependency ${dependency}`);
      if (dependency === child.id) fail(`Federation child ${child.id} cannot depend on itself`);
    }
    for (const dependency of child.rollbackAfter) {
      if (!ids.has(dependency)) fail(`Federation child ${child.id} references unknown rollback dependency ${dependency}`);
      if (dependency === child.id) fail(`Federation child ${child.id} cannot roll back after itself`);
    }
  }
  return { children, id: input.id };
}

function canonicalCycle(cycle) {
  const ring = cycle.slice(0, -1);
  const variants = ring.map((_, index) => [...ring.slice(index), ...ring.slice(0, index)]);
  variants.sort((left, right) => left.join("\0").localeCompare(right.join("\0")));
  return [...variants[0], variants[0][0]];
}

function findCycle(ids, dependencies) {
  const color = new Map(ids.map((id) => [id, 0]));
  const stack = [];
  let witness = null;
  function visit(id) {
    if (witness) return;
    color.set(id, 1);
    stack.push(id);
    for (const dependency of [...(dependencies.get(id) ?? [])].sort()) {
      if (color.get(dependency) === 0) visit(dependency);
      else if (color.get(dependency) === 1) {
        const index = stack.lastIndexOf(dependency);
        witness = canonicalCycle([...stack.slice(index), dependency]);
        return;
      }
    }
    stack.pop();
    color.set(id, 2);
  }
  for (const id of ids) if (color.get(id) === 0) visit(id);
  return witness;
}

function topologicalWaves(ids, dependencies) {
  const cycle = findCycle(ids, dependencies);
  if (cycle) return { cycle, waves: [] };
  const completed = new Set();
  const waves = [];
  while (completed.size < ids.length) {
    const wave = ids.filter((id) => !completed.has(id) && [...(dependencies.get(id) ?? [])].every((item) => completed.has(item))).sort();
    if (!wave.length) fail("Acyclic release graph did not produce a ready wave");
    waves.push(wave);
    wave.forEach((id) => completed.add(id));
  }
  return { cycle: null, waves };
}

function dependencyClosure(id, dependencies) {
  const seen = new Set();
  const queue = [...(dependencies.get(id) ?? [])];
  while (queue.length) {
    const current = queue.shift();
    if (seen.has(current)) continue;
    seen.add(current);
    queue.push(...(dependencies.get(current) ?? []));
  }
  return seen;
}

function gapKey(gap) {
  return `${gap.code}\0${gap.childId ?? ""}\0${gap.contract ?? ""}`;
}

export function compileFederation(manifestInput) {
  const manifest = validateManifest(manifestInput);
  const ids = manifest.children.map(({ id }) => id);
  const byId = new Map(manifest.children.map((child) => [child.id, child]));
  const deployDependencies = new Map(manifest.children.map((child) => [child.id, new Set(child.dependencies)]));
  const rollbackDependencies = new Map(manifest.children.map((child) => [child.id, new Set(child.rollbackAfter)]));
  for (const child of manifest.children) {
    for (const dependency of child.dependencies) rollbackDependencies.get(dependency).add(child.id);
  }
  const deploy = topologicalWaves(ids, deployDependencies);
  const rollback = topologicalWaves(ids, rollbackDependencies);
  const gaps = [];
  if (deploy.cycle) gaps.push({ code: "dependency_cycle", childId: null, message: "Deployment dependencies contain a cycle.", witness: deploy.cycle });
  if (rollback.cycle) gaps.push({ code: "rollback_cycle", childId: null, message: "Rollback dependencies contain a cycle.", witness: rollback.cycle });
  for (const child of manifest.children) {
    if (child.status !== "ready") gaps.push({ code: "child_not_ready", childId: child.id, message: `${child.id} is ${child.status}.` });
    if (!validDigest(child.stateDigest) || !validDigest(child.reportDigest)) {
      gaps.push({ code: "child_digest_invalid", childId: child.id, message: `${child.id} is missing a valid state or readiness report digest.` });
    }
    if (!child.deployAction) gaps.push({ code: "deploy_action_missing", childId: child.id, message: `${child.id} has no deploy action.` });
    if (!child.rollbackAction) gaps.push({ code: "rollback_action_missing", childId: child.id, message: `${child.id} has no rollback action.` });
  }

  const compatibility = [];
  for (const child of manifest.children) {
    const providers = dependencyClosure(child.id, deployDependencies);
    for (const requirement of child.requires) {
      const provider = [...providers].sort().map((id) => byId.get(id)).find((candidate) =>
        candidate.provides.some((item) => item.name === requirement.name && item.version === requirement.version));
      if (!provider) {
        gaps.push({
          code: "compatibility_unsatisfied",
          childId: child.id,
          contract: requirement.name,
          message: `${child.id} requires ${requirement.name}@${requirement.version}, but no declared dependency provides it.`,
        });
      } else {
        compatibility.push({ consumerId: child.id, contract: requirement.name, providerId: provider.id, version: requirement.version });
      }
    }
  }
  compatibility.sort((left, right) => left.consumerId.localeCompare(right.consumerId) || left.contract.localeCompare(right.contract));
  gaps.sort((left, right) => gapKey(left).localeCompare(gapKey(right)));
  return canonicalReport("tugboat.federated-release.v1", {
    status: gaps.length ? "blocked" : "ready",
    federationId: manifest.id,
    children: manifest.children,
    compatibility,
    deployWaves: deploy.waves,
    gaps,
    rollbackWaves: rollback.waves,
  });
}
