import { canonicalJson, sha256 } from "./canonical.mjs";
import {
  boundedList,
  canonicalReport,
  missionSummary,
  normalizeObservedAt,
  validateObject,
} from "./intelligence-core.mjs";

const FRESHNESS_POLICY_FIELDS = [
  "expectedDeploymentSha",
  "expiringWithinHours",
  "ttlHoursByKind",
  "volatilityHoursByRequirement",
];
const EVIDENCE_KINDS = new Set(["browser", "command", "deployment", "operator"]);

function fail(message) {
  throw new Error(message);
}

function valuesById(value) {
  return Array.isArray(value) ? value : Object.values(value ?? {});
}

function requirementMap(state) {
  const requirements = new Map(valuesById(state?.requirements).map((item) => [item.id, item]));
  if (!requirements.size) fail("Proof intelligence needs mission requirements");
  return requirements;
}

function hours(value, label, { allowZero = false } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value) || (allowZero ? value < 0 : value <= 0) || value > 87_600) {
    fail(`${label} must be a ${allowZero ? "non-negative" : "positive"} number no greater than 87600`);
  }
  return value;
}

function validateHoursMap(value, label, allowedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const result = {};
  for (const key of Object.keys(value).sort()) {
    if (allowedKeys && !allowedKeys.has(key)) fail(`${label} references unknown ${allowedKeys === EVIDENCE_KINDS ? "evidence kind" : "requirement"} ${key}`);
    result[key] = hours(value[key], `${label}.${key}`);
  }
  return result;
}

function validateFreshnessPolicy(state, input) {
  validateObject(input, { label: "freshness policy", allowed: FRESHNESS_POLICY_FIELDS, required: ["ttlHoursByKind"] });
  const requirements = requirementMap(state);
  const ttlHoursByKind = validateHoursMap(input.ttlHoursByKind, "ttlHoursByKind", EVIDENCE_KINDS);
  const volatilityHoursByRequirement = input.volatilityHoursByRequirement === undefined
    ? {}
    : validateHoursMap(input.volatilityHoursByRequirement, "volatilityHoursByRequirement", new Set(requirements.keys()));
  const expiringWithinHours = hours(input.expiringWithinHours ?? 0, "expiringWithinHours", { allowZero: true });
  if (input.expectedDeploymentSha !== undefined && !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(input.expectedDeploymentSha)) {
    fail("expectedDeploymentSha must be a full lowercase Git object ID");
  }
  return {
    ...(input.expectedDeploymentSha ? { expectedDeploymentSha: input.expectedDeploymentSha } : {}),
    expiringWithinHours,
    ttlHoursByKind,
    volatilityHoursByRequirement,
  };
}

function verifyReportDigest(report, label, schemaVersion) {
  if (!report || typeof report !== "object" || Array.isArray(report)) fail(`${label} must be a report object`);
  if (report.schemaVersion !== schemaVersion) fail(`${label} must use ${schemaVersion}`);
  if (!/^sha256:[0-9a-f]{64}$/.test(report.digest ?? "")) fail(`${label} digest is missing or invalid`);
  const { digest, ...body } = report;
  const expected = `sha256:${sha256(canonicalJson(body))}`;
  if (digest !== expected) fail(`${label} digest does not match its contents`);
  return report;
}

function verifyMissionReport(report, label, schemaVersion, state) {
  const verified = verifyReportDigest(report, label, schemaVersion);
  if (typeof verified.mission?.id !== "string" || verified.mission.id.length === 0) fail(`${label} mission id is required`);
  if (verified.mission.id !== state.metadata.id) fail(`${label} mission ${verified.mission.id} does not match ${state.metadata.id}`);
  return verified;
}

function invalidatedByAmendment(state) {
  const invalidated = new Set();
  for (const amendment of valuesById(state.amendments)) {
    for (const value of Object.values(amendment.invalidatedProof ?? {})) {
      for (const evidenceId of value.evidenceRefs ?? []) invalidated.add(evidenceId);
    }
  }
  return invalidated;
}

function reason(code, message) {
  return { code, message };
}

export function compileEvidenceFreshness(state, policyInput, observedAtInput, impactInput) {
  const observedAt = normalizeObservedAt(observedAtInput);
  const observedMilliseconds = Date.parse(observedAt);
  const policy = validateFreshnessPolicy(state, policyInput);
  const requirements = requirementMap(state);
  const impact = impactInput === undefined ? null : verifyMissionReport(impactInput, "Impact report", "tugboat.proof-impact.v1", state);
  const impactInvalidated = new Set(impact?.impact?.invalidatedEvidenceIds ?? []);
  const amendmentInvalidated = invalidatedByAmendment(state);
  const evidence = [];

  for (const item of valuesById(state.evidence).sort((left, right) => left.id.localeCompare(right.id))) {
    const reasons = [];
    const requirementIds = [...new Set(item.requirementIds ?? [])].sort();
    const kindTtl = policy.ttlHoursByKind[item.kind];
    if (kindTtl === undefined) {
      reasons.push(reason("policy_missing", `No freshness TTL is declared for evidence kind ${item.kind}.`));
    }
    let capturedMilliseconds = Number.NaN;
    try {
      capturedMilliseconds = Date.parse(normalizeObservedAt(item.capturedAt));
    } catch {
      reasons.push(reason("captured_at_invalid", `${item.id} has no valid capturedAt timestamp.`));
    }
    const volatilityEntries = requirementIds
      .filter((id) => policy.volatilityHoursByRequirement[id] !== undefined)
      .map((id) => [id, policy.volatilityHoursByRequirement[id]]);
    const maxAgeHours = kindTtl === undefined
      ? null
      : Math.min(kindTtl, ...volatilityEntries.map(([, value]) => value), Number.POSITIVE_INFINITY);
    const ageHours = Number.isFinite(capturedMilliseconds) ? (observedMilliseconds - capturedMilliseconds) / 3_600_000 : null;
    const expiresAt = maxAgeHours === null || !Number.isFinite(capturedMilliseconds)
      ? null
      : new Date(capturedMilliseconds + maxAgeHours * 3_600_000).toISOString();
    if (ageHours !== null && ageHours < 0) reasons.push(reason("captured_in_future", `${item.id} was captured after observedAt.`));
    if (ageHours !== null && maxAgeHours !== null && ageHours >= maxAgeHours) {
      const volatility = volatilityEntries.find(([, value]) => value === maxAgeHours);
      reasons.push(reason(
        "age_exceeded",
        volatility
          ? `${item.id} exceeds the ${maxAgeHours}-hour volatility TTL for ${volatility[0]}.`
          : `${item.id} exceeds the ${maxAgeHours}-hour TTL for ${item.kind}.`,
      ));
    }
    if (impactInvalidated.has(item.id)) reasons.push(reason("impact_invalidated", `${item.id} is invalidated by the supplied change impact.`));
    if (item.kind === "deployment" && policy.expectedDeploymentSha && item.deployment?.deployedSha !== policy.expectedDeploymentSha) {
      reasons.push(reason("deployment_sha_mismatch", `${item.id} attests ${item.deployment?.deployedSha ?? "no SHA"}, expected ${policy.expectedDeploymentSha}.`));
    }
    if (amendmentInvalidated.has(item.id) || requirementIds.some((id) => (requirements.get(id)?.amendedBy ?? []).length > 0)) {
      reasons.push(reason("superseded_requirement", `${item.id} covers a requirement whose meaning was amended or superseded.`));
    }
    const unknownPolicy = reasons.some(({ code }) => new Set(["captured_at_invalid", "policy_missing"]).has(code));
    const stale = reasons.some(({ code }) => !new Set(["captured_at_invalid", "policy_missing"]).has(code));
    const remainingHours = expiresAt ? (Date.parse(expiresAt) - observedMilliseconds) / 3_600_000 : null;
    const freshness = unknownPolicy
      ? "unknown_policy"
      : stale
        ? "stale"
        : remainingHours !== null && remainingHours <= policy.expiringWithinHours
          ? "expiring"
          : "fresh";
    evidence.push({
      ageHours,
      expiresAt,
      freshness,
      id: item.id,
      kind: item.kind,
      maxAgeHours,
      reasons,
      requirementIds,
    });
  }

  const summary = {
    expiring: evidence.filter(({ freshness }) => freshness === "expiring").length,
    fresh: evidence.filter(({ freshness }) => freshness === "fresh").length,
    stale: evidence.filter(({ freshness }) => freshness === "stale").length,
    unknownPolicy: evidence.filter(({ freshness }) => freshness === "unknown_policy").length,
  };
  return canonicalReport("tugboat.evidence-freshness.v1", {
    status: summary.unknownPolicy > 0 ? "insufficient_evidence" : summary.stale > 0 ? "blocked" : "ready",
    mission: missionSummary(state),
    observedAt,
    inputs: {
      impactDigest: impact?.digest ?? null,
      policyDigest: `sha256:${sha256(canonicalJson(policy))}`,
    },
    evidence,
    summary,
  });
}

const SIMULATION_PROFILE_FIELDS = ["controls", "failureModes"];
const CONTROL_FIELDS = ["containment", "detectionEvidenceKinds", "recoveryGates", "rollbackAction"];
const FAILURE_FIELDS = ["affectedRequirementIds", "containment", "detectionEvidenceKinds", "id", "recoveryGates", "rollbackAction", "trigger"];
const BUILT_IN_FAILURES = Object.freeze({
  dependency_unavailable: "A declared release dependency becomes unavailable during the operator journey.",
  deployment_failed: "The canonical deployment reports failure after release work begins.",
  operator_denied: "The intended operator cannot authenticate or authorize the release journey.",
  rollback_anchor_missing: "The release must roll back but the recorded rollback anchor cannot be restored.",
  stale_proof: "Evidence used for release readiness no longer describes the changed implementation.",
  target_drift: "The target Git state changes after validation and before release completion.",
});

function stringList(value, label, max = 64) {
  const result = boundedList(value ?? [], label, max);
  for (const item of result) if (typeof item !== "string" || item.length === 0) fail(`${label} values must be non-empty strings`);
  return [...new Set(result)].sort((left, right) => left.localeCompare(right));
}

function validateProofKinds(value, label) {
  const kinds = stringList(value, label);
  for (const kind of kinds) if (!EVIDENCE_KINDS.has(kind)) fail(`${label} contains unknown evidence kind ${kind}`);
  return kinds;
}

function requirementIds(value, requirements, label, { allowEmpty = false } = {}) {
  const ids = stringList(value, label);
  if (!allowEmpty && !ids.length) fail(`${label} must not be empty`);
  for (const id of ids) if (!requirements.has(id)) fail(`${label} references unknown requirement ${id}`);
  return ids;
}

function validateControl(input, label, { validateShape = true } = {}) {
  if (validateShape) validateObject(input, { label: "failure control", allowed: CONTROL_FIELDS });
  return {
    containment: input.containment ?? null,
    detectionEvidenceKinds: validateProofKinds(input.detectionEvidenceKinds, `${label} detectionEvidenceKinds`),
    recoveryGates: stringList(input.recoveryGates, `${label} recoveryGates`),
    rollbackAction: input.rollbackAction ?? null,
  };
}

function builtInAffected(state, id, materialIds, productionIds) {
  if (["deployment_failed", "rollback_anchor_missing"].includes(id)) return productionIds;
  if (id === "dependency_unavailable") {
    const dependentSliceIds = new Set(valuesById(state.slices).filter((slice) => (slice.dependencies ?? []).length).flatMap((slice) => slice.requirementIds ?? []));
    return materialIds.filter((requirementId) => dependentSliceIds.has(requirementId));
  }
  if (id === "stale_proof") return materialIds.filter((requirementId) => (state.requirements?.[requirementId]?.evidenceRefs ?? []).length > 0);
  return materialIds;
}

function validateSimulationProfile(state, input = {}) {
  validateObject(input, { label: "release simulation profile", allowed: SIMULATION_PROFILE_FIELDS });
  const requirements = requirementMap(state);
  const controlsInput = input.controls ?? {};
  if (!controlsInput || typeof controlsInput !== "object" || Array.isArray(controlsInput)) fail("failure controls must be an object");
  const controls = {};
  for (const id of Object.keys(controlsInput).sort()) {
    if (!Object.hasOwn(BUILT_IN_FAILURES, id)) fail(`Unknown built-in failure control ${id}`);
    controls[id] = validateControl(controlsInput[id], `failure control ${id}`);
  }
  const failureModes = boundedList(input.failureModes ?? [], "failure modes", 64, { uniqueBy: "id" }).map((item) => {
    validateObject(item, { label: "failure mode", allowed: FAILURE_FIELDS, required: ["id", "trigger", "affectedRequirementIds"] });
    if (Object.hasOwn(BUILT_IN_FAILURES, item.id)) fail(`Failure mode ${item.id} duplicates built-in failure ${item.id}`);
    return {
      id: item.id,
      trigger: item.trigger,
      affectedRequirementIds: requirementIds(item.affectedRequirementIds, requirements, `failure mode ${item.id} affectedRequirementIds`),
      ...validateControl(item, `failure mode ${item.id}`, { validateShape: false }),
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
  return { controls, failureModes, requirements };
}

function journey(id, trigger, affectedRequirementIds, control) {
  const detectionCovered = control.detectionEvidenceKinds.length > 0;
  const recoveryCovered = Boolean(control.containment && control.rollbackAction && control.recoveryGates.length);
  const gaps = [];
  if (!detectionCovered) gaps.push("detection_missing");
  if (!recoveryCovered) gaps.push("recovery_missing");
  return {
    affectedRequirementIds,
    containment: control.containment,
    detection: { covered: detectionCovered, evidenceKinds: control.detectionEvidenceKinds },
    gaps,
    id,
    recovery: { covered: recoveryCovered, gates: control.recoveryGates },
    rollbackAction: control.rollbackAction,
    trigger,
    verdict: gaps.length ? "blocked" : "ready",
  };
}

export function compileReleaseSimulation(state, profileInput = {}, impactInput, adversarialInput) {
  const profile = validateSimulationProfile(state, profileInput);
  const impact = impactInput === undefined ? null : verifyMissionReport(impactInput, "Impact report", "tugboat.proof-impact.v1", state);
  const adversarial = adversarialInput === undefined ? null : verifyMissionReport(adversarialInput, "Adversarial report", "tugboat.adversarial-acceptance.v1", state);
  if (adversarial && (!Array.isArray(adversarial.cases) || !Array.isArray(adversarial.oracleGaps))) {
    fail("Adversarial report must contain cases and oracleGaps arrays");
  }
  const allRequirements = [...profile.requirements.values()];
  const materialIds = allRequirements.filter((item) => item.material !== false).map(({ id }) => id).sort();
  const productionIds = allRequirements.filter((item) => item.material !== false && item.proofTarget === "production").map(({ id }) => id).sort();
  const impacted = impact ? new Set(impact.impact?.allRequirementIds ?? []) : null;
  const journeys = [];
  for (const id of Object.keys(BUILT_IN_FAILURES).sort()) {
    let affected = builtInAffected(state, id, materialIds, productionIds);
    if (impacted) affected = affected.filter((requirementId) => impacted.has(requirementId));
    const relevant = affected.length > 0
      || (id === "target_drift" && Boolean(state.metadata?.baselineGitSha))
      || (id === "stale_proof" && valuesById(state.evidence).length > 0);
    if (!relevant) continue;
    journeys.push(journey(
      id,
      BUILT_IN_FAILURES[id],
      affected,
      profile.controls[id] ?? { containment: null, detectionEvidenceKinds: [], recoveryGates: [], rollbackAction: null },
    ));
  }
  for (const item of profile.failureModes) journeys.push(journey(item.id, item.trigger, item.affectedRequirementIds, item));
  journeys.sort((left, right) => left.id.localeCompare(right.id));
  return canonicalReport("tugboat.release-simulation.v1", {
    status: (adversarial?.oracleGaps?.length ?? 0) > 0
      ? "insufficient_evidence"
      : journeys.some(({ verdict }) => verdict === "blocked") ? "blocked" : "ready",
    mission: missionSummary(state),
    inputs: { adversarialDigest: adversarial?.digest ?? null, impactDigest: impact?.digest ?? null },
    adversarialCoverage: {
      caseCount: adversarial?.cases?.length ?? 0,
      oracleGapCount: adversarial?.oracleGaps?.length ?? 0,
    },
    journeys,
    summary: {
      blocked: journeys.filter(({ verdict }) => verdict === "blocked").length,
      ready: journeys.filter(({ verdict }) => verdict === "ready").length,
    },
  });
}

const CATALOG_FIELDS = ["gates"];
const GATE_FIELDS = ["cost", "id", "proofKinds", "requirementIds", "riskTags"];
const COST_SCALE = 1_000_000;

function validateGateCatalog(state, input) {
  validateObject(input, { label: "proof gate catalog", allowed: CATALOG_FIELDS, required: ["gates"] });
  const requirements = requirementMap(state);
  const gates = boundedList(input.gates, "proof gates", 20, { uniqueBy: "id" }).map((item) => {
    validateObject(item, { label: "proof gate", allowed: GATE_FIELDS, required: ["id", "cost", "requirementIds", "proofKinds", "riskTags"] });
    if (typeof item.cost !== "number" || !Number.isFinite(item.cost) || item.cost <= 0 || item.cost > 1_000_000) {
      fail(`Proof gate ${item.id} cost must be a positive number no greater than 1000000`);
    }
    const costUnits = Math.round(item.cost * COST_SCALE);
    if (Math.abs(costUnits / COST_SCALE - item.cost) > Number.EPSILON * Math.max(1, item.cost) * 4) {
      fail(`Proof gate ${item.id} cost must use no more than six decimal places`);
    }
    return {
      cost: item.cost,
      costUnits,
      id: item.id,
      proofKinds: validateProofKinds(item.proofKinds, `proof gate ${item.id} proofKinds`),
      requirementIds: requirementIds(item.requirementIds, requirements, `proof gate ${item.id} requirementIds`, { allowEmpty: true }),
      riskTags: stringList(item.riskTags, `proof gate ${item.id} riskTags`),
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
  return { gates, requirements };
}

function obligationsFor(state, requirements, impact) {
  const obligations = new Set();
  for (const requirementId of impact.impact?.allRequirementIds ?? []) {
    const requirement = requirements.get(requirementId);
    if (!requirement) fail(`Impact report references unknown requirement ${requirementId}`);
    obligations.add(`requirement:${requirementId}`);
    obligations.add(`proof:${requirementId}:command`);
    obligations.add(`proof:${requirementId}:operator`);
    if (requirement.proofTarget === "production") obligations.add(`proof:${requirementId}:deployment`);
  }
  for (const risk of impact.impact?.riskTags ?? []) obligations.add(`risk:${risk}`);
  return [...obligations].sort();
}

function gateCoverage(gate) {
  const coverage = new Set(gate.riskTags.map((risk) => `risk:${risk}`));
  for (const requirementId of gate.requirementIds) {
    coverage.add(`requirement:${requirementId}`);
    for (const kind of gate.proofKinds) coverage.add(`proof:${requirementId}:${kind}`);
  }
  return coverage;
}

function compareCandidate(left, right) {
  if (!right) return -1;
  if (left.costUnits !== right.costUnits) return left.costUnits - right.costUnits;
  if (left.gates.length !== right.gates.length) return left.gates.length - right.gates.length;
  return left.gates.map(({ id }) => id).join("\0").localeCompare(right.gates.map(({ id }) => id).join("\0"));
}

export function compileProofPortfolio(state, impactInput, catalogInput) {
  const impact = verifyMissionReport(impactInput, "Impact report", "tugboat.proof-impact.v1", state);
  const catalog = validateGateCatalog(state, catalogInput);
  const obligations = obligationsFor(state, catalog.requirements, impact);
  const obligationSet = new Set(obligations);
  const coverage = catalog.gates.map((gate) => gateCoverage(gate));
  let best = null;
  const subsetCount = 2 ** catalog.gates.length;
  for (let mask = 1; mask < subsetCount; mask += 1) {
    const covered = new Set();
    const gates = [];
    let costUnits = 0;
    for (let index = 0; index < catalog.gates.length; index += 1) {
      if ((mask & (2 ** index)) === 0) continue;
      gates.push(catalog.gates[index]);
      costUnits += catalog.gates[index].costUnits;
      for (const item of coverage[index]) if (obligationSet.has(item)) covered.add(item);
    }
    if (covered.size !== obligations.length) continue;
    const candidate = { costUnits, gates };
    if (compareCandidate(candidate, best) < 0) best = candidate;
  }
  const potentialCoverage = new Set(coverage.flatMap((items) => [...items]));
  const uncoveredObligations = best ? [] : obligations.filter((item) => !potentialCoverage.has(item));
  return canonicalReport("tugboat.proof-portfolio.v1", {
    status: best || obligations.length === 0 ? "ready" : "blocked",
    mission: missionSummary(state),
    impactDigest: impact.digest,
    obligations,
    planStatus: "not_executed",
    selectedGates: best?.gates.map(({ costUnits: _costUnits, ...gate }) => gate) ?? [],
    totalCost: best ? best.costUnits / COST_SCALE : null,
    uncoveredObligations,
  });
}
