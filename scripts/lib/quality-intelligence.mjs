import {
  boundedList,
  canonicalReport,
  missionSummary,
  validateObject,
} from "./intelligence-core.mjs";

const PROFILE_FIELDS = ["architecture", "claims", "gates"];
const ARCHITECTURE_FIELDS = ["capability", "consumers", "id", "requirementIds"];
const GATE_FIELDS = ["id", "proofKinds", "requirementIds"];
const CLAIM_FIELDS = ["confidence", "evidenceIds", "id", "requirementIds", "text"];
const PROOF_KINDS = new Set(["browser", "command", "deployment", "operator"]);
const CONFIDENCE = new Set(["certain", "conditional", "strong"]);

const ADVERSARIAL_PROFILE_FIELDS = ["contracts"];
const CONTRACT_FIELDS = ["class", "evidenceKind", "mutation", "oracle", "setup"];
const ADVERSARIAL_CLASSES = Object.freeze([
  "concurrent",
  "dependency_error",
  "duplicate",
  "empty",
  "malformed",
  "out_of_order",
  "partial",
  "rollback",
  "stale",
  "unauthorized",
]);

const CLASS_RULES = Object.freeze({
  concurrent: /\b(?:concurrent|conflict|race)\b/i,
  dependency_error: /\b(?:dependency|downstream|timeout|unavailable|503)\b/i,
  duplicate: /\b(?:duplicate|idempoten|replay|second record)\b/i,
  empty: /\b(?:empty|missing)\b/i,
  malformed: /\b(?:malformed|invalid format|invalid input)\b/i,
  out_of_order: /\b(?:out[- ]of[- ]order|sequence|earlier event)\b/i,
  partial: /\bpartial\b/i,
  rollback: /\b(?:rollback|prior version|previous version)\b/i,
  stale: /\bstale\b/i,
  unauthorized: /\b(?:unauthorized|forbidden|permission|403)\b/i,
});

const CASE_SHAPES = Object.freeze({
  concurrent: { setup: "Create two valid updates against the same current version.", mutation: "Submit both updates without serializing them." },
  dependency_error: { setup: "Prepare an otherwise valid operation with its external dependency available.", mutation: "Make the declared dependency unavailable for the operation." },
  duplicate: { setup: "Complete one valid operation and retain its stable identifier.", mutation: "Replay the identical operation identifier." },
  empty: { setup: "Prepare an authenticated request at the input boundary.", mutation: "Remove the required payload or collection contents." },
  malformed: { setup: "Prepare a valid request at the input boundary.", mutation: "Replace one required value with a malformed representation." },
  out_of_order: { setup: "Persist the latest valid sequence or version.", mutation: "Deliver an earlier sequence after the latest one." },
  partial: { setup: "Prepare a complete record or dependency response.", mutation: "Remove one non-optional portion while retaining the rest." },
  rollback: { setup: "Deploy or apply the candidate after recording the prior version.", mutation: "Trigger the declared rollback path." },
  stale: { setup: "Prepare a record with a known current version.", mutation: "Present an older version as current input." },
  unauthorized: { setup: "Prepare a valid operation for an authorized actor.", mutation: "Repeat it with an actor lacking the required permission." },
});

function fail(message) {
  throw new Error(message);
}

function sortedUnique(values) {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function valuesById(value) {
  return Array.isArray(value) ? value : Object.values(value ?? {});
}

function requirementMap(state) {
  const requirements = new Map(valuesById(state?.requirements).map((item) => [item.id, item]));
  if (!requirements.size) fail("Quality compiler needs mission requirements");
  return requirements;
}

function evidenceMap(state) {
  return new Map(valuesById(state?.evidence).map((item) => [item.id, item]));
}

function stringList(value, label, max = 64) {
  const result = boundedList(value ?? [], label, max);
  for (const item of result) if (typeof item !== "string" || item.length === 0) fail(`${label} values must be non-empty strings`);
  return sortedUnique(result);
}

function validateRequirementIds(ids, requirements, label) {
  const result = stringList(ids, label);
  for (const id of result) if (!requirements.has(id)) fail(`${label} references unknown requirement ${id}`);
  return result;
}

function validateAntiSlopProfile(state, profileInput = {}) {
  validateObject(profileInput, { label: "anti-slop profile", allowed: PROFILE_FIELDS });
  const requirements = requirementMap(state);
  const evidence = evidenceMap(state);
  const architecture = boundedList(profileInput.architecture ?? [], "architecture components", 128, { uniqueBy: "id" })
    .map((item) => {
      validateObject(item, { label: "architecture component", allowed: ARCHITECTURE_FIELDS, required: ["id", "capability", "requirementIds", "consumers"] });
      return {
        id: item.id,
        capability: item.capability,
        requirementIds: validateRequirementIds(item.requirementIds, requirements, `architecture component ${item.id}`),
        consumers: stringList(item.consumers, `architecture component ${item.id} consumers`),
      };
    }).sort((left, right) => left.id.localeCompare(right.id));
  const gates = boundedList(profileInput.gates ?? [], "gates", 128, { uniqueBy: "id" })
    .map((item) => {
      validateObject(item, { label: "gate", allowed: GATE_FIELDS, required: ["id", "requirementIds", "proofKinds"] });
      const proofKinds = stringList(item.proofKinds, `gate ${item.id} proofKinds`);
      for (const kind of proofKinds) if (!PROOF_KINDS.has(kind)) fail(`Gate ${item.id} has unknown proof kind ${kind}`);
      return { id: item.id, requirementIds: validateRequirementIds(item.requirementIds, requirements, `gate ${item.id}`), proofKinds };
    }).sort((left, right) => left.id.localeCompare(right.id));
  const claims = boundedList(profileInput.claims ?? [], "claims", 128, { uniqueBy: "id" })
    .map((item) => {
      validateObject(item, { label: "claim", allowed: CLAIM_FIELDS, required: ["id", "text", "confidence", "requirementIds", "evidenceIds"] });
      if (!CONFIDENCE.has(item.confidence)) fail(`Claim ${item.id} has unknown confidence ${item.confidence}`);
      const evidenceIds = stringList(item.evidenceIds, `claim ${item.id} evidenceIds`);
      for (const id of evidenceIds) if (!evidence.has(id)) fail(`Claim ${item.id} references unknown evidence ${id}`);
      return {
        id: item.id,
        text: item.text,
        confidence: item.confidence,
        requirementIds: validateRequirementIds(item.requirementIds, requirements, `claim ${item.id}`),
        evidenceIds,
      };
    }).sort((left, right) => left.id.localeCompare(right.id));
  return { architecture, claims, gates, requirements, evidence };
}

function finding(ruleId, severity, subject, requirementIds, remediation, message) {
  return { message, remediation, requirementIds: sortedUnique(requirementIds), ruleId, severity, subject };
}

function measurableOracle(text) {
  if (typeof text !== "string" || text.trim().length < 12) return false;
  return /\b(?:returns?|rejects?|emits?|exits?|shows?|labels?|writes?|persists?|preserves?|equals?|contains?|passes?|fails?|restores?|ignored?|remains?|prevents?|does not|must not)\b|\b\d+(?:\.\d+)?\b|sha256|https?:\/\//i.test(text);
}

function vagueLanguage(text) {
  return /\b(?:world[- ]class|intuitive|robust|scalable|seamless|best|good|great|easy|fast|works?|complete|done)\b/i.test(text ?? "");
}

function slopFindings(state, profile) {
  const findings = [];
  const requirements = [...profile.requirements.values()].sort((left, right) => left.id.localeCompare(right.id));
  const sliced = new Set(valuesById(state.slices).flatMap((slice) => slice.requirementIds ?? []));
  for (const requirement of requirements) {
    if (requirement.material !== false && (!measurableOracle(requirement.acceptance) || vagueLanguage(requirement.acceptance))) {
      findings.push(finding(
        "acceptance.vague_oracle", "error", `requirement:${requirement.id}`, [requirement.id],
        "Replace adjectives with an observable input, result, boundary, and failure condition.",
        `${requirement.id} has no measurable acceptance oracle.`,
      ));
    }
    const scopeText = `${requirement.requirement ?? ""} ${requirement.acceptance ?? ""} ${requirement.source ?? ""}`;
    if (/\b(?:follow[- ]?up|later|future|phase\s*2|nice to have|tbd|to be determined)\b/i.test(scopeText)) {
      findings.push(finding(
        "scope.follow_up_laundering", "error", `requirement:${requirement.id}`, [requirement.id],
        "Keep approved material scope in the active ledger or record an explicit user-approved scope change.",
        `${requirement.id} moves scope into an unspecified future.`,
      ));
    }
    if (!new Set(["documentation", "local", "production"]).has(requirement.proofTarget)) {
      findings.push(finding(
        "proof.placeholder", "error", `requirement:${requirement.id}`, [requirement.id],
        "Choose documentation, local, or production and name the observable proof.",
        `${requirement.id} has placeholder or missing proof target ${requirement.proofTarget ?? "none"}.`,
      ));
    }
    if (requirement.material !== false && !sliced.has(requirement.id)) {
      findings.push(finding(
        "scope.unsliced_material", "error", `requirement:${requirement.id}`, [requirement.id],
        "Place the material requirement in a dependency-ordered release slice.",
        `${requirement.id} is material but absent from every release slice.`,
      ));
    }
  }

  for (const component of profile.architecture) {
    if (!component.requirementIds.length || !component.consumers.length) {
      findings.push(finding(
        "architecture.ornamental", "error", `architecture:${component.id}`, component.requirementIds,
        "Remove the component or bind it to a material requirement and a concrete consumer.",
        `${component.id} has no complete requirement-to-consumer path.`,
      ));
    }
  }
  const componentGroups = new Map();
  for (const component of profile.architecture) {
    const key = `${component.capability}\0${component.requirementIds.join(",")}\0${component.consumers.join(",")}`;
    if (!componentGroups.has(key)) componentGroups.set(key, []);
    componentGroups.get(key).push(component);
  }
  for (const components of componentGroups.values()) {
    if (components.length < 2) continue;
    const ids = components.map(({ id }) => id).sort();
    findings.push(finding(
      "architecture.duplicate_abstraction", "warning", `architecture:${ids.join(",")}`,
      sortedUnique(components.flatMap(({ requirementIds }) => requirementIds)),
      "Select one owned abstraction or document distinct consumers and failure boundaries.",
      `${ids.join(", ")} declare the same capability, owners, and consumers.`,
    ));
  }
  for (const gate of profile.gates) {
    const kinds = new Set(gate.proofKinds);
    const incomplete = gate.requirementIds.some((id) => {
      const target = profile.requirements.get(id)?.proofTarget;
      if (target === "documentation") return !kinds.has("command");
      if (!kinds.has("command") || !(kinds.has("operator") || kinds.has("browser"))) return true;
      return target === "production" && !kinds.has("deployment");
    });
    if (!gate.requirementIds.length || incomplete) {
      findings.push(finding(
        "gate.fake", "error", `gate:${gate.id}`, gate.requirementIds,
        "Bind the gate to each requirement's complete command, operator/browser, and production deployment obligations.",
        `${gate.id} covers no complete requirement-to-proof obligation.`,
      ));
    }
  }
  for (const claim of profile.claims) {
    if (!new Set(["certain", "strong"]).has(claim.confidence)) continue;
    const covered = new Set();
    for (const id of claim.evidenceIds) {
      const item = profile.evidence.get(id);
      if (item?.verification?.status !== "passed") continue;
      for (const requirementId of item.requirementIds ?? []) covered.add(requirementId);
    }
    const unsupported = !claim.requirementIds.length || claim.requirementIds.some((id) => !covered.has(id));
    if (unsupported) {
      findings.push(finding(
        "claim.unsupported_confidence", "error", `claim:${claim.id}`, claim.requirementIds,
        "Downgrade the claim or cite passing structured evidence that covers the requirements.",
        `${claim.id} asserts ${claim.confidence} confidence without passing evidence.`,
      ));
    }
  }
  return findings.sort((left, right) => left.ruleId.localeCompare(right.ruleId) || left.subject.localeCompare(right.subject));
}

export function compileAntiSlopReport(state, profileInput = {}) {
  const profile = validateAntiSlopProfile(state, profileInput);
  const findings = slopFindings(state, profile);
  return canonicalReport("tugboat.anti-slop.v1", {
    status: findings.some(({ severity }) => severity === "error") ? "blocked" : "ready",
    mission: missionSummary(state),
    findings,
    summary: {
      errors: findings.filter(({ severity }) => severity === "error").length,
      warnings: findings.filter(({ severity }) => severity === "warning").length,
    },
  });
}

function observableOracle(text) {
  return typeof text === "string"
    && text.trim().length >= 8
    && /\b(?:returns?|rejects?|emits?|shows?|label(?:s|ed)?|ignores?|restores?|remains?|preserves?|fails?|passes?|does not|do not|must not|no second|count)\b|\b\d{3}\b/i.test(text);
}

function validateAdversarialProfile(state, profileInput = {}) {
  validateObject(profileInput, { label: "adversarial profile", allowed: ADVERSARIAL_PROFILE_FIELDS });
  const requirements = requirementMap(state);
  const contractsInput = profileInput.contracts ?? {};
  if (!contractsInput || typeof contractsInput !== "object" || Array.isArray(contractsInput)) fail("adversarial contracts must be an object");
  const contracts = {};
  for (const requirementId of Object.keys(contractsInput).sort()) {
    if (!requirements.has(requirementId)) fail(`Adversarial contracts reference unknown requirement ${requirementId}`);
    const byClass = new Map();
    for (const contract of boundedList(contractsInput[requirementId], `adversarial contracts ${requirementId}`, 32)) {
      validateObject(contract, { label: "adversarial contract", allowed: CONTRACT_FIELDS, required: CONTRACT_FIELDS });
      if (!ADVERSARIAL_CLASSES.includes(contract.class)) fail(`Unknown adversarial class ${contract.class}`);
      if (!PROOF_KINDS.has(contract.evidenceKind)) fail(`Unknown adversarial evidence kind ${contract.evidenceKind}`);
      if (!observableOracle(contract.oracle)) fail("Adversarial oracle must state an observable result");
      if (byClass.has(contract.class)) fail(`Duplicate adversarial class ${contract.class} for ${requirementId}`);
      byClass.set(contract.class, { ...contract, requirementId, source: "profile" });
    }
    contracts[requirementId] = byClass;
  }
  return { contracts, requirements };
}

function acceptanceClauses(text) {
  return String(text ?? "")
    .split(/[;.]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function inferredCases(requirement) {
  const cases = new Map();
  const clauses = acceptanceClauses(requirement.acceptance);
  for (const caseClass of ADVERSARIAL_CLASSES) {
    const clause = clauses.find((item) => CLASS_RULES[caseClass].test(item) && observableOracle(item));
    if (!clause) continue;
    cases.set(caseClass, {
      class: caseClass,
      evidenceKind: "command",
      mutation: CASE_SHAPES[caseClass].mutation,
      oracle: clause.endsWith(".") ? clause : `${clause}.`,
      requirementId: requirement.id,
      setup: CASE_SHAPES[caseClass].setup,
      source: "ledger",
    });
  }
  return cases;
}

export function compileAdversarialAcceptance(state, profileInput = {}) {
  const profile = validateAdversarialProfile(state, profileInput);
  const cases = [];
  const oracleGaps = [];
  for (const requirement of [...profile.requirements.values()].sort((left, right) => left.id.localeCompare(right.id))) {
    if (requirement.material === false) continue;
    const byClass = inferredCases(requirement);
    for (const [caseClass, contract] of profile.contracts[requirement.id] ?? []) byClass.set(caseClass, contract);
    const compiled = [...byClass.values()].sort((left, right) => left.class.localeCompare(right.class));
    cases.push(...compiled);
    if (!compiled.length) {
      oracleGaps.push({
        code: "oracle_missing",
        requirementId: requirement.id,
        message: `No literal negative-state oracle is grounded for ${requirement.id}.`,
      });
    }
  }
  return canonicalReport("tugboat.adversarial-acceptance.v1", {
    status: oracleGaps.length ? "insufficient_evidence" : "ready",
    mission: missionSummary(state),
    cases,
    oracleGaps,
  });
}
