import { canonicalJson, sha256 } from "./canonical.mjs";
import {
  boundedList,
  canonicalReport,
  normalizeObservedAt,
  validateObject,
} from "./intelligence-core.mjs";

const RECORD_FIELDS = ["assumptions", "contextTags", "constraints", "decidedAt", "decision", "evidence", "id", "outcome", "rejectedAlternatives", "supersedes"];
const ASSUMPTION_FIELDS = ["halfLifeDays", "id", "text"];
const EVIDENCE_FIELDS = ["digest", "kind"];
const OUTCOME_FIELDS = ["observedAt", "status"];
const ALTERNATIVE_FIELDS = ["decision", "reason"];
const CONTEXT_FIELDS = ["constraints", "minAssumptionRetention", "tags"];
const EVIDENCE_KINDS = new Set(["local", "production"]);
const OUTCOME_STATUSES = new Set(["failure", "mixed", "success"]);

function fail(message) {
  throw new Error(message);
}

function strings(value, label, max = 64) {
  const items = boundedList(value ?? [], label, max);
  for (const item of items) if (typeof item !== "string" || item.length === 0) fail(`${label} values must be non-empty strings`);
  return [...new Set(items)].sort((left, right) => left.localeCompare(right));
}

function validateConstraints(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  validateObject(value, { label, allowed: Object.keys(value) });
  const result = {};
  for (const key of Object.keys(value).sort()) {
    const item = value[key];
    if (!["boolean", "number", "string"].includes(typeof item) || (typeof item === "number" && !Number.isFinite(item))) {
      fail(`${label}.${key} must be a finite scalar`);
    }
    result[key] = item;
  }
  return result;
}

function validateDigest(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? "")) fail(`${label} must be a SHA-256 digest`);
  return value;
}

function validateRecords(input, observedMilliseconds) {
  const records = boundedList(input, "decision records", 256, { uniqueBy: "id" }).map((record) => {
    validateObject(record, { label: "decision record", allowed: RECORD_FIELDS, required: RECORD_FIELDS });
    const decidedAt = normalizeObservedAt(record.decidedAt);
    if (Date.parse(decidedAt) > observedMilliseconds) fail(`Decision record ${record.id} is dated after observedAt`);
    const assumptions = boundedList(record.assumptions, `decision record ${record.id} assumptions`, 64, { uniqueBy: "id" }).map((assumption) => {
      validateObject(assumption, { label: "decision assumption", allowed: ASSUMPTION_FIELDS, required: ASSUMPTION_FIELDS });
      if (typeof assumption.halfLifeDays !== "number" || !Number.isFinite(assumption.halfLifeDays) || assumption.halfLifeDays <= 0 || assumption.halfLifeDays > 36_500) {
        fail(`Decision assumption ${assumption.id} halfLifeDays must be a positive number no greater than 36500`);
      }
      return { halfLifeDays: assumption.halfLifeDays, id: assumption.id, text: assumption.text };
    }).sort((left, right) => left.id.localeCompare(right.id));
    validateObject(record.evidence, { label: "decision evidence", allowed: EVIDENCE_FIELDS, required: EVIDENCE_FIELDS });
    if (!EVIDENCE_KINDS.has(record.evidence.kind)) fail(`Decision record ${record.id} has unknown evidence kind ${record.evidence.kind}`);
    validateObject(record.outcome, { label: "decision outcome", allowed: OUTCOME_FIELDS, required: OUTCOME_FIELDS });
    if (!OUTCOME_STATUSES.has(record.outcome.status)) fail(`Decision record ${record.id} has unknown outcome ${record.outcome.status}`);
    const outcomeObservedAt = normalizeObservedAt(record.outcome.observedAt);
    if (Date.parse(outcomeObservedAt) > observedMilliseconds) fail(`Decision record ${record.id} outcome is dated after observedAt`);
    const rejectedAlternatives = boundedList(record.rejectedAlternatives, `decision record ${record.id} rejectedAlternatives`, 64).map((alternative) => {
      validateObject(alternative, { label: "rejected alternative", allowed: ALTERNATIVE_FIELDS, required: ALTERNATIVE_FIELDS });
      return { decision: alternative.decision, reason: alternative.reason };
    }).sort((left, right) => left.decision.localeCompare(right.decision) || left.reason.localeCompare(right.reason));
    return {
      assumptions,
      contextTags: strings(record.contextTags, `decision record ${record.id} contextTags`),
      constraints: validateConstraints(record.constraints, `decision record ${record.id} constraints`),
      decidedAt,
      decision: record.decision,
      evidence: { digest: validateDigest(record.evidence.digest, `Decision record ${record.id} evidence digest`), kind: record.evidence.kind },
      id: record.id,
      outcome: { observedAt: outcomeObservedAt, status: record.outcome.status },
      rejectedAlternatives,
      supersedes: strings(record.supersedes, `decision record ${record.id} supersedes`),
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
  const ids = new Set(records.map(({ id }) => id));
  for (const record of records) {
    for (const id of record.supersedes) {
      if (!ids.has(id)) fail(`Decision record ${record.id} supersedes unknown record ${id}`);
      if (id === record.id) fail(`Decision record ${record.id} cannot supersede itself`);
    }
  }
  return records;
}

function validateContext(input) {
  validateObject(input, { label: "decision context", allowed: CONTEXT_FIELDS, required: CONTEXT_FIELDS });
  if (typeof input.minAssumptionRetention !== "number" || !Number.isFinite(input.minAssumptionRetention)
    || input.minAssumptionRetention < 0 || input.minAssumptionRetention > 1) {
    fail("minAssumptionRetention must be a number from 0 to 1");
  }
  return {
    constraints: validateConstraints(input.constraints, "decision context constraints"),
    minAssumptionRetention: input.minAssumptionRetention,
    tags: strings(input.tags, "decision context tags"),
  };
}

function outcomeGroupKey(record) {
  return canonicalJson({ contextTags: record.contextTags, constraints: record.constraints, decision: record.decision });
}

function retention(decidedAt, halfLifeDays, observedMilliseconds) {
  const elapsedDays = Math.max(0, (observedMilliseconds - Date.parse(decidedAt)) / 86_400_000);
  return Number((2 ** (-elapsedDays / halfLifeDays)).toFixed(12));
}

function dispositionRank(value) {
  return { reusable: 0, conditional: 1, rejected: 2 }[value];
}

export function compileDecisionMemory(recordsInput, contextInput, observedAtInput) {
  const observedAt = normalizeObservedAt(observedAtInput);
  const observedMilliseconds = Date.parse(observedAt);
  const context = validateContext(contextInput);
  const records = validateRecords(recordsInput, observedMilliseconds);
  const superseded = new Set(records.flatMap(({ supersedes }) => supersedes));
  const outcomes = new Map();
  for (const record of records) {
    if (superseded.has(record.id)) continue;
    const key = outcomeGroupKey(record);
    if (!outcomes.has(key)) outcomes.set(key, new Set());
    outcomes.get(key).add(record.outcome.status);
  }
  const matches = records.map((record) => {
    const reasons = [];
    const exactContext = canonicalJson(record.contextTags) === canonicalJson(context.tags);
    const exactConstraints = canonicalJson(record.constraints) === canonicalJson(context.constraints);
    if (!exactContext) reasons.push("context_mismatch");
    if (!exactConstraints) reasons.push("constraints_mismatch");
    if (record.evidence.kind !== "production") reasons.push("production_evidence_missing");
    if (superseded.has(record.id)) reasons.push("superseded");
    if (record.outcome.status !== "success") reasons.push("outcome_not_success");
    if ((outcomes.get(outcomeGroupKey(record)) ?? new Set()).size > 1) reasons.push("contradictory_outcome");
    const assumptions = record.assumptions.map((assumption) => ({
      ...assumption,
      retention: retention(record.decidedAt, assumption.halfLifeDays, observedMilliseconds),
    }));
    if (assumptions.some((assumption) => assumption.retention < context.minAssumptionRetention)) reasons.push("assumption_stale");
    reasons.sort();
    const rejected = reasons.some((item) => new Set(["contradictory_outcome", "outcome_not_success", "superseded"]).has(item));
    return {
      assumptions,
      decidedAt: record.decidedAt,
      decision: record.decision,
      disposition: rejected ? "rejected" : reasons.length ? "conditional" : "reusable",
      evidence: record.evidence,
      id: record.id,
      outcome: record.outcome,
      reasons,
      rejectedAlternatives: record.rejectedAlternatives,
    };
  }).sort((left, right) =>
    dispositionRank(left.disposition) - dispositionRank(right.disposition)
    || right.decidedAt.localeCompare(left.decidedAt)
    || left.id.localeCompare(right.id));
  const reusable = matches.find(({ disposition }) => disposition === "reusable");
  return canonicalReport("tugboat.decision-memory.v1", {
    status: reusable ? "ready" : "insufficient_evidence",
    observedAt,
    inputs: {
      contextDigest: `sha256:${sha256(canonicalJson(context))}`,
      recordsDigest: `sha256:${sha256(canonicalJson(records))}`,
    },
    recommendation: reusable ? { decision: reusable.decision, recordId: reusable.id } : null,
    matches,
  });
}
