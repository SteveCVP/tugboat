import { canonicalJson } from "./canonical.mjs";
import { canonicalReport } from "./intelligence-core.mjs";
import { boundedList, validateObject } from "./intelligence-core.mjs";
import { canonicalDigest } from "./proof-runtime.mjs";

const SEVERITY = ["low", "medium", "high", "critical"];

function normalized(value) {
  return value.trim().replace(/\s+/g, " ").toLowerCase();
}

function validateReviews(reviews) {
  boundedList(reviews, "reviews", 32);
  if (reviews.length < 2) throw new Error("Differential review requires at least two reviews");
  const reviewers = new Set();
  return reviews.map((review, reviewIndex) => {
    validateObject(review, { label: `review[${reviewIndex}]`, allowed: ["schemaVersion", "reviewer", "inputDigest", "findings"], required: ["schemaVersion", "reviewer", "inputDigest", "findings"] });
    if (review.schemaVersion !== "tugboat.agent-review.v1") throw new Error("Unsupported agent review schemaVersion");
    if (reviewers.has(review.reviewer)) throw new Error(`Duplicate reviewer ${review.reviewer}`);
    reviewers.add(review.reviewer);
    if (!/^sha256:[0-9a-f]{64}$/.test(review.inputDigest)) throw new Error(`Invalid inputDigest for ${review.reviewer}`);
    boundedList(review.findings, `findings for ${review.reviewer}`, 256, { uniqueBy: "id" });
    return { ...review, findings: review.findings.map((finding, findingIndex) => {
      validateObject(finding, { label: `finding[${reviewIndex}][${findingIndex}]`, allowed: ["id", "severity", "claim", "subjects", "evidenceDigests", "recommendation", "disposition"], required: ["id", "severity", "claim", "subjects", "evidenceDigests", "recommendation", "disposition"] });
      if (!SEVERITY.includes(finding.severity) || !["open", "resolved", "accepted"].includes(finding.disposition)) throw new Error(`Invalid finding ${finding.id}`);
      boundedList(finding.subjects, `subjects for ${finding.id}`, 64);
      boundedList(finding.evidenceDigests, `evidence for ${finding.id}`, 64);
      if (finding.evidenceDigests.some((value) => !/^sha256:[0-9a-f]{64}$/.test(value))) throw new Error(`Invalid evidence digest for ${finding.id}`);
      return { ...finding, subjects: [...finding.subjects].sort(), evidenceDigests: [...finding.evidenceDigests].sort() };
    }) };
  }).sort((left, right) => left.reviewer.localeCompare(right.reviewer));
}

export function compileDifferentialReview(inputReviews) {
  const reviews = validateReviews(inputReviews);
  const groups = new Map();
  for (const review of reviews) for (const finding of review.findings) {
    const key = canonicalJson({ claim: normalized(finding.claim), subjects: finding.subjects });
    const item = { reviewer: review.reviewer, ...finding };
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }
  const consensus = [];
  const unique = [];
  const conflicts = [];
  const evidenceGaps = [];
  const inputDigests = [...new Set(reviews.map((review) => review.inputDigest))].sort();
  if (inputDigests.length > 1) conflicts.push({ kind: "input", values: inputDigests });
  for (const [key, findings] of [...groups.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const summary = { key: canonicalDigest(JSON.parse(key)), claim: findings[0].claim, subjects: findings[0].subjects, reviewers: findings.map((item) => item.reviewer).sort(), findings: findings.map((item) => item.id).sort() };
    if (findings.length > 1) consensus.push(summary); else unique.push(summary);
    const severities = [...new Set(findings.map((item) => item.severity))].sort();
    const recommendations = [...new Set(findings.map((item) => normalized(item.recommendation)))].sort();
    const evidenceSets = [...new Set(findings.map((item) => canonicalJson(item.evidenceDigests)))].sort();
    if (severities.length > 1) conflicts.push({ kind: "severity", key: summary.key, values: severities });
    if (recommendations.length > 1) conflicts.push({ kind: "recommendation", key: summary.key, values: recommendations });
    if (evidenceSets.length > 1) conflicts.push({ kind: "evidence", key: summary.key, values: evidenceSets.map(JSON.parse) });
    if (findings.every((item) => item.evidenceDigests.length === 0)) evidenceGaps.push({ key: summary.key, claim: summary.claim, reviewers: summary.reviewers });
  }
  const unresolvedHigh = reviews.flatMap((review) => review.findings.map((finding) => ({ reviewer: review.reviewer, ...finding }))).filter((item) => ["high", "critical"].includes(item.severity) && item.disposition === "open").map((item) => ({ reviewer: item.reviewer, id: item.id, severity: item.severity, claim: item.claim })).sort((left, right) => `${left.reviewer}:${left.id}`.localeCompare(`${right.reviewer}:${right.id}`));
  const insufficient = inputDigests.length > 1 || evidenceGaps.length > 0;
  const blocked = unresolvedHigh.length > 0 || conflicts.some((item) => item.kind !== "input");
  return canonicalReport("tugboat.differential-review.v1", {
    status: insufficient ? "insufficient_evidence" : blocked ? "blocked" : "ready",
    inputDigests,
    consensus,
    unique,
    conflicts,
    evidenceGaps,
    unresolvedHigh,
    policy: "Reviewer count is not confidence and consensus is not proof.",
  });
}
