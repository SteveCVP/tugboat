import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { assertNoSecrets } from "./security.mjs";

export const CERTIFIED_CHANGESET_LIMITS = Object.freeze({
  maxEnvelopeBytes: 4 * 1024 * 1024,
  maxBodyBytes: 1024 * 1024,
  maxSubjects: 256,
  maxInputs: 256,
  maxClaims: 256,
  maxCounterexamples: 256,
  maxSubjectIds: 256,
  maxWitnessPath: 256,
  maxEvidence: 256,
  maxTextBytes: 16 * 1024,
});

export const CERTIFIED_FORMATS = Object.freeze([
  "tugboat.effect-footprint.v1",
  "tugboat.non-interference-witness.v1",
  "tugboat.composition-certificate.v1",
  "tugboat.merge-certificate.v1",
  "tugboat.rollback-equivalence.v1",
  "tugboat.selective-proof.v1",
]);

const FORMAT_SET = new Set(CERTIFIED_FORMATS);
const VERDICTS = new Set(["ready", "blocked", "insufficient_evidence"]);
const CLAIM_STATUSES = new Set(["passed", "failed", "indeterminate"]);
const ID_NAMESPACE = /^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*$/;
const ID_VALUE = /^[A-Za-z0-9][A-Za-z0-9._/@+-]*$/;
const TOKEN = /^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

export class CertificateValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "CertificateValidationError";
    this.exitCode = 2;
  }
}

function fail(message) {
  throw new CertificateValidationError(message);
}

function exactObject(value, label, allowed, required = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`Unknown ${label} field ${key}`);
  for (const key of required) if (value[key] === undefined || value[key] === null || value[key] === "") fail(`${label} is missing ${key}`);
  return value;
}

function boundedText(value, label, limits, { token = false } = {}) {
  if (typeof value !== "string" || !value || Buffer.byteLength(value) > limits.maxTextBytes || /[\u0000-\u001f\u007f]/.test(value)) {
    fail(`${label} must be non-empty bounded text without control characters`);
  }
  if (token && !TOKEN.test(value)) fail(`${label} must be a stable lowercase token`);
  return value;
}

function sha256Digest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail(`${label} must be a sha256 digest`);
  return value;
}

function isoTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || !/^\d{4}-\d{2}-\d{2}T/.test(value)) fail(`${label} must be an ISO timestamp`);
  return value;
}

function boundedArray(value, label, maximum, { allowEmpty = true } = {}) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  if (!allowEmpty && value.length === 0) fail(`${label} must not be empty`);
  if (value.length > maximum) fail(`${label} exceeds ${maximum} items`);
  return value;
}

function uniqueSorted(values, label) {
  const sorted = [...values].sort((left, right) => left.localeCompare(right));
  if (new Set(sorted).size !== sorted.length) fail(`${label} must not contain duplicates`);
  return sorted;
}

function effectiveLimits(overrides = {}) {
  exactObject(overrides, "certificate limits", Object.keys(CERTIFIED_CHANGESET_LIMITS));
  const result = { ...CERTIFIED_CHANGESET_LIMITS };
  for (const [key, value] of Object.entries(overrides)) {
    if (!Number.isInteger(value) || value < 1 || value > CERTIFIED_CHANGESET_LIMITS[key]) fail(`${key} may only lower the certified changeset limit`);
    result[key] = value;
  }
  return result;
}

function secretScan(value, label) {
  try {
    assertNoSecrets(value, label);
  } catch (error) {
    fail(error.message);
  }
}

export function portableSubjectId(value, label = "Value") {
  if (typeof value !== "string" || !value || Buffer.byteLength(value) > 1024 || /[\\\u0000-\u001f\u007f]/.test(value)) {
    fail(`${label} must be a portable subject ID`);
  }
  const separator = value.indexOf(":");
  if (separator < 1 || separator === value.length - 1 || value.indexOf(":", separator + 1) >= 0) fail(`${label} must be a portable subject ID`);
  const namespace = value.slice(0, separator);
  const identifier = value.slice(separator + 1);
  if (!ID_NAMESPACE.test(namespace) || identifier.startsWith("/") || !ID_VALUE.test(identifier)) fail(`${label} must be a portable subject ID`);
  const segments = identifier.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) fail(`${label} must be a portable subject ID`);
  return value;
}

function subjectReference(value, label, limits) {
  exactObject(value, label, ["kind", "id", "digest"], ["kind", "id", "digest"]);
  return {
    kind: boundedText(value.kind, `${label} kind`, limits, { token: true }),
    id: portableSubjectId(value.id, `${label} ID`),
    digest: sha256Digest(value.digest, `${label} digest`),
  };
}

function identity(value, label, limits) {
  exactObject(value, label, ["name", "kind", "runtime"], ["name", "kind", "runtime"]);
  return {
    name: boundedText(value.name, `${label} name`, limits),
    kind: boundedText(value.kind, `${label} kind`, limits, { token: true }),
    runtime: boundedText(value.runtime, `${label} runtime`, limits, { token: true }),
  };
}

function evidenceReference(value, label, limits) {
  exactObject(value, label, ["id", "digest"], ["id", "digest"]);
  return {
    id: portableSubjectId(value.id, `${label} ID`),
    digest: sha256Digest(value.digest, `${label} digest`),
  };
}

export function createCounterexample(value, options = {}) {
  const limits = effectiveLimits(options.limits);
  exactObject(
    value,
    "counterexample",
    ["code", "invariantId", "message", "expected", "actual", "subjectIds", "witnessPath", "evidence"],
    ["code", "invariantId", "message", "expected", "actual", "subjectIds", "witnessPath", "evidence"],
  );
  const subjectIds = boundedArray(value.subjectIds, "counterexample subjectIds", limits.maxSubjectIds, { allowEmpty: false })
    .map((item) => portableSubjectId(item, "Counterexample subject ID"));
  const witnessPath = boundedArray(value.witnessPath, "counterexample witnessPath", limits.maxWitnessPath, { allowEmpty: false })
    .map((item) => portableSubjectId(item, "Counterexample witness path item"));
  const evidence = boundedArray(value.evidence, "counterexample evidence", limits.maxEvidence)
    .map((item, index) => evidenceReference(item, `counterexample evidence ${index}`, limits))
    .sort((left, right) => left.id.localeCompare(right.id));
  if (new Set(evidence.map((item) => item.id)).size !== evidence.length) fail("counterexample evidence IDs must not contain duplicates");
  const result = {
    code: boundedText(value.code, "counterexample code", limits, { token: true }),
    invariantId: portableSubjectId(value.invariantId, "Counterexample invariant ID"),
    message: boundedText(value.message, "counterexample message", limits),
    expected: boundedText(value.expected, "counterexample expected", limits),
    actual: boundedText(value.actual, "counterexample actual", limits),
    subjectIds: uniqueSorted(subjectIds, "counterexample subjectIds"),
    witnessPath,
    evidence,
  };
  secretScan(result, "Counterexample");
  return result;
}

function claim(value, index, limits) {
  const label = `claim ${index}`;
  exactObject(value, label, ["id", "type", "status", "subjectIds", "summary"], ["id", "type", "status", "subjectIds", "summary"]);
  if (!CLAIM_STATUSES.has(value.status)) fail(`${label} status is unsupported`);
  const subjectIds = boundedArray(value.subjectIds, `${label} subjectIds`, limits.maxSubjectIds, { allowEmpty: false })
    .map((item) => portableSubjectId(item, `${label} subject ID`));
  return {
    id: portableSubjectId(value.id, `${label} ID`),
    type: boundedText(value.type, `${label} type`, limits, { token: true }),
    status: value.status,
    subjectIds: uniqueSorted(subjectIds, `${label} subjectIds`),
    summary: boundedText(value.summary, `${label} summary`, limits),
  };
}

function normalizePayload(value, limits) {
  exactObject(
    value,
    "certificate payload",
    ["id", "generatedAt", "verdict", "subjects", "inputs", "producer", "verifier", "claims", "counterexamples", "body"],
    ["id", "generatedAt", "verdict", "subjects", "inputs", "producer", "claims", "counterexamples", "body"],
  );
  if (!VERDICTS.has(value.verdict)) fail("certificate payload verdict is unsupported");
  const subjects = boundedArray(value.subjects, "certificate payload subjects", limits.maxSubjects, { allowEmpty: false })
    .map((item, index) => subjectReference(item, `subject ${index}`, limits))
    .sort((left, right) => left.id.localeCompare(right.id));
  const inputs = boundedArray(value.inputs, "certificate payload inputs", limits.maxInputs, { allowEmpty: false })
    .map((item, index) => subjectReference(item, `input ${index}`, limits))
    .sort((left, right) => left.id.localeCompare(right.id));
  for (const [label, items] of [["subject", subjects], ["input", inputs]]) {
    if (new Set(items.map((item) => item.id)).size !== items.length) fail(`certificate ${label} IDs must not contain duplicates`);
  }
  const claims = boundedArray(value.claims, "certificate payload claims", limits.maxClaims, { allowEmpty: false })
    .map((item, index) => claim(item, index, limits))
    .sort((left, right) => left.id.localeCompare(right.id));
  if (new Set(claims.map((item) => item.id)).size !== claims.length) fail("certificate claim IDs must not contain duplicates");
  const counterexamples = boundedArray(value.counterexamples, "certificate payload counterexamples", limits.maxCounterexamples)
    .map((item) => createCounterexample(item, { limits }))
    .sort((left, right) => `${left.code}:${left.invariantId}:${left.message}`.localeCompare(`${right.code}:${right.invariantId}:${right.message}`));
  exactObject(value.body, "certificate body", Object.keys(value.body));
  if (Buffer.byteLength(canonicalJson(value.body)) > limits.maxBodyBytes) fail(`certificate body exceeds ${limits.maxBodyBytes} bytes`);
  const result = {
    id: portableSubjectId(value.id, "Certificate ID"),
    generatedAt: isoTimestamp(value.generatedAt, "certificate payload generatedAt"),
    verdict: value.verdict,
    subjects,
    inputs,
    producer: identity(value.producer, "producer", limits),
    ...(value.verifier === undefined ? {} : { verifier: identity(value.verifier, "verifier", limits) }),
    claims,
    counterexamples,
    body: structuredClone(value.body),
  };
  secretScan(result, "Certificate payload");
  return result;
}

function validateFormat(format) {
  if (!FORMAT_SET.has(format)) fail(`Unsupported certified format ${String(format)}`);
  return format;
}

function normalizeEnvelope(envelope, limits, { verifyDigest = true } = {}) {
  exactObject(envelope, "certificate envelope", ["schemaVersion", "format", "payload", "digest"], ["schemaVersion", "format", "payload", "digest"]);
  if (envelope.schemaVersion !== 1) fail("Unsupported certificate schema version");
  const format = validateFormat(envelope.format);
  const payload = normalizePayload(envelope.payload, limits);
  const expectedDigest = `sha256:${sha256(canonicalJson(payload))}`;
  if (verifyDigest && envelope.digest !== expectedDigest) fail("Certificate payload digest mismatch");
  if (!verifyDigest && envelope.digest !== undefined) sha256Digest(envelope.digest, "Certificate digest");
  return { schemaVersion: 1, format, payload, digest: expectedDigest };
}

export function createCertifiedEnvelope({ format, payload }, options = {}) {
  const limits = effectiveLimits(options.limits);
  const normalizedPayload = normalizePayload(payload, limits);
  const envelope = {
    schemaVersion: 1,
    format: validateFormat(format),
    payload: normalizedPayload,
    digest: `sha256:${sha256(canonicalJson(normalizedPayload))}`,
  };
  if (Buffer.byteLength(canonicalJson(envelope)) > limits.maxEnvelopeBytes) fail(`certificate envelope exceeds ${limits.maxEnvelopeBytes} bytes`);
  return envelope;
}

export function verifyCertifiedEnvelope(envelope, options = {}) {
  const limits = effectiveLimits(options.limits);
  const normalized = normalizeEnvelope(envelope, limits);
  if (options.expectedFormat !== undefined && normalized.format !== options.expectedFormat) {
    fail(`Certificate format mismatch: expected ${options.expectedFormat}, received ${normalized.format}`);
  }
  return {
    ...normalized,
    verdict: normalized.payload.verdict,
    semanticProof: false,
    reason: "shared envelope integrity only; format-specific semantics were not evaluated",
  };
}

export function readCertifiedEnvelope(file, options = {}) {
  const limits = effectiveLimits(options.limits);
  let contents;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) fail(`Certificate path is not a regular file: ${file}`);
    if (stat.size > limits.maxEnvelopeBytes) fail(`certificate envelope exceeds ${limits.maxEnvelopeBytes} bytes`);
    contents = fs.readFileSync(file, "utf8");
  } catch (error) {
    if (error instanceof CertificateValidationError) throw error;
    fail(`Cannot read certificate ${file}: ${error.message}`);
  }
  let envelope;
  try {
    envelope = JSON.parse(contents);
  } catch (error) {
    fail(`Cannot parse certificate ${file}: ${error.message}`);
  }
  return verifyCertifiedEnvelope(envelope, { ...options, limits });
}

export function writeCertifiedEnvelope(file, envelope, options = {}) {
  const limits = effectiveLimits(options.limits);
  const verified = verifyCertifiedEnvelope(envelope, { ...options, limits });
  const output = `${canonicalJson({ schemaVersion: verified.schemaVersion, format: verified.format, payload: verified.payload, digest: verified.digest })}\n`;
  if (Buffer.byteLength(output) > limits.maxEnvelopeBytes) fail(`certificate envelope exceeds ${limits.maxEnvelopeBytes} bytes`);
  const target = path.resolve(file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.tmp-${process.pid}-${randomUUID()}`;
  try {
    fs.writeFileSync(temporary, output, { flag: "wx", mode: 0o600 });
    fs.renameSync(temporary, target);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
  return target;
}
