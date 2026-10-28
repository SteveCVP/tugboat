import path from "node:path";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { missionReducer } from "./reducer.mjs";
import { assertNoSecrets } from "./security.mjs";
import { verifySnapshot } from "./store.mjs";

export const INTELLIGENCE_STATUS = Object.freeze(["blocked", "insufficient_evidence", "ready"]);

const MAX_STRING_BYTES = 4096;
const MAX_REPORT_BYTES = 1024 * 1024;
const MAX_REPORT_ITEMS = 16_384;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function fail(message) {
  throw new Error(message);
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function looksAbsolute(value) {
  return path.posix.isAbsolute(value) || path.win32.isAbsolute(value);
}

function validateScalarSafety(value, label) {
  if (typeof value !== "string") return;
  if (Buffer.byteLength(value, "utf8") > MAX_STRING_BYTES) fail(`${label} exceeds ${MAX_STRING_BYTES} bytes`);
  if (/[\u0000-\u001f\u007f]/.test(value)) fail(`${label} contains control characters`);
  if (looksAbsolute(value)) fail(`${label} contains an absolute path`);
}

function validateValueSafety(value, label, seen = new Set(), maxItems = 256) {
  if (typeof value === "string") {
    validateScalarSafety(value, label);
    return;
  }
  if (!value || typeof value !== "object") return;
  if (seen.has(value)) fail(`${label} contains a cycle`);
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > maxItems) fail(`${label} has more than ${maxItems} items`);
    value.forEach((item, index) => validateValueSafety(item, `${label}[${index}]`, seen, maxItems));
  } else {
    for (const [key, item] of Object.entries(value)) {
      validateScalarSafety(key, `${label} field name`);
      validateValueSafety(item, `${label}.${key}`, seen, maxItems);
    }
  }
  seen.delete(value);
}

export function validateObject(value, { label = "value", allowed = [], required = [] } = {}) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  const allowedSet = new Set(allowed);
  for (const field of Object.keys(value)) {
    if (!allowedSet.has(field)) fail(`Unknown ${label} field ${field}`);
  }
  for (const field of required) {
    if (value[field] === undefined || value[field] === null || value[field] === "") fail(`${label} is missing ${field}`);
  }
  validateValueSafety(value, label);
  assertNoSecrets(value, label);
  return value;
}

export function boundedList(value, label, max = 256, { uniqueBy } = {}) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  if (!Number.isInteger(max) || max < 0 || max > 256) fail(`${label} bound must be an integer from 0 to 256`);
  if (value.length > max) fail(`${label} must contain at most ${max} items`);
  validateValueSafety(value, label);
  assertNoSecrets(value, label);
  if (uniqueBy) {
    const seen = new Set();
    for (const item of value) {
      if (!isPlainObject(item)) fail(`${label} items must be objects when uniqueBy is used`);
      const key = item[uniqueBy];
      if (typeof key !== "string" || key.length === 0) fail(`${label} items need a non-empty ${uniqueBy}`);
      if (seen.has(key)) fail(`Duplicate ${label} ${uniqueBy} ${key}`);
      seen.add(key);
    }
  }
  return value;
}

export function canonicalReport(schemaVersion, body) {
  if (typeof schemaVersion !== "string" || !/^tugboat\.[a-z0-9.-]+\.v\d+$/.test(schemaVersion)) {
    fail("schemaVersion must be a versioned Tugboat schema name");
  }
  if (!isPlainObject(body)) fail("Report body must be an object");
  if (!INTELLIGENCE_STATUS.includes(body.status)) fail(`Report status must be one of ${INTELLIGENCE_STATUS.join(", ")}`);
  if (Object.hasOwn(body, "schemaVersion") || Object.hasOwn(body, "digest")) fail("Report body cannot override schemaVersion or digest");
  validateValueSafety(body, "report", new Set(), MAX_REPORT_ITEMS);
  assertNoSecrets(body, "report");
  const report = { schemaVersion, ...body };
  const encoded = canonicalJson(report);
  if (Buffer.byteLength(encoded, "utf8") > MAX_REPORT_BYTES) fail(`Report exceeds ${MAX_REPORT_BYTES} bytes`);
  return { ...report, digest: `sha256:${sha256(encoded)}` };
}

export function missionSummary(state) {
  if (!state?.metadata?.id) fail("Mission state is missing metadata.id");
  return {
    activeSliceId: state.activeSliceId ?? null,
    id: state.metadata.id,
    protocolVersion: state.protocolVersion,
    revision: state.revision,
    status: state.status,
  };
}

export function readMissionState(dir) {
  if (typeof dir !== "string" || dir.length === 0) fail("Mission directory is required");
  return verifySnapshot(dir, { reducer: missionReducer });
}

export function normalizeObservedAt(value) {
  if (typeof value !== "string" || !UTC_TIMESTAMP.test(value)) fail("observedAt must be an ISO-8601 UTC timestamp with milliseconds");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail("observedAt must be an ISO-8601 UTC timestamp with milliseconds");
  }
  return value;
}

function portableRelative(value, label) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} must be a non-empty portable relative path`);
  if (value.includes("\\") || looksAbsolute(value)) fail(`${label} must be a portable relative path`);
  const segments = value.split("/");
  if (segments.some((segment) => segment === ".." || segment === "")) fail(`${label} must be a portable relative path`);
  validateScalarSafety(value, label);
  return value;
}

function globRegex(pattern) {
  let expression = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*") {
      if (pattern[index + 1] === "*") {
        index += 1;
        if (pattern[index + 1] === "/") {
          index += 1;
          expression += "(?:.*/)?";
        } else {
          expression += ".*";
        }
      } else {
        expression += "[^/]*";
      }
    } else if (character === "?") {
      expression += "[^/]";
    } else {
      expression += character.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
    }
  }
  return new RegExp(`${expression}$`);
}

export function portableGlobMatch(pattern, candidate) {
  const safePattern = portableRelative(pattern, "Glob pattern");
  const safeCandidate = portableRelative(candidate, "Candidate path");
  return globRegex(safePattern).test(safeCandidate);
}
