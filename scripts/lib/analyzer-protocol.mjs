import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { inspectAdapter, runAdapter } from "./adapter-sdk.mjs";
import { sha256 } from "./canonical.mjs";
import { canonicalReport, validateObject } from "./intelligence-core.mjs";
import { assertNoSecrets } from "./security.mjs";
import { canonicalDigest, exactObject, portableRelativePath } from "./proof-runtime.mjs";

const ANALYZER_IDS = Object.freeze(["cloudformation-cdk", "github-actions", "go", "graphql", "oci", "openapi", "python", "sql", "terraform", "typescript"]);
const ANALYZER_ID_SET = new Set(ANALYZER_IDS);
const ANALYZER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../analyzers");
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REPORT_FIELDS = ["schemaVersion", "status", "analyzer", "subject", "requestDigest", "compatibility", "effects", "uncertainty", "counterexamples", "limitations", "digest"];
const SEMANTIC_LIMITATIONS = Object.freeze({
  typescript: "Certified contract: explicit top-level exports; re-exports and unsupported declarations yield insufficient evidence.",
  python: "Certified contract: explicit top-level public functions and classes; star imports yield insufficient evidence.",
  go: "Certified contract: exported package declarations; cgo and method-set analysis yield insufficient evidence.",
  openapi: "Certified contract: OpenAPI 3.x JSON operations and component schemas; YAML requires a separately pinned parser.",
  graphql: "Certified contract: explicit schema type and field definitions; schema extensions and directive definitions yield insufficient evidence.",
  sql: "Certified contract: declarative CREATE TABLE schema snapshots; procedural and imperative migration bodies yield insufficient evidence.",
  terraform: "Certified contract: explicit Terraform resource blocks; modules, data sources, dynamic blocks, and unknown expressions yield insufficient evidence.",
  "cloudformation-cdk": "Certified contract: CloudFormation JSON resources plus optional CDK source-digest binding; YAML requires a separately pinned parser.",
  "github-actions": "Certified contract: GitHub Actions JSON triggers, permissions, action pins, and secret references; YAML requires a separately pinned parser.",
  oci: "Certified contract: OCI v2 inspection documents binding config, layers, capabilities, user, entrypoint, and provenance subject.",
});

function integer(value, label, minimum = 0) {
  if (!Number.isInteger(value) || value < minimum) throw new Error(`${label} must be an integer of at least ${minimum}`);
}

function digest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new Error(`${label} is invalid`);
}

function shortString(value, label, maximum = 4096) {
  if (typeof value !== "string" || !value || Buffer.byteLength(value) > maximum || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(`${label} is invalid`);
}

function validateSpan(span, label) {
  exactObject(span, label, ["source", "start", "end"], ["source", "start", "end"]);
  if (!["before", "after"].includes(span.source)) throw new Error(`${label}.source is invalid`);
  for (const edge of ["start", "end"]) {
    exactObject(span[edge], `${label}.${edge}`, ["line", "column", "offset"], ["line", "column", "offset"]);
    integer(span[edge].line, `${label}.${edge}.line`, 1);
    integer(span[edge].column, `${label}.${edge}.column`, 1);
    integer(span[edge].offset, `${label}.${edge}.offset`);
  }
  if (span.end.offset < span.start.offset) throw new Error(`${label} end precedes start`);
}

function validateCompatibility(value) {
  exactObject(value, "analyzer compatibility", ["verdict", "summary"], ["verdict", "summary"]);
  if (!["compatible", "breaking", "insufficient_evidence"].includes(value.verdict)) throw new Error("Analyzer compatibility verdict is invalid");
  shortString(value.summary, "Analyzer compatibility summary");
}

function validateEffects(effects) {
  if (!Array.isArray(effects) || effects.length > 256) throw new Error("Analyzer effects are invalid");
  const ids = new Set();
  for (const [index, effect] of effects.entries()) {
    exactObject(effect, `analyzer effect ${index}`, ["id", "type", "subject", "change", "compatibility", "certainty", "span", "rationale"], ["id", "type", "subject", "change", "compatibility", "certainty", "span", "rationale"]);
    for (const key of ["id", "type", "subject", "rationale"]) shortString(effect[key], `Analyzer effect ${index}.${key}`);
    if (ids.has(effect.id)) throw new Error(`Duplicate analyzer effect id ${effect.id}`);
    ids.add(effect.id);
    if (!["add", "modify", "remove"].includes(effect.change)) throw new Error(`Analyzer effect ${index}.change is invalid`);
    if (!["compatible", "breaking"].includes(effect.compatibility)) throw new Error(`Analyzer effect ${index}.compatibility is invalid`);
    if (effect.certainty !== "proven") throw new Error(`Analyzer effect ${index}.certainty must be proven`);
    validateSpan(effect.span, `analyzer effect ${index}.span`);
  }
  const sorted = [...effects].sort((left, right) => left.subject.localeCompare(right.subject) || left.change.localeCompare(right.change));
  if (JSON.stringify(sorted) !== JSON.stringify(effects)) throw new Error("Analyzer effects must be canonically ordered");
}

function validateFindings(items, label) {
  if (!Array.isArray(items) || items.length > 256) throw new Error(`${label} are invalid`);
  for (const [index, item] of items.entries()) {
    exactObject(item, `${label} ${index}`, ["code", "subject", "message", "span"], ["code", "subject", "message", "span"]);
    for (const key of ["code", "subject", "message"]) shortString(item[key], `${label} ${index}.${key}`);
    validateSpan(item.span, `${label} ${index}.span`);
  }
}

function validateRawOutput(output) {
  exactObject(output, "analyzer adapter output", ["status", "compatibility", "effects", "uncertainty", "counterexamples"], ["status", "compatibility", "effects", "uncertainty", "counterexamples"]);
  if (!["ready", "blocked", "insufficient_evidence"].includes(output.status)) throw new Error("Analyzer adapter status is invalid");
  validateCompatibility(output.compatibility);
  validateEffects(output.effects);
  validateFindings(output.uncertainty, "analyzer uncertainty");
  validateFindings(output.counterexamples, "analyzer counterexample");
  if (output.status === "ready" && output.compatibility.verdict !== "compatible") throw new Error("Ready analyzer output must be compatible");
  if (output.status === "blocked" && (output.compatibility.verdict !== "breaking" || output.counterexamples.length === 0)) throw new Error("Blocked analyzer output needs a breaking counterexample");
  if (output.status === "insufficient_evidence" && (output.compatibility.verdict !== "insufficient_evidence" || output.uncertainty.length === 0)) throw new Error("Insufficient analyzer output needs uncertainty");
}

function sourceDescriptor(value, label) {
  exactObject(value, label, ["path", "source"], ["path"]);
  portableRelativePath(value.path, `${label} path`);
  if (typeof value.source !== "string" || Buffer.byteLength(value.source) > 256 * 1024) throw new Error(`${label} source must be at most 256 KiB`);
  return { path: value.path, digest: `sha256:${sha256(value.source)}`, source: value.source };
}

function tightenedManifest(manifest, executionLimits = {}) {
  exactObject(executionLimits, "analyzer execution limits", ["timeoutMs", "maxOutputBytes"]);
  const copy = structuredClone(manifest);
  if (executionLimits.timeoutMs !== undefined) {
    integer(executionLimits.timeoutMs, "Analyzer timeoutMs", 1);
    copy.timeoutMs = Math.min(copy.timeoutMs, executionLimits.timeoutMs);
  }
  if (executionLimits.maxOutputBytes !== undefined) {
    integer(executionLimits.maxOutputBytes, "Analyzer maxOutputBytes", 64);
    copy.maxOutputBytes = Math.min(copy.maxOutputBytes, executionLimits.maxOutputBytes);
  }
  return copy;
}

export function loadCertifiedAnalyzerManifest(analyzerId, { analyzerDir = ANALYZER_DIR } = {}) {
  if (!ANALYZER_ID_SET.has(analyzerId)) throw new Error("Certified analyzer id is invalid");
  const manifestPath = path.join(analyzerDir, `${analyzerId}.manifest.json`);
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")); } catch (error) { throw new Error(`Certified analyzer manifest could not be loaded: ${error.message}`); }
  if (manifest.id !== `tugboat.analyzer.${analyzerId}`) throw new Error("Certified analyzer manifest id mismatch");
  const inspection = inspectAdapter(manifest, { manifestDir: analyzerDir });
  if (inspection.status !== "ready" || inspection.adapter.isolation !== manifest.isolation) throw new Error("Certified analyzer manifest inspection failed");
  return manifest;
}

export function inspectCertifiedAnalyzerAvailability(analyzerId, { analyzerDir = ANALYZER_DIR } = {}) {
  if (!ANALYZER_ID_SET.has(analyzerId)) throw new Error("Certified analyzer id is invalid");
  try {
    const manifest = loadCertifiedAnalyzerManifest(analyzerId, { analyzerDir });
    const parserAsset = manifest.assets.find((asset) => asset.path === "analyzer-runtime.mjs");
    return canonicalReport("tugboat.certified-analyzer-availability.v1", {
      status: "ready",
      analyzerId,
      available: true,
      executableDigest: canonicalDigest({ entrypoint: manifest.entrypointDigest, assets: manifest.assets }),
      toolchainDigest: parserAsset.digest,
      uncertainty: null,
    });
  } catch {
    return canonicalReport("tugboat.certified-analyzer-availability.v1", {
      status: "insufficient_evidence",
      analyzerId,
      available: false,
      executableDigest: null,
      toolchainDigest: null,
      uncertainty: {
        code: "toolchain_unavailable",
        subject: analyzerId,
        message: "The pinned analyzer manifest, executable, or parser asset is unavailable or failed integrity verification.",
      },
    });
  }
}

export function analyzeCertifiedChange({ analyzerId, before, after, executionLimits = {}, analyzerDir = ANALYZER_DIR }) {
  const beforeDescriptor = sourceDescriptor(before, "Analyzer before source");
  const afterDescriptor = sourceDescriptor(after, "Analyzer after source");
  assertNoSecrets({ before: before.source, after: after.source }, "Analyzer source");
  const manifest = tightenedManifest(loadCertifiedAnalyzerManifest(analyzerId, { analyzerDir }), executionLimits);
  const input = {
    analyzer: analyzerId,
    beforePath: beforeDescriptor.path,
    beforeDigest: beforeDescriptor.digest,
    beforeSource: beforeDescriptor.source,
    afterPath: afterDescriptor.path,
    afterDigest: afterDescriptor.digest,
    afterSource: afterDescriptor.source,
  };
  const result = runAdapter({ manifest, manifestDir: analyzerDir, inputRoot: analyzerDir, input });
  validateRawOutput(result.output);
  const parserAsset = manifest.assets.find((asset) => asset.path === "analyzer-runtime.mjs");
  if (!parserAsset) throw new Error("Certified analyzer parser asset is missing");
  const report = canonicalReport("tugboat.certified-analyzer-report.v1", {
    status: result.output.status,
    analyzer: {
      id: analyzerId,
      version: "1.0.0",
      executableDigest: canonicalDigest({ entrypoint: manifest.entrypointDigest, assets: manifest.assets }),
      isolation: manifest.isolation,
      toolchain: { name: `tugboat-${analyzerId}-surface-parser`, version: "1.0.0", digest: parserAsset.digest },
    },
    subject: {
      before: { path: beforeDescriptor.path, digest: beforeDescriptor.digest },
      after: { path: afterDescriptor.path, digest: afterDescriptor.digest },
    },
    requestDigest: canonicalDigest({
      analyzer: analyzerId,
      before: { path: beforeDescriptor.path, digest: beforeDescriptor.digest },
      after: { path: afterDescriptor.path, digest: afterDescriptor.digest },
    }),
    compatibility: result.output.compatibility,
    effects: result.output.effects,
    uncertainty: result.output.uncertainty,
    counterexamples: result.output.counterexamples,
    limitations: [...result.limitations, SEMANTIC_LIMITATIONS[analyzerId]],
  });
  return validateAnalyzerReport(report);
}

export function validateAnalyzerReport(report) {
  validateObject(report, { label: "certified analyzer report", allowed: REPORT_FIELDS, required: REPORT_FIELDS });
  if (report.schemaVersion !== "tugboat.certified-analyzer-report.v1") throw new Error("Unsupported certified analyzer report schemaVersion");
  if (!["ready", "blocked", "insufficient_evidence"].includes(report.status)) throw new Error("Certified analyzer report status is invalid");
  exactObject(report.analyzer, "certified analyzer identity", ["id", "version", "executableDigest", "isolation", "toolchain"], ["id", "version", "executableDigest", "isolation", "toolchain"]);
  if (!ANALYZER_ID_SET.has(report.analyzer.id)) throw new Error("Certified analyzer identity is invalid");
  if (report.analyzer.version !== "1.0.0" || report.analyzer.isolation !== "brokered") throw new Error("Certified analyzer version or isolation is invalid");
  digest(report.analyzer.executableDigest, "Certified analyzer executable digest");
  exactObject(report.analyzer.toolchain, "certified analyzer toolchain", ["name", "version", "digest"], ["name", "version", "digest"]);
  shortString(report.analyzer.toolchain.name, "Certified analyzer toolchain name");
  shortString(report.analyzer.toolchain.version, "Certified analyzer toolchain version");
  digest(report.analyzer.toolchain.digest, "Certified analyzer toolchain digest");
  exactObject(report.subject, "certified analyzer subject", ["before", "after"], ["before", "after"]);
  for (const side of ["before", "after"]) {
    exactObject(report.subject[side], `certified analyzer subject ${side}`, ["path", "digest"], ["path", "digest"]);
    portableRelativePath(report.subject[side].path, `Certified analyzer ${side} path`);
    digest(report.subject[side].digest, `Certified analyzer ${side} digest`);
  }
  digest(report.requestDigest, "Certified analyzer request digest");
  const expectedRequestDigest = canonicalDigest({ analyzer: report.analyzer.id, before: report.subject.before, after: report.subject.after });
  if (report.requestDigest !== expectedRequestDigest) throw new Error("Certified analyzer request digest mismatch");
  validateCompatibility(report.compatibility);
  validateEffects(report.effects);
  validateFindings(report.uncertainty, "certified analyzer uncertainty");
  validateFindings(report.counterexamples, "certified analyzer counterexample");
  if (!Array.isArray(report.limitations) || report.limitations.length > 16) throw new Error("Certified analyzer limitations are invalid");
  report.limitations.forEach((value, index) => shortString(value, `Certified analyzer limitation ${index}`));
  digest(report.digest, "Certified analyzer report digest");
  const { digest: claimedDigest, ...body } = report;
  const expected = canonicalDigest(body);
  if (claimedDigest !== expected) throw new Error("Certified analyzer report digest mismatch");
  const manifest = loadCertifiedAnalyzerManifest(report.analyzer.id);
  const parserAsset = manifest.assets.find((asset) => asset.path === "analyzer-runtime.mjs");
  const expectedExecutableDigest = canonicalDigest({ entrypoint: manifest.entrypointDigest, assets: manifest.assets });
  if (report.analyzer.executableDigest !== expectedExecutableDigest || report.analyzer.toolchain.digest !== parserAsset?.digest) {
    throw new Error("Certified analyzer executable or toolchain digest mismatch");
  }
  if (report.status === "ready" && report.compatibility.verdict !== "compatible") throw new Error("Ready certified analyzer report must be compatible");
  if (report.status === "blocked" && (report.compatibility.verdict !== "breaking" || report.counterexamples.length === 0)) throw new Error("Blocked certified analyzer report needs a counterexample");
  if (report.status === "insufficient_evidence" && (report.compatibility.verdict !== "insufficient_evidence" || report.uncertainty.length === 0)) throw new Error("Insufficient certified analyzer report needs uncertainty");
  return report;
}

export function compareAnalyzerRuns(first, second) {
  try {
    validateAnalyzerReport(first);
    validateAnalyzerReport(second);
  } catch (error) {
    return canonicalReport("tugboat.analyzer-determinism.v1", {
      status: "blocked",
      deterministic: false,
      counterexample: { code: "analyzer_nondeterminism", subject: first?.analyzer?.id ?? "unknown", message: `One analyzer run was not a valid deterministic report: ${error.message}` },
    });
  }
  const deterministic = first.digest === second.digest;
  return canonicalReport("tugboat.analyzer-determinism.v1", {
    status: deterministic ? "ready" : "blocked",
    deterministic,
    counterexample: deterministic ? null : { code: "analyzer_nondeterminism", subject: first.analyzer.id, message: `Repeated analyzer runs differed: ${first.digest} != ${second.digest}` },
  });
}

export { ANALYZER_IDS };
