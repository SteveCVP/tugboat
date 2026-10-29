import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  analyzeCertifiedChange,
  compareAnalyzerRuns,
  inspectCertifiedAnalyzerAvailability,
  loadCertifiedAnalyzerManifest,
  validateAnalyzerReport,
} from "./lib/analyzer-protocol.mjs";
import { canonicalDigest } from "./lib/proof-runtime.mjs";

const root = path.dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(fs.readFileSync(path.join(root, "fixtures/analyzers/conformance-fixtures.json"), "utf8"));
const analyzerIds = Object.keys(fixtures).sort();

function analyze(id, before, after, options = {}) {
  const fixture = fixtures[id];
  return analyzeCertifiedChange({
    analyzerId: id,
    before: { path: fixture.path, source: before },
    after: { path: fixture.path, source: after },
    ...options,
  });
}

for (const id of analyzerIds) {
  test(`${id} analyzer certifies compatible additions with pinned identity and exact spans`, () => {
    const fixture = fixtures[id];
    const report = analyze(id, fixture.safe.before, fixture.safe.after);
    assert.equal(report.status, "ready");
    assert.equal(report.compatibility.verdict, "compatible");
    assert.equal(report.analyzer.id, id);
    assert.match(report.analyzer.executableDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(report.analyzer.toolchain.digest, /^sha256:[0-9a-f]{64}$/);
    assert.ok(report.effects.length > 0);
    assert.ok(report.effects.every((effect) => effect.span.start.offset >= 0 && effect.span.end.offset >= effect.span.start.offset));
    assert.deepEqual(validateAnalyzerReport(report), report);
  });

  test(`${id} analyzer blocks a breaking public-surface change with a counterexample`, () => {
    const fixture = fixtures[id];
    const report = analyze(id, fixture.breaking.before, fixture.breaking.after);
    assert.equal(report.status, "blocked");
    assert.equal(report.compatibility.verdict, "breaking");
    assert.ok(report.counterexamples.length > 0);
    assert.match(report.counterexamples[0].code, /^breaking_/);
    assert.ok(report.counterexamples[0].subject.length > 0);
  });

  test(`${id} analyzer fails closed for malformed and unsupported source`, () => {
    const fixture = fixtures[id];
    const malformed = analyze(id, fixture.safe.before, fixture.malformed);
    assert.equal(malformed.status, "insufficient_evidence");
    assert.equal(malformed.compatibility.verdict, "insufficient_evidence");
    assert.equal(malformed.uncertainty[0].code, "parse_error");
    const unsupported = analyze(id, fixture.safe.before, fixture.unsupported);
    assert.equal(unsupported.status, "insufficient_evidence");
    assert.equal(unsupported.uncertainty[0].code, "unsupported_construct");
  });

  test(`${id} analyzer is deterministic and its execution bounds fail closed`, () => {
    const fixture = fixtures[id];
    const first = analyze(id, fixture.safe.before, fixture.safe.after);
    const second = analyze(id, fixture.safe.before, fixture.safe.after);
    assert.equal(compareAnalyzerRuns(first, second).status, "ready");
    assert.equal(first.digest, second.digest);
    assert.throws(() => analyze(id, fixture.safe.before, fixture.safe.after, { executionLimits: { timeoutMs: 1 } }), /timed out/);
    assert.throws(() => analyze(id, fixture.safe.before, fixture.safe.after, { executionLimits: { maxOutputBytes: 64 } }), /output exceeded/);
  });

  test(`${id} analyzer rejects secret-bearing input and nondeterministic output`, () => {
    const fixture = fixtures[id];
    const fakeSecret = ["ghp", "abcdefghijklmnopqrstuvwxyz1234567890"].join("_");
    assert.throws(() => analyze(id, fixture.safe.before, `${fixture.safe.after}\nconst token = \"${fakeSecret}\";`), /secret/i);
    const first = analyze(id, fixture.safe.before, fixture.safe.after);
    const changed = structuredClone(first);
    changed.effects[0].rationale += " changed";
    changed.digest = canonicalDigest(Object.fromEntries(Object.entries(changed).filter(([key]) => key !== "digest")));
    assert.deepEqual(validateAnalyzerReport(changed), changed);
    const comparison = compareAnalyzerRuns(first, changed);
    assert.equal(comparison.status, "blocked");
    assert.equal(comparison.counterexample.code, "analyzer_nondeterminism");
  });
}

test("certified analyzer manifests pin the executable and packaged parser assets", () => {
  for (const id of analyzerIds) {
    const manifest = loadCertifiedAnalyzerManifest(id);
    assert.equal(manifest.id, `tugboat.analyzer.${id}`);
    assert.match(manifest.entrypointDigest, /^sha256:[0-9a-f]{64}$/);
    assert.ok(manifest.assets.some((asset) => asset.path === "analyzer-runtime.mjs"));
    assert.ok(manifest.assets.every((asset) => /^sha256:[0-9a-f]{64}$/.test(asset.digest)));
  }
});

test("every certified analyzer reports insufficient evidence when its pinned toolchain is unavailable", (context) => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-missing-analyzers-"));
  context.after(() => fs.rmSync(empty, { recursive: true, force: true }));
  for (const id of analyzerIds) {
    const availability = inspectCertifiedAnalyzerAvailability(id, { analyzerDir: empty });
    assert.equal(availability.status, "insufficient_evidence");
    assert.equal(availability.available, false);
    assert.equal(availability.uncertainty.code, "toolchain_unavailable");
    assert.doesNotMatch(JSON.stringify(availability), new RegExp(empty.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
  }
});

test("analyzer reports reject tampering, unknown fields, and request digest substitution", () => {
  const fixture = fixtures.typescript;
  const report = analyze("typescript", fixture.safe.before, fixture.safe.after);
  assert.throws(() => validateAnalyzerReport({ ...report, surprise: true }), /unknown/i);
  assert.throws(() => validateAnalyzerReport({ ...report, requestDigest: `sha256:${"0".repeat(64)}` }), /digest/i);
  const substituted = { ...report, requestDigest: `sha256:${"0".repeat(64)}` };
  substituted.digest = canonicalDigest(Object.fromEntries(Object.entries(substituted).filter(([key]) => key !== "digest")));
  assert.throws(() => validateAnalyzerReport(substituted), /request digest mismatch/i);
  assert.throws(() => loadCertifiedAnalyzerManifest("../../escape"), /analyzer id/i);
});

test("structural compatibility cases fail closed instead of admitting shallow symbol matches", () => {
  const cases = [
    ["typescript", "export interface Public { keep: string; removed: number; }\n", "export interface Public { keep: string; }\n"],
    ["python", "class Public:\n    def keep(self):\n        return 1\n    def removed(self):\n        return 2\n", "class Public:\n    def keep(self):\n        return 1\n"],
    ["go", "package public\ntype Public struct { Keep string; Removed int }\n", "package public\ntype Public struct { Keep string }\n"],
    ["openapi", "{\"openapi\":\"3.1.0\",\"paths\":{},\"components\":{\"schemas\":{\"Public\":{\"type\":\"object\",\"required\":[\"keep\",\"removed\"],\"properties\":{\"keep\":{\"type\":\"string\"},\"removed\":{\"type\":\"number\"}}}}}}", "{\"openapi\":\"3.1.0\",\"paths\":{},\"components\":{\"schemas\":{\"Public\":{\"type\":\"object\",\"required\":[\"keep\"],\"properties\":{\"keep\":{\"type\":\"string\"}}}}}}"],
    ["graphql", "type Query { keep: String }\ninput Filter { keep: String }\n", "type Query { keep: String }\ninput Filter { keep: String required: String! }\n"],
    ["sql", "CREATE TABLE users (id INTEGER);\n", "CREATE TABLE users (id INTEGER, required TEXT NOT NULL);\n"],
  ];
  for (const [id, before, after] of cases) {
    const report = analyze(id, before, after);
    assert.equal(report.status, "blocked", `${id} admitted a structurally breaking change`);
    assert.equal(report.compatibility.verdict, "breaking");
  }
});

test("certified analyzers bind create and delete transitions with an empty source on one side", () => {
  const created = analyzeCertifiedChange({
    analyzerId: "sql",
    before: { path: "schema/new.sql", source: "" },
    after: { path: "schema/new.sql", source: "CREATE TABLE companies (id INTEGER);\n" },
  });
  assert.equal(created.status, "ready");
  assert.equal(created.subject.before.digest, `sha256:${"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`);
  const deleted = analyzeCertifiedChange({
    analyzerId: "sql",
    before: { path: "schema/old.sql", source: "CREATE TABLE companies (id INTEGER);\n" },
    after: { path: "schema/old.sql", source: "" },
  });
  assert.equal(deleted.status, "blocked");
  assert.ok(deleted.counterexamples.length > 0);
});
