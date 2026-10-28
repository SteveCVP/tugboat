import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { compileImpactGraph, inspectTrackedChanges } from "./lib/causality-intelligence.mjs";
import { compileDecisionMemory } from "./lib/decision-memory.mjs";
import { readMissionState } from "./lib/intelligence-core.mjs";
import { createMission } from "./lib/reducer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, "tugboat.mjs");
const NOW = "2026-10-28T18:00:00.000Z";
const DIGEST = `sha256:${"a".repeat(64)}`;

function git(cwd, args) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function writeJson(root, name, value) {
  const file = path.join(root, name);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
  return file;
}

function fixture() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-intelligence-cli-"));
  git(repo, ["init", "-b", "main"]);
  git(repo, ["config", "user.name", "Tugboat Test"]);
  git(repo, ["config", "user.email", "tugboat@example.invalid"]);
  fs.mkdirSync(path.join(repo, "src"));
  fs.writeFileSync(path.join(repo, "spec.md"), "# Intelligence\n");
  fs.writeFileSync(path.join(repo, "src", "app.mjs"), "export const version = 1;\n");
  git(repo, ["add", "spec.md", "src/app.mjs"]);
  git(repo, ["commit", "-m", "baseline"]);
  const baseline = git(repo, ["rev-parse", "HEAD"]);
  const missionDir = path.join(repo, ".tugboat");
  createMission({
    dir: missionDir,
    actor: { name: "Tugboat Test", kind: "human", runtime: "test" },
    metadata: {
      id: "intelligence-cli",
      title: "Intelligence CLI",
      owner: "Test",
      target: "local",
      repository: repo,
      worktree: repo,
      branch: "main",
      baselineGitSha: baseline,
      source: { path: "spec.md", digest: DIGEST },
      criticalPath: ["R1"],
      deployPath: "none",
    },
    requirements: [{
      id: "R1",
      requirement: "Compile mission intelligence",
      source: "spec",
      material: true,
      acceptance: "The CLI returns a canonical report digest and rejects malformed input.",
      proofTarget: "local",
    }],
    preservations: [{ id: "P1", instruction: "Preserve mission bytes", source: "spec", regressionProofTarget: "byte comparison" }],
    slices: [{ id: "S1", name: "Intelligence", requirementIds: ["R1"], dependencies: [], status: "ACTIVE", operatorJourney: "Compile a report" }],
  });
  fs.writeFileSync(path.join(repo, "src", "app.mjs"), "export const version = 2;\n");
  git(repo, ["add", "src/app.mjs"]);
  git(repo, ["commit", "-m", "change app"]);
  const head = git(repo, ["rev-parse", "HEAD"]);
  const impactProfile = { rules: [{ id: "app", pattern: "src/**", requirementIds: ["R1"], evidenceIds: [], tests: ["node --test"], risks: ["runtime"] }] };
  return { repo, missionDir, baseline, head, impactProfile };
}

function missionBytes(dir) {
  return Object.fromEntries(fs.readdirSync(dir).sort().map((name) => [name, fs.readFileSync(path.join(dir, name))]));
}

function run(cwd, args) {
  return spawnSync(process.execPath, [CLI, "intelligence", ...args], { cwd, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
}

function jsonRun(cwd, operation, args) {
  const result = run(cwd, [operation, ...args, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

test("intelligence CLI exposes all ten canonical operations without mutating mission or profile bytes", () => {
  const { repo, missionDir, baseline, head, impactProfile } = fixture();
  const impactProfileFile = writeJson(repo, "impact.json", impactProfile);
  const beforeMission = missionBytes(missionDir);
  const beforeProfile = fs.readFileSync(impactProfileFile);

  const impact = jsonRun(repo, "impact", ["--dir", missionDir, "--repo", repo, "--base", baseline, "--head", head, "--profile", impactProfileFile]);
  assert.equal(impact.schemaVersion, "tugboat.proof-impact.v1");
  const impactFile = writeJson(repo, "impact-report.json", impact);

  const lint = jsonRun(repo, "lint", ["--dir", missionDir]);
  assert.equal(lint.schemaVersion, "tugboat.anti-slop.v1");

  const simulate = jsonRun(repo, "simulate", ["--dir", missionDir]);
  assert.equal(simulate.schemaVersion, "tugboat.release-simulation.v1");

  const workers = writeJson(repo, "workers.json", { workers: [{
    id: "worker-a", trustNodeId: "worker-a", trustLevel: "standard", maxClassification: "confidential",
    costUnits: 1, latencyUnits: 1, capacity: 1, activeAssignments: 0,
    attestations: [{ capability: "node", evidenceDigest: DIGEST, issuer: "trusted-ci", issuedAt: "2026-10-28T16:00:00.000Z", expiresAt: "2026-10-28T20:00:00.000Z" }],
  }] });
  const routing = writeJson(repo, "routing.json", {
    trustLevels: ["untrusted", "standard", "privileged"],
    classifications: ["public", "internal", "confidential"],
    trustedIssuers: ["trusted-ci"],
    packets: { R1: { capabilities: ["node"], minTrust: "standard", classification: "confidential" } },
  });
  assert.equal(jsonRun(repo, "route", ["--dir", missionDir, "--workers", workers, "--profile", routing, "--observed-at", NOW]).schemaVersion, "tugboat.execution-routing.v1");

  const recordsValue = [{
    id: "D1", decidedAt: "2026-10-18T18:00:00.000Z", contextTags: ["node"], constraints: { team: "small" },
    decision: "Use Node.js for the portable CLI.", rejectedAlternatives: [{ decision: "Shell", reason: "Portability" }],
    assumptions: [{ id: "runtime", text: "Node remains available.", halfLifeDays: 30 }],
    evidence: { kind: "production", digest: DIGEST }, outcome: { status: "success", observedAt: "2026-10-20T18:00:00.000Z" }, supersedes: [],
  }];
  const records = writeJson(repo, "records.json", recordsValue);
  const contextValue = { tags: ["node"], constraints: { team: "small" }, minAssumptionRetention: 0.5 };
  const context = writeJson(repo, "context.json", contextValue);
  const memory = jsonRun(repo, "memory", ["--records", records, "--context", context, "--observed-at", NOW]);
  assert.equal(memory.schemaVersion, "tugboat.decision-memory.v1");
  assert.equal(memory.digest, compileDecisionMemory(recordsValue, contextValue, NOW).digest);

  const catalog = writeJson(repo, "gates.json", { gates: [{ id: "full", cost: 1, requirementIds: ["R1"], proofKinds: ["command", "operator"], riskTags: ["runtime"] }] });
  assert.equal(jsonRun(repo, "portfolio", ["--dir", missionDir, "--impact", impactFile, "--catalog", catalog]).schemaVersion, "tugboat.proof-portfolio.v1");

  const policy = writeJson(repo, "freshness.json", { ttlHoursByKind: { command: 24, operator: 24, browser: 24, deployment: 24 } });
  assert.equal(jsonRun(repo, "freshness", ["--dir", missionDir, "--policy", policy, "--observed-at", NOW]).schemaVersion, "tugboat.evidence-freshness.v1");

  const graph = writeJson(repo, "graph.json", { nodes: [{ id: "source", type: "artifact", classification: "internal", authorities: ["read"] }], edges: [] });
  const trustPolicy = writeJson(repo, "trust-policy.json", { classifications: ["public", "internal", "confidential"], sinks: [{ nodeId: "source", maxClassification: "internal", allowedAuthorities: ["read"] }], approvedSanitizers: [] });
  assert.equal(jsonRun(repo, "trust", ["--graph", graph, "--policy", trustPolicy]).schemaVersion, "tugboat.trust-taint.v1");

  assert.equal(jsonRun(repo, "adversary", ["--dir", missionDir]).schemaVersion, "tugboat.adversarial-acceptance.v1");

  const manifest = writeJson(repo, "federation.json", { id: "release", children: [{ id: "app", status: "ready", stateDigest: DIGEST, reportDigest: DIGEST, dependencies: [], rollbackAfter: [], deployAction: "deploy-app", rollbackAction: "rollback-app", provides: [], requires: [] }] });
  assert.equal(jsonRun(repo, "federation", ["--manifest", manifest]).schemaVersion, "tugboat.federated-release.v1");

  const direct = compileImpactGraph(readMissionState(missionDir), inspectTrackedChanges(repo, baseline, head).changes, impactProfile);
  assert.equal(impact.digest, direct.digest);
  assert.deepEqual(missionBytes(missionDir), beforeMission);
  assert.deepEqual(fs.readFileSync(impactProfileFile), beforeProfile);
});

test("intelligence CLI text is concise and gate mode has a distinct non-ready exit", () => {
  const { repo, missionDir } = fixture();
  const text = run(repo, ["lint", "--dir", missionDir]);
  assert.equal(text.status, 0, text.stderr);
  assert.match(text.stdout, /^lint: (?:ready|blocked|insufficient_evidence)$/m);
  assert.match(text.stdout, /^Digest: sha256:[0-9a-f]{64}$/m);
  assert.ok(text.stdout.trim().split("\n").length <= 6, text.stdout);

  const gated = run(repo, ["simulate", "--dir", missionDir, "--gate", "--json"]);
  assert.equal(gated.status, 2, gated.stderr);
  assert.equal(JSON.parse(gated.stdout).status, "blocked");
});

test("intelligence CLI rejects unknown operations, malformed JSON, and files above the declared bound", () => {
  const { repo, missionDir } = fixture();
  const unknown = run(repo, ["explode", "--dir", missionDir]);
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /unknown intelligence operation/i);

  const malformed = path.join(repo, "malformed.json");
  fs.writeFileSync(malformed, "{nope");
  const bad = run(repo, ["lint", "--dir", missionDir, "--profile", malformed, "--json"]);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /invalid json/i);

  const huge = path.join(repo, "huge.json");
  fs.writeFileSync(huge, JSON.stringify({ padding: "x".repeat(70 * 1024) }));
  const bounded = run(repo, ["lint", "--dir", missionDir, "--profile", huge, "--json"]);
  assert.equal(bounded.status, 2);
  assert.match(bounded.stderr, /64 KiB/i);
});
