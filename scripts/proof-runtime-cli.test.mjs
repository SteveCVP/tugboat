import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { sha256 } from "./lib/canonical.mjs";
import { createMission } from "./lib/reducer.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const CLI = path.join(ROOT, "scripts", "tugboat.mjs");

function repository() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-cli-v4-"));
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: root });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: root });
  execFileSync("git", ["config", "user.email", "tugboat@example.invalid"], { cwd: root });
  fs.writeFileSync(path.join(root, "rule.mjs"), "export const allowed = true;\n");
  fs.writeFileSync(path.join(root, "gate.mjs"), "import { allowed } from './rule.mjs'; if (!allowed) process.exit(9);\n");
  fs.writeFileSync(path.join(root, "input.txt"), "proof\n");
  execFileSync("git", ["add", "."], { cwd: root });
  execFileSync("git", ["commit", "-qm", "fixture"], { cwd: root });
  return root;
}

function json(root, name, value) {
  const file = path.join(root, name);
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
  return file;
}

function run(args, cwd = ROOT) {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim() ? JSON.parse(result.stdout) : null;
}

test("proof-runtime CLI reaches mutation, capsule, provenance, kernel, adapter, history, and differential review workflows", () => {
  const repo = repository();
  const plan = json(repo, "plan.json", { schemaVersion: "tugboat.proof-mutation-plan.v1", mutations: [{ id: "M1", requirementId: "R1", gateId: "unit", path: "rule.mjs", find: "true", replace: "false", expectedOccurrences: 1 }] });
  execFileSync("git", ["add", "plan.json"], { cwd: repo });
  execFileSync("git", ["commit", "-qm", "plan"], { cwd: repo });
  const mutation = run(["proof", "mutate", "--repo", repo, "--plan", plan, "--json", "--", process.execPath, "gate.mjs"], repo);
  assert.equal(mutation.status, "ready");

  const capsuleFile = path.join(os.tmpdir(), `capsule-${process.pid}-${Date.now()}.json`);
  run(["capsule", "capture", "--repo", repo, "--inputs", "input.txt", "--captured-at", "2026-10-28T20:00:00.000Z", "--output", capsuleFile, "--json", "--", process.execPath, "-e", "process.stdout.write('proof')"], repo);
  const capsule = run(["capsule", "verify", "--file", capsuleFile, "--repo", repo, "--json"], repo);
  assert.equal(capsule.status, "ready");

  const provenanceFile = path.join(os.tmpdir(), `provenance-${process.pid}-${Date.now()}.json`);
  run(["provenance", "create", "--root", repo, "--subjects", "input.txt", "--builder", "cli-test", "--output", provenanceFile, "--json"], repo);
  const provenance = run(["provenance", "verify", "--file", provenanceFile, "--root", repo, "--json"], repo);
  assert.equal(provenance.status, "ready");

  const graph = json(repo, "graph.json", { schemaVersion: "tugboat.causal-graph.v1", nodes: [{ id: "a", compiler: "canonical", version: "1", dependencies: [], input: { value: 1 } }] });
  const kernel = run(["kernel", "compile", "--graph", graph, "--cache", path.join(os.tmpdir(), `kernel-${process.pid}-${Date.now()}`), "--json"], repo);
  assert.equal(kernel.status, "ready");

  const adapterSource = "process.stdout.write('{}');\n";
  fs.writeFileSync(path.join(repo, "adapter.mjs"), adapterSource);
  const manifest = json(repo, "manifest.json", { schemaVersion: "tugboat.adapter-manifest.v1", id: "cli", runtime: "node20", entrypoint: "adapter.mjs", entrypointDigest: `sha256:${sha256(adapterSource)}`, inputSchema: { type: "object", properties: {}, required: [], additionalProperties: false }, outputSchema: { type: "object", properties: {}, required: [], additionalProperties: false }, capabilities: ["review"], allowedInputPaths: [], environment: [], timeoutMs: 1000, maxOutputBytes: 1024, isolation: "brokered" });
  const adapter = run(["adapter", "inspect", "--manifest", manifest, "--json"], repo);
  assert.equal(adapter.status, "ready");

  const missionDir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-cli-history-"));
  createMission({
    dir: missionDir,
    actor: { name: "test", kind: "human", runtime: "node-test" },
    metadata: { id: "history-cli", title: "History CLI", owner: "test", target: "local", repository: repo, worktree: repo, branch: "main", baselineGitSha: execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim(), source: { path: "input.txt", digest: `sha256:${"c".repeat(64)}` }, criticalPath: ["R1"], deployPath: "none" },
    requirements: [{ id: "R1", requirement: "Explain history", source: "test", material: true, acceptance: "Revision is exact", proofTarget: "local" }],
    preservations: [],
    slices: [{ id: "S1", name: "History", requirementIds: ["R1"], dependencies: [], status: "ACTIVE", operatorJourney: "Inspect history" }],
  });
  const missionEvents = path.join(missionDir, "events.jsonl");
  const before = fs.readFileSync(missionEvents);
  const history = run(["history", "explain", "--dir", missionDir, "--revision", "1", "--requirement", "R1", "--json"]);
  assert.equal(history.status, "ready");
  assert.deepEqual(fs.readFileSync(missionEvents), before);

  const digest = `sha256:${"a".repeat(64)}`;
  const evidence = `sha256:${"b".repeat(64)}`;
  const makeReview = (reviewer, id) => ({ schemaVersion: "tugboat.agent-review.v1", reviewer, inputDigest: digest, findings: [{ id, severity: "low", claim: "Exact issue", subjects: ["rule.mjs"], evidenceDigests: [evidence], recommendation: "inspect", disposition: "accepted" }] });
  const left = json(repo, "left.json", makeReview("left", "L1"));
  const right = json(repo, "right.json", makeReview("right", "R1"));
  const review = run(["review", "compare", "--reviews", `${left},${right}`, "--json"], repo);
  assert.equal(review.status, "ready");
  assert.equal(review.consensus.length, 1);
});
