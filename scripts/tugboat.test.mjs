import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createMission } from "./lib/reducer.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, "tugboat.mjs");

function run(cwd, args) {
  return execFileSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });
}

function setupRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-cli-"));
  execFileSync("git", ["init", "-b", "main"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "tugboat@example.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: dir });
  fs.writeFileSync(path.join(dir, "spec.md"), "# Mission\n\nBuild the complete workflow.\n");
  fs.writeFileSync(path.join(dir, "requirements.json"), JSON.stringify({
    preservation: [{ id: "P1", instruction: "Preserve login", source: "spec section 1" }],
    requirements: [{
      id: "R1",
      requirement: "Complete workflow",
      source: "spec section 2",
      material: true,
      acceptance: "`Operator` completes the workflow",
      proofTarget: "local",
    }],
  }, null, 2));
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "baseline"], { cwd: dir });
  return dir;
}

function setupRepoWithDocumentedContract() {
  const dir = setupRepo();
  fs.writeFileSync(path.join(dir, "requirements.json"), JSON.stringify({
    preservations: [{ id: "P1", instruction: "Preserve login", source: "spec section 1", regression_proof: "Authenticated browser journey" }],
    requirements: [{
      id: "R1", requirement: "Complete workflow", source: "spec section 2",
      acceptance: "Operator completes the workflow", proof_target: "local",
    }],
  }, null, 2));
  return dir;
}

function init(dir) {
  return run(dir, [
    "init", "--legacy", "--dir", "tugboat", "--mission", "test-mission", "--title", "Test mission",
    "--owner", "Alex", "--source", "spec.md", "--requirements-file", "requirements.json",
    "--target", "local", "--critical-path", "R1", "--deploy-path", "not requested",
  ]);
}

test("init creates a source-bound, Git-aware mission that validates", () => {
  const dir = setupRepo();
  const output = init(dir);
  assert.match(output, /initialized/i);
  for (const file of ["requirement-ledger.md", "audit-log.md", "context-handoff.md", "completion-report.md"]) {
    assert.ok(fs.existsSync(path.join(dir, "tugboat", file)), file);
  }
  const ledger = fs.readFileSync(path.join(dir, "tugboat", "requirement-ledger.md"), "utf8");
  assert.match(ledger, /- Critical path: `R1`/);
  assert.match(ledger, /sha256:[0-9a-f]{64}/);
  assert.match(run(dir, ["validate", "--ledger", "tugboat/requirement-ledger.md"]), /valid/i);
});

test("init accepts the documented contract shape", () => {
  const dir = setupRepoWithDocumentedContract();
  assert.match(init(dir), /initialized/i);
  const ledger = fs.readFileSync(path.join(dir, "tugboat", "requirement-ledger.md"), "utf8");
  assert.match(ledger, /\| R1 \| Complete workflow .* \| local \|/);
  assert.match(ledger, /\| P1 \| Preserve login/);
});

test("failed init leaves no partial mission directory", () => {
  const dir = setupRepo();
  const result = spawnSync(process.execPath, [CLI,
    "init", "--legacy", "--dir", "broken-mission", "--mission", "broken", "--title", "Broken mission",
    "--owner", "Alex", "--source", "missing-spec.md", "--requirements-file", "requirements.json",
    "--target", "local", "--critical-path", "R1", "--deploy-path", "not requested",
  ], { cwd: dir, encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.equal(fs.existsSync(path.join(dir, "broken-mission")), false);
});

test("checkpoint updates proof, appends audit, refreshes handoff, and resumes compactly", () => {
  const dir = setupRepo();
  init(dir);
  run(dir, [
    "checkpoint", "--ledger", "tugboat/requirement-ledger.md", "--requirements", "R1",
    "--status", "PROVEN(local)", "--implementation", "src/workflow.mjs",
    "--tests", "workflow.test.mjs passes", "--browser", "N/A: command-line workflow",
    "--result", "Operator completes the command-line workflow",
    "--action", "proved workflow", "--evidence", "test output", "--next", "close mission",
    "--next-check", "close validates the complete proof map",
  ]);
  run(dir, [
    "checkpoint", "--ledger", "tugboat/requirement-ledger.md", "--preservations", "P1",
    "--status", "PROVEN(local)", "--preservation-proof", "login regression passes",
    "--action", "proved preservation", "--evidence", "login test", "--next", "close mission",
    "--next-check", "close validates the complete proof map",
  ]);
  const state = JSON.parse(run(dir, ["resume", "--ledger", "tugboat/requirement-ledger.md", "--json"]));
  assert.deepEqual(state.activeRequirements, []);
  assert.equal(state.nextAction, "close mission");
  const audit = fs.readFileSync(path.join(dir, "tugboat", "audit-log.md"), "utf8");
  assert.match(audit, /proved workflow/);
  assert.match(audit, /proved preservation/);
  const ledger = fs.readFileSync(path.join(dir, "tugboat", "requirement-ledger.md"), "utf8");
  assert.match(ledger, /`Operator` completes the workflow/);
  assert.match(ledger, /\| R1 \| Operator completes the command-line workflow \|/);
  assert.match(ledger, /\| R1 .* \| N\/A: local proof target \| N\/A: local proof target \|/);
  const handoff = fs.readFileSync(path.join(dir, "tugboat", "context-handoff.md"), "utf8");
  assert.match(handoff, /- Latest commits: `[0-9a-f]{40} checkpoint`/);
  assert.match(handoff, /- Next acceptance check: `close validates the complete proof map`/);
});

test("checkpoint leaves every mission file unchanged when proposed proof is invalid", () => {
  const dir = setupRepo();
  init(dir);
  const missionDir = path.join(dir, "tugboat");
  const before = Object.fromEntries(fs.readdirSync(missionDir).map((file) => [file, fs.readFileSync(path.join(missionDir, file), "utf8")]));
  const result = spawnSync(process.execPath, [CLI,
    "checkpoint", "--ledger", "tugboat/requirement-ledger.md", "--requirements", "R1",
    "--status", "PROVEN(production)", "--implementation", "src/workflow.mjs",
    "--tests", "tests pass", "--browser", "browser pass", "--action", "claim live",
    "--result", "Operator uses the live workflow",
    "--evidence", "none", "--next", "stop",
  ], { cwd: dir, encoding: "utf8" });
  assert.notEqual(result.status, 0);
  for (const [file, contents] of Object.entries(before)) {
    assert.equal(fs.readFileSync(path.join(missionDir, file), "utf8"), contents, file);
  }
});

test("downgrading a requirement removes its stale completion-map proof", () => {
  const dir = setupRepo();
  init(dir);
  run(dir, [
    "checkpoint", "--ledger", "tugboat/requirement-ledger.md", "--requirements", "R1",
    "--status", "PROVEN(local)", "--implementation", "src/workflow.mjs", "--tests", "tests pass",
    "--browser", "N/A: command-line workflow", "--result", "Operator completes the workflow",
    "--action", "proved R1", "--evidence", "tests", "--next", "review",
  ]);
  run(dir, [
    "checkpoint", "--ledger", "tugboat/requirement-ledger.md", "--requirements", "R1",
    "--status", "BLOCKED", "--action", "corrected premature proof", "--evidence", "provider unavailable",
    "--next", "authenticate provider", "--blocker", "provider authentication required",
  ]);
  const ledger = fs.readFileSync(path.join(dir, "tugboat", "requirement-ledger.md"), "utf8");
  const completionSection = ledger.split("## Completion Map")[1];
  assert.doesNotMatch(completionSection, /^\| R1 \|/m);
  assert.match(ledger, /\| R1 .* \| BLOCKED \|/);
  assert.match(fs.readFileSync(path.join(dir, "tugboat", "context-handoff.md"), "utf8"), /Current blocker\/decision: `provider authentication required`/);
});

test("close refuses incomplete missions and closes fully proven ones", () => {
  const dir = setupRepo();
  init(dir);
  let result = spawnSync(process.execPath, [CLI, "close", "--ledger", "tugboat/requirement-ledger.md"], { cwd: dir, encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(fs.readFileSync(path.join(dir, "tugboat", "requirement-ledger.md"), "utf8"), /Mission status: `ACTIVE`/);

  run(dir, [
    "checkpoint", "--ledger", "tugboat/requirement-ledger.md", "--requirements", "R1",
    "--status", "PROVEN(local)", "--implementation", "src/workflow.mjs", "--tests", "tests pass",
    "--browser", "N/A: command-line workflow", "--result", "Operator completes the workflow",
    "--action", "proved R1", "--evidence", "tests",
    "--next", "close mission",
  ]);
  run(dir, [
    "checkpoint", "--ledger", "tugboat/requirement-ledger.md", "--preservations", "P1",
    "--status", "PROVEN(local)", "--preservation-proof", "login regression passes",
    "--action", "proved P1", "--evidence", "login test", "--next", "close mission",
  ]);
  result = spawnSync(process.execPath, [CLI, "close", "--ledger", "tugboat/requirement-ledger.md"], { cwd: dir, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(fs.readFileSync(path.join(dir, "tugboat", "requirement-ledger.md"), "utf8"), /Mission status: `COMPLETE`/);
  assert.match(fs.readFileSync(path.join(dir, "tugboat", "completion-report.md"), "utf8"), /- Current SHA:/);
  assert.doesNotMatch(fs.readFileSync(path.join(dir, "tugboat", "completion-report.md"), "utf8"), /- Deployed SHA:/);
});

function setupLanguageMission() {
  const repo = setupRepo();
  fs.mkdirSync(path.join(repo, "src"));
  fs.writeFileSync(path.join(repo, "src", "operator.ts"), "export const operator = true;\n");
  fs.writeFileSync(path.join(repo, "package.json"), "{}\n");
  execFileSync("git", ["add", "src/operator.ts", "package.json"], { cwd: repo });
  execFileSync("git", ["commit", "-m", "operator stack"], { cwd: repo });
  const baseline = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  const missionDir = path.join(repo, "mission");
  createMission({
    dir: missionDir,
    actor: { name: "Tugboat Test", kind: "human", runtime: "test" },
    metadata: { id: "language-mission", title: "Language Mission", owner: "Test", target: "local", repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline, source: { path: "spec.md", digest: `sha256:${"d".repeat(64)}` }, criticalPath: ["R1"], deployPath: "none" },
    requirements: [{ id: "R1", requirement: "Deliver the operator workflow", source: "spec", material: true, acceptance: "A responsive browser user interface works", proofTarget: "local" }],
    preservations: [{ id: "P1", instruction: "Preserve replay", source: "spec", regressionProofTarget: "state tests" }],
    slices: [{ id: "S1", name: "UI", requirementIds: ["R1"], dependencies: [], status: "ACTIVE", operatorJourney: "Choose the implementation stack" }],
  });
  return { repo, missionDir };
}

test("language recommend CLI is concise, deterministic, bounded, and byte-preserving", () => {
  const { repo, missionDir } = setupLanguageMission();
  const profilePath = path.join(repo, "architecture-profile.json");
  fs.writeFileSync(profilePath, JSON.stringify({
    maxLanguages: 1,
    requirementSignals: { R1: ["browser_ui"] },
    teamLanguages: ["typescript"],
  }));
  const eventsPath = path.join(missionDir, "events.jsonl");
  const before = fs.readFileSync(eventsPath);

  const jsonOutput = run(repo, ["language", "recommend", "--dir", missionDir, "--repo", repo, "--profile", profilePath, "--json"]);
  const report = JSON.parse(jsonOutput);
  const textOutput = run(repo, ["language", "recommend", "--dir", missionDir, "--repo", repo, "--profile", profilePath]);

  assert.equal(report.schemaVersion, "tugboat.language-recommendation.v1");
  assert.equal(report.recommendation.primary.language, "typescript");
  assert.match(report.digest, /^[0-9a-f]{64}$/);
  assert.equal(jsonOutput.includes(repo), false);
  assert.match(textOutput, /^Architecture: strong/m);
  assert.match(textOutput, /^Primary: TypeScript/m);
  assert.match(textOutput, /^Topology: single language/m);
  assert.doesNotMatch(textOutput, /ordinalRankScore|contributions|candidates/);
  assert.deepEqual(fs.readFileSync(eventsPath), before);

  const oversized = path.join(repo, "oversized-profile.json");
  fs.writeFileSync(oversized, JSON.stringify({ padding: "x".repeat(70 * 1024) }));
  const rejected = spawnSync(process.execPath, [CLI, "language", "recommend", "--dir", missionDir, "--profile", oversized, "--json"], { cwd: repo, encoding: "utf8" });
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /profile exceeds 64 KiB/i);
  assert.deepEqual(fs.readFileSync(eventsPath), before);
});

test("language recommend CLI refuses to turn hype-only requirements into architecture confidence", () => {
  const repo = setupRepo();
  const baseline = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  const missionDir = path.join(repo, "hype-mission");
  createMission({
    dir: missionDir,
    actor: { name: "Tugboat Test", kind: "human", runtime: "test" },
    metadata: { id: "hype-mission", title: "Hype Mission", owner: "Test", target: "local", repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline, source: { path: "spec.md", digest: `sha256:${"e".repeat(64)}` }, criticalPath: ["R1"], deployPath: "none" },
    requirements: [{ id: "R1", requirement: "Build a fast, secure, scalable AI-powered platform", source: "spec", material: true, acceptance: "Make it world class", proofTarget: "local" }],
    preservations: [{ id: "P1", instruction: "Preserve replay", source: "spec", regressionProofTarget: "state tests" }],
    slices: [{ id: "S1", name: "Platform", requirementIds: ["R1"], dependencies: [], status: "ACTIVE", operatorJourney: "Choose an architecture" }],
  });
  const eventsPath = path.join(missionDir, "events.jsonl");
  const before = fs.readFileSync(eventsPath);

  const report = JSON.parse(run(repo, ["language", "recommend", "--dir", missionDir, "--repo", repo, "--json"]));
  const textOutput = run(repo, ["language", "recommend", "--dir", missionDir, "--repo", repo]);

  assert.equal(report.recommendation.status, "insufficient_evidence");
  assert.equal(report.recommendation.primary, null);
  assert.equal(report.recommendation.topology.kind, "undecided");
  assert.match(textOutput, /^Topology: undecided/m);
  assert.deepEqual(report.antiSlop.unclassifiedRequirementIds, ["R1"]);
  assert.deepEqual(fs.readFileSync(eventsPath), before);
});
