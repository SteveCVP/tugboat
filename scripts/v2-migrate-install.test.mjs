import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { installTugboat } from "./install.mjs";
import { migrateLegacyMission } from "./lib/migrate.mjs";
import { backupMission, rebuildMission } from "./lib/recovery.mjs";
import { readState } from "./lib/store.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const CLI = path.join(HERE, "tugboat.mjs");

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-migrate-"));
  execFileSync("git", ["init", "-b", "main"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: dir });
  fs.writeFileSync(path.join(dir, "spec.md"), "# Mission\n\nBuild everything.\n");
  fs.writeFileSync(path.join(dir, "requirements.json"), JSON.stringify({
    requirements: [{ id: "R1", requirement: "Complete A | B workflow", source: "spec 1", acceptance: "Operator completes A | B", proof_target: "local" }],
    preservations: [{ id: "P1", instruction: "Preserve login", source: "spec 2", regression_proof: "browser" }],
  }));
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "baseline"], { cwd: dir });
  return dir;
}

function initArgs(dir, missionDir, extra = []) {
  return [CLI, "init", "--dir", missionDir, "--mission", "migration-test", "--title", "Migration test", "--owner", "Alex", "--source", "spec.md", "--requirements-file", "requirements.json", "--target", "local", "--critical-path", "R1", "--deploy-path", "not requested", ...extra];
}

function proveCopiedControlPlane(runtimeRoot) {
  const project = repo();
  const missionDir = path.join(project, "runtime-mission");
  const runtimeCli = path.join(runtimeRoot, "scripts", "tugboat.mjs");
  const runtimeMcp = path.join(runtimeRoot, "scripts", "tugboat-mcp.mjs");
  const initialized = spawnSync(process.execPath, initArgs(project, missionDir).with(0, runtimeCli), { cwd: project, encoding: "utf8" });
  assert.equal(initialized.status, 0, initialized.stderr);
  const next = spawnSync(process.execPath, [runtimeCli, "next", "--dir", missionDir, "--observed-at", "2026-10-28T21:00:00.000Z", "--json"], { cwd: project, encoding: "utf8" });
  assert.equal(next.status, 0, next.stderr);
  assert.equal(JSON.parse(next.stdout).schemaVersion, "tugboat.execution-packet.v1");
  const profile = path.join(project, "architecture-profile.json");
  fs.writeFileSync(profile, JSON.stringify({ requirementSignals: { R1: ["cloud_service"] }, teamLanguages: ["go"] }));
  const sourceDecision = spawnSync(process.execPath, [CLI, "language", "recommend", "--dir", missionDir, "--repo", project, "--profile", profile, "--json"], { cwd: project, encoding: "utf8" });
  const copiedDecision = spawnSync(process.execPath, [runtimeCli, "language", "recommend", "--dir", missionDir, "--repo", project, "--profile", profile, "--json"], { cwd: project, encoding: "utf8" });
  assert.equal(sourceDecision.status, 0, sourceDecision.stderr);
  assert.equal(copiedDecision.status, 0, copiedDecision.stderr);
  assert.equal(JSON.parse(copiedDecision.stdout).digest, JSON.parse(sourceDecision.stdout).digest);
  const handshake = spawnSync(process.execPath, [runtimeMcp, "--dir", missionDir], {
    cwd: project,
    input: `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "installed-test", version: "1" } } })}\n`,
    encoding: "utf8",
  });
  assert.equal(handshake.status, 0, handshake.stderr);
  assert.equal(JSON.parse(handshake.stdout).result.serverInfo.name, "tugboat");
}

test("init defaults to protocol 2 while protocol 1.1 remains an explicit compatibility mode", () => {
  const dir = repo();
  execFileSync(process.execPath, initArgs(dir, "tugboat-v2"), { cwd: dir });
  assert.equal(readState(path.join(dir, "tugboat-v2")).protocolVersion, "2.0");
  execFileSync(process.execPath, initArgs(dir, "tugboat-v1", ["--legacy"]), { cwd: dir });
  assert.equal(fs.existsSync(path.join(dir, "tugboat-v1", "state.json")), false);
  assert.match(fs.readFileSync(path.join(dir, "tugboat-v1", "requirement-ledger.md"), "utf8"), /Protocol version: `1\.1`/);
});

test("legacy migration preserves every requirement, preservation, and audit entry but resets prose proof", () => {
  const dir = repo();
  execFileSync(process.execPath, initArgs(dir, "legacy", ["--legacy"]), { cwd: dir });
  const legacy = path.join(dir, "legacy");
  fs.appendFileSync(path.join(legacy, "audit-log.md"), "| 2026-10-28T12:00:00Z | Claude | R1 | claimed proof | old prose | tests pass | close |\n");
  const migrated = path.join(dir, "migrated");
  const state = migrateLegacyMission({ legacyDir: legacy, destinationDir: migrated, actor: { name: "Codex", kind: "agent", runtime: "codex" } });
  assert.equal(state.requirements.R1.requirement, "Complete A | B workflow");
  assert.equal(state.requirements.R1.status, "PENDING");
  assert.deepEqual(state.requirements.R1.evidenceRefs, []);
  assert.equal(state.preservations.P1.instruction, "Preserve login");
  assert.equal(state.legacyImport.requirementCount, 1);
  assert.ok(state.legacyImport.auditRows.length >= 2);
  assert.match(fs.readFileSync(path.join(migrated, "audit-log.md"), "utf8"), /LEGACY_MIGRATED/);
});

test("installer puts the same versioned payload in shared, Claude, and Codex skill locations", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-home-"));
  const result = installTugboat({ sourceDir: ROOT, home, targets: ["agents", "claude", "codex"] });
  assert.equal(result.installed.length, 3);
  const manifests = result.installed.map((dir) => JSON.parse(fs.readFileSync(path.join(dir, ".tugboat-install.json"), "utf8")));
  assert.deepEqual(new Set(manifests.map((item) => item.version)), new Set(["2.3.0"]));
  assert.equal(new Set(manifests.map((item) => item.payloadDigest)).size, 1);
  for (const dir of result.installed) {
    assert.ok(fs.existsSync(path.join(dir, "SKILL.md")));
    assert.ok(fs.existsSync(path.join(dir, "scripts", "tugboat.mjs")));
    assert.ok(fs.existsSync(path.join(dir, "scripts", "tugboat-mcp.mjs")));
    assert.ok(fs.existsSync(path.join(dir, "scripts", "lib", "language-optimizer.mjs")));
  }
  proveCopiedControlPlane(result.installed[0]);
});

test("CI install vendors the runtime and a workflow that invokes that exact copy", () => {
  const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-ci-repo-"));
  const result = installTugboat({ sourceDir: ROOT, home: repoDir, repo: repoDir, targets: ["repo"] });
  const runtime = path.join(repoDir, ".tugboat", "runtime");
  assert.deepEqual(result.installed, [runtime]);
  assert.ok(fs.existsSync(path.join(runtime, "scripts", "tugboat.mjs")));
  const workflow = fs.readFileSync(path.join(repoDir, ".github", "workflows", "tugboat-validate.yml"), "utf8");
  assert.match(workflow, /node \.tugboat\/runtime\/scripts\/tugboat\.mjs validate/);
  assert.doesNotMatch(workflow, /npx --no-install/);
});

test("backup and rebuild recover projections and snapshot from the append-only log", () => {
  const dir = repo();
  execFileSync(process.execPath, initArgs(dir, "tugboat"), { cwd: dir });
  const missionDir = path.join(dir, "tugboat");
  const before = readState(missionDir);
  const backup = backupMission(missionDir, { destinationRoot: path.join(dir, "backups") });
  assert.ok(fs.existsSync(path.join(backup, "backup-manifest.json")));
  fs.rmSync(path.join(missionDir, "state.json"));
  fs.rmSync(path.join(missionDir, "requirement-ledger.md"));
  const rebuilt = rebuildMission(missionDir);
  assert.equal(rebuilt.lastEventHash, before.lastEventHash);
  assert.ok(fs.existsSync(path.join(missionDir, "requirement-ledger.md")));
});

test("corrupt logs fail rebuild without overwriting the last valid snapshot", () => {
  const dir = repo();
  execFileSync(process.execPath, initArgs(dir, "tugboat"), { cwd: dir });
  const missionDir = path.join(dir, "tugboat");
  const snapshot = fs.readFileSync(path.join(missionDir, "state.json"), "utf8");
  fs.appendFileSync(path.join(missionDir, "events.jsonl"), "{not-json}\n");
  assert.throws(() => rebuildMission(missionDir), /not valid JSON/i);
  assert.equal(fs.readFileSync(path.join(missionDir, "state.json"), "utf8"), snapshot);
});

test("headless install CLI accepts an isolated HOME and explicit targets", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-cli-home-"));
  const result = spawnSync(process.execPath, [path.join(HERE, "install.mjs"), "--source", ROOT, "--home", home, "--targets", "agents,codex", "--json"], { encoding: "utf8", env: { ...process.env, HOME: home } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).installed.length, 2);
});

test("installed executable runs when its entry point is a symlink", () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-bin-"));
  const executable = path.join(binDir, "tugboat");
  fs.symlinkSync(CLI, executable);
  const result = spawnSync(executable, ["--help"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^Usage:/);
});

test("installer CLI runs through a symlinked path", () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-installer-bin-"));
  const installer = path.join(binDir, "install.mjs");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-installer-home-"));
  fs.symlinkSync(path.join(HERE, "install.mjs"), installer);
  const result = spawnSync(process.execPath, [installer, "--source", ROOT, "--home", home, "--targets", "agents", "--json"], { encoding: "utf8", env: { ...process.env, HOME: home } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).installed.length, 1);
});

test("installer help is side-effect free", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-installer-help-"));
  const result = spawnSync(process.execPath, [path.join(HERE, "install.mjs"), "--home", home, "--help"], { encoding: "utf8", env: { ...process.env, HOME: home } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^Usage:/);
  assert.equal(fs.existsSync(path.join(home, ".agents", "skills", "tugboat")), false);
});

test("package payload includes the behavior evaluation data used by its shipped runner", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.ok(manifest.files.includes("evals/"), "package files must include evals/ because test:behavior ships");
});
