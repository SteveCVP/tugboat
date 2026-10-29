import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { installTugboat } from "./install.mjs";
import { compileDoctorReport } from "./lib/doctor.mjs";
import { createMission } from "./lib/reducer.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function installedCli() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-doctor-install-"));
  const result = installTugboat({ sourceDir: ROOT, home, targets: ["claude"] });
  return path.join(result.installed[0], "scripts", "tugboat.mjs");
}

function setupMission() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-doctor-mission-"));
  const missionDir = path.join(repo, "mission");
  spawnSync("git", ["init", "-b", "main"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["config", "user.name", "Tugboat Test"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["config", "user.email", "tugboat@example.invalid"], { cwd: repo, encoding: "utf8" });
  fs.writeFileSync(path.join(repo, "spec.md"), "# Doctor fixture\n");
  spawnSync("git", ["add", "spec.md"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["commit", "-m", "baseline"], { cwd: repo, encoding: "utf8" });
  const baselineGitSha = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).stdout.trim();
  createMission({
    dir: missionDir,
    actor: { name: "Tugboat Test", kind: "human", runtime: "test" },
    metadata: {
      id: "doctor-fixture", title: "Doctor Fixture", owner: "Test", target: "local",
      repository: repo, worktree: repo, branch: "main", baselineGitSha,
      source: { path: "spec.md", digest: `sha256:${"a".repeat(64)}` },
      criticalPath: ["R1"], deployPath: "none",
    },
    requirements: [{ id: "R1", requirement: "Stay healthy", source: "spec", material: true, acceptance: "Healthy", proofTarget: "local" }],
    preservations: [],
    slices: [{ id: "S1", name: "Health", requirementIds: ["R1"], dependencies: [], status: "ACTIVE", operatorJourney: "Check health" }],
  });
  return { repo, missionDir };
}

function bytes(root) {
  const result = {};
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else result[path.relative(root, absolute)] = fs.readFileSync(absolute).toString("base64");
    }
  };
  walk(root);
  return result;
}

function doctor(cli, args = []) {
  return spawnSync(process.execPath, [cli, "doctor", ...args, "--json"], { encoding: "utf8" });
}

test("doctor reports a healthy installed payload and protocol 2 mission without changing bytes", () => {
  const cli = installedCli();
  const installDir = path.dirname(path.dirname(cli));
  const { repo, missionDir } = setupMission();
  const beforeInstall = bytes(installDir);
  const beforeMission = bytes(missionDir);

  const result = doctor(cli, ["--dir", missionDir]);

  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.schemaVersion, "tugboat.doctor.v1");
  assert.equal(report.status, "healthy");
  assert.deepEqual(report.checks.map(({ id, status }) => [id, status]), [
    ["runtime.node", "pass"],
    ["install.package", "pass"],
    ["install.payload", "pass"],
    ["mission.protocol", "pass"],
    ["mission.replay", "pass"],
    ["mission.lock", "pass"],
  ]);
  assert.deepEqual(bytes(installDir), beforeInstall);
  assert.deepEqual(bytes(missionDir), beforeMission);
  assert.equal(fs.existsSync(path.join(repo, ".tugboat-lock")), false);
});

test("doctor text output leads with the verdict and gives scan-friendly checks", () => {
  const cli = installedCli();
  const result = spawnSync(process.execPath, [cli, "doctor"], { encoding: "utf8" });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^Tugboat doctor: healthy\n/);
  assert.match(result.stdout, /^PASS runtime\.node:/m);
  assert.match(result.stdout, /^PASS install\.package:/m);
});

test("doctor rejects a Node runtime below the supported major version", () => {
  const report = compileDoctorReport({ rootDir: ROOT, nodeVersion: "v18.20.0" });

  assert.equal(report.status, "attention");
  const runtime = report.checks.find(({ id }) => id === "runtime.node");
  assert.equal(runtime.status, "attention");
  assert.match(runtime.action, /Node 20 or newer/i);
});

test("doctor detects a changed installed payload and recommends reinstalling", () => {
  const cli = installedCli();
  const installDir = path.dirname(path.dirname(cli));
  fs.appendFileSync(path.join(installDir, "README.md"), "\nchanged after install\n");

  const result = doctor(cli);

  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, "attention");
  const payload = report.checks.find(({ id }) => id === "install.payload");
  assert.equal(payload.status, "attention");
  assert.match(payload.action, /reinstall/i);
});

test("doctor identifies a legacy mission and gives the explicit migration command", () => {
  const cli = installedCli();
  const missionDir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-doctor-legacy-"));
  fs.writeFileSync(path.join(missionDir, "requirement-ledger.md"), "# Tugboat Requirement Ledger\n\n- Protocol version: `1.1`\n");
  const before = bytes(missionDir);

  const result = doctor(cli, ["--dir", missionDir]);

  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  const protocol = report.checks.find(({ id }) => id === "mission.protocol");
  assert.equal(protocol.status, "attention");
  assert.match(protocol.action, /tugboat migrate --legacy-dir/);
  assert.deepEqual(bytes(missionDir), before);
});

test("doctor reports snapshot corruption and an active lock without mutating either", () => {
  const cli = installedCli();
  const { missionDir } = setupMission();
  const stateFile = path.join(missionDir, "state.json");
  const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
  state.revision += 1;
  fs.writeFileSync(stateFile, `${JSON.stringify(state, null, 2)}\n`);
  fs.mkdirSync(path.join(missionDir, ".tugboat-lock"));
  fs.writeFileSync(path.join(missionDir, ".tugboat-lock", "owner.json"), "{}\n");
  const before = bytes(missionDir);

  const result = doctor(cli, ["--dir", missionDir]);

  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.checks.find(({ id }) => id === "mission.replay").status, "attention");
  assert.match(report.checks.find(({ id }) => id === "mission.replay").action, /back up.*tugboat rebuild --dir/i);
  assert.equal(report.checks.find(({ id }) => id === "mission.lock").status, "attention");
  assert.match(report.checks.find(({ id }) => id === "mission.lock").action, /wait|owner/i);
  assert.deepEqual(bytes(missionDir), before);
});
