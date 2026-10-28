import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { installTugboat } from "./install.mjs";
import { createMission } from "./lib/reducer.mjs";
import { readState } from "./lib/store.mjs";
import { sha256 } from "./lib/canonical.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const CLI = path.join(HERE, "tugboat.mjs");

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function commit(cwd, message) {
  git(cwd, ["add", "-A"]);
  git(cwd, ["commit", "-m", message]);
  return git(cwd, ["rev-parse", "HEAD"]);
}

function repo(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  git(dir, ["init", "-b", "main"]);
  git(dir, ["config", "user.email", "test@example.com"]);
  git(dir, ["config", "user.name", "Tugboat Test"]);
  fs.writeFileSync(path.join(dir, "spec.md"), "# Approved\n");
  fs.writeFileSync(path.join(dir, "app.mjs"), "export const ready = false;\n");
  return dir;
}

function mission(dir, name, requirementId) {
  const baseline = git(dir, ["rev-parse", "HEAD"]);
  const missionDir = path.join(dir, name);
  createMission({
    dir: missionDir, actor: { name: "Alex", kind: "human" },
    metadata: {
      id: name, title: name, owner: "Alex", target: "local", repository: dir, worktree: dir, branch: "main", baselineGitSha: baseline,
      source: { path: "spec.md", digest: `sha256:${sha256(fs.readFileSync(path.join(dir, "spec.md")))}` }, criticalPath: [requirementId], deployPath: "not requested",
    },
    requirements: [{ id: requirementId, requirement: `${name} workflow`, source: "spec", material: true, acceptance: "works", proofTarget: "local" }],
    preservations: [{ id: "P1", instruction: "Preserve baseline", source: "spec", regressionProofTarget: "test" }],
  });
  commit(dir, `initialize ${name}`);
  return missionDir;
}

function setup() {
  const source = repo("tugboat-bundle-cli-source-");
  commit(source, "source baseline");
  const sourceMission = mission(source, "source-mission", "SRC-1");
  fs.writeFileSync(path.join(source, "app.mjs"), "export const ready = true;\n");
  const sourceCommit = commit(source, "build candidate");
  const artifacts = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-bundle-cli-artifacts-"));
  const component = path.join(artifacts, "design.bin");
  fs.writeFileSync(component, Buffer.from([1, 2, 3, 255]));
  const componentsFile = path.join(artifacts, "components.json");
  fs.writeFileSync(componentsFile, JSON.stringify([{ type: "image", sourcePath: component, targetPath: "assets/design.bin", requirementIds: ["SRC-1"] }]));
  const commitMapFile = path.join(artifacts, "commit-map.json");
  fs.writeFileSync(commitMapFile, JSON.stringify({ [sourceCommit]: ["SRC-1"] }));

  const target = repo("tugboat-bundle-cli-target-");
  commit(target, "target baseline");
  const targetMission = mission(target, "target-mission", "R-1");
  return { source, sourceMission, sourceCommit, artifacts, componentsFile, commitMapFile, target, targetMission };
}

function run(cwd, cli, args) {
  return execFileSync(process.execPath, [cli, ...args], { cwd, encoding: "utf8" });
}

test("bundle subcommands create, inspect, and compare stable redacted JSON", () => {
  const context = setup();
  const alpha = path.join(context.artifacts, "alpha.tugboat");
  const beta = path.join(context.artifacts, "beta.tugboat");
  const common = [
    "--dir", context.sourceMission, "--requirements", "SRC-1", "--commits", context.sourceCommit,
    "--components-file", context.componentsFile, "--commit-requirements-file", context.commitMapFile, "--json",
  ];
  const created = JSON.parse(run(context.source, CLI, ["bundle", "create", "--id", "B-ALPHA", "--output", alpha, ...common]));
  assert.equal(created.id, "B-ALPHA");
  assert.doesNotMatch(JSON.stringify(created), /"content"|git-format-patch/);
  JSON.parse(run(context.source, CLI, ["bundle", "create", "--id", "B-BETA", "--output", beta, ...common]));
  const inspected = JSON.parse(run(context.source, CLI, ["bundle", "inspect", "--file", alpha, "--json"]));
  assert.equal(inspected.id, "B-ALPHA");
  assert.doesNotMatch(JSON.stringify(inspected), /"content"|git-format-patch/);
  const compared = JSON.parse(run(context.source, CLI, ["bundle", "compare", "--bundles", `${beta},${alpha}`, "--json"]));
  assert.deepEqual(compared.candidates.map((item) => item.id), ["B-ALPHA", "B-BETA"]);

  const policyFailure = spawnSync(process.execPath, [CLI, "bundle", "inspect", "--file", alpha, "--require-signature", "--json"], { cwd: context.source, encoding: "utf8" });
  assert.equal(policyFailure.status, 3);
  assert.match(policyFailure.stderr, /signature/i);
  const unknown = spawnSync(process.execPath, [CLI, "bundle", "unknown", "--file", alpha], { cwd: context.source, encoding: "utf8" });
  assert.equal(unknown.status, 2);
});

test("cherry-pick dry-run is non-mutating and real CLI promotion runs the supplied validation command", () => {
  const context = setup();
  const bundle = path.join(context.artifacts, "candidate.tugboat");
  run(context.source, CLI, [
    "bundle", "create", "--dir", context.sourceMission, "--id", "B-CLI", "--output", bundle,
    "--requirements", "SRC-1", "--commits", context.sourceCommit,
    "--components-file", context.componentsFile, "--commit-requirements-file", context.commitMapFile, "--json",
  ]);
  const before = git(context.target, ["rev-parse", "HEAD"]);
  const selection = ["--dir", context.targetMission, "--bundle", bundle, "--requirements", "SRC-1", "--map", "SRC-1:R-1", "--json"];
  const dryRun = JSON.parse(run(context.target, CLI, ["cherry-pick", ...selection, "--dry-run"]));
  assert.equal(dryRun.dryRun, true);
  assert.equal(git(context.target, ["rev-parse", "HEAD"]), before);
  const promoted = JSON.parse(run(context.target, CLI, [
    "cherry-pick", ...selection, "--", process.execPath, "-e", "import('./app.mjs').then(m => { if (!m.ready) process.exit(8) })",
  ]));
  assert.equal(promoted.dryRun, false);
  assert.notEqual(promoted.head, before);
  assert.equal(readState(context.targetMission).requirements["R-1"].status, "IN_PROGRESS");
  assert.deepEqual(fs.readFileSync(path.join(context.target, "assets", "design.bin")), Buffer.from([1, 2, 3, 255]));
});

test("installed shared runtime executes the same bundle inspection command", () => {
  const context = setup();
  const bundle = path.join(context.artifacts, "installed.tugboat");
  run(context.source, CLI, [
    "bundle", "create", "--dir", context.sourceMission, "--id", "B-INSTALLED", "--output", bundle,
    "--requirements", "SRC-1", "--commits", context.sourceCommit,
    "--components-file", context.componentsFile, "--commit-requirements-file", context.commitMapFile,
  ]);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-bundle-cli-home-"));
  const installed = installTugboat({ sourceDir: ROOT, home, targets: ["agents"] }).installed[0];
  const inspected = JSON.parse(run(context.source, path.join(installed, "scripts", "tugboat.mjs"), ["bundle", "inspect", "--file", bundle, "--json"]));
  assert.equal(inspected.id, "B-INSTALLED");
});
