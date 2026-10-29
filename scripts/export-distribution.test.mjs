import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { exportDistribution } from "./export-distribution.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const FORBIDDEN = [
  new RegExp(["@crys", "talvp"].join(""), "i"),
  new RegExp(`\\b${["crys", "tal"].join("")}\\b`, "i"),
  new RegExp(`\\b${["c", "vp"].join("")}\\b`, "i"),
  new RegExp(`\\b${["deal", "flow"].join("")}\\b`, "i"),
  new RegExp(`\\b${["ste", "ve(?:n|phen)?"].join("")}\\b`, "i"),
  new RegExp(["/Us", "ers/"].join("")),
];

function temporaryDestination(name = "distribution") {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-export-"));
  return path.join(parent, name);
}

function walk(root, current = root) {
  return fs.readdirSync(current, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name)).flatMap((entry) => {
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) return walk(root, absolute);
    return [path.relative(root, absolute)];
  });
}

function copyPublicSource() {
  const destination = temporaryDestination("source");
  const ignored = new Set([".git", ".superpowers", ".worktrees", "tugboat", "tugboat-external-release"]);
  fs.cpSync(ROOT, destination, {
    recursive: true,
    filter(source) {
      const relative = path.relative(ROOT, source);
      return !relative.split(path.sep).some((segment) => ignored.has(segment));
    },
  });
  return destination;
}

function run(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, encoding: "utf8" });
  assert.equal(result.status, 0, `${command} ${args.join(" ")}\n${result.stdout}\n${result.stderr}`);
  return result;
}

function proveExportedControlPlane(runtimeRoot) {
  const project = temporaryDestination("control-plane-project");
  fs.mkdirSync(project);
  run("git", ["init", "-b", "main"], project);
  run("git", ["config", "user.name", "Tugboat Test"], project);
  run("git", ["config", "user.email", "tugboat@example.invalid"], project);
  fs.writeFileSync(path.join(project, "spec.md"), "# Portable control plane\n");
  fs.writeFileSync(path.join(project, "requirements.json"), JSON.stringify({
    requirements: [{ id: "R1", requirement: "Run anywhere", source: "spec", acceptance: "Execution packet compiles", proof_target: "local" }],
    preservations: [{ id: "P1", instruction: "Preserve replay", source: "spec", regression_proof: "state tests" }],
  }));
  run("git", ["add", "."], project);
  run("git", ["commit", "-m", "portable fixture"], project);
  const missionDir = path.join(project, "tugboat");
  const cli = path.join(runtimeRoot, "scripts", "tugboat.mjs");
  const mcp = path.join(runtimeRoot, "scripts", "tugboat-mcp.mjs");
  run(process.execPath, [cli, "init", "--dir", missionDir, "--mission", "portable", "--title", "Portable", "--owner", "Test", "--source", "spec.md", "--requirements-file", "requirements.json", "--target", "local", "--critical-path", "R1", "--deploy-path", "none"], project);
  const packet = JSON.parse(run(process.execPath, [cli, "next", "--dir", missionDir, "--observed-at", "2026-10-28T21:00:00.000Z", "--json"], project).stdout);
  assert.deepEqual(packet.ready.map((item) => item.id), ["R1"]);
  const profile = path.join(project, "architecture-profile.json");
  fs.writeFileSync(profile, JSON.stringify({ requirementSignals: { R1: ["cloud_service"] }, teamLanguages: ["go"] }));
  const exportedDecision = JSON.parse(run(process.execPath, [cli, "language", "recommend", "--dir", missionDir, "--repo", project, "--profile", profile, "--json"], project).stdout);
  const sourceDecision = JSON.parse(run(process.execPath, [path.join(ROOT, "scripts", "tugboat.mjs"), "language", "recommend", "--dir", missionDir, "--repo", project, "--profile", profile, "--json"], project).stdout);
  assert.equal(exportedDecision.digest, sourceDecision.digest);
  const handshake = spawnSync(process.execPath, [mcp, "--dir", missionDir], {
    cwd: project,
    input: `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "server/discover" })}\n`,
    encoding: "utf8",
  });
  assert.equal(handshake.status, 0, handshake.stderr);
  const discovery = JSON.parse(handshake.stdout).result;
  assert.equal(discovery.protocolVersion, "2026-07-28");
  assert.deepEqual(discovery.tools.map((tool) => tool.name), ["tugboat_adapter_inspect", "tugboat_boundary_verify", "tugboat_bundle_commute", "tugboat_capsule_verify", "tugboat_certificate_verify", "tugboat_history_explain", "tugboat_intelligence", "tugboat_language_recommend", "tugboat_next", "tugboat_provenance_verify", "tugboat_review_compare", "tugboat_rollback_verify", "tugboat_status"]);

  fs.writeFileSync(path.join(project, "operator.ts"), "export const operator = 2;\n");
  run("git", ["add", "operator.ts"], project);
  run("git", ["commit", "-m", "change operator"], project);
  const impactProfile = path.join(project, "impact.json");
  fs.writeFileSync(impactProfile, JSON.stringify({ rules: [{ id: "operator", pattern: "operator.ts", requirementIds: ["R1"], evidenceIds: [], tests: ["node --test"], risks: ["runtime"] }] }));
  const impactArgs = ["intelligence", "impact", "--dir", missionDir, "--repo", project, "--base", packet.observation.git.head, "--head", "HEAD", "--profile", impactProfile, "--json"];
  const exportedImpact = JSON.parse(run(process.execPath, [cli, ...impactArgs], project).stdout);
  const sourceImpact = JSON.parse(run(process.execPath, [path.join(ROOT, "scripts", "tugboat.mjs"), ...impactArgs], project).stdout);
  assert.equal(exportedImpact.digest, sourceImpact.digest);
  assert.equal(exportedImpact.schemaVersion, "tugboat.proof-impact.v1");

  const graph = path.join(project, "trust-graph.json");
  const policy = path.join(project, "trust-policy.json");
  fs.writeFileSync(graph, JSON.stringify({ nodes: [{ id: "source", type: "artifact", classification: "internal", authorities: ["read"] }], edges: [] }));
  fs.writeFileSync(policy, JSON.stringify({ classifications: ["public", "internal"], sinks: [{ nodeId: "source", maxClassification: "internal", allowedAuthorities: ["read"] }], approvedSanitizers: [] }));
  const trust = JSON.parse(run(process.execPath, [cli, "intelligence", "trust", "--graph", graph, "--policy", policy, "--json"], project).stdout);
  assert.equal(trust.status, "ready");
}

test("exports a neutral freestanding repository from the public allowlist", () => {
  const destination = temporaryDestination();
  const result = exportDistribution({ sourceDir: ROOT, destinationDir: destination });
  const packageJson = JSON.parse(fs.readFileSync(path.join(destination, "package.json"), "utf8"));

  assert.equal(result.destinationDir, fs.realpathSync(destination));
  assert.equal(result.packageName, "tugboat-mission-control");
  assert.equal(result.version, "4.1.1");
  assert.equal(packageJson.name, "tugboat-mission-control");
  assert.equal(packageJson.private, false);
  assert.equal(packageJson.license, "MIT");
  assert.ok(fs.existsSync(path.join(destination, "LICENSE")));
  assert.ok(fs.existsSync(path.join(destination, "CONTRIBUTING.md")));
  assert.ok(fs.existsSync(path.join(destination, "SECURITY.md")));
  assert.ok(fs.existsSync(path.join(destination, ".github", "workflows", "ci.yml")));
  assert.ok(fs.existsSync(path.join(destination, "docs", "release-audit-4.0.0.md")));
  assert.ok(fs.existsSync(path.join(destination, "docs", "release-audit-4.1.0.md")));
  assert.ok(fs.existsSync(path.join(destination, "docs", "release-audit-4.1.1.md")));
  assert.equal(fs.existsSync(path.join(destination, "tugboat")), false);
  assert.equal(fs.existsSync(path.join(destination, "tugboat-external-release")), false);
  assert.deepEqual(fs.readdirSync(path.join(destination, "docs")), ["release-audit-4.0.0.md", "release-audit-4.1.0.md", "release-audit-4.1.1.md"]);
  assert.equal(fs.existsSync(path.join(destination, ".git")), false);

  const ci = fs.readFileSync(path.join(destination, ".github", "workflows", "ci.yml"), "utf8");
  const codeql = fs.readFileSync(path.join(destination, ".github", "workflows", "codeql.yml"), "utf8");
  const dependabot = fs.readFileSync(path.join(destination, ".github", "dependabot.yml"), "utf8");
  assert.match(ci, /permissions:\n  contents: read/);
  assert.match(ci, /persist-credentials: false/);
  assert.match(ci, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
  assert.doesNotMatch(ci, /uses:\s+[^\s]+@v\d/);
  assert.match(codeql, /security-events: write/);
  assert.match(codeql, /schedule:/);
  assert.doesNotMatch(codeql, /uses:\s+[^\s]+@v\d/);
  assert.match(dependabot, /package-ecosystem: "github-actions"/);

  for (const relative of walk(destination)) {
    const absolute = path.join(destination, relative);
    if (fs.statSync(absolute).isFile()) {
      const text = fs.readFileSync(absolute, "utf8");
      for (const pattern of FORBIDDEN) assert.doesNotMatch(text, pattern, relative);
    }
  }
});

test("refuses a non-empty destination without changing its files", () => {
  const destination = temporaryDestination();
  fs.mkdirSync(destination);
  fs.writeFileSync(path.join(destination, "keep.txt"), "preserve me\n");

  assert.throws(() => exportDistribution({ sourceDir: ROOT, destinationDir: destination }), /destination.*empty/i);
  assert.equal(fs.readFileSync(path.join(destination, "keep.txt"), "utf8"), "preserve me\n");
  assert.deepEqual(fs.readdirSync(destination), ["keep.txt"]);
});

test("rejects an unexpected personal path and removes staged output", () => {
  const source = copyPublicSource();
  const destination = temporaryDestination();
  const privatePath = ["/Us", "ers/private/repository"].join("");
  fs.writeFileSync(path.join(source, "scripts", "leak-note.txt"), `Built in ${privatePath}\n`);

  assert.throws(() => exportDistribution({ sourceDir: source, destinationDir: destination }), /forbidden provenance.*scripts\/leak-note\.txt/i);
  assert.equal(fs.existsSync(destination), false);
});

test("rejects secret-like content and removes staged output", () => {
  const source = copyPublicSource();
  const destination = temporaryDestination();
  fs.writeFileSync(path.join(source, "scripts", "credential-note.txt"), `token ghp_${"A".repeat(36)}\n`);

  assert.throws(() => exportDistribution({ sourceDir: source, destinationDir: destination }), /secret material.*scripts\/credential-note\.txt/i);
  assert.equal(fs.existsSync(destination), false);
});

test("rejects symbolic links in allowlisted content", () => {
  const source = copyPublicSource();
  const destination = temporaryDestination();
  fs.symlinkSync(path.join(source, "README.md"), path.join(source, "scripts", "linked-readme.md"));

  assert.throws(() => exportDistribution({ sourceDir: source, destinationDir: destination }), /symbolic link.*scripts\/linked-readme\.md/i);
  assert.equal(fs.existsSync(destination), false);
});

test("public verification accepts neutral history and rejects forbidden commit identity", () => {
  const neutral = temporaryDestination();
  exportDistribution({ sourceDir: ROOT, destinationDir: neutral });
  run("git", ["init", "-b", "main"], neutral);
  run("git", ["config", "user.name", "Tugboat Maintainers"], neutral);
  run("git", ["config", "user.email", "maintainers@users.noreply.github.com"], neutral);
  run("git", ["add", "."], neutral);
  run("git", ["commit", "-m", "neutral public history"], neutral);
  run("npm", ["run", "verify:public"], neutral);

  const unsafe = temporaryDestination();
  exportDistribution({ sourceDir: ROOT, destinationDir: unsafe });
  run("git", ["init", "-b", "main"], unsafe);
  run("git", ["config", "user.name", ["St", "ephen McGovern"].join("")], unsafe);
  run("git", ["config", "user.email", ["st", "eve@crys", "talventurepartners.com"].join("")], unsafe);
  run("git", ["add", "."], unsafe);
  run("git", ["commit", "-m", "unsafe public history"], unsafe);
  const rejected = spawnSync("npm", ["run", "verify:public"], { cwd: unsafe, encoding: "utf8" });
  assert.notEqual(rejected.status, 0);
  assert.match(`${rejected.stdout}\n${rejected.stderr}`, /forbidden provenance.*commit metadata/i);
});

test("public verification rejects sensitive content removed from the current tree", () => {
  const destination = temporaryDestination();
  exportDistribution({ sourceDir: ROOT, destinationDir: destination });
  run("git", ["init", "-b", "main"], destination);
  run("git", ["config", "user.name", "Tugboat Maintainers"], destination);
  run("git", ["config", "user.email", "maintainers@users.noreply.github.com"], destination);
  fs.writeFileSync(path.join(destination, "leak.txt"), ["/Us", "ers/private/repository"].join(""));
  run("git", ["add", "."], destination);
  run("git", ["commit", "-m", "add temporary fixture"], destination);
  fs.unlinkSync(path.join(destination, "leak.txt"));
  run("git", ["add", "-u"], destination);
  run("git", ["commit", "-m", "remove temporary fixture"], destination);

  const rejected = spawnSync("npm", ["run", "verify:public"], { cwd: destination, encoding: "utf8" });
  assert.notEqual(rejected.status, 0);
  assert.match(`${rejected.stdout}\n${rejected.stderr}`, /forbidden provenance.*historical blob/i);
});

test("public verification rejects sensitive Git reference names", () => {
  const destination = temporaryDestination();
  exportDistribution({ sourceDir: ROOT, destinationDir: destination });
  run("git", ["init", "-b", "main"], destination);
  run("git", ["config", "user.name", "Tugboat Maintainers"], destination);
  run("git", ["config", "user.email", "maintainers@users.noreply.github.com"], destination);
  run("git", ["add", "."], destination);
  run("git", ["commit", "-m", "neutral public history"], destination);
  run("git", ["branch", ["private-", "ste", "ve-record"].join("")], destination);

  const rejected = spawnSync("npm", ["run", "verify:public"], { cwd: destination, encoding: "utf8" });
  assert.notEqual(rejected.status, 0);
  assert.match(`${rejected.stdout}\n${rejected.stderr}`, /forbidden provenance.*reference metadata/i);
});

test("generated repository tests, packages, and installs independently", { skip: process.env.TUGBOAT_DISTRIBUTION_E2E_CHILD === "1" }, () => {
  const destination = temporaryDestination();
  exportDistribution({ sourceDir: ROOT, destinationDir: destination });
  assert.match(fs.readFileSync(path.join(destination, "README.md"), "utf8"), /npm run export:distribution -- --destination/);
  proveExportedControlPlane(destination);

  const childEnvironment = { ...process.env, TUGBOAT_DISTRIBUTION_E2E_CHILD: "1" };
  delete childEnvironment.NODE_TEST_CONTEXT;
  const suite = run("npm", ["test"], destination, childEnvironment);
  const testCount = Number(suite.stdout.match(/# tests (\d+)/)?.[1] ?? 0);
  assert.ok(testCount >= 108, `generated suite ran only ${testCount} tests`);
  assert.match(suite.stdout, /# fail 0/);
  run("npm", ["run", "test:behavior"], destination);
  const packed = JSON.parse(run("npm", ["pack", "--dry-run", "--json"], destination).stdout)[0];
  assert.equal(packed.name, "tugboat-mission-control");
  const packedFiles = new Set(packed.files.map((entry) => entry.path));
  for (const required of ["LICENSE", "SKILL.md", "evals/evals.json", "scripts/tugboat.mjs", "scripts/tugboat-mcp.mjs"]) assert.ok(packedFiles.has(required), required);
  assert.ok(packedFiles.has("docs/release-audit-4.0.0.md"));
  assert.ok(packedFiles.has("docs/release-audit-4.1.0.md"));
  assert.ok(packedFiles.has("docs/release-audit-4.1.1.md"));
  assert.ok([...packedFiles].every((file) => !file.startsWith("tugboat/")));

  const home = temporaryDestination("home");
  fs.mkdirSync(home);
  const installed = JSON.parse(run(process.execPath, ["scripts/install.mjs", "--source", destination, "--home", home, "--targets", "agents,claude,codex", "--json"], destination).stdout);
  assert.equal(installed.version, "4.1.1");
  assert.equal(installed.installed.length, 3);
  for (const relative of [[".agents"], [".claude"], [".codex"]]) {
    const runtime = path.join(home, ...relative, "skills", "tugboat");
    assert.ok(fs.existsSync(path.join(runtime, "SKILL.md")), runtime);
    run(process.execPath, [path.join(runtime, "scripts", "tugboat.mjs"), "--help"], destination);
  }
});
