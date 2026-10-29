import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createBoundaryManifest, writeBoundaryManifest } from "../../lib/boundary-manifest.mjs";
import { createBundle, readBundle } from "../../lib/bundle.mjs";
import { createMission } from "../../lib/reducer.mjs";
import { sha256 } from "../../lib/canonical.mjs";

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function commit(cwd, message) {
  git(cwd, ["add", "-A"]);
  git(cwd, ["commit", "-m", message]);
  return git(cwd, ["rev-parse", "HEAD"]);
}

export function writeFixtureFile(root, relative, contents, mode) {
  const file = path.join(root, ...relative.split("/"));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  if (mode) fs.chmodSync(file, mode);
  return file;
}

export function effectFixture() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-effects-"));
  git(repo, ["init", "-b", "main"]);
  git(repo, ["config", "user.name", "Effects Test"]);
  git(repo, ["config", "user.email", "effects@example.invalid"]);
  writeFixtureFile(repo, "spec.md", "# Effect mission\n");
  writeFixtureFile(repo, "docs/architecture.md", "# Architecture v1\n");
  writeFixtureFile(repo, "src/core/modify.mjs", "export const answer = 1;\n");
  writeFixtureFile(repo, "src/core/delete.mjs", "export const remove = true;\n");
  writeFixtureFile(repo, "src/core/old-name.mjs", "export const name = 'stable';\n");
  writeFixtureFile(repo, "src/core/mode.sh", "#!/bin/sh\nexit 0\n", 0o644);
  writeFixtureFile(repo, "src/api/existing.mjs", "export const api = true;\n");
  const baseline = commit(repo, "baseline");
  const missionDir = path.join(repo, "tugboat-source");
  createMission({
    dir: missionDir,
    actor: { name: "Codex", kind: "agent", runtime: "codex" },
    metadata: {
      id: "effect-source", title: "Effect source", owner: "Test", target: "local",
      repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline,
      source: { path: "spec.md", digest: `sha256:${sha256(fs.readFileSync(path.join(repo, "spec.md")))}` },
      criticalPath: ["R1"], deployPath: "not requested",
    },
    requirements: [
      { id: "R1", requirement: "Change core", source: "spec", material: true, acceptance: "Core works", proofTarget: "local" },
      { id: "R2", requirement: "Preserve API", source: "spec", material: true, acceptance: "API works", proofTarget: "local" },
      { id: "R3", requirement: "Preserve docs", source: "spec", material: true, acceptance: "Docs work", proofTarget: "local" },
    ],
    preservations: [{ id: "P1", instruction: "Preserve API", source: "spec", regressionProofTarget: "test" }],
    slices: [{ id: "S1", name: "Core", requirementIds: ["R1", "R2", "R3"], dependencies: [], status: "ACTIVE", operatorJourney: "Use core" }],
  });
  commit(repo, "initialize mission");

  writeFixtureFile(repo, "src/core/create.mjs", "export const created = true;\n");
  writeFixtureFile(repo, "src/core/modify.mjs", "export const answer = 2;\n");
  fs.rmSync(path.join(repo, "src/core/delete.mjs"));
  fs.renameSync(path.join(repo, "src/core/old-name.mjs"), path.join(repo, "src/core/renamed.mjs"));
  fs.chmodSync(path.join(repo, "src/core/mode.sh"), 0o755);
  const coreCommit = commit(repo, "change core paths");
  const coreBundlePath = path.join(repo, "core.tugboat.json");
  createBundle({
    missionDir, id: "B-CORE", outputPath: coreBundlePath, requirementIds: ["R1"], commitShas: [coreCommit],
    actor: { name: "Codex", kind: "agent", runtime: "codex" }, createdAt: "2026-10-29T16:00:00.000Z",
  });

  writeFixtureFile(repo, "src/api/cross.mjs", "export const cross = true;\n");
  const crossCommit = commit(repo, "cross boundary");
  const crossBundlePath = path.join(repo, "cross.tugboat.json");
  createBundle({
    missionDir, id: "B-CROSS", outputPath: crossBundlePath, requirementIds: ["R1"], commitShas: [crossCommit],
    actor: { name: "Claude", kind: "agent", runtime: "claude" }, createdAt: "2026-10-29T16:01:00.000Z",
  });

  writeFixtureFile(repo, "config/secrets.env", "SAFE_FIXTURE=true\n");
  const secretCommit = commit(repo, "write sensitive path");
  const secretBundlePath = path.join(repo, "secret.tugboat.json");
  createBundle({
    missionDir, id: "B-SECRET", outputPath: secretBundlePath, requirementIds: ["R1"], commitShas: [secretCommit],
    actor: { name: "Codex", kind: "agent", runtime: "codex" }, createdAt: "2026-10-29T16:02:00.000Z",
  });

  const sourceDigest = `sha256:${sha256(fs.readFileSync(path.join(repo, "docs/architecture.md")))}`;
  const boundaryInput = {
    id: "manifest:effect-fixture", generatedAt: "2026-10-29T16:03:00.000Z", disclosure: "confidential",
    sources: [{ id: "source:architecture", path: "docs/architecture.md", digest: sourceDigest, disclosure: "confidential" }],
    components: [
      { id: "component:core", owner: "team:platform", disclosure: "confidential", paths: ["src/core/**", "config/**"], requirementIds: ["R1"], dependencies: [], interfaces: [], invariantIds: ["invariant:core"], gateIds: ["gate:core"] },
      { id: "component:api", owner: "team:api", disclosure: "confidential", paths: ["src/api/**"], requirementIds: ["R2"], dependencies: ["component:core"], interfaces: [], invariantIds: ["invariant:api"], gateIds: ["gate:api"] },
      { id: "component:docs", owner: "team:docs", disclosure: "internal", paths: ["docs/public/**"], requirementIds: ["R3"], dependencies: [], interfaces: [], invariantIds: ["invariant:docs"], gateIds: ["gate:docs"] },
    ],
    invariants: [
      { id: "invariant:core", kind: "behavior", description: "Core behavior is preserved.", subjectIds: ["component:core"], gateIds: ["gate:core"] },
      { id: "invariant:api", kind: "behavior", description: "API behavior is preserved.", subjectIds: ["component:api"], gateIds: ["gate:api"] },
      { id: "invariant:docs", kind: "behavior", description: "Documentation behavior is preserved.", subjectIds: ["component:docs"], gateIds: ["gate:docs"] },
    ],
    gates: [
      { id: "gate:core", kind: "test", description: "Run core tests.", subjectIds: ["component:core"], mandatory: false },
      { id: "gate:api", kind: "test", description: "Run API tests.", subjectIds: ["component:api"], mandatory: false },
      { id: "gate:docs", kind: "test", description: "Run docs tests.", subjectIds: ["component:docs"], mandatory: false },
    ],
  };
  const boundary = createBoundaryManifest(boundaryInput);
  const boundaryPath = path.join(repo, "tugboat.boundaries.json");
  writeBoundaryManifest(boundaryPath, boundary);
  return {
    repo, missionDir, boundary, boundaryPath,
    coreBundlePath, crossBundlePath, secretBundlePath,
    coreBundle: readBundle(coreBundlePath), crossBundle: readBundle(crossBundlePath), secretBundle: readBundle(secretBundlePath),
  };
}
