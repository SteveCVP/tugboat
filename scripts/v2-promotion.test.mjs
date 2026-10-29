import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createBundle } from "./lib/bundle.mjs";
import { inspectContinuity } from "./lib/continuity.mjs";
import { planPromotion, promoteBundle, PromotionError } from "./lib/promotion.mjs";
import { createMission, missionReducer } from "./lib/reducer.mjs";
import { appendEvent, readState, replayEvents } from "./lib/store.mjs";
import { canonicalJson, sha256 } from "./lib/canonical.mjs";

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function commit(cwd, message) {
  git(cwd, ["add", "-A"]);
  git(cwd, ["commit", "-m", message]);
  return git(cwd, ["rev-parse", "HEAD"]);
}

function initRepo(prefix) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  git(repo, ["init", "-b", "main"]);
  git(repo, ["config", "user.email", "test@example.com"]);
  git(repo, ["config", "user.name", "Tugboat Test"]);
  return repo;
}

function createTestMission({ repo, dirName, id, requirements, preservations = [], baseline, provenId }) {
  const missionDir = path.join(repo, dirName);
  createMission({
    dir: missionDir,
    actor: { name: "Alex", kind: "human" },
    metadata: {
      id, title: id, owner: "Alex", target: "local", repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline,
      source: { path: "spec.md", digest: `sha256:${sha256(fs.readFileSync(path.join(repo, "spec.md")))}` },
      criticalPath: [requirements[0].id], deployPath: "not requested",
    },
    requirements,
    preservations,
  });
  if (provenId) {
    appendEvent(missionDir, {
      type: "REQUIREMENT_PROVEN", actor: { name: "Codex", kind: "agent" },
      payload: { requirementId: provenId, status: "PROVEN(local)", evidenceRefs: ["E-OLD-COMMAND", "E-OLD-OPERATOR"], result: "old target result" },
    }, { reducer: missionReducer, currentHead: baseline });
  }
  commit(repo, `initialize ${id}`);
  return missionDir;
}

function pair({ dependsOn = [], conflictingComponent = false, conflictingPatch = false, includeMissionAttack = false, patchSymlink = false } = {}) {
  const source = initRepo("tugboat-promotion-source-");
  fs.writeFileSync(path.join(source, "spec.md"), "# Source approved\n");
  fs.writeFileSync(path.join(source, "app.mjs"), "export const answer = 0;\n");
  const sourceBaseline = commit(source, "source baseline");
  const sourceMission = createTestMission({
    repo: source, dirName: "source-mission", id: "source",
    requirements: [
      { id: "SRC-UI", requirement: "Candidate UI", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
      { id: "SRC-WORK", requirement: "Candidate worker", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
    ],
    preservations: [{ id: "SRC-P1", instruction: "Preserve auth", source: "spec", regressionProofTarget: "test" }],
    baseline: sourceBaseline,
  });
  fs.writeFileSync(path.join(source, "app.mjs"), "export const answer = 42;\n");
  const uiCommit = commit(source, "build candidate UI");
  fs.writeFileSync(path.join(source, "worker.mjs"), "export const run = () => 'ready';\n");
  if (includeMissionAttack) {
    fs.mkdirSync(path.join(source, "target-mission"));
    fs.writeFileSync(path.join(source, "target-mission", "events.jsonl"), "attacker controlled\n");
  }
  const workerCommit = commit(source, "build candidate worker");
  const componentRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-promotion-component-"));
  const componentPath = path.join(componentRoot, "ui.bin");
  fs.writeFileSync(componentPath, Buffer.from([0, 255, 10, 11, 12]));
  const bundlePath = path.join(componentRoot, "candidate.tugboat");
  createBundle({
    missionDir: sourceMission, id: "B-CANDIDATE", requirementIds: ["SRC-UI", "SRC-WORK"],
    commitShas: [uiCommit, workerCommit], commitRequirements: { [uiCommit]: ["SRC-UI"], [workerCommit]: ["SRC-WORK"] },
    components: [{ type: "image", sourcePath: componentPath, targetPath: "assets/ui.bin", label: "UI asset", requirementIds: ["SRC-UI"] }],
    dependsOn, actor: { name: "Claude", kind: "agent", runtime: "claude" }, outputPath: bundlePath,
  });

  const target = initRepo("tugboat-promotion-target-");
  fs.writeFileSync(path.join(target, "spec.md"), "# Target approved\n");
  fs.writeFileSync(path.join(target, "app.mjs"), conflictingPatch ? "export const answer = 'diverged';\n" : "export const answer = 0;\n");
  if (conflictingComponent) {
    fs.mkdirSync(path.join(target, "assets"));
    fs.writeFileSync(path.join(target, "assets", "ui.bin"), Buffer.from("different"));
  }
  if (patchSymlink) {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-promotion-outside-"));
    fs.symlinkSync(outside, path.join(target, "linked"));
  }
  const targetBaseline = commit(target, "target baseline");
  const targetMission = createTestMission({
    repo: target, dirName: "target-mission", id: "target",
    requirements: [
      { id: "R-UI", requirement: "Target UI", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
      { id: "R-WORK", requirement: "Target worker", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
    ],
    preservations: [{ id: "P1", instruction: "Preserve auth", source: "spec", regressionProofTarget: "test" }],
    baseline: targetBaseline, provenId: "R-UI",
  });
  return { source, sourceMission, uiCommit, workerCommit, target, targetMission, bundlePath, componentPath };
}

function rewriteFirstPatchPath(context, from, to) {
  const envelope = JSON.parse(fs.readFileSync(context.bundlePath, "utf8"));
  const patch = Buffer.from(envelope.payload.patches[0].content, "base64").toString("utf8").replaceAll(from, to);
  const contents = Buffer.from(patch);
  envelope.payload.patches[0].content = contents.toString("base64");
  envelope.payload.patches[0].size = contents.length;
  envelope.payload.patches[0].digest = `sha256:${sha256(contents)}`;
  envelope.digest = `sha256:${sha256(canonicalJson(envelope.payload))}`;
  fs.writeFileSync(context.bundlePath, `${canonicalJson(envelope)}\n`);
}

function options(context, overrides = {}) {
  return {
    missionDir: context.targetMission,
    bundlePath: context.bundlePath,
    requirementIds: ["SRC-UI"],
    excludeIds: ["SRC-WORK"],
    mappings: { "SRC-UI": "R-UI" },
    actor: { name: "Alex", kind: "human", runtime: "shell" },
    validationCommand: [process.execPath, "-e", "import('./app.mjs').then(m => { if (m.answer !== 42) process.exit(9) })"],
    ...overrides,
  };
}

function snapshot(context) {
  return {
    head: git(context.target, ["rev-parse", "HEAD"]),
    tree: git(context.target, ["rev-parse", "HEAD^{tree}"]),
    status: git(context.target, ["status", "--porcelain=v1", "--untracked-files=all"]),
    events: fs.readFileSync(path.join(context.targetMission, "events.jsonl"), "utf8"),
  };
}

function preservationProof(bundleDigest) {
  const body = {
    kind: "non_interference",
    authority: "invalidation_only",
    witnessDigest: `sha256:${"a".repeat(64)}`,
    invalidationDigest: `sha256:${"b".repeat(64)}`,
    bundleDigest,
    boundaryManifestDigest: `sha256:${"c".repeat(64)}`,
    retainedNodeIds: ["requirement:R-WORK"],
    invalidatedNodeIds: ["requirement:R-UI"],
  };
  return { ...body, digest: `sha256:${sha256(canonicalJson(body))}` };
}

test("plans mapped selective impact and dry-run leaves the target byte-for-byte unchanged", () => {
  const context = pair();
  const before = snapshot(context);
  const plan = planPromotion(options(context));
  assert.equal(plan.valid, true);
  assert.deepEqual(plan.sourceRequirementIds, ["SRC-UI"]);
  assert.deepEqual(plan.targetRequirementIds, ["R-UI"]);
  assert.deepEqual(plan.excludedSourceIds, ["SRC-WORK"]);
  assert.deepEqual(plan.commits.map((item) => item.sourceSha), [context.uiCommit]);
  assert.deepEqual(plan.components.map((item) => item.targetPath), ["assets/ui.bin"]);
  assert.equal(plan.proofInvalidations[0].previousStatus, "PROVEN(local)");
  const dryRun = promoteBundle(options(context, { dryRun: true }));
  assert.equal(dryRun.dryRun, true);
  assert.deepEqual(snapshot(context), before);
});

test("promotion carries verified non-interference only as invalidation preservation metadata", () => {
  const context = pair();
  const bundleDigest = JSON.parse(fs.readFileSync(context.bundlePath, "utf8")).digest;
  const proof = preservationProof(bundleDigest);
  const plan = planPromotion(options(context, { preservationProofs: [proof] }));
  assert.deepEqual(plan.preservationProofs, [proof]);
  const result = promoteBundle(options(context, { preservationProofs: [proof] }));
  assert.deepEqual(result.preservationProofs, [proof]);
  const state = readState(context.targetMission);
  assert.deepEqual(state.promotions[0].preservationProofs, [proof]);
  assert.equal(state.requirements["R-UI"].status, "IN_PROGRESS");
  assert.deepEqual(state.requirements["R-UI"].evidenceRefs, []);
});

test("requires complete one-to-one mappings and satisfied promoted bundle dependencies", () => {
  const context = pair({ dependsOn: ["B-FOUNDATION"] });
  assert.throws(() => planPromotion(options(context, { mappings: {} })), /target requirement|mapping/i);
  const dependencyPlan = planPromotion(options(context));
  assert.equal(dependencyPlan.valid, false);
  assert.match(dependencyPlan.conflicts.map((item) => item.message).join(" "), /B-FOUNDATION/);
});

test("reports component conflicts and refuses promotion without target mutation", () => {
  const context = pair({ conflictingComponent: true });
  const before = snapshot(context);
  const plan = planPromotion(options(context));
  assert.equal(plan.valid, false);
  assert.match(plan.conflicts.map((item) => item.code).join(","), /component_conflict/);
  assert.throws(() => promoteBundle(options(context)), PromotionError);
  assert.deepEqual(snapshot(context), before);
});

test("rejects a source patch that targets the canonical target mission", () => {
  const context = pair({ includeMissionAttack: true });
  assert.throws(() => planPromotion(options(context, {
    requirementIds: ["SRC-WORK"], excludeIds: ["SRC-UI"], mappings: { "SRC-WORK": "R-WORK" },
  })), /target mission|mission path/i);
});

test("rejects bundle patches that cross a target symbolic link before mutation", () => {
  const context = pair({ patchSymlink: true });
  rewriteFirstPatchPath(context, "app.mjs", "linked/escape.mjs");
  const before = snapshot(context);
  assert.throws(() => planPromotion(options(context)), /symbolic link|symlink|unsafe patch path/i);
  assert.deepEqual(snapshot(context), before);
});

test("failed patch application or validation leaves target branch, files, and mission unchanged", () => {
  const patchConflict = pair({ conflictingPatch: true });
  const patchBefore = snapshot(patchConflict);
  assert.throws(() => promoteBundle(options(patchConflict)), /apply|patch|git am/i);
  assert.deepEqual(snapshot(patchConflict), patchBefore);

  const validationFailure = pair();
  const validationBefore = snapshot(validationFailure);
  assert.throws(() => promoteBundle(options(validationFailure, { validationCommand: [process.execPath, "-e", "process.exit(7)"] })), /validation.*7/i);
  assert.deepEqual(snapshot(validationFailure), validationBefore);
});

test("successful promotion fast-forwards clean target and records reopened proof plus provenance", () => {
  const context = pair();
  const before = snapshot(context);
  const result = promoteBundle(options(context));
  assert.notEqual(result.head, before.head);
  assert.equal(git(context.target, ["rev-parse", "HEAD"]), result.head);
  assert.equal(git(context.target, ["status", "--porcelain=v1", "--untracked-files=all"]), "");
  assert.match(fs.readFileSync(path.join(context.target, "app.mjs"), "utf8"), /42/);
  assert.deepEqual(fs.readFileSync(path.join(context.target, "assets", "ui.bin")), fs.readFileSync(context.componentPath));
  assert.equal(fs.existsSync(path.join(context.target, "worker.mjs")), false);

  const state = readState(context.targetMission);
  assert.equal(state.requirements["R-UI"].status, "IN_PROGRESS");
  assert.deepEqual(state.requirements["R-UI"].evidenceRefs, []);
  assert.equal(state.requirements["R-WORK"].status, "PENDING");
  assert.equal(state.bundleImports["B-CANDIDATE"].evidence.some((item) => item.kind === "operator"), false);
  assert.equal(state.promotions[0].invalidatedProof["R-UI"].previousStatus, "PROVEN(local)");
  assert.equal(state.promotions[0].sliceProgressionVersion, 1);
  assert.equal(state.activeSliceId, "S1");
  assert.deepEqual(replayEvents(context.targetMission, { reducer: missionReducer }).state, state);
  assert.deepEqual(inspectContinuity(context.targetMission, { maxHandoffAgeHours: 24 }).issues, []);
});

test("detects a target HEAD change after preparation and does not add promotion state", () => {
  const context = pair();
  const originalEvents = fs.readFileSync(path.join(context.targetMission, "events.jsonl"), "utf8");
  const mutateTarget = [process.execPath, "-e", `const {execFileSync}=require('node:child_process');execFileSync('git',['commit','--allow-empty','-m','concurrent target change'],{cwd:${JSON.stringify(context.target)}})`];
  assert.throws(() => promoteBundle(options(context, { validationCommand: mutateTarget })), /target.*changed|stale/i);
  assert.equal(fs.readFileSync(path.join(context.targetMission, "events.jsonl"), "utf8"), originalEvents);
  assert.equal(readState(context.targetMission).promotions.length, 0);
  assert.match(git(context.target, ["log", "-1", "--format=%s"]), /concurrent target change/);
});
