import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { readBundle, trackedContentDigest } from "./bundle.mjs";
import { sha256 } from "./canonical.mjs";
import { missionReducer } from "./reducer.mjs";
import { validateNonInterferencePreservation } from "./proof-invalidation.mjs";
import { renderMission } from "./render.mjs";
import { appendEvent, readState } from "./store.mjs";

export class PromotionError extends Error {
  constructor(message, { plan, cause } = {}) {
    super(message);
    this.name = "PromotionError";
    this.exitCode = 3;
    this.plan = plan;
    this.cause = cause;
  }
}

function fail(message, options) {
  throw new PromotionError(message, options);
}

function git(cwd, args, { buffer = false } = {}) {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: buffer ? null : "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 128 * 1024 * 1024,
    }).toString().trim();
  } catch (error) {
    const detail = error.stderr?.toString().trim() || error.message;
    fail(`Git command failed: git ${args.join(" ")}: ${detail}`, { cause: error });
  }
}

function unique(values) {
  return [...new Set(values ?? [])].sort();
}

function relativeMission(repo, missionDir) {
  const value = path.relative(repo, missionDir).replaceAll(path.sep, "/");
  if (!value || value.startsWith("../") || path.isAbsolute(value)) fail("Target mission must be inside its recorded worktree");
  return value;
}

function isWithin(file, directory) {
  return file === directory || file.startsWith(`${directory}/`);
}

function normalizedPatchPath(value) {
  if (typeof value !== "string" || !value) fail("Bundle patch contains an empty path");
  if (/[\u0000-\u001f\u007f]/.test(value)) fail(`Bundle patch path contains control characters: ${JSON.stringify(value)}`);
  const portable = value.replaceAll("\\", "/");
  if (path.isAbsolute(value) || /^[A-Za-z]:\//.test(portable) || portable.startsWith("/")) fail(`Bundle patch contains an unsafe absolute path: ${value}`);
  const segments = portable.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) fail(`Bundle patch contains an unsafe path: ${value}`);
  if (segments.some((segment) => segment.toLowerCase() === ".git")) fail(`Bundle patch may not target Git internals: ${value}`);
  return segments.join("/");
}

function patchPaths(patch) {
  const result = spawnSync("git", ["apply", "--numstat", "-z", "-"], { input: patch, encoding: null, maxBuffer: 128 * 1024 * 1024 });
  if (result.status !== 0) fail(`Cannot inspect bundle patch paths: ${result.stderr?.toString().trim() || "invalid patch"}`);
  const paths = [];
  for (const token of result.stdout.toString().split("\0").filter(Boolean)) {
    const fields = token.split("\t");
    if (fields.length >= 3) paths.push(fields.slice(2).join("\t"));
    else if (fields.length === 1) paths.push(fields[0]);
  }
  return paths;
}

function pathHasSymlink(root, relative) {
  let current = root;
  for (const segment of relative.split("/")) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) continue;
    if (fs.lstatSync(current).isSymbolicLink()) return true;
  }
  return false;
}

function selectedItems(payload, selectedIds) {
  const selected = new Set(selectedIds);
  const conflicts = [];
  const commits = [];
  for (let index = 0; index < payload.commits.length; index += 1) {
    const commit = payload.commits[index];
    const intersecting = commit.requirementIds.filter((id) => selected.has(id));
    if (!intersecting.length) continue;
    const unselected = commit.requirementIds.filter((id) => !selected.has(id));
    if (unselected.length) conflicts.push({ code: "mixed_commit", message: `Commit ${commit.sha} also covers unselected requirements ${unselected.join(",")}` });
    else commits.push({ ...commit, patchIndex: index });
  }
  const components = [];
  for (let index = 0; index < payload.components.length; index += 1) {
    const component = payload.components[index];
    const intersecting = component.requirementIds.filter((id) => selected.has(id));
    if (!intersecting.length) continue;
    const unselected = component.requirementIds.filter((id) => !selected.has(id));
    if (unselected.length) conflicts.push({ code: "mixed_component", message: `Component ${component.targetPath} also covers unselected requirements ${unselected.join(",")}` });
    else components.push({ ...component, componentIndex: index });
  }
  return { commits, components, conflicts };
}

function componentConflict(repo, component, missionRelative) {
  if (isWithin(component.targetPath, missionRelative)) fail(`Component ${component.targetPath} targets the canonical target mission path`);
  if (pathHasSymlink(repo, component.targetPath)) return { code: "component_symlink", message: `Component path crosses a symbolic link: ${component.targetPath}` };
  const target = path.join(repo, ...component.targetPath.split("/"));
  if (!fs.existsSync(target)) return null;
  const stat = fs.lstatSync(target);
  if (!stat.isFile()) return { code: "component_conflict", message: `Component target is not a file: ${component.targetPath}` };
  const digest = `sha256:${sha256(fs.readFileSync(target))}`;
  return digest === component.digest ? null : { code: "component_conflict", message: `Component target already has different content: ${component.targetPath}` };
}

function policyFromOptions(options) {
  return { publicKey: options.publicKey, requireSignature: options.requireSignature === true };
}

function planFromVerified(options, verified, state, repo, missionRelative) {
  const payload = verified.payload;
  const availableIds = new Set(payload.selection.requirements.map((item) => item.id));
  const requested = unique(options.requirementIds);
  const excluded = unique(options.excludeIds);
  if (!requested.length) fail("Promotion needs at least one source requirement");
  for (const id of [...requested, ...excluded]) if (!availableIds.has(id)) fail(`Bundle does not contain source requirement ${id}`);
  const excludedSet = new Set(excluded);
  const sourceRequirementIds = requested.filter((id) => !excludedSet.has(id));
  if (!sourceRequirementIds.length) fail("Promotion selection is empty after exclusions");
  const mappings = {};
  const targetRequirementIds = [];
  for (const sourceId of sourceRequirementIds) {
    const targetId = options.mappings?.[sourceId] ?? sourceId;
    if (!state.requirements[targetId]) fail(`No target requirement ${targetId}; provide an explicit mapping`);
    if (targetRequirementIds.includes(targetId)) fail(`Requirement mappings must be one-to-one; ${targetId} is mapped more than once`);
    mappings[sourceId] = targetId;
    targetRequirementIds.push(targetId);
  }
  for (const sourceId of Object.keys(options.mappings ?? {})) if (!sourceRequirementIds.includes(sourceId)) fail(`Mapping references unselected source requirement ${sourceId}`);
  const selection = selectedItems(payload, sourceRequirementIds);
  const conflicts = [...selection.conflicts];
  if (!selection.commits.length && !selection.components.length) conflicts.push({ code: "empty_selection", message: "Selected requirements contain no independently promotable commits or components" });
  const alreadyImported = state.bundleImports?.[payload.id];
  if (alreadyImported) conflicts.push({ code: "bundle_already_imported", message: `Bundle ${payload.id} is already imported` });
  const promotedIds = new Set((state.promotions ?? []).map((item) => item.bundleId));
  for (const dependency of payload.selection.bundleDependencies) {
    if (!promotedIds.has(dependency)) conflicts.push({ code: "dependency_missing", message: `Required bundle ${dependency} has not been promoted` });
  }
  const status = git(repo, ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status) conflicts.push({ code: "dirty_target", message: "Target worktree must be clean before promotion" });
  const branch = git(repo, ["branch", "--show-current"]);
  if (branch !== state.metadata.branch) conflicts.push({ code: "branch_drift", message: `Target branch ${branch || "detached"} does not match mission branch ${state.metadata.branch}` });
  for (const item of selection.commits) {
    const patch = verified.patches[item.patchIndex];
    for (const rawPath of patchPaths(patch)) {
      const file = normalizedPatchPath(rawPath);
      if (isWithin(file, missionRelative)) fail(`Bundle patch ${item.sha} targets the canonical target mission path ${missionRelative}`);
      if (pathHasSymlink(repo, file)) fail(`Bundle patch ${item.sha} crosses a symbolic link: ${file}`);
    }
  }
  for (const component of selection.components) {
    const conflict = componentConflict(repo, component, missionRelative);
    if (conflict) conflicts.push(conflict);
  }
  const proofInvalidations = targetRequirementIds.map((id) => ({
    id,
    previousStatus: state.requirements[id].status,
    evidenceRefs: [...state.requirements[id].evidenceRefs],
    result: state.requirements[id].result,
  }));
  const preservationProofs = options.preservationProofs ?? [];
  if (!Array.isArray(preservationProofs) || preservationProofs.length > 32) fail("Promotion preservationProofs must be an array of at most 32 records");
  const verifiedPreservationProofs = preservationProofs.map((item) => validateNonInterferencePreservation(item, { bundleDigest: verified.digest }));
  return {
    valid: conflicts.length === 0,
    bundleId: payload.id,
    digest: verified.digest,
    signature: { status: verified.signatureStatus, keyFingerprint: verified.envelope.signature?.keyFingerprint ?? null },
    target: { repository: repo, branch, head: git(repo, ["rev-parse", "HEAD"]), missionRelative },
    sourceRequirementIds,
    targetRequirementIds,
    excludedSourceIds: excluded,
    mappings,
    dependencies: [...payload.selection.bundleDependencies],
    commits: selection.commits.map(({ patchIndex: _ignored, ...item }) => ({ sourceSha: item.sha, requirementIds: item.requirementIds, subject: item.subject })),
    components: selection.components.map(({ componentIndex: _ignored, content: _body, ...item }) => item),
    proofInvalidations,
    preservationProofs: verifiedPreservationProofs,
    conflicts,
  };
}

export function planPromotion(options) {
  const state = readState(options.missionDir);
  if (!state?.metadata) fail(`No Tugboat v2 target mission in ${options.missionDir}`);
  const repo = state.metadata.worktree;
  const missionRelative = relativeMission(repo, options.missionDir);
  const verified = readBundle(options.bundlePath, policyFromOptions(options));
  return planFromVerified(options, verified, state, repo, missionRelative);
}

function writeComponent(worktree, component) {
  if (pathHasSymlink(worktree, component.targetPath)) fail(`Component path crosses a symbolic link: ${component.targetPath}`);
  const target = path.join(worktree, ...component.targetPath.split("/"));
  const contents = Buffer.from(component.content, "base64");
  if (fs.existsSync(target)) {
    if (!fs.lstatSync(target).isFile()) fail(`Component target is not a file: ${component.targetPath}`);
    if (`sha256:${sha256(fs.readFileSync(target))}` !== component.digest) fail(`Component target conflicts after patch application: ${component.targetPath}`);
    return false;
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents, { mode: 0o600, flag: "wx" });
  return true;
}

function runValidation(command, cwd) {
  if (!Array.isArray(command) || !command.length) fail("Promotion requires a coordinator-supplied validation command");
  const result = spawnSync(command[0], command.slice(1), { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 128 * 1024 * 1024 });
  const exitCode = result.status ?? 1;
  if (exitCode !== 0) fail(`Promotion validation failed with exit code ${exitCode}`);
  return {
    command,
    exitCode,
    stdoutDigest: `sha256:${sha256(result.stdout ?? "")}`,
    stderrDigest: `sha256:${sha256(result.stderr ?? "")}`,
  };
}

function proofDisposition(verified, targetContentDigest) {
  const exactContent = verified.payload.source.contentDigest === targetContentDigest;
  const reusableEvidence = [];
  const expiredEvidence = [];
  for (const evidence of verified.payload.evidence) {
    const reusable = evidence.kind === "command" && exactContent && evidence.git?.clean === true && evidence.git?.sha === verified.payload.source.tipSha;
    const record = { sourceEvidenceId: evidence.id, kind: evidence.kind, reason: reusable ? "exact tracked content digest and source tip" : evidence.kind === "operator" || evidence.kind === "browser" ? "target context requires a new observation" : evidence.kind === "deployment" ? "target requires a new deployment" : "target content or source revision differs" };
    (reusable ? reusableEvidence : expiredEvidence).push(record);
  }
  return { reusableEvidence, expiredEvidence };
}

function importPayload(verified) {
  const payload = verified.payload;
  return {
    bundleId: payload.id,
    digest: verified.digest,
    source: payload.source,
    signature: { status: verified.signatureStatus, keyFingerprint: verified.envelope.signature?.keyFingerprint ?? null },
    requirementIds: payload.selection.requirements.map((item) => item.id),
    dependencies: payload.selection.bundleDependencies,
    commits: payload.commits.map(({ sha, requirementIds, subject }) => ({ sha, requirementIds, subject })),
    components: payload.components.map(({ type, targetPath, requirementIds, size, digest }) => ({ type, targetPath, requirementIds, size, digest })),
    evidence: payload.evidence,
  };
}

function selectedComponents(verified, plan) {
  const targets = new Set(plan.components.map((item) => item.targetPath));
  return verified.payload.components.filter((item) => targets.has(item.targetPath));
}

export function promoteBundle(options) {
  const plan = planPromotion(options);
  if (options.dryRun) return { dryRun: true, plan };
  if (!plan.valid) throw new PromotionError(`Bundle promotion is blocked:\n- ${plan.conflicts.map((item) => `${item.code}: ${item.message}`).join("\n- ")}`, { plan });
  if (!Array.isArray(options.validationCommand) || !options.validationCommand.length) fail("Promotion requires a coordinator-supplied validation command", { plan });
  const originalState = readState(options.missionDir);
  const verified = readBundle(options.bundlePath, policyFromOptions(options));
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-promote-"));
  const temporaryWorktree = path.join(temporaryRoot, "worktree");
  let worktreeAdded = false;
  try {
    git(plan.target.repository, ["worktree", "add", "--detach", temporaryWorktree, plan.target.head]);
    worktreeAdded = true;
    const selectedCommitIds = new Set(plan.commits.map((item) => item.sourceSha));
    const appliedCommits = [];
    for (let index = 0; index < verified.payload.commits.length; index += 1) {
      const sourceCommit = verified.payload.commits[index];
      if (!selectedCommitIds.has(sourceCommit.sha)) continue;
      const patchFile = path.join(temporaryRoot, `patch-${index}.patch`);
      fs.writeFileSync(patchFile, verified.patches[index], { mode: 0o600 });
      try {
        git(temporaryWorktree, ["am", "--3way", "--keep-cr", patchFile]);
      } catch (error) {
        throw new PromotionError(`Could not apply bundle patch ${sourceCommit.sha}: ${error.message}`, { plan, cause: error });
      }
      appliedCommits.push({ sourceSha: sourceCommit.sha, targetSha: git(temporaryWorktree, ["rev-parse", "HEAD"]) });
    }
    const changedPaths = git(temporaryWorktree, ["diff", "--name-only", "-z", plan.target.head, "HEAD"], { buffer: true }).split("\0").filter(Boolean);
    if (changedPaths.some((file) => isWithin(file, plan.target.missionRelative))) fail(`Applied patch changed the canonical target mission path ${plan.target.missionRelative}`, { plan });
    const components = selectedComponents(verified, plan);
    const written = components.filter((component) => writeComponent(temporaryWorktree, component));
    if (written.length) {
      git(temporaryWorktree, ["add", "--", ...written.map((item) => item.targetPath)]);
      git(temporaryWorktree, ["commit", "-m", `feat: add components from ${plan.bundleId}`]);
    }
    const validation = runValidation(options.validationCommand, temporaryWorktree);
    const dirtyAfterValidation = git(temporaryWorktree, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (dirtyAfterValidation) fail(`Promotion validation left uncommitted files: ${dirtyAfterValidation.replaceAll("\n", ", ")}`, { plan });
    const codeHead = git(temporaryWorktree, ["rev-parse", "HEAD"]);
    const targetContentDigest = trackedContentDigest(temporaryWorktree, codeHead, plan.target.missionRelative);
    const disposition = proofDisposition(verified, targetContentDigest);
    const temporaryMission = path.join(temporaryWorktree, ...plan.target.missionRelative.split("/"));
    const imported = appendEvent(temporaryMission, {
      type: "BUNDLE_IMPORTED", actor: options.actor, payload: importPayload(verified),
    }, { reducer: missionReducer, expectedRevision: originalState.revision, currentHead: codeHead });
    const promotedPayload = {
      bundleId: plan.bundleId,
      digest: plan.digest,
      sourceRequirementIds: plan.sourceRequirementIds,
      targetRequirementIds: plan.targetRequirementIds,
      excludedSourceIds: plan.excludedSourceIds,
      mappings: plan.mappings,
      appliedCommits,
      components: plan.components.map(({ content: _body, ...item }) => item),
      ...disposition,
      validation,
      targetContentDigest,
      preservationProofs: plan.preservationProofs,
      sliceProgressionVersion: 1,
    };
    const promoted = appendEvent(temporaryMission, {
      type: "BUNDLE_PROMOTED", actor: options.actor, payload: promotedPayload,
    }, { reducer: missionReducer, expectedRevision: imported.state.revision, currentHead: codeHead });
    renderMission(temporaryMission, promoted.state);
    git(temporaryWorktree, ["add", "--", plan.target.missionRelative]);
    git(temporaryWorktree, ["commit", "-m", `chore(tugboat): promote bundle ${plan.bundleId}`]);
    const preparedHead = git(temporaryWorktree, ["rev-parse", "HEAD"]);

    const actualHead = git(plan.target.repository, ["rev-parse", "HEAD"]);
    const actualBranch = git(plan.target.repository, ["branch", "--show-current"]);
    const actualStatus = git(plan.target.repository, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (actualHead !== plan.target.head || actualBranch !== plan.target.branch || actualStatus) {
      fail("Target changed after promotion preparation; prepared result was not applied", { plan });
    }
    git(plan.target.repository, ["merge", "--ff-only", preparedHead]);
    return {
      dryRun: false,
      bundleId: plan.bundleId,
      head: git(plan.target.repository, ["rev-parse", "HEAD"]),
      appliedCommits,
      components: plan.components.map((item) => item.targetPath),
      validation,
      reusableEvidence: disposition.reusableEvidence,
      expiredEvidence: disposition.expiredEvidence,
      preservationProofs: plan.preservationProofs,
    };
  } catch (error) {
    if (error instanceof PromotionError) throw error;
    throw new PromotionError(error.message, { plan, cause: error });
  } finally {
    if (worktreeAdded) {
      try {
        git(plan.target.repository, ["worktree", "remove", "--force", temporaryWorktree]);
      } catch {
        // The promotion result is already determined; stale temporary registration is recoverable with git worktree prune.
      }
    }
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
