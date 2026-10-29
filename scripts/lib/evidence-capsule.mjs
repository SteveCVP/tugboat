import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { canonicalJson } from "./canonical.mjs";
import { assertNoSecrets } from "./security.mjs";
import { assertArgv, canonicalDigest, describeFile, exactObject, operatorExecutionEnvironment, portableRelativePath, runBounded } from "./proof-runtime.mjs";

function git(repo, args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function assertClean(repo) {
  if (git(repo, ["status", "--porcelain=v1"])) throw new Error("Evidence capture and replay require a clean repository");
}

function inDetachedWorktree(repo, action) {
  const head = git(repo, ["rev-parse", "HEAD"]);
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-capsule-run-"));
  const worktree = path.join(parent, "worktree");
  let added = false;
  try {
    git(repo, ["worktree", "add", "--detach", worktree, head]);
    added = true;
    return action(worktree, head);
  } finally {
    if (added) {
      try { git(repo, ["worktree", "remove", "--force", worktree]); } catch { /* explicit directory cleanup follows */ }
    }
    fs.rmSync(parent, { recursive: true, force: true });
    try { git(repo, ["worktree", "prune"]); } catch { /* best effort */ }
  }
}

function bodyDigest(capsule) {
  const { digest: _digest, ...body } = capsule;
  return canonicalDigest(body);
}

function validateCapsule(capsule) {
  exactObject(capsule, "evidence capsule", ["schemaVersion", "capturedAt", "source", "runtime", "invocation", "inputs", "artifacts", "execution", "reproducibility", "digest"], ["schemaVersion", "capturedAt", "source", "runtime", "invocation", "inputs", "artifacts", "execution", "reproducibility", "digest"]);
  if (capsule.schemaVersion !== "tugboat.evidence-capsule.v1") throw new Error("Unsupported evidence capsule schemaVersion");
  assertNoSecrets(capsule, "Evidence capsule");
  if (capsule.digest !== bodyDigest(capsule)) throw new Error("Evidence capsule digest mismatch");
  if (!Number.isFinite(Date.parse(capsule.capturedAt)) || new Date(Date.parse(capsule.capturedAt)).toISOString() !== capsule.capturedAt) throw new Error("Evidence capsule capturedAt is invalid");
  exactObject(capsule.source, "capsule source", ["vcs", "head", "clean"], ["vcs", "head", "clean"]);
  if (capsule.source.vcs !== "git" || !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(capsule.source.head) || capsule.source.clean !== true) throw new Error("Evidence capsule source is invalid");
  exactObject(capsule.runtime, "capsule runtime", ["name", "version", "platform", "architecture"], ["name", "version", "platform", "architecture"]);
  exactObject(capsule.invocation, "capsule invocation", ["argv", "commandDigest", "timeoutMs", "maxOutputBytes", "launcherPolicyDigest"], ["argv", "commandDigest", "timeoutMs", "maxOutputBytes", "launcherPolicyDigest"]);
  assertArgv(capsule.invocation.argv);
  if (capsule.invocation.commandDigest !== canonicalDigest(capsule.invocation.argv)) throw new Error("Evidence capsule command digest mismatch");
  if (!/^sha256:[0-9a-f]{64}$/.test(capsule.invocation.launcherPolicyDigest)) throw new Error("Evidence capsule launcher policy digest is invalid");
  if (!Number.isInteger(capsule.invocation.timeoutMs) || capsule.invocation.timeoutMs < 1 || capsule.invocation.timeoutMs > 300_000) throw new Error("Evidence capsule timeout is invalid");
  if (!Number.isInteger(capsule.invocation.maxOutputBytes) || capsule.invocation.maxOutputBytes < 64 || capsule.invocation.maxOutputBytes > 16 * 1024 * 1024) throw new Error("Evidence capsule output bound is invalid");
  for (const [label, descriptors] of [["inputs", capsule.inputs], ["artifacts", capsule.artifacts]]) {
    if (!Array.isArray(descriptors) || descriptors.length > 256) throw new Error(`Evidence capsule ${label} are invalid`);
    const paths = new Set();
    for (const descriptor of descriptors) {
      exactObject(descriptor, `capsule ${label} descriptor`, ["path", "bytes", "digest"], ["path", "bytes", "digest"]);
      portableRelativePath(descriptor.path, `capsule ${label} path`);
      if (paths.has(descriptor.path)) throw new Error(`Evidence capsule has duplicate ${label} path ${descriptor.path}`);
      paths.add(descriptor.path);
      if (!Number.isInteger(descriptor.bytes) || descriptor.bytes < 0 || !/^sha256:[0-9a-f]{64}$/.test(descriptor.digest)) throw new Error(`Evidence capsule ${label} descriptor is invalid`);
    }
  }
  exactObject(capsule.execution, "capsule execution", ["exitCode", "signal", "timedOut", "stdoutDigest", "stderrDigest"], ["timedOut", "stdoutDigest", "stderrDigest"]);
  if (!Object.hasOwn(capsule.execution, "exitCode") || !Object.hasOwn(capsule.execution, "signal")) throw new Error("Evidence capsule execution is missing exitCode or signal");
  if (!(capsule.execution.exitCode === null || Number.isInteger(capsule.execution.exitCode)) || !(capsule.execution.signal === null || typeof capsule.execution.signal === "string") || typeof capsule.execution.timedOut !== "boolean") throw new Error("Evidence capsule execution status is invalid");
  if (!/^sha256:[0-9a-f]{64}$/.test(capsule.execution.stdoutDigest) || !/^sha256:[0-9a-f]{64}$/.test(capsule.execution.stderrDigest)) throw new Error("Evidence capsule execution digest is invalid");
  exactObject(capsule.reproducibility, "capsule reproducibility", ["level", "reason"], ["level", "reason"]);
  if (!["declared", "hermetic", "insufficient_evidence"].includes(capsule.reproducibility.level)) throw new Error("Evidence capsule reproducibility level is invalid");
  return capsule;
}

export function captureEvidenceCapsule({
  repoDir,
  inputPaths,
  command,
  artifactPaths = [],
  capturedAt = new Date().toISOString(),
  timeoutMs = 30_000,
  maxOutputBytes = 1024 * 1024,
}) {
  const repo = fs.realpathSync(repoDir);
  assertClean(repo);
  assertArgv(command);
  if (!Array.isArray(inputPaths) || inputPaths.length < 1 || inputPaths.length > 256) throw new Error("inputPaths must contain 1 to 256 paths");
  if (!Array.isArray(artifactPaths) || artifactPaths.length > 256) throw new Error("artifactPaths must contain at most 256 paths");
  inputPaths.forEach((value) => portableRelativePath(value, "Input path"));
  artifactPaths.forEach((value) => portableRelativePath(value, "Artifact path"));
  if (!Number.isFinite(Date.parse(capturedAt)) || new Date(Date.parse(capturedAt)).toISOString() !== capturedAt) throw new Error("capturedAt must be canonical ISO-8601 UTC");
  return inDetachedWorktree(repo, (worktree, head) => {
    const inputs = [...new Set(inputPaths)].sort().map((relative) => describeFile(worktree, relative));
    const operatorEnvironment = operatorExecutionEnvironment();
    const execution = runBounded(command[0], command.slice(1), { cwd: worktree, environment: operatorEnvironment, timeoutMs, maxOutputBytes });
    const artifacts = [...new Set(artifactPaths)].sort().map((relative) => describeFile(worktree, relative));
    const body = {
      schemaVersion: "tugboat.evidence-capsule.v1",
      capturedAt,
      source: { vcs: "git", head, clean: true },
      runtime: { name: "node", version: process.version, platform: process.platform, architecture: process.arch },
      invocation: { argv: [...command], commandDigest: canonicalDigest(command), timeoutMs, maxOutputBytes, launcherPolicyDigest: canonicalDigest(operatorEnvironment) },
      inputs,
      artifacts,
      execution: {
        exitCode: execution.exitCode,
        signal: execution.signal,
        timedOut: execution.timedOut,
        stdoutDigest: execution.stdoutDigest,
        stderrDigest: execution.stderrDigest,
      },
      reproducibility: { level: "declared", reason: "Git inputs and runtime are content-addressed; host kernel and executable image are not hermetically pinned." },
    };
    assertNoSecrets(body, "Evidence capsule");
    return { ...body, digest: canonicalDigest(body) };
  });
}

export function verifyEvidenceCapsule(capsule, { repoDir } = {}) {
  validateCapsule(capsule);
  const findings = [];
  if (repoDir) {
    const repo = fs.realpathSync(repoDir);
    let currentHead;
    try { currentHead = git(repo, ["rev-parse", "HEAD"]); } catch { currentHead = null; }
    if (currentHead !== capsule.source.head) findings.push({ code: "head_changed", expected: capsule.source.head, actual: currentHead });
    for (const expected of capsule.inputs) {
      try {
        const actual = describeFile(repo, expected.path);
        if (actual.digest !== expected.digest || actual.bytes !== expected.bytes) findings.push({ code: "input_changed", path: expected.path, expected: expected.digest, actual: actual.digest });
      } catch (error) {
        findings.push({ code: "input_unavailable", path: expected.path, reason: error.message });
      }
    }
  }
  return {
    schemaVersion: "tugboat.evidence-capsule-verification.v1",
    status: findings.length ? "blocked" : "ready",
    capsuleDigest: capsule.digest,
    findings,
    digest: canonicalDigest({ capsuleDigest: capsule.digest, findings }),
  };
}

export function replayEvidenceCapsule(capsule, { repoDir, command, timeoutMs, maxOutputBytes } = {}) {
  validateCapsule(capsule);
  assertArgv(command);
  const repo = fs.realpathSync(repoDir);
  assertClean(repo);
  return inDetachedWorktree(repo, (worktree, head) => {
    const unavailable = [];
    for (const expected of capsule.inputs) {
      try {
        const actual = describeFile(worktree, expected.path);
        if (actual.digest !== expected.digest) unavailable.push(expected.path);
      } catch { unavailable.push(expected.path); }
    }
    if (head !== capsule.source.head || unavailable.length) {
      const body = { comparison: "insufficient_evidence", capsuleDigest: capsule.digest, headMatches: head === capsule.source.head, unavailableInputs: unavailable.sort() };
      return { schemaVersion: "tugboat.evidence-replay.v1", status: "insufficient_evidence", ...body, digest: canonicalDigest(body) };
    }
    const operatorEnvironment = operatorExecutionEnvironment();
    const execution = runBounded(command[0], command.slice(1), {
      cwd: worktree,
      environment: operatorEnvironment,
      timeoutMs: timeoutMs ?? capsule.invocation.timeoutMs,
      maxOutputBytes: maxOutputBytes ?? capsule.invocation.maxOutputBytes,
    });
    const actual = { exitCode: execution.exitCode, signal: execution.signal, timedOut: execution.timedOut, stdoutDigest: execution.stdoutDigest, stderrDigest: execution.stderrDigest };
    const launcherMatches = canonicalDigest(operatorEnvironment) === capsule.invocation.launcherPolicyDigest;
    const comparison = launcherMatches && canonicalJson(actual) === canonicalJson(capsule.execution) ? "exact" : "different";
    const body = { comparison, capsuleDigest: capsule.digest, commandDigest: canonicalDigest(command), launcherMatches, expected: capsule.execution, actual };
    return { schemaVersion: "tugboat.evidence-replay.v1", status: comparison === "exact" ? "ready" : "blocked", ...body, digest: canonicalDigest(body) };
  });
}
