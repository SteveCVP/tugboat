import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { verifyBoundaryManifest } from "./boundary-manifest.mjs";
import { canonicalJson, sha256 } from "./canonical.mjs";
import { createCertifiedEnvelope, createCounterexample, verifyCertifiedEnvelope } from "./certified-changeset.mjs";
import { normalizeObservedAt } from "./intelligence-core.mjs";
import { operatorExecutionEnvironment, portableRelativePath } from "./proof-runtime.mjs";

const FORMAT = "tugboat.rollback-equivalence.v1";
const MAX_COMMITS = 64;
const MAX_OBSERVABLE_PATHS = 256;
const MAX_EFFECTS = 256;
const MAX_MISMATCHES = 256;
const GIT_TIMEOUT_MS = 120_000;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const GIT_OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const RUNTIME_REVERSIBILITY = new Set(["irreversible", "unknown"]);
const EQUIVALENCE = new Set(["equivalent", "not_equivalent", "insufficient_evidence"]);
const HERMETIC_GIT_CONFIG = [
  "-c", "core.hooksPath=/dev/null",
  "-c", "core.autocrlf=false",
  "-c", "core.eol=lf",
  "-c", "core.safecrlf=false",
  "-c", "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab",
  "-c", `core.attributesFile=${process.platform === "win32" ? "NUL" : "/dev/null"}`,
  "-c", "core.fileMode=true",
  "-c", "core.ignoreCase=false",
  "-c", "core.symlinks=true",
  "-c", "core.sparseCheckout=false",
  "-c", "core.sparseCheckoutCone=false",
  "-c", "apply.whitespace=error-all",
  "-c", "apply.ignoreWhitespace=false",
  "-c", "am.keepcr=true",
  "-c", "mailinfo.scissors=false",
  "-c", "merge.renormalize=false",
  "-c", "merge.autoStash=false",
  "-c", "rerere.enabled=false",
  "-c", "rerere.autoupdate=false",
  "-c", "commit.gpgSign=false",
  "-c", "user.name=Tugboat Rollback",
  "-c", "user.email=tugboat-rollback@example.invalid",
];

export class RollbackEquivalenceError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "RollbackEquivalenceError";
    this.exitCode = 3;
    this.details = details;
  }
}

function fail(message, details) {
  throw new RollbackEquivalenceError(message, details);
}

function gitEnvironment() {
  return {
    ...operatorExecutionEnvironment(),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_AUTHOR_NAME: "Tugboat Rollback",
    GIT_AUTHOR_EMAIL: "tugboat-rollback@example.invalid",
    GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
    GIT_COMMITTER_NAME: "Tugboat Rollback",
    GIT_COMMITTER_EMAIL: "tugboat-rollback@example.invalid",
    GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
  };
}

function git(cwd, args, { optional = false } = {}) {
  try {
    return execFileSync("git", [...HERMETIC_GIT_CONFIG, ...args], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 128 * 1024 * 1024,
      timeout: GIT_TIMEOUT_MS,
      env: gitEnvironment(),
    }).trim();
  } catch (error) {
    if (optional && error.status === 1) return null;
    const detail = error.stderr?.toString().trim() || error.message;
    fail(`Git command failed: git ${args.join(" ")}: ${detail}`, { cause: error });
  }
}

function gitRaw(cwd, args) {
  try {
    return execFileSync("git", [...HERMETIC_GIT_CONFIG, ...args], {
      cwd,
      encoding: null,
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 128 * 1024 * 1024,
      timeout: GIT_TIMEOUT_MS,
      env: gitEnvironment(),
    });
  } catch (error) {
    const detail = error.stderr?.toString().trim() || error.message;
    fail(`Git command failed: git ${args.join(" ")}: ${detail}`, { cause: error });
  }
}

function exactObject(value, label, allowed, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`Unknown ${label} field ${key}`);
  for (const key of required) if (value[key] === undefined) fail(`${label} is missing ${key}`);
  return value;
}

function text(value, label) {
  if (typeof value !== "string" || !value || Buffer.byteLength(value) > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) fail(`${label} must be bounded non-empty text`);
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail(`${label} must be a sha256 digest`);
  return value;
}

function oid(value, label) {
  if (typeof value !== "string" || !GIT_OID.test(value)) fail(`${label} must be a full Git object ID`);
  return value;
}

function contentDigest(value) {
  const body = structuredClone(value);
  delete body.digest;
  return `sha256:${sha256(canonicalJson(body))}`;
}

function portablePattern(value, label) {
  text(value, label);
  if (path.isAbsolute(value) || /^[A-Za-z]:[\\/]/u.test(value) || value.includes("\\")) fail(`${label} must be a portable relative path or glob`);
  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === ".." || segment.toLowerCase() === ".git")) fail(`${label} is unsafe`);
  if (/[^A-Za-z0-9._/@+*?-]/u.test(value)) fail(`${label} contains unsupported glob syntax`);
  return value;
}

function globRegex(pattern) {
  let output = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (char === "*" && pattern[index + 1] === "*") {
      index += 1;
      if (pattern[index + 1] === "/") {
        index += 1;
        output += "(?:.*/)?";
      } else output += ".*";
    } else if (char === "*") output += "[^/]*";
    else if (char === "?") output += "[^/]";
    else output += char.replace(/[|\\{}()[\]^$+?.-]/gu, "\\$&");
  }
  return new RegExp(`${output}$`, "u");
}

function validateBoundary(value) {
  let verification;
  try { verification = verifyBoundaryManifest(value); } catch (error) { fail(`Rollback boundary manifest is invalid: ${error.message}`); }
  const observablePaths = [...new Set(verification.components.flatMap((component) => component.paths))]
    .map((item, index) => portablePattern(item, `Rollback observable path ${index}`))
    .sort();
  if (!observablePaths.length || observablePaths.length > MAX_OBSERVABLE_PATHS) fail(`Rollback boundary manifest must declare 1 to ${MAX_OBSERVABLE_PATHS} observable component paths`);
  return { envelope: structuredClone(value), verification, observablePaths };
}

function validateRuntimeEffects(value = []) {
  if (!Array.isArray(value) || value.length > MAX_EFFECTS) fail(`Rollback runtimeEffects must contain at most ${MAX_EFFECTS} effects`);
  const effects = value.map((effect, index) => {
    exactObject(effect, `rollback runtime effect ${index}`, ["kind", "subject", "reversibility"]);
    if (!new Set(["schema", "data", "infrastructure", "external"]).has(effect.kind)) fail(`Rollback runtime effect ${index} kind is unsupported`);
    text(effect.subject, `Rollback runtime effect ${index} subject`);
    if (!RUNTIME_REVERSIBILITY.has(effect.reversibility)) fail(`Rollback runtime effect ${index} may only be irreversible or unknown without runtime recovery evidence`);
    return { kind: effect.kind, subject: effect.subject, reversibility: effect.reversibility };
  }).sort((left, right) => `${left.kind}:${left.subject}`.localeCompare(`${right.kind}:${right.subject}`));
  if (new Set(effects.map((item) => `${item.kind}:${item.subject}`)).size !== effects.length) fail("Rollback runtimeEffects must not contain duplicates");
  return effects;
}

function validatePolicy(value) {
  exactObject(value, "rollback policy", ["id", "requiredStatus", "digest"]);
  if (!/^policy:[A-Za-z0-9][A-Za-z0-9._/@+-]*$/u.test(value.id)) fail("Rollback policy ID must be portable");
  if (value.requiredStatus !== "equivalent") fail("Rollback policy requiredStatus must be equivalent");
  const normalized = { id: value.id, requiredStatus: value.requiredStatus };
  if (value.digest !== contentDigest(normalized)) fail("Rollback policy digest mismatch");
  return { ...normalized, digest: value.digest };
}

function validateRollback(value) {
  exactObject(value, "rollback operation", ["mode", "commits"]);
  if (!new Set(["exact_inverse", "declared"]).has(value.mode)) fail("Rollback mode must be exact_inverse or declared");
  if (!Array.isArray(value.commits) || value.commits.length > MAX_COMMITS) fail(`Rollback commits must contain at most ${MAX_COMMITS} commits`);
  const commits = value.commits.map((item, index) => oid(item, `Rollback commit ${index}`));
  if (new Set(commits).size !== commits.length) fail("Rollback commits must not contain duplicates");
  if (value.mode === "exact_inverse" && commits.length) fail("Exact-inverse rollback may not provide declared commits");
  return { mode: value.mode, commits };
}

function assertHermeticRepository(repository) {
  const unsafePattern = "^(apply\\.|am\\.|checkout\\.|commit\\.(cleanup|gpgsign|status|verbose)$|core\\.(attributesfile|autocrlf|eol|safecrlf|whitespace|fsmonitor|sparsecheckout|sparsecheckoutcone)$|diff\\..*\\.(command|textconv|cachetextconv)$|filter\\..*\\.(clean|smudge|process|required)$|i18n\\.(commitencoding|logoutputencoding)$|mailinfo\\.scissors$|merge\\.|rebase\\.|rerere\\.)";
  const worktreeConfigEnabled = git(repository, ["config", "--local", "--get", "extensions.worktreeConfig"], { optional: true }) === "true";
  const unsafe = [
    git(repository, ["config", "--local", "--get-regexp", unsafePattern], { optional: true }),
    worktreeConfigEnabled ? git(repository, ["config", "--worktree", "--get-regexp", unsafePattern], { optional: true }) : null,
  ].filter(Boolean).join("\n");
  if (unsafe) fail(`Target repository has ambient Git configuration that rollback proof will not run: ${unsafe.split("\n").map((line) => line.split(/\s/u)[0]).join(", ")}`);
  const replaceRefs = git(repository, ["for-each-ref", "--format=%(refname)", "refs/replace/"]);
  if (replaceRefs) fail(`Target repository has Git replace refs that rollback proof will not interpret: ${replaceRefs.replaceAll("\n", ", ")}`);
  const grafts = path.resolve(repository, git(repository, ["rev-parse", "--git-path", "info/grafts"]));
  if (fs.existsSync(grafts)) {
    const stat = fs.lstatSync(grafts);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 0) fail("Target repository has ambient .git/info/grafts; rollback proof requires native commit ancestry");
  }
  const attributes = path.resolve(repository, git(repository, ["rev-parse", "--git-path", "info/attributes"]));
  if (fs.existsSync(attributes)) {
    const stat = fs.lstatSync(attributes);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 0) fail("Target repository has ambient .git/info/attributes; rollback proof accepts only tracked attributes");
  }
}

function resolveCommit(repository, value, label) {
  const resolved = git(repository, ["rev-parse", "--verify", `${value}^{commit}`]);
  return oid(resolved, label);
}

function parents(repository, commit) {
  return git(repository, ["show", "-s", "--format=%P", commit]).split(/\s+/u).filter(Boolean);
}

function validateLinearCommits(repository, baseHead, commits, label) {
  let expectedParent = baseHead;
  for (const [index, commit] of commits.entries()) {
    const commitParents = parents(repository, commit);
    if (commitParents.length !== 1 || commitParents[0] !== expectedParent) fail(`${label} commit ${index} is not a linear child of ${expectedParent}`);
    expectedParent = commit;
  }
}

function repositoryIdentity(repository) {
  const remote = git(repository, ["config", "--get", "remote.origin.url"], { optional: true });
  const roots = git(repository, ["rev-list", "--max-parents=0", "--all"]).split("\n").filter(Boolean).sort().join(":");
  return `sha256:${sha256(remote || roots)}`;
}

function targetSnapshot(repository) {
  return {
    head: git(repository, ["rev-parse", "HEAD"]),
    branch: git(repository, ["branch", "--show-current"]),
    status: git(repository, ["status", "--porcelain=v1", "--untracked-files=all"]),
  };
}

function assertTargetUnchanged(repository, initial) {
  const final = targetSnapshot(repository);
  if (final.head !== initial.head || final.branch !== initial.branch || final.status !== initial.status) fail("Target changed during rollback proof; no certificate was emitted", {
    counterexample: { code: "target_drift", expected: initial, actual: final, witnessPath: ["target:initial", "rollback:disposable", "target:final"] },
  });
  return final;
}

function treeEntries(repository, ref, patterns) {
  const matchers = patterns.map(globRegex);
  const output = git(repository, ["ls-tree", "-r", "-z", "--full-tree", ref]);
  return output.split("\0").filter(Boolean).map((line) => {
    const tab = line.indexOf("\t");
    const [mode, type, object] = line.slice(0, tab).split(" ");
    const file = line.slice(tab + 1);
    return { path: file, mode, type, object };
  }).filter((entry) => matchers.some((matcher) => matcher.test(entry.path))).sort((left, right) => left.path.localeCompare(right.path));
}

function observation(repository, ref, patterns) {
  const entries = treeEntries(repository, ref, patterns);
  const body = { entries };
  return { ...body, digest: `sha256:${sha256(canonicalJson(body))}` };
}

function deriveMismatches(base, rolledBack) {
  const expected = new Map(base.entries.map((entry) => [entry.path, entry]));
  const actual = new Map(rolledBack.entries.map((entry) => [entry.path, entry]));
  return [...new Set([...expected.keys(), ...actual.keys()])].sort().flatMap((file) => {
    const left = expected.get(file) ?? null;
    const right = actual.get(file) ?? null;
    return canonicalJson(left) === canonicalJson(right) ? [] : [{ path: file, expected: left, actual: right }];
  }).slice(0, MAX_MISMATCHES);
}

function decodeGitPath(buffer, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    fail(`${label} is not valid UTF-8 and cannot be represented safely in a portable certificate`);
  }
}

function changedPathsForPair(repository, parent, commit) {
  const fields = gitRaw(repository, ["--literal-pathspecs", "diff", "--name-only", "-z", parent, commit, "--"]);
  const paths = [];
  let start = 0;
  for (let index = 0; index < fields.length; index += 1) {
    if (fields[index] !== 0) continue;
    const file = decodeGitPath(fields.subarray(start, index), "Changed path");
    start = index + 1;
    if (!file) continue;
    portableRelativePath(file, "Changed path");
    paths.push(file);
  }
  if (start !== fields.length) fail("Git returned an unterminated changed path");
  return paths;
}

function changedPaths(repository, baseHead, forwardCommits) {
  const paths = new Set();
  let parent = baseHead;
  for (const commit of forwardCommits) {
    for (const file of changedPathsForPair(repository, parent, commit)) paths.add(file);
    parent = commit;
  }
  return [...paths].sort();
}

function scopeContains(scope, candidate) {
  if (scope.endsWith("/**")) {
    const base = scope.slice(0, -3);
    return candidate === base || candidate.startsWith(`${base}/`);
  }
  return candidate === scope;
}

function treeEntry(repository, ref, file) {
  const raw = gitRaw(repository, ["--literal-pathspecs", "ls-tree", "-z", ref, "--", file]);
  if (!raw.length) return null;
  const records = raw.subarray(0, raw.length - (raw.at(-1) === 0 ? 1 : 0)).toString("binary").split("\0");
  if (records.length !== 1) fail(`Boundary descriptor path is ambiguous at ${ref}: ${file}`);
  const record = Buffer.from(records[0], "binary");
  const tab = record.indexOf(9);
  if (tab < 0) fail(`Cannot parse Git tree entry for ${file}`);
  const header = record.subarray(0, tab).toString("ascii").split(" ");
  const entryPath = decodeGitPath(record.subarray(tab + 1), "Git tree path");
  if (entryPath !== file || header.length !== 3) fail(`Unexpected Git tree entry for ${file}`);
  const [mode, type, object] = header;
  oid(object, `Git tree object for ${file}`);
  return { path: entryPath, mode, type, object };
}

function verifyBoundaryAtBase(repository, baseHead, boundary) {
  const descriptors = [
    ...boundary.envelope.manifest.sources,
    ...boundary.envelope.manifest.components.flatMap((component) => component.interfaces),
  ].sort((left, right) => left.id.localeCompare(right.id));
  for (const descriptor of descriptors) {
    const entry = treeEntry(repository, baseHead, descriptor.path);
    if (!entry || entry.type !== "blob" || entry.mode === "120000") fail(`Boundary descriptor ${descriptor.id} is not a regular tracked blob at base ${baseHead}: ${descriptor.path}`);
    const actual = `sha256:${sha256(gitRaw(repository, ["cat-file", "blob", entry.object]))}`;
    if (actual !== descriptor.digest) fail(`Boundary descriptor ${descriptor.id} is stale at base ${baseHead}: expected ${descriptor.digest}, received ${actual}`);
  }
}

const INTERFACE_RUNTIME_KINDS = new Map([
  ["sql", ["schema", "data"]],
  ["database", ["schema", "data"]],
  ["migration", ["schema", "data"]],
  ["ddl", ["schema", "data"]],
  ["prisma", ["schema", "data"]],
  ["data_migration", ["data"]],
  ["terraform", ["infrastructure"]],
  ["cloudformation", ["infrastructure"]],
  ["cloudformation-cdk", ["infrastructure"]],
  ["cloudformation_cdk", ["infrastructure"]],
  ["aws_cdk", ["infrastructure"]],
  ["cdk", ["infrastructure"]],
  ["kubernetes", ["infrastructure"]],
  ["helm", ["infrastructure"]],
  ["pulumi", ["infrastructure"]],
  ["bicep", ["infrastructure"]],
  ["oci", ["infrastructure"]],
  ["openapi", ["external"]],
  ["graphql", ["external"]],
  ["github-actions", ["external"]],
  ["github_actions", ["external"]],
  ["workflow", ["external"]],
  ["webhook", ["external"]],
]);

function pathRuntimeKinds(file) {
  const kinds = new Set();
  if (file.endsWith(".sql") || /(^|\/)migrations?\//u.test(file)) {
    kinds.add("schema");
    kinds.add("data");
  }
  if (file.endsWith(".tf") || file.endsWith(".tfvars") || /(^|\/)(?:infra|infrastructure|k8s|kubernetes|helm)\//u.test(file)) kinds.add("infrastructure");
  if (/^\.github\/workflows\//u.test(file)) kinds.add("external");
  return [...kinds].sort();
}

function effectId(effect) {
  return `effect:${sha256(canonicalJson(effect)).slice(0, 32)}`;
}

function deriveEffects(repository, baseHead, forwardCommits, boundary, rollback, runtimeEffects) {
  verifyBoundaryAtBase(repository, baseHead, boundary);
  const files = changedPaths(repository, baseHead, forwardCommits);
  if (!files.length) fail("Rollback proof forward range has no changed files");
  const ownership = boundary.verification.ownership;
  for (const file of files) if (!ownership.some((item) => scopeContains(item.path, file))) fail(`Changed path is not owned by the verified boundary manifest: ${file}`);

  const rollbackOperationId = `operation:rollback-${sha256(canonicalJson(rollback)).slice(0, 32)}`;
  const effects = files.map((file) => {
    const core = { kind: "file", subject: file, reversibility: rollback.mode === "exact_inverse" ? "exact" : "declared", rollbackOperationId };
    return { id: effectId(core), ...core };
  });

  const obligations = new Map();
  for (const file of files) for (const kind of pathRuntimeKinds(file)) obligations.set(`${kind}:path:${file}`, { kind, subject: `path:${file}` });
  const affectedComponentIds = new Set(ownership.filter((item) => files.some((file) => scopeContains(item.path, file))).map((item) => item.componentId));
  for (const component of boundary.envelope.manifest.components) {
    if (!affectedComponentIds.has(component.id)) continue;
    for (const contract of component.interfaces) {
      for (const kind of INTERFACE_RUNTIME_KINDS.get(contract.kind) ?? []) obligations.set(`${kind}:${contract.id}`, { kind, subject: contract.id });
    }
  }
  const declarations = new Map(runtimeEffects.map((item) => [`${item.kind}:${item.subject}`, item]));
  for (const key of declarations.keys()) if (!obligations.has(key)) fail(`Runtime effect declaration does not match a derived changed-interface obligation: ${key}`);
  for (const [key, obligation] of [...obligations.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const declaration = declarations.get(key);
    const core = { ...obligation, reversibility: declaration?.reversibility ?? "unknown" };
    effects.push({ id: effectId(core), ...core });
  }
  if (effects.length > MAX_EFFECTS) fail(`Derived rollback effects exceed ${MAX_EFFECTS}`);
  return effects.sort((left, right) => `${left.kind}:${left.subject}`.localeCompare(`${right.kind}:${right.subject}`));
}

function assessEffects(effects, rollback, mismatches) {
  const mismatched = new Set(mismatches.map((item) => item.path));
  return effects.map((effect) => {
    let status;
    let reason;
    if (effect.kind !== "file") {
      status = effect.reversibility === "irreversible" ? "not_equivalent" : "insufficient_evidence";
      reason = effect.reversibility === "irreversible"
        ? `${effect.kind} effect is declared irreversible`
        : `${effect.kind} runtime recovery is unknown; repository bytes cannot prove runtime reversal`;
    } else if (effect.reversibility === "declared" && !rollback.commits.length) {
      status = "insufficient_evidence";
      reason = "declared rollback operation was not supplied";
    } else if (mismatched.has(effect.subject)) {
      status = "not_equivalent";
      reason = "rolled-back file differs from the exact base";
    } else {
      status = "equivalent";
      reason = "rolled-back file tree entry matches the exact base";
    }
    return { ...effect, status, reason };
  });
}

function deriveEquivalence({ rollback, execution, mismatches, effectAssessments }) {
  if (!execution.forwardApplied || !execution.rollbackApplied || (rollback.mode === "declared" && !rollback.commits.length)) return "insufficient_evidence";
  if (mismatches.length || effectAssessments.some((effect) => effect.status === "not_equivalent")) return "not_equivalent";
  if (effectAssessments.some((effect) => effect.status === "insufficient_evidence")) return "insufficient_evidence";
  return "equivalent";
}

function counterexamples({ rollback, execution, mismatches, effectAssessments }) {
  const result = [];
  if (rollback.mode === "declared" && !rollback.commits.length) result.push({
    code: "rollback_operation_missing", invariantId: "invariant:rollback-equivalence", message: "Declared rollback operation is missing.", expected: "at least one declared rollback commit", actual: "no rollback commits", subjectIds: ["rollback:declared"], witnessPath: ["change:forward", "rollback:declared"], evidence: [],
  });
  if (execution.error) result.push({
    code: "rollback_execution_failed", invariantId: "invariant:rollback-equivalence", message: "Rollback operation could not be executed completely.", expected: "forward and rollback operations apply cleanly", actual: execution.error, subjectIds: ["rollback:execution"], witnessPath: ["change:forward", "rollback:execution"], evidence: [],
  });
  if (mismatches.length) result.push({
    code: "rollback_state_mismatch", invariantId: "invariant:rollback-equivalence", message: "Rolled-back boundary-observable state differs from the exact base.", expected: "all declared observable paths match the base", actual: mismatches[0].path, subjectIds: [`path:${mismatches[0].path}`], witnessPath: ["state:base", "change:forward", "rollback:execution", "state:rolled-back"], evidence: [],
  });
  for (const effect of effectAssessments.filter((item) => item.reversibility === "irreversible" || item.reversibility === "unknown" || item.kind !== "file" || (item.reversibility === "declared" && !rollback.commits.length))) result.push({
    code: effect.status === "not_equivalent" ? "irreversible_effect" : "rollback_effect_unknown",
    invariantId: "invariant:rollback-equivalence",
    message: effect.reason,
    expected: "effect has an executed, observable inverse",
    actual: `${effect.kind} ${effect.reversibility}`,
    subjectIds: [effect.id],
    witnessPath: [effect.id, "rollback:assessment"],
    evidence: [],
  });
  return result;
}

function normalizeObservation(value, label) {
  exactObject(value, label, ["entries", "digest"]);
  if (!Array.isArray(value.entries) || value.entries.length > 10_000) fail(`${label} entries are invalid`);
  const entries = value.entries.map((entry, index) => {
    exactObject(entry, `${label} entry ${index}`, ["path", "mode", "type", "object"]);
    portableRelativePath(entry.path, `${label} entry path`);
    text(entry.mode, `${label} entry mode`);
    if (entry.type !== "blob") fail(`${label} entry type must be blob`);
    oid(entry.object, `${label} entry object`);
    return { path: entry.path, mode: entry.mode, type: entry.type, object: entry.object };
  });
  if (canonicalJson(entries) !== canonicalJson([...entries].sort((left, right) => left.path.localeCompare(right.path))) || new Set(entries.map((entry) => entry.path)).size !== entries.length) fail(`${label} entries must be unique and sorted`);
  const expected = `sha256:${sha256(canonicalJson({ entries }))}`;
  if (value.digest !== expected) fail(`${label} digest mismatch`);
  return { entries, digest: value.digest };
}

function verifyBody(body, repository) {
  exactObject(body, "rollback certificate body", ["schemaVersion", "repositoryIdentity", "baseHead", "forwardCommits", "rollback", "boundary", "policy", "runtimeEffects", "observations", "mismatches", "effectAssessments", "equivalence", "execution", "targetObservation", "changeDigest"]);
  if (body.schemaVersion !== "tugboat.rollback-proof.v1") fail("Unsupported rollback proof body schema");
  digest(body.repositoryIdentity, "Rollback repositoryIdentity");
  oid(body.baseHead, "Rollback baseHead");
  if (!Array.isArray(body.forwardCommits) || !body.forwardCommits.length || body.forwardCommits.length > MAX_COMMITS) fail("Rollback forwardCommits are invalid");
  body.forwardCommits.forEach((item, index) => oid(item, `Rollback forward commit ${index}`));
  if (new Set(body.forwardCommits).size !== body.forwardCommits.length) fail("Rollback forwardCommits must not contain duplicates");
  const rollback = validateRollback(body.rollback);
  const boundary = validateBoundary(body.boundary);
  const policy = validatePolicy(body.policy);
  const runtimeEffects = validateRuntimeEffects(body.runtimeEffects);
  exactObject(body.observations, "rollback observations", ["base", "rolledBack"]);
  const base = normalizeObservation(body.observations.base, "base observation");
  const rolledBack = normalizeObservation(body.observations.rolledBack, "rolled-back observation");
  const mismatches = deriveMismatches(base, rolledBack);
  if (canonicalJson(body.mismatches) !== canonicalJson(mismatches)) fail("Rollback certificate mismatches do not match the bound observations");
  exactObject(body.execution, "rollback execution", ["disposableWorktree", "forwardApplied", "rollbackApplied", "error"]);
  if (body.execution.disposableWorktree !== true || typeof body.execution.forwardApplied !== "boolean" || typeof body.execution.rollbackApplied !== "boolean" || (body.execution.error !== null && typeof body.execution.error !== "string")) fail("Rollback execution record is invalid");
  if (body.execution.error !== null) text(body.execution.error, "Rollback execution error");
  exactObject(body.targetObservation, "rollback targetObservation", ["initialHead", "prePublicationHead", "branch", "clean"]);
  oid(body.targetObservation.initialHead, "Rollback targetObservation initialHead");
  oid(body.targetObservation.prePublicationHead, "Rollback targetObservation prePublicationHead");
  text(body.targetObservation.branch, "Rollback targetObservation branch");
  if (body.targetObservation.initialHead !== body.targetObservation.prePublicationHead || body.targetObservation.clean !== true) fail("Rollback certificate target snapshot checks are invalid");
  const changeBody = { baseHead: body.baseHead, forwardCommits: body.forwardCommits, rollback, boundaryDigest: boundary.verification.digest, policyDigest: policy.digest, runtimeEffects };
  const expectedChangeDigest = `sha256:${sha256(canonicalJson(changeBody))}`;
  if (body.changeDigest !== expectedChangeDigest) fail("Rollback certificate changeDigest mismatch");

  if (!repository) fail("Rollback certificate verification requires the exact local repository; integrity-only verification is not admission evidence");
  const root = fs.realpathSync(path.resolve(repository));
  assertHermeticRepository(root);
  if (repositoryIdentity(root) !== body.repositoryIdentity) fail("Rollback certificate repository identity does not match the supplied repository");
  resolveCommit(root, body.targetObservation.initialHead, "Rollback certificate observed target head");
  const baseHead = resolveCommit(root, body.baseHead, "Rollback certificate baseHead");
  if (baseHead !== body.baseHead) fail("Rollback certificate baseHead is not canonical");
  const forwardCommits = body.forwardCommits.map((item, index) => resolveCommit(root, item, `Rollback certificate forward commit ${index}`));
  if (canonicalJson(forwardCommits) !== canonicalJson(body.forwardCommits)) fail("Rollback certificate forward commits are not canonical");
  validateLinearCommits(root, baseHead, forwardCommits, "Certificate forward");
  if (rollback.mode === "declared" && rollback.commits.length) {
    const resolved = rollback.commits.map((item, index) => resolveCommit(root, item, `Rollback certificate declared commit ${index}`));
    if (canonicalJson(resolved) !== canonicalJson(rollback.commits)) fail("Rollback certificate declared commits are not canonical");
    validateLinearCommits(root, forwardCommits.at(-1), rollback.commits, "Certificate rollback");
  }
  const expectedBase = observation(root, baseHead, boundary.observablePaths);
  const rolledBackRef = rollback.mode === "exact_inverse" ? baseHead : (rollback.commits.at(-1) ?? forwardCommits.at(-1));
  const expectedRolledBack = observation(root, rolledBackRef, boundary.observablePaths);
  if (canonicalJson(base) !== canonicalJson(expectedBase) || canonicalJson(rolledBack) !== canonicalJson(expectedRolledBack)) fail("Rollback certificate observations do not match repository objects");
  const expectedMismatches = deriveMismatches(expectedBase, expectedRolledBack);
  if (canonicalJson(body.mismatches) !== canonicalJson(expectedMismatches)) fail("Rollback certificate mismatches do not match repository objects");
  const derivedEffects = deriveEffects(root, baseHead, forwardCommits, boundary, rollback, runtimeEffects);
  const effects = assessEffects(derivedEffects, rollback, expectedMismatches);
  if (canonicalJson(body.effectAssessments) !== canonicalJson(effects)) fail("Rollback certificate effect assessments are inconsistent with the repository and verified boundary");
  const expectedExecution = {
    disposableWorktree: true,
    forwardApplied: true,
    rollbackApplied: rollback.mode === "exact_inverse" || rollback.commits.length > 0,
    error: null,
  };
  if (canonicalJson(body.execution) !== canonicalJson(expectedExecution)) fail("Rollback certificate execution record is not supported by the exact repository range");
  const equivalence = deriveEquivalence({ rollback, execution: expectedExecution, mismatches: expectedMismatches, effectAssessments: effects });
  if (!EQUIVALENCE.has(body.equivalence) || body.equivalence !== equivalence) fail("Rollback certificate equivalence is inconsistent with repository state, mismatches, or effect assessments");
  return { rollback, boundary, policy, runtimeEffects, base: expectedBase, rolledBack: expectedRolledBack, mismatches: expectedMismatches, effects, equivalence, changeDigest: expectedChangeDigest, repository: root };
}

export function verifyRollbackCertificate(envelope, { repository } = {}) {
  const verified = verifyCertifiedEnvelope(envelope, { expectedFormat: FORMAT });
  const details = verifyBody(verified.payload.body, repository);
  const verdict = details.equivalence === "equivalent" ? "ready" : details.equivalence === "not_equivalent" ? "blocked" : "insufficient_evidence";
  if (verified.payload.verdict !== verdict) fail("Rollback certificate verdict disagrees with equivalence");
  const short = sha256(details.changeDigest).slice(0, 32);
  const subjectId = `git_range:rollback-${short}`;
  if (verified.payload.id !== `certificate:rollback-${short}`) fail("Rollback certificate ID does not bind the exact change");
  const expectedSubject = [{ kind: "git_range", id: subjectId, digest: details.changeDigest }];
  if (canonicalJson(verified.payload.subjects) !== canonicalJson(expectedSubject)) fail("Rollback certificate subject does not bind the exact change and rollback operations");
  const expectedInputs = [
    { kind: "boundary_manifest", id: details.boundary.verification.id, digest: details.boundary.verification.digest },
    { kind: "rollback_policy", id: details.policy.id, digest: details.policy.digest },
  ].sort((left, right) => left.id.localeCompare(right.id));
  if (canonicalJson(verified.payload.inputs) !== canonicalJson(expectedInputs)) fail("Rollback certificate inputs do not bind the exact boundary and policy");
  const expectedClaim = details.equivalence === "equivalent" ? "passed" : details.equivalence === "not_equivalent" ? "failed" : "indeterminate";
  const expectedClaims = [{
    id: `claim:rollback-${short}`,
    type: "rollback_equivalence",
    status: expectedClaim,
    subjectIds: [subjectId],
    summary: details.equivalence === "equivalent"
      ? "Executed rollback restored every declared boundary-observable path and has no irreversible or unknown effect."
      : details.equivalence === "not_equivalent"
        ? "Executed rollback did not restore an equivalent declared boundary state."
        : "Rollback equivalence could not be established from the declared operation and effects.",
  }];
  if (canonicalJson(verified.payload.claims) !== canonicalJson(expectedClaims)) fail("Rollback certificate claim is inconsistent with equivalence");
  const expectedCounterexamples = counterexamples({ rollback: details.rollback, execution: verified.payload.body.execution, mismatches: details.mismatches, effectAssessments: details.effects });
  const normalizedExpectedCounterexamples = expectedCounterexamples
    .map((item) => createCounterexample(item))
    .sort((left, right) => `${left.code}:${left.invariantId}:${left.message}`.localeCompare(`${right.code}:${right.invariantId}:${right.message}`));
  if (canonicalJson(verified.payload.counterexamples) !== canonicalJson(normalizedExpectedCounterexamples)) fail("Rollback certificate counterexamples are incomplete or inconsistent");
  if ((details.equivalence === "equivalent") !== (verified.payload.body.policy.requiredStatus === details.equivalence)) fail("Rollback policy admission result is inconsistent");
  return { verified: true, digest: verified.digest, status: details.equivalence, verdict: verified.payload.verdict, body: verified.payload.body, payload: verified.payload };
}

function certificateFor({ repository, baseHead, forwardCommits, rollback, boundary, policy, runtimeEffects, generatedAt, producer, observations, mismatches, effectAssessments, equivalence, execution, initial, prePublication }) {
  const changeBody = { baseHead, forwardCommits, rollback, boundaryDigest: boundary.verification.digest, policyDigest: policy.digest, runtimeEffects };
  const changeDigest = `sha256:${sha256(canonicalJson(changeBody))}`;
  const short = sha256(changeDigest).slice(0, 32);
  const examples = counterexamples({ rollback, execution, mismatches, effectAssessments });
  const envelope = createCertifiedEnvelope({
    format: FORMAT,
    payload: {
      id: `certificate:rollback-${short}`,
      generatedAt,
      verdict: equivalence === "equivalent" ? "ready" : equivalence === "not_equivalent" ? "blocked" : "insufficient_evidence",
      subjects: [{ kind: "git_range", id: `git_range:rollback-${short}`, digest: changeDigest }],
      inputs: [
        { kind: "boundary_manifest", id: boundary.verification.id, digest: boundary.verification.digest },
        { kind: "rollback_policy", id: policy.id, digest: policy.digest },
      ],
      producer,
      claims: [{
        id: `claim:rollback-${short}`,
        type: "rollback_equivalence",
        status: equivalence === "equivalent" ? "passed" : equivalence === "not_equivalent" ? "failed" : "indeterminate",
        subjectIds: [`git_range:rollback-${short}`],
        summary: equivalence === "equivalent" ? "Executed rollback restored every declared boundary-observable path and has no irreversible or unknown effect." : equivalence === "not_equivalent" ? "Executed rollback did not restore an equivalent declared boundary state." : "Rollback equivalence could not be established from the declared operation and effects.",
      }],
      counterexamples: examples,
      body: {
        schemaVersion: "tugboat.rollback-proof.v1",
        repositoryIdentity: repositoryIdentity(repository),
        baseHead,
        forwardCommits,
        rollback,
        boundary: boundary.envelope,
        policy,
        runtimeEffects,
        observations,
        mismatches,
        effectAssessments,
        equivalence,
        execution,
        targetObservation: { initialHead: initial.head, prePublicationHead: prePublication.head, branch: initial.branch, clean: !initial.status && !prePublication.status },
        changeDigest,
      },
    },
  });
  verifyRollbackCertificate(envelope, { repository });
  return envelope;
}

function canonicalOutputPath(file) {
  const absolute = path.resolve(file);
  const suffix = [path.basename(absolute)];
  let ancestor = path.dirname(absolute);
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) break;
    suffix.unshift(path.basename(ancestor));
    ancestor = parent;
  }
  return path.resolve(fs.realpathSync(ancestor), ...suffix);
}

function pathIsInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function stageCertificateArtifact(outputPath, certificate) {
  const directory = path.dirname(outputPath);
  fs.mkdirSync(directory, { recursive: true });
  const temporary = `${outputPath}.stage-${process.pid}-${randomUUID()}`;
  const bytes = Buffer.from(`${canonicalJson(certificate)}\n`);
  let descriptor;
  let closed = false;
  let identity;
  const close = () => {
    if (!closed && descriptor !== undefined) {
      fs.closeSync(descriptor);
      closed = true;
    }
  };
  const assertIdentity = (file, label) => {
    const current = fs.lstatSync(file);
    if (!current.isFile() || current.isSymbolicLink() || current.dev !== identity.dev || current.ino !== identity.ino || current.size !== bytes.length) fail(`${label} inode or size changed before rollback certificate publication`);
  };
  try {
    descriptor = fs.openSync(temporary, "wx+", 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    identity = fs.fstatSync(descriptor);
    fsyncDirectory(directory);
  } catch (error) {
    close();
    fs.rmSync(temporary, { force: true });
    fail(`Could not durably stage rollback certificate: ${error.message}`);
  }
  return {
    publish() {
      let linked = false;
      try {
        assertIdentity(temporary, "Staged rollback certificate");
        const sealed = Buffer.alloc(bytes.length);
        let offset = 0;
        while (offset < sealed.length) {
          const read = fs.readSync(descriptor, sealed, offset, sealed.length - offset, offset);
          if (!read) break;
          offset += read;
        }
        if (offset !== bytes.length || !sealed.equals(bytes)) fail("Staged rollback certificate content changed before publication");
        fs.linkSync(temporary, outputPath);
        linked = true;
        assertIdentity(outputPath, "Published rollback certificate");
        fsyncDirectory(directory);
        close();
        fs.unlinkSync(temporary);
        fsyncDirectory(directory);
      } catch (error) {
        close();
        if (linked) {
          try {
            const current = fs.lstatSync(outputPath);
            if (current.dev === identity.dev && current.ino === identity.ino) fs.unlinkSync(outputPath);
          } catch { /* no partial publication remains when cleanup succeeds */ }
        }
        fs.rmSync(temporary, { force: true });
        fail(`Could not atomically publish rollback certificate: ${error.message}`);
      }
    },
    abort() {
      close();
      fs.rmSync(temporary, { force: true });
    },
  };
}

export function proveRollbackEquivalence(options) {
  exactObject(options, "rollback proof options", ["repository", "baseRef", "forwardCommits", "rollback", "boundary", "policy", "runtimeEffects", "producer", "generatedAt", "outputPath"], ["repository", "baseRef", "forwardCommits", "rollback", "boundary", "policy", "producer"]);
  const repository = fs.realpathSync(path.resolve(options.repository));
  const outputPath = options.outputPath === undefined ? undefined : canonicalOutputPath(options.outputPath);
  if (outputPath && pathIsInside(repository, outputPath)) fail("Rollback certificate output must be outside the target repository so proof cannot mutate target bytes");
  if (outputPath && fs.existsSync(outputPath)) fail("Rollback certificate output already exists; refusing to overwrite evidence");
  assertHermeticRepository(repository);
  const initial = targetSnapshot(repository);
  if (initial.status) fail("Target worktree must be clean before rollback proof");
  if (!initial.branch) fail("Target worktree must be on a branch before rollback proof");
  const baseHead = resolveCommit(repository, options.baseRef, "Rollback baseRef");
  if (!Array.isArray(options.forwardCommits) || !options.forwardCommits.length || options.forwardCommits.length > MAX_COMMITS) fail(`Rollback proof needs 1 to ${MAX_COMMITS} forward commits`);
  const forwardCommits = options.forwardCommits.map((item, index) => resolveCommit(repository, item, `Forward commit ${index}`));
  if (new Set(forwardCommits).size !== forwardCommits.length) fail("Forward commits must not contain duplicates");
  validateLinearCommits(repository, baseHead, forwardCommits, "Forward");
  const rollbackInput = validateRollback(options.rollback);
  const rollback = { ...rollbackInput, commits: rollbackInput.commits.map((item, index) => resolveCommit(repository, item, `Rollback commit ${index}`)) };
  if (rollback.mode === "declared" && rollback.commits.length) validateLinearCommits(repository, forwardCommits.at(-1), rollback.commits, "Rollback");
  const boundary = validateBoundary(options.boundary);
  const policy = validatePolicy(options.policy);
  const runtimeEffects = validateRuntimeEffects(options.runtimeEffects ?? []);
  const derivedEffects = deriveEffects(repository, baseHead, forwardCommits, boundary, rollback, runtimeEffects);
  const generatedAt = normalizeObservedAt(options.generatedAt ?? new Date().toISOString());
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-rollback-"));
  const worktree = path.join(root, "worktree");
  let worktreeRegistered = false;
  let primaryError;
  let stagedArtifact;
  let result;
  try {
    git(repository, ["worktree", "add", "--detach", worktree, forwardCommits.at(-1)]);
    worktreeRegistered = true;
    const baseObservation = observation(repository, baseHead, boundary.observablePaths);
    const appliedForward = [...forwardCommits];
    let rollbackApplied = false;
    let executionError = null;
    if (rollback.mode === "exact_inverse") {
      try {
        for (const appliedCommit of [...appliedForward].reverse()) {
          const parent = parents(repository, appliedCommit)[0];
          const commitTree = git(repository, ["rev-parse", `${appliedCommit}^{tree}`]);
          const parentTree = git(repository, ["rev-parse", `${parent}^{tree}`]);
          if (commitTree !== parentTree) git(worktree, ["revert", "--no-edit", appliedCommit]);
        }
        rollbackApplied = true;
      } catch (error) {
        executionError = error.message;
        try { git(worktree, ["revert", "--abort"]); } catch { /* cleanup removes disposable worktree */ }
      }
    } else if (rollback.commits.length) {
      try {
        git(worktree, ["reset", "--hard", rollback.commits.at(-1)]);
        rollbackApplied = true;
      } catch (error) {
        executionError = error.message;
        try { git(worktree, ["cherry-pick", "--abort"]); } catch { /* cleanup removes disposable worktree */ }
      }
    }
    const dirty = git(worktree, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (dirty) fail(`Rollback proof left a dirty disposable worktree: ${dirty.replaceAll("\n", ", ")}`);
    const rolledBackObservation = observation(worktree, "HEAD", boundary.observablePaths);
    const mismatches = deriveMismatches(baseObservation, rolledBackObservation);
    const effectAssessments = assessEffects(derivedEffects, rollback, mismatches);
    const execution = { disposableWorktree: true, forwardApplied: appliedForward.length === forwardCommits.length, rollbackApplied, error: executionError };
    const equivalence = deriveEquivalence({ rollback, execution, mismatches, effectAssessments });
    const prePublication = assertTargetUnchanged(repository, initial);
    const certificate = certificateFor({ repository, baseHead, forwardCommits, rollback, boundary, policy, runtimeEffects, generatedAt, producer: options.producer, observations: { base: baseObservation, rolledBack: rolledBackObservation }, mismatches, effectAssessments, equivalence, execution, initial, prePublication });
    if (outputPath) stagedArtifact = stageCertificateArtifact(outputPath, certificate);
    assertTargetUnchanged(repository, prePublication);
    if (outputPath) {
      stagedArtifact.publish();
      stagedArtifact = undefined;
    }
    result = { status: equivalence, certificate, targetSnapshotMatched: true };
    return result;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    const failures = [];
    if (stagedArtifact) {
      try { stagedArtifact.abort(); } catch (error) { failures.push(error.message); }
    }
    if (worktreeRegistered) {
      try { git(repository, ["worktree", "remove", "--force", worktree]); } catch (error) { failures.push(error.message); }
    }
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (error) { failures.push(error.message); }
    try { git(repository, ["worktree", "prune"]); } catch (error) { failures.push(error.message); }
    if (failures.length) {
      const details = { cleanupFailures: failures, recoveryRequired: true };
      if (primaryError) primaryError.details = { ...(primaryError.details ?? {}), ...details };
      else fail("Rollback proof cleanup was incomplete", details);
    }
  }
}
