import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { compileBundleAlgebra } from "./bundle-algebra.mjs";
import { analyzeCertifiedChange, validateAnalyzerReport } from "./analyzer-protocol.mjs";
import { readBundle, trackedContentDigest } from "./bundle.mjs";
import { canonicalJson, sha256 } from "./canonical.mjs";
import { createCertifiedEnvelope, verifyCertifiedEnvelope } from "./certified-changeset.mjs";
import { normalizeObservedAt } from "./intelligence-core.mjs";
import { withMissionLock } from "./lock.mjs";
import { operatorExecutionEnvironment, portableRelativePath, runBounded } from "./proof-runtime.mjs";
import { compileProofInvalidation } from "./proof-invalidation.mjs";
import { proveRollbackEquivalence, verifyRollbackCertificate } from "./rollback-equivalence.mjs";
import { missionReducer } from "./reducer.mjs";
import { renderMission } from "./render.mjs";
import { appendEvent, eventHash, verifySnapshot } from "./store.mjs";

const COMPOSITION_SCHEMA = "tugboat.composition-certificate.v1";
const MERGE_SCHEMA = "tugboat.merge-certificate.v1";
const MAX_CANDIDATES = 5;
const MAX_APPLICATION_OPERATIONS = 10_000;
const GIT_TIMEOUT_MS = 120_000;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const GIT_OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
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
  "-c", "user.name=Tugboat Composition",
  "-c", "user.email=tugboat-composition@example.invalid",
];

function gitEnvironment() {
  return {
    PATH: operatorExecutionEnvironment().PATH,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_AUTHOR_NAME: "Tugboat Composition",
    GIT_AUTHOR_EMAIL: "tugboat-composition@example.invalid",
    GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
    GIT_COMMITTER_NAME: "Tugboat Composition",
    GIT_COMMITTER_EMAIL: "tugboat-composition@example.invalid",
    GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
  };
}

export class CompositionError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "CompositionError";
    this.exitCode = 3;
    this.details = details;
  }
}

function fail(message, details) {
  throw new CompositionError(message, details);
}

function git(cwd, args) {
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
    const detail = error.stderr?.toString().trim() || error.message;
    fail(`Git command failed: git ${args.join(" ")}: ${detail}`, { cause: error });
  }
}

function gitOptional(cwd, args, { absentStatuses = [1] } = {}) {
  try {
    return execFileSync("git", [...HERMETIC_GIT_CONFIG, ...args], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: GIT_TIMEOUT_MS, env: gitEnvironment() }).trim();
  } catch (error) {
    if (absentStatuses.includes(error.status)) return null;
    const detail = error.stderr?.toString().trim() || error.message;
    fail(`Git command failed: git ${args.join(" ")}: ${detail}`, { cause: error });
  }
}

function gitBuffer(cwd, args, maxBuffer = 16 * 1024 * 1024) {
  try {
    return execFileSync("git", [...HERMETIC_GIT_CONFIG, ...args], {
      cwd,
      encoding: null,
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer,
      timeout: GIT_TIMEOUT_MS,
      env: gitEnvironment(),
    });
  } catch (error) {
    const detail = error.stderr?.toString().trim() || error.message;
    fail(`Git command failed: git ${args.join(" ")}: ${detail}`, { cause: error });
  }
}

function assertHermeticRepositoryConfiguration(repository) {
  const unsafePattern = "^(apply\\.|am\\.|checkout\\.|commit\\.(cleanup|gpgsign|status|verbose)$|core\\.(attributesfile|autocrlf|eol|safecrlf|whitespace|fsmonitor|sparsecheckout|sparsecheckoutcone)$|diff\\..*\\.(command|textconv|cachetextconv)$|filter\\..*\\.(clean|smudge|process|required)$|i18n\\.(commitencoding|logoutputencoding)$|mailinfo\\.scissors$|merge\\.|rebase\\.|rerere\\.)";
  const unsafe = [
    gitOptional(repository, ["config", "--local", "--get-regexp", unsafePattern]),
    gitOptional(repository, ["config", "--worktree", "--get-regexp", unsafePattern]),
  ].filter(Boolean).join("\n");
  if (unsafe) fail(`Target repository has executable or ambient Git configuration that composition will not run: ${[...new Set(unsafe.split("\n").map((line) => line.split(/\s/u)[0]))].join(", ")}`);
  const attributesValue = git(repository, ["rev-parse", "--git-path", "info/attributes"]);
  const attributesPath = path.resolve(repository, attributesValue);
  if (fs.existsSync(attributesPath)) {
    const stat = fs.lstatSync(attributesPath);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 0) fail("Target repository has ambient .git/info/attributes; composition accepts only content-addressed tracked attributes");
  }
}

function unique(values, label) {
  if (!Array.isArray(values)) fail(`${label} must be an array`);
  const normalized = [...new Set(values)];
  if (normalized.length !== values.length) fail(`${label} must not contain duplicates`);
  return normalized;
}

function relativeMission(repo, missionDir) {
  const repositoryPath = path.resolve(repo);
  const missionPath = path.resolve(missionDir);
  const relative = path.relative(repositoryPath, missionPath).replaceAll(path.sep, "/");
  try {
    const portable = portableRelativePath(relative, "Mission path");
    const repositoryReal = fs.realpathSync(repositoryPath);
    if (hasSymlink(repositoryReal, portable)) fail("Mission path may not contain symbolic links");
    const expectedPhysical = path.join(repositoryReal, ...portable.split("/"));
    if (fs.realpathSync(missionPath) !== expectedPhysical) fail("Mission path must resolve inside the target repository without aliases");
    return portable;
  } catch (error) {
    if (error instanceof CompositionError) throw error;
    fail(error.message);
  }
}

function inside(relative, parent) {
  return relative === parent || relative.startsWith(`${parent}/`);
}

function hasSymlink(root, relative) {
  let current = root;
  for (const segment of relative.split("/")) {
    current = path.join(current, segment);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) return true;
  }
  return false;
}

function assertCanonicalMissionTree(missionDir) {
  const root = path.resolve(missionDir);
  const pending = [root];
  let entries = 0;
  while (pending.length) {
    const current = pending.pop();
    let stat;
    try { stat = fs.lstatSync(current); } catch (error) { fail(`Cannot inspect canonical mission path ${current}: ${error.message}`); }
    if (stat.isSymbolicLink()) fail(`Canonical mission path may not contain symbolic links: ${current}`);
    if (stat.isDirectory()) {
      let children;
      try { children = fs.readdirSync(current); } catch (error) { fail(`Cannot inspect canonical mission directory ${current}: ${error.message}`); }
      entries += children.length;
      if (entries > 10_000) fail("Canonical mission tree exceeds 10000 entries");
      for (const child of children) pending.push(path.join(current, child));
    } else if (!stat.isFile()) fail(`Canonical mission path is not a regular file or directory: ${current}`);
  }
}

function exactKeys(value, label, allowed, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`Unknown ${label} field ${key}`);
  for (const key of required) if (value[key] === undefined) fail(`${label} is missing ${key}`);
}

function textValue(value, label) {
  if (typeof value !== "string" || !value || Buffer.byteLength(value) > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) fail(`${label} must be bounded non-empty text`);
  return value;
}

function digestValue(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail(`${label} must be a sha256 digest`);
  return value;
}

function proofGate(gate, label) {
  exactKeys(gate, label, ["id", "kind", "mandatory", "commandDigest", "exitCode", "stdoutDigest", "stderrDigest"]);
  textValue(gate.id, `${label} id`);
  if (!["test", "security", "release", "build", "lint", "operator"].includes(gate.kind) || typeof gate.mandatory !== "boolean" || gate.exitCode !== 0) fail(`${label} result is invalid`);
  digestValue(gate.commandDigest, `${label} commandDigest`);
  digestValue(gate.stdoutDigest, `${label} stdoutDigest`);
  digestValue(gate.stderrDigest, `${label} stderrDigest`);
  return gate;
}

function sameSet(left, right) {
  return left.length === right.length && left.every((item) => right.includes(item));
}

function readyClaims(payload, expectedType) {
  if (payload.counterexamples.length !== 0 || payload.claims.length !== 1 || payload.claims[0].status !== "passed" || payload.claims[0].type !== expectedType) {
    fail(`Ready ${expectedType} certificate requires exactly one passed claim and no counterexamples`);
  }
}

function proofGraphDigestFor(composition) {
  return `sha256:${sha256(canonicalJson({
    compositionCertificateDigest: composition.digest,
    algebraDigest: composition.body.algebraDigest,
    analyzerCoverageDigest: composition.body.analyzerCoverageDigest,
    candidateDigests: composition.body.candidateDigests,
    invalidatedGateIds: composition.body.invalidatedGateIds,
    mandatoryGateIds: composition.body.mandatoryGateIds,
    gateIds: composition.body.gates.map((gate) => gate.id),
    rollbackCertificateDigest: composition.body.rollbackEvidence?.digest ?? null,
  }))}`;
}

function gitHashAlgorithm(oid) {
  if (/^[0-9a-f]{40}$/u.test(oid ?? "")) return "sha1";
  if (/^[0-9a-f]{64}$/u.test(oid ?? "")) return "sha256";
  fail("Git object ID has an unsupported hash format");
}

function gitObjectId(type, content, algorithm) {
  return createHash(algorithm).update(Buffer.from(`${type} ${content.length}\0`)).update(content).digest("hex");
}

function encodedObject(record, type, algorithm, label, maxBytes = 16 * 1024 * 1024) {
  exactKeys(record, label, ["oid", "content"]);
  if (gitHashAlgorithm(record.oid) !== algorithm || typeof record.content !== "string") fail(`${label} has an invalid object ID or content`);
  const content = Buffer.from(record.content, "base64");
  if (content.length > maxBytes || content.toString("base64") !== record.content || gitObjectId(type, content, algorithm) !== record.oid) fail(`${label} does not hash to its certified Git object ID`);
  return content;
}

function buildGitObjectProof(repository, resultHead) {
  const algorithm = gitHashAlgorithm(resultHead);
  const commit = gitBuffer(repository, ["cat-file", "commit", resultHead]);
  if (commit.length > 1024 * 1024) fail("Result commit object exceeds the 1 MiB certificate limit");
  return {
    hashAlgorithm: algorithm,
    commit: { oid: resultHead, content: commit.toString("base64") },
  };
}

function verifyGitObjectProof(proof, body) {
  exactKeys(proof, "merge gitObjectProof", ["hashAlgorithm", "commit"]);
  if (!new Set(["sha1", "sha256"]).has(proof.hashAlgorithm) || gitHashAlgorithm(body.resultHead) !== proof.hashAlgorithm || gitHashAlgorithm(body.resultTree) !== proof.hashAlgorithm) fail("Merge gitObjectProof hash algorithm is invalid");
  const commit = encodedObject(proof.commit, "commit", proof.hashAlgorithm, "merge result commit", 1024 * 1024);
  if (proof.commit.oid !== body.resultHead) fail("Merge gitObjectProof is for a different result commit");
  const headerEnd = commit.indexOf(Buffer.from("\n\n"));
  if (headerEnd < 0) fail("Certified result commit has no canonical header terminator");
  const header = commit.subarray(0, headerEnd).toString("utf8").split("\n");
  const trees = header.filter((line) => line.startsWith("tree ")).map((line) => line.slice(5));
  const parents = header.filter((line) => line.startsWith("parent ")).map((line) => line.slice(7));
  if (trees.length !== 1 || trees[0] !== body.resultTree || parents.length !== 1 || parents[0] !== body.resultParentHead) fail("Certified result commit does not bind the declared tree and sole canonical parent");
  const message = commit.subarray(headerEnd + 2).toString("utf8");
  const compositionTrailers = message.split("\n").filter((line) => line.startsWith("Tugboat-Composition: "));
  const eventTrailers = message.split("\n").filter((line) => line.startsWith("Tugboat-Event: "));
  if (compositionTrailers.length !== 1 || compositionTrailers[0] !== `Tugboat-Composition: ${body.compositionCertificateDigest}` || eventTrailers.length !== 1 || eventTrailers[0] !== `Tugboat-Event: ${body.missionEvent.hash}`) fail("Certified result commit does not bind the exact composition certificate and mission event hash");
}

function verifyCompositionBody(body, payload, repository) {
  exactKeys(body, "composition certificate body", [
    "repositoryIdentity", "branch", "baseHead", "missionId", "missionRevision", "algebraDigest", "analyzerCoverageDigest", "candidateDigests", "canonicalOrder",
    "dependencyDag", "pairwiseMatrix", "transitiveHazards", "composedFootprint", "canonicalApplications", "orders", "observableTreeDigest", "gates",
    "invalidatedGateIds", "mandatoryGateIds", "rollbackRequired", "rollbackEvidence", "proofBasis", "executionAuthorized",
  ]);
  if (body.executionAuthorized !== true || !GIT_OID.test(body.baseHead ?? "") || !DIGEST.test(body.repositoryIdentity ?? "") || !DIGEST.test(body.algebraDigest ?? "") || !DIGEST.test(body.analyzerCoverageDigest ?? "") || !DIGEST.test(body.observableTreeDigest ?? "")) fail("Composition certificate bindings are invalid");
  textValue(body.branch, "Composition branch");
  textValue(body.missionId, "Composition missionId");
  if (!Number.isInteger(body.missionRevision) || body.missionRevision < 0) fail("Composition missionRevision is invalid");
  if (!Array.isArray(body.orders) || !body.orders.length || !Array.isArray(body.candidateDigests) || body.candidateDigests.length < 2 || body.candidateDigests.length > MAX_CANDIDATES) fail("Composition certificate is incomplete");
  const candidateIds = [];
  for (const [index, candidate] of body.candidateDigests.entries()) {
    exactKeys(candidate, `composition candidate digest ${index}`, ["id", "digest", "witnessDigest", "invalidationDigest"]);
    textValue(candidate.id, `Composition candidate digest ${index} id`);
    digestValue(candidate.digest, `Composition candidate ${candidate.id} digest`);
    digestValue(candidate.witnessDigest, `Composition candidate ${candidate.id} witnessDigest`);
    digestValue(candidate.invalidationDigest, `Composition candidate ${candidate.id} invalidationDigest`);
    candidateIds.push(candidate.id);
  }
  if (new Set(candidateIds).size !== candidateIds.length) fail("Composition candidate IDs must be unique");
  if (!sameSet(payload.claims[0].subjectIds, candidateIds.map((id) => `bundle:${id}`))) fail("Composition claim subjects do not cover the exact candidate bundles");
  const subjectBindings = new Map(payload.subjects.map((subject) => [subject.id, subject]));
  const inputBindings = new Map(payload.inputs.map((input) => [input.id, input]));
  if (typeof body.rollbackRequired !== "boolean" || (body.rollbackRequired && !body.rollbackEvidence) || (!body.rollbackRequired && body.rollbackEvidence !== null)) fail("Composition rollback admission declaration is invalid");
  if (payload.subjects.length !== candidateIds.length || payload.inputs.length !== candidateIds.length * 2 + 2 + (body.rollbackRequired ? 1 : 0)) fail("Composition certificate subject or input coverage is invalid");
  for (const candidate of body.candidateDigests) {
    const subject = subjectBindings.get(`bundle:${candidate.id}`);
    const witness = inputBindings.get(`witness:${candidate.id}`);
    const invalidation = inputBindings.get(`invalidation:${candidate.id}`);
    if (subject?.kind !== "bundle" || subject.digest !== candidate.digest || witness?.kind !== "non_interference_witness" || witness.digest !== candidate.witnessDigest || invalidation?.kind !== "proof_invalidation" || invalidation.digest !== candidate.invalidationDigest) fail(`Composition candidate ${candidate.id} is not bound to certificate subjects and inputs`);
  }
  const algebraInput = inputBindings.get(`algebra:${body.algebraDigest.slice("sha256:".length, "sha256:".length + 32)}`);
  const analyzerInput = inputBindings.get(`analyzer-coverage:${body.analyzerCoverageDigest.slice("sha256:".length, "sha256:".length + 32)}`);
  if (algebraInput?.kind !== "bundle_algebra" || algebraInput.digest !== body.algebraDigest) fail("Composition algebra digest is not bound to the exact certificate input");
  if (analyzerInput?.kind !== "analyzer_coverage" || analyzerInput.digest !== body.analyzerCoverageDigest) fail("Composition analyzer coverage digest is not bound to the exact certificate input");
  if (body.rollbackRequired) {
    exactKeys(body.rollbackEvidence, "composition rollbackEvidence", ["certificate", "digest", "status", "baseHead", "forwardCommits", "forwardTip", "changeDigest"]);
    if (body.rollbackEvidence.status !== "equivalent" || body.rollbackEvidence.baseHead !== body.baseHead || !Array.isArray(body.rollbackEvidence.forwardCommits) || !body.rollbackEvidence.forwardCommits.length || body.rollbackEvidence.forwardTip !== body.rollbackEvidence.forwardCommits.at(-1)) fail("Composition rollback evidence does not cover a complete equivalent forward range");
    digestValue(body.rollbackEvidence.digest, "Composition rollback evidence digest");
    digestValue(body.rollbackEvidence.changeDigest, "Composition rollback evidence changeDigest");
    if (!repository) fail("Composition rollback admission verification requires the exact local repository");
    const verifiedRollback = verifyRollbackCertificate(body.rollbackEvidence.certificate, { repository });
    if (verifiedRollback.status !== "equivalent" || verifiedRollback.digest !== body.rollbackEvidence.digest || verifiedRollback.body.baseHead !== body.baseHead || canonicalJson(verifiedRollback.body.forwardCommits) !== canonicalJson(body.rollbackEvidence.forwardCommits) || verifiedRollback.body.changeDigest !== body.rollbackEvidence.changeDigest) fail("Composition rollback evidence is not the exact admitted repository-backed certificate");
    const rollbackInput = inputBindings.get(body.rollbackEvidence.certificate.payload.id);
    if (rollbackInput?.kind !== "rollback_certificate" || rollbackInput.digest !== body.rollbackEvidence.digest) fail("Composition certificate does not bind its rollback evidence input");
  } else if (payload.inputs.some((input) => input.kind === "rollback_certificate")) fail("Composition certificate binds unexpected rollback evidence");
  if (!Array.isArray(body.canonicalOrder) || !sameSet(body.canonicalOrder, candidateIds) || new Set(body.canonicalOrder).size !== body.canonicalOrder.length) fail("Composition certificate canonical order is invalid");
  if (!Array.isArray(body.dependencyDag) || !Array.isArray(body.pairwiseMatrix) || !Array.isArray(body.transitiveHazards) || !Array.isArray(body.composedFootprint)) fail("Composition certificate semantic proof collections are invalid");
  if (body.dependencyDag.length !== candidateIds.length || body.transitiveHazards.length !== 0) fail("Composition dependency proof or hazards are invalid");
  const dependencyRecords = body.dependencyDag.map((record, index) => {
    exactKeys(record, `composition dependency ${index}`, ["id", "dependencies"]);
    if (!candidateIds.includes(record.id) || !Array.isArray(record.dependencies) || new Set(record.dependencies).size !== record.dependencies.length || record.dependencies.some((id) => !candidateIds.includes(id) || id === record.id)) fail(`Composition dependency ${index} is invalid`);
    return { id: record.id, dependencies: record.dependencies };
  });
  if (new Set(dependencyRecords.map((record) => record.id)).size !== candidateIds.length) fail("Composition dependency graph must cover every candidate exactly once");
  const expectedOrders = validOrders(dependencyRecords);
  if (expectedOrders.length !== body.orders.length) fail("Composition certificate did not execute every dependency-valid order");
  const encodedOrders = new Set();
  for (const [index, order] of body.orders.entries()) {
    exactKeys(order, `composition order ${index}`, ["order", "head", "observableTreeDigest"]);
    if (!Array.isArray(order.order) || !sameSet(order.order, candidateIds) || new Set(order.order).size !== order.order.length || !GIT_OID.test(order.head ?? "") || order.observableTreeDigest !== body.observableTreeDigest) fail(`Composition order ${index} is invalid or diverges`);
    encodedOrders.add(canonicalJson(order.order));
  }
  if (encodedOrders.size !== body.orders.length || expectedOrders.some((order) => !encodedOrders.has(canonicalJson(order)))) fail("Composition order proof is incomplete or duplicated");
  if (!encodedOrders.has(canonicalJson(body.canonicalOrder))) fail("Composition canonical order was not executed");
  if (body.rollbackRequired) {
    const canonicalRecord = body.orders.find((order) => canonicalJson(order.order) === canonicalJson(body.canonicalOrder));
    if (!canonicalRecord || canonicalRecord.head !== body.rollbackEvidence.forwardTip) fail("Composition rollback evidence does not cover the canonical prepared head");
  }
  exactKeys(body.canonicalApplications, "composition canonicalApplications", ["commits", "components"]);
  if (!Array.isArray(body.canonicalApplications.commits) || !Array.isArray(body.canonicalApplications.components)) fail("Composition canonical applications are invalid");
  const commitMappings = new Set();
  for (const [index, application] of body.canonicalApplications.commits.entries()) {
    exactKeys(application, `composition commit application ${index}`, ["bundleId", "sourceSha", "targetSha"]);
    if (!candidateIds.includes(application.bundleId) || !GIT_OID.test(application.sourceSha ?? "") || !GIT_OID.test(application.targetSha ?? "")) fail(`Composition commit application ${index} is invalid`);
    const key = `${application.bundleId}\0${application.sourceSha}`;
    if (commitMappings.has(key)) fail(`Composition commit application ${index} is duplicated`);
    commitMappings.add(key);
  }
  const componentMappings = new Set();
  for (const [index, application] of body.canonicalApplications.components.entries()) {
    exactKeys(application, `composition component application ${index}`, ["bundleId", "targetPath", "digest", "status"]);
    if (!candidateIds.includes(application.bundleId) || !["applied", "reconciled"].includes(application.status)) fail(`Composition component application ${index} is invalid`);
    try { portableRelativePath(application.targetPath, `Composition component application ${index} targetPath`); } catch (error) { fail(error.message); }
    digestValue(application.digest, `Composition component application ${index} digest`);
    const key = `${application.bundleId}\0${application.targetPath}`;
    if (componentMappings.has(key)) fail(`Composition component application ${index} is duplicated`);
    componentMappings.add(key);
  }
  for (const id of candidateIds) {
    if (!body.canonicalApplications.commits.some((item) => item.bundleId === id) && !body.canonicalApplications.components.some((item) => item.bundleId === id)) fail(`Composition canonical applications omit candidate ${id}`);
  }
  const expectedPairs = candidateIds.length * (candidateIds.length - 1) / 2;
  if (body.pairwiseMatrix.length !== expectedPairs) fail("Composition pairwise matrix is incomplete");
  const pairs = new Set();
  for (const [index, pair] of body.pairwiseMatrix.entries()) {
    exactKeys(pair, `composition pair ${index}`, ["leftBundleId", "rightBundleId", "commutes", "composable", "requiredOrder", "hazards"]);
    if (!candidateIds.includes(pair.leftBundleId) || !candidateIds.includes(pair.rightBundleId) || pair.leftBundleId === pair.rightBundleId || typeof pair.commutes !== "boolean" || pair.composable !== true || !Array.isArray(pair.requiredOrder) || !Array.isArray(pair.hazards) || pair.hazards.length) fail(`Composition pair ${index} is invalid or hazardous`);
    const forward = dependencyPathBetween(dependencyRecords, pair.leftBundleId, pair.rightBundleId);
    const reverse = dependencyPathBetween(dependencyRecords, pair.rightBundleId, pair.leftBundleId);
    const expectedRequiredOrder = forward ? [pair.leftBundleId, pair.rightBundleId] : reverse ? [pair.rightBundleId, pair.leftBundleId] : [];
    if (canonicalJson(pair.requiredOrder) !== canonicalJson(expectedRequiredOrder) || pair.commutes !== (expectedRequiredOrder.length === 0)) fail(`Composition pair ${index} ordering does not match the dependency graph`);
    pairs.add([pair.leftBundleId, pair.rightBundleId].sort().join("\u0000"));
  }
  if (pairs.size !== expectedPairs) fail("Composition pairwise matrix contains duplicate or missing pairs");
  if (!Array.isArray(body.gates) || !Array.isArray(body.invalidatedGateIds) || !Array.isArray(body.mandatoryGateIds)) fail("Composition gate proof is invalid");
  body.gates.forEach((gate, index) => proofGate(gate, `composition gate ${index}`));
  const gateIds = body.gates.map((gate) => gate.id);
  if (new Set(gateIds).size !== gateIds.length || new Set(body.invalidatedGateIds).size !== body.invalidatedGateIds.length || new Set(body.mandatoryGateIds).size !== body.mandatoryGateIds.length || [...body.invalidatedGateIds, ...body.mandatoryGateIds].some((id) => !gateIds.includes(id))) fail("Composition selected gate coverage is invalid");
  const actualMandatory = body.gates.filter((gate) => gate.mandatory || gate.kind === "security" || gate.kind === "release").map((gate) => gate.id);
  if (!sameSet(actualMandatory, body.mandatoryGateIds)) fail("Composition mandatory gate coverage is incomplete");
  exactKeys(body.proofBasis, "composition proofBasis", ["everyDependencyValidOrderExecuted", "orderCount", "exactObservableTreeComparison", "analyzerCoverageComplete", "invalidatedAndMandatoryGatesPassed", "targetMutationBeforeAuthorization"]);
  if (body.proofBasis.everyDependencyValidOrderExecuted !== true || body.proofBasis.orderCount !== body.orders.length || body.proofBasis.exactObservableTreeComparison !== true || body.proofBasis.analyzerCoverageComplete !== true || body.proofBasis.invalidatedAndMandatoryGatesPassed !== true || body.proofBasis.targetMutationBeforeAuthorization !== false) fail("Composition proofBasis does not authorize execution");
  for (const [index, effect] of body.composedFootprint.entries()) {
    if (!effect || typeof effect !== "object" || Array.isArray(effect) || !candidateIds.includes(effect.bundleId)) fail(`Composition effect ${index} is invalid`);
    textValue(effect.id, `Composition effect ${index} id`);
    digestValue(effect.sourceDigest, `Composition effect ${index} sourceDigest`);
    if (effect.domain !== undefined) {
      exactKeys(effect, `composition effect ${index}`, ["bundleId", "id", "domain", "subject", "access", "operation", "sourceDigest", "signature", "sequence"], ["bundleId", "id", "domain", "subject", "access", "operation", "sourceDigest"]);
      if (!["path", "interface", "schema", "infrastructure", "workflow"].includes(effect.domain) || !["read", "write"].includes(effect.access)) fail(`Composition effect ${index} domain or access is invalid`);
      textValue(effect.subject, `Composition effect ${index} subject`);
      textValue(effect.operation, `Composition effect ${index} operation`);
      if (effect.signature !== undefined) digestValue(effect.signature, `Composition effect ${index} signature`);
      if (effect.sequence !== undefined && (!Number.isInteger(effect.sequence) || effect.sequence < 0)) fail(`Composition effect ${index} sequence is invalid`);
    } else {
      exactKeys(effect, `composition effect ${index}`, ["bundleId", "id", "level", "operation", "path", "previousPath", "oldMode", "newMode", "sourceKind", "sourceId", "sourceDigest", "requirementIds", "componentId", "owner"], ["bundleId", "id", "level", "operation", "path", "sourceKind", "sourceId", "sourceDigest", "requirementIds"]);
      try { portableRelativePath(effect.path, `Composition effect ${index} path`); } catch (error) { fail(error.message); }
      if (effect.previousPath !== undefined) try { portableRelativePath(effect.previousPath, `Composition effect ${index} previousPath`); } catch (error) { fail(error.message); }
      if (effect.level !== "file" || !["create", "delete", "modify", "rename", "mode_change"].includes(effect.operation) || !["patch", "component"].includes(effect.sourceKind)) fail(`Composition effect ${index} file semantics are invalid`);
      textValue(effect.sourceId, `Composition effect ${index} sourceId`);
      if (!Array.isArray(effect.requirementIds) || new Set(effect.requirementIds).size !== effect.requirementIds.length) fail(`Composition effect ${index} requirementIds are invalid`);
      effect.requirementIds.forEach((id) => textValue(id, `Composition effect ${index} requirementId`));
      for (const field of ["oldMode", "newMode", "componentId", "owner"]) if (effect[field] !== undefined) textValue(effect[field], `Composition effect ${index} ${field}`);
      textValue(effect.operation ?? effect.change ?? "modify", `Composition effect ${index} operation`);
    }
  }
  if (new Set(body.composedFootprint.map((effect) => `${effect.bundleId}\0${effect.id}`)).size !== body.composedFootprint.length) fail("Composition footprint contains duplicate effects");
  for (const id of candidateIds) if (!body.composedFootprint.some((effect) => effect.bundleId === id)) fail(`Composition footprint omits candidate ${id}`);
  return body;
}

export function verifyCompositionCertificate(envelope, { repository } = {}) {
  const verified = verifyCertifiedEnvelope(envelope, { expectedFormat: COMPOSITION_SCHEMA });
  if (verified.payload.verdict !== "ready") fail("Composition certificate does not authorize execution");
  readyClaims(verified.payload, "commutativity");
  verifyCompositionBody(verified.payload.body, verified.payload, repository);
  return { verified: true, digest: verified.digest, payload: verified.payload, body: verified.payload.body };
}

function verifyMissionEventBinding(body, composition) {
  const event = body.missionEvent;
  exactKeys(event, "merge missionEvent", ["id", "sequence", "timestamp", "actor", "type", "payload", "gitHead", "previousHash", "hash"]);
  textValue(event.id, "Merge missionEvent id");
  normalizeObservedAt(event.timestamp);
  exactKeys(event.actor, "merge missionEvent actor", ["name", "kind", "runtime"]);
  for (const field of ["name", "kind", "runtime"]) textValue(event.actor[field], `Merge missionEvent actor ${field}`);
  if (event.type !== "COMPOSITION_MERGED" || event.sequence !== body.missionRevisionAfter || event.gitHead !== body.canonicalPreparedHead || !/^[0-9a-f]{64}$/u.test(event.previousHash ?? "") || event.hash !== eventHash(event)) fail("Merge missionEvent identity, sequence, Git head, or hash is invalid");
  const payload = event.payload;
  exactKeys(payload, "merge missionEvent payload", ["compositionId", "certificateDigest", "canonicalOrder", "candidates", "targetContentDigest", "gates", "rollbackEvidence", "sliceProgressionVersion"], ["compositionId", "certificateDigest", "canonicalOrder", "candidates", "targetContentDigest", "gates", "sliceProgressionVersion"]);
  if (payload.compositionId !== composition.payload.id || payload.certificateDigest !== composition.digest || canonicalJson(payload.canonicalOrder) !== canonicalJson(composition.body.canonicalOrder) || payload.targetContentDigest !== composition.body.observableTreeDigest || canonicalJson(payload.gates) !== canonicalJson(composition.body.gates) || payload.sliceProgressionVersion !== 1) fail("Merge missionEvent payload disagrees with the admitted composition proof");
  if (composition.body.rollbackRequired) {
    exactKeys(payload.rollbackEvidence, "merge missionEvent rollbackEvidence", ["digest", "status", "changeDigest", "baseHead", "forwardTip"]);
    const expectedRollback = composition.body.rollbackEvidence;
    if (payload.rollbackEvidence.digest !== expectedRollback.digest || payload.rollbackEvidence.status !== "equivalent" || payload.rollbackEvidence.changeDigest !== expectedRollback.changeDigest || payload.rollbackEvidence.baseHead !== expectedRollback.baseHead || payload.rollbackEvidence.forwardTip !== expectedRollback.forwardTip) fail("Merge missionEvent does not record the admitted rollback evidence");
  } else if (payload.rollbackEvidence !== undefined) fail("Merge missionEvent records unexpected rollback evidence");
  if (!Array.isArray(payload.candidates) || payload.candidates.length !== composition.body.candidateDigests.length) fail("Merge missionEvent candidate coverage is invalid");
  const compositionCandidates = new Map(composition.body.candidateDigests.map((candidate) => [candidate.id, candidate]));
  const recordedCandidates = new Set();
  const recordedCommits = [];
  const recordedComponents = [];
  for (const [index, candidate] of payload.candidates.entries()) {
    exactKeys(candidate, `merge missionEvent candidate ${index}`, ["bundleId", "digest", "sourceRequirementIds", "targetRequirementIds", "mappings", "appliedCommits", "components", "source"]);
    const admitted = compositionCandidates.get(candidate.bundleId);
    if (!admitted || admitted.digest !== candidate.digest || recordedCandidates.has(candidate.bundleId)) fail(`Merge missionEvent candidate ${index} is not an exact admitted bundle`);
    recordedCandidates.add(candidate.bundleId);
    if (!Array.isArray(candidate.sourceRequirementIds) || !Array.isArray(candidate.targetRequirementIds) || !candidate.sourceRequirementIds.length || candidate.sourceRequirementIds.length !== candidate.targetRequirementIds.length || new Set(candidate.sourceRequirementIds).size !== candidate.sourceRequirementIds.length || new Set(candidate.targetRequirementIds).size !== candidate.targetRequirementIds.length) fail(`Merge missionEvent candidate ${index} requirement mapping is invalid`);
    candidate.sourceRequirementIds.forEach((id) => textValue(id, `Merge missionEvent candidate ${index} sourceRequirementId`));
    candidate.targetRequirementIds.forEach((id) => textValue(id, `Merge missionEvent candidate ${index} targetRequirementId`));
    exactKeys(candidate.mappings, `merge missionEvent candidate ${index} mappings`, candidate.sourceRequirementIds, candidate.sourceRequirementIds);
    for (const [sourceId, targetId] of Object.entries(candidate.mappings)) if (!candidate.targetRequirementIds.includes(targetId)) fail(`Merge missionEvent candidate ${index} maps ${sourceId} outside its targets`);
    if (!Array.isArray(candidate.appliedCommits) || !Array.isArray(candidate.components)) fail(`Merge missionEvent candidate ${index} application evidence is invalid`);
    for (const [applicationIndex, application] of candidate.appliedCommits.entries()) {
      exactKeys(application, `merge missionEvent candidate ${index} commit ${applicationIndex}`, ["sourceSha", "targetSha"]);
      if (!GIT_OID.test(application.sourceSha ?? "") || !GIT_OID.test(application.targetSha ?? "")) fail(`Merge missionEvent candidate ${index} commit ${applicationIndex} is invalid`);
      recordedCommits.push({ bundleId: candidate.bundleId, ...application });
    }
    for (const [applicationIndex, application] of candidate.components.entries()) {
      exactKeys(application, `merge missionEvent candidate ${index} component ${applicationIndex}`, ["targetPath", "digest", "type", "status"]);
      try { portableRelativePath(application.targetPath, `Merge missionEvent candidate ${index} component ${applicationIndex} targetPath`); } catch (error) { fail(error.message); }
      digestValue(application.digest, `Merge missionEvent candidate ${index} component ${applicationIndex} digest`);
      textValue(application.type, `Merge missionEvent candidate ${index} component ${applicationIndex} type`);
      if (!["applied", "reconciled"].includes(application.status)) fail(`Merge missionEvent candidate ${index} component ${applicationIndex} status is invalid`);
      recordedComponents.push({ bundleId: candidate.bundleId, targetPath: application.targetPath, digest: application.digest, status: application.status });
    }
    exactKeys(candidate.source, `merge missionEvent candidate ${index} source`, ["missionId", "protocolVersion", "missionRevision", "branch", "sourceDigest", "baseSha", "tipSha", "contentDigest"]);
    textValue(candidate.source.missionId, `Merge missionEvent candidate ${index} source missionId`);
    textValue(candidate.source.protocolVersion, `Merge missionEvent candidate ${index} source protocolVersion`);
    if (!Number.isInteger(candidate.source.missionRevision) || candidate.source.missionRevision < 1 || !GIT_OID.test(candidate.source.baseSha ?? "") || !GIT_OID.test(candidate.source.tipSha ?? "")) fail(`Merge missionEvent candidate ${index} source is invalid`);
    textValue(candidate.source.branch, `Merge missionEvent candidate ${index} source branch`);
    digestValue(candidate.source.sourceDigest, `Merge missionEvent candidate ${index} sourceDigest`);
    digestValue(candidate.source.contentDigest, `Merge missionEvent candidate ${index} contentDigest`);
  }
  const commitKey = (item) => `${item.bundleId}\0${item.sourceSha}\0${item.targetSha}`;
  const componentKey = (item) => `${item.bundleId}\0${item.targetPath}\0${item.digest}\0${item.status}`;
  if (canonicalJson(recordedCommits.map(commitKey).sort()) !== canonicalJson(composition.body.canonicalApplications.commits.map(commitKey).sort()) || canonicalJson(recordedComponents.map(componentKey).sort()) !== canonicalJson(composition.body.canonicalApplications.components.map(componentKey).sort())) fail("Merge missionEvent does not bind the canonical commit and component applications");
}

export function verifyMergeCertificate(envelope, { compositionCertificate, repository } = {}) {
  if (!compositionCertificate) fail("Merge certificate verification requires its exact composition certificate");
  const composition = verifyCompositionCertificate(compositionCertificate, { repository });
  const verified = verifyCertifiedEnvelope(envelope, { expectedFormat: MERGE_SCHEMA });
  const body = verified.payload.body;
  readyClaims(verified.payload, "merge_integrity");
  exactKeys(body, "merge certificate body", [
    "compositionCertificateDigest", "baseHead", "resultHead", "resultTree", "resultTreeDigest", "branch", "missionRevisionBefore",
    "missionRevisionAfter", "canonicalPreparedHead", "resultParentHead", "missionPath", "missionEvent", "gitObjectProof", "fastForwardOnly", "raceChecks", "eventType", "gateOutputs", "proofGraphDigest", "executionAuthorized",
  ]);
  if (!GIT_OID.test(body.baseHead ?? "") || !GIT_OID.test(body.resultHead ?? "") || !GIT_OID.test(body.resultTree ?? "") || !GIT_OID.test(body.canonicalPreparedHead ?? "") || !GIT_OID.test(body.resultParentHead ?? "") || !DIGEST.test(body.resultTreeDigest ?? "") || !DIGEST.test(body.proofGraphDigest ?? "")) fail("Merge certificate bindings are invalid");
  if (!sameSet(verified.payload.claims[0].subjectIds, [`git_tree:${body.resultTree}`])) fail("Merge claim subject does not bind the exact result tree");
  if (body.resultTreeDigest !== `sha256:${sha256(body.resultTree)}`) fail("Merge certificate resultTreeDigest does not bind the result tree object");
  if (verified.payload.verdict !== "ready" || body.fastForwardOnly !== true || body.executionAuthorized !== true || body.eventType !== "COMPOSITION_MERGED") fail("Merge certificate does not authorize the recorded merge");
  textValue(body.branch, "Merge branch");
  digestValue(body.compositionCertificateDigest, "Merge compositionCertificateDigest");
  if (!Number.isInteger(body.missionRevisionBefore) || body.missionRevisionBefore < 0 || body.missionRevisionAfter !== body.missionRevisionBefore + 1 || body.baseHead === body.resultHead) fail("Merge revision or head transition is invalid");
  exactKeys(body.raceChecks, "merge raceChecks", ["headStable", "branchStable", "clean", "missionRevisionStable", "resultHeadMatched"]);
  if (Object.values(body.raceChecks).some((value) => value !== true)) fail("Merge race checks did not all pass");
  if (!Array.isArray(body.gateOutputs)) fail("Merge gate outputs are invalid");
  body.gateOutputs.forEach((gate, index) => proofGate(gate, `merge gate ${index}`));
  if (new Set(body.gateOutputs.map((gate) => gate.id)).size !== body.gateOutputs.length) fail("Merge gate outputs contain duplicates");
  if (verified.payload.inputs.length !== 1 || verified.payload.inputs[0].kind !== "composition_certificate" || verified.payload.inputs[0].id !== composition.payload.id || verified.payload.inputs[0].digest !== body.compositionCertificateDigest || verified.payload.subjects.length !== 1 || verified.payload.subjects[0].kind !== "git_tree" || verified.payload.subjects[0].id !== `git_tree:${body.resultTree}` || verified.payload.subjects[0].digest !== body.resultTreeDigest) fail("Merge certificate subject or input bindings are invalid");
  if (body.compositionCertificateDigest !== composition.digest) fail("Merge certificate is bound to a different composition certificate");
  if (body.baseHead !== composition.body.baseHead || body.branch !== composition.body.branch || body.missionRevisionBefore !== composition.body.missionRevision || canonicalJson(body.gateOutputs) !== canonicalJson(composition.body.gates)) fail("Merge certificate disagrees with its composition proof");
  const canonicalRecord = composition.body.orders.find((order) => canonicalJson(order.order) === canonicalJson(composition.body.canonicalOrder));
  if (!canonicalRecord || body.canonicalPreparedHead !== canonicalRecord.head || body.resultParentHead !== body.canonicalPreparedHead) fail("Merge result is not bound to the canonical prepared order as its sole parent");
  try { portableRelativePath(body.missionPath, "Merge missionPath"); } catch (error) { fail(error.message); }
  verifyMissionEventBinding(body, composition);
  verifyGitObjectProof(body.gitObjectProof, body);
  if (body.proofGraphDigest !== proofGraphDigestFor(composition)) fail("Merge certificate proofGraphDigest does not bind the exact admitted composition proof");
  if (repository !== undefined) {
    const resolved = fs.realpathSync(path.resolve(repository));
    if (git(resolved, ["cat-file", "-t", body.resultHead]) !== "commit" || git(resolved, ["rev-parse", `${body.resultHead}^{tree}`]) !== body.resultTree) fail("Repository does not contain the certified result commit and tree");
    const parents = git(resolved, ["rev-list", "--parents", "-n", "1", body.resultHead]).split(/\s+/u);
    if (parents.length !== 2 || parents[1] !== body.resultParentHead) fail("Repository result commit does not have the certified canonical prepared head as its sole parent");
    const events = git(resolved, ["show", `${body.resultHead}:${body.missionPath}/events.jsonl`]).split("\n").filter(Boolean);
    let recorded;
    try { recorded = JSON.parse(events.at(-1) ?? ""); } catch { fail("Repository result commit does not contain a readable final mission event"); }
    if (canonicalJson(recorded) !== canonicalJson(body.missionEvent)) fail("Repository result commit does not contain the certified COMPOSITION_MERGED event as its final event");
  }
  return { verified: true, digest: verified.digest, payload: verified.payload, body };
}

function permutations(values) {
  if (values.length <= 1) return [[...values]];
  const result = [];
  for (let index = 0; index < values.length; index += 1) {
    const head = values[index];
    const tail = [...values.slice(0, index), ...values.slice(index + 1)];
    for (const rest of permutations(tail)) result.push([head, ...rest]);
  }
  return result;
}

function validOrders(candidates) {
  const dependencies = new Map(candidates.map((candidate) => [candidate.id, candidate.dependencies]));
  return permutations(candidates.map((candidate) => candidate.id).sort()).filter((order) => {
    const position = new Map(order.map((id, index) => [id, index]));
    return order.every((id) => dependencies.get(id).every((dependency) => position.has(dependency) && position.get(dependency) < position.get(id)));
  });
}

function dependencyPathBetween(dependencyRecords, start, target) {
  const outgoing = new Map(dependencyRecords.map((record) => [record.id, []]));
  for (const record of dependencyRecords) for (const dependency of record.dependencies) outgoing.get(dependency).push(record.id);
  const queue = [[start]];
  const seen = new Set([start]);
  while (queue.length) {
    const current = queue.shift();
    for (const next of outgoing.get(current.at(-1)) ?? []) {
      if (next === target) return [...current, next];
      if (!seen.has(next)) { seen.add(next); queue.push([...current, next]); }
    }
  }
  return null;
}

function candidateRecord(input, verified, state) {
  exactKeys(input, "composition candidate", ["bundlePath", "requirementIds", "mappings", "witness", "proofGraph", "policyGates", "policyRequiredInvalidatedGateIds", "analyzerObligations", "analyzerReports", "publicKey", "requireSignature"], ["bundlePath", "witness", "proofGraph", "policyGates", "policyRequiredInvalidatedGateIds", "analyzerObligations"]);
  const sourceIds = unique(input.requirementIds ?? verified.payload.selection.requirements.map((item) => item.id), `Bundle ${verified.payload.id} requirementIds`).sort();
  if (!sourceIds.length) fail(`Bundle ${verified.payload.id} selection is empty`);
  const available = new Set(verified.payload.selection.requirements.map((item) => item.id));
  if (!sameSet(sourceIds, [...available])) fail(`Composition requires the complete certified selection for bundle ${verified.payload.id}; use selective promotion for partial requirements`);
  const mappings = {};
  const targetIds = [];
  for (const sourceId of sourceIds) {
    if (!available.has(sourceId)) fail(`Bundle ${verified.payload.id} does not contain source requirement ${sourceId}`);
    const targetId = input.mappings?.[sourceId] ?? sourceId;
    if (!state.requirements[targetId]) fail(`No target requirement ${targetId} for bundle ${verified.payload.id}`);
    if (targetIds.includes(targetId)) fail(`Bundle ${verified.payload.id} mappings must be one-to-one`);
    mappings[sourceId] = targetId;
    targetIds.push(targetId);
  }
  for (const sourceId of Object.keys(input.mappings ?? {})) if (!sourceIds.includes(sourceId)) fail(`Bundle ${verified.payload.id} mapping references unselected requirement ${sourceId}`);
  const selected = new Set(sourceIds);
  const commits = verified.payload.commits.map((commit, index) => ({ commit, index })).filter(({ commit }) => commit.requirementIds.some((id) => selected.has(id)));
  for (const { commit } of commits) if (commit.requirementIds.some((id) => !selected.has(id))) fail(`Bundle ${verified.payload.id} commit ${commit.sha} mixes selected and unselected requirements`);
  const components = verified.payload.components.filter((component) => component.requirementIds.some((id) => selected.has(id)));
  for (const component of components) if (component.requirementIds.some((id) => !selected.has(id))) fail(`Bundle ${verified.payload.id} component ${component.targetPath} mixes selected and unselected requirements`);
  if (!commits.length && !components.length) fail(`Bundle ${verified.payload.id} has no selected changes`);
  if (!input.witness?.semanticProof) fail(`Bundle ${verified.payload.id} needs a semantically verified non-interference witness`);
  const witnessEnvelope = { schemaVersion: 1, format: "tugboat.non-interference-witness.v1", payload: input.witness.payload, digest: input.witness.digest };
  const witnessIntegrity = verifyCertifiedEnvelope(witnessEnvelope, { expectedFormat: "tugboat.non-interference-witness.v1" });
  if (witnessIntegrity.payload.verdict !== "ready" || witnessIntegrity.payload.body.bundleId !== verified.payload.id || witnessIntegrity.payload.body.bundleDigest !== verified.digest) {
    fail(`Bundle ${verified.payload.id} non-interference witness is stale or not ready`);
  }
  const invalidation = compileProofInvalidation(input.proofGraph, { witness: input.witness });
  if (!Array.isArray(input.policyGates)) fail(`Bundle ${verified.payload.id} policyGates must be an array`);
  const policyGates = input.policyGates.map((gate, index) => {
    exactKeys(gate, `Bundle ${verified.payload.id} policy gate ${index}`, ["id", "kind", "mandatory"]);
    textValue(gate.id, `Bundle ${verified.payload.id} policy gate ${index} id`);
    textValue(gate.kind, `Bundle ${verified.payload.id} policy gate ${index} kind`);
    if (typeof gate.mandatory !== "boolean") fail(`Bundle ${verified.payload.id} policy gate ${gate.id} mandatory must be a boolean`);
    return { id: gate.id, kind: gate.kind, mandatory: gate.mandatory };
  }).sort((left, right) => left.id.localeCompare(right.id));
  if (new Set(policyGates.map((gate) => gate.id)).size !== policyGates.length) fail(`Bundle ${verified.payload.id} policyGates must not contain duplicates`);
  const policyGateIds = policyGates.map((gate) => gate.id);
  const proofGateIds = [...invalidation.invalidated, ...invalidation.retained].filter((item) => item.kind === "gate").map((item) => item.id).sort();
  if (!sameSet(policyGateIds, proofGateIds)) fail(`Bundle ${verified.payload.id} invalidation graph must cover every verified boundary-policy gate exactly once`);
  const mandatoryPolicyGateIds = policyGates.filter((gate) => gate.mandatory).map((gate) => gate.id);
  if (!sameSet(mandatoryPolicyGateIds, invalidation.mandatoryGateIds)) fail(`Bundle ${verified.payload.id} invalidation graph changed verified boundary-policy mandatory semantics`);
  const policyRequiredInvalidatedGateIds = unique(input.policyRequiredInvalidatedGateIds, `Bundle ${verified.payload.id} policyRequiredInvalidatedGateIds`).sort();
  for (const id of policyRequiredInvalidatedGateIds) if (!policyGateIds.includes(id)) fail(`Bundle ${verified.payload.id} requires invalidation of unknown boundary-policy gate ${id}`);
  const invalidatedPolicyGateIds = invalidation.invalidated.filter((item) => item.kind === "gate").map((item) => item.id);
  for (const id of policyRequiredInvalidatedGateIds) if (!invalidatedPolicyGateIds.includes(id)) fail(`Bundle ${verified.payload.id} invalidation graph omits a required effect-to-policy-gate path for ${id}`);
  if (!Array.isArray(input.analyzerObligations)) fail(`Bundle ${verified.payload.id} analyzerObligations must be an array`);
  const analyzerObligations = input.analyzerObligations.map((obligation, index) => {
    exactKeys(obligation, `Bundle ${verified.payload.id} analyzer obligation ${index}`, ["analyzerId", "path"]);
    const analyzerId = textValue(obligation.analyzerId, `Bundle ${verified.payload.id} analyzer obligation ${index} analyzerId`);
    const subject = portableRelativePath(obligation.path, `Bundle ${verified.payload.id} analyzer obligation ${index} path`);
    return { analyzerId, path: subject };
  }).sort((left, right) => `${left.analyzerId}:${left.path}`.localeCompare(`${right.analyzerId}:${right.path}`));
  if (new Set(analyzerObligations.map((item) => `${item.analyzerId}\0${item.path}`)).size !== analyzerObligations.length) fail(`Bundle ${verified.payload.id} analyzerObligations must not contain duplicates`);
  return {
    id: verified.payload.id,
    verified,
    witness: input.witness,
    invalidation,
    policyGates,
    policyRequiredInvalidatedGateIds,
    analyzerObligations,
    analyzerReports: input.analyzerReports ?? [],
    dependencies: [...verified.payload.selection.bundleDependencies],
    sourceRequirementIds: sourceIds,
    targetRequirementIds: targetIds,
    mappings,
    commits,
    components,
  };
}

function selectedGates(gates, invalidatedGateIds, policyGates) {
  if (!Array.isArray(gates) || gates.length > 128) fail("Composition gates must be an array of at most 128 records");
  const ids = new Set();
  const normalized = gates.map((gate) => {
    exactKeys(gate, "composition gate", ["id", "command", "mandatory", "kind"], ["id", "command", "mandatory"]);
    if (typeof gate.id !== "string" || !gate.id || ids.has(gate.id)) fail("Composition gate IDs must be non-empty and unique");
    ids.add(gate.id);
    if (!Array.isArray(gate.command) || !gate.command.length) fail(`Gate ${gate.id} needs an argv command`);
    if (typeof gate.mandatory !== "boolean") fail(`Gate ${gate.id} mandatory must be a boolean`);
    const kind = gate.kind ?? "test";
    if (!new Set(["test", "security", "release", "build", "lint", "operator"]).has(kind)) fail(`Gate ${gate.id} has unsupported kind ${kind}`);
    return { id: gate.id, command: [...gate.command], mandatory: gate.mandatory === true, kind };
  });
  const invalidated = unique(invalidatedGateIds ?? [], "invalidatedGateIds");
  for (const id of invalidated) if (!ids.has(id)) fail(`Invalidated gate ${id} has no declared command`);
  const byId = new Map(normalized.map((gate) => [gate.id, gate]));
  for (const policyGate of policyGates) {
    const declared = byId.get(policyGate.id);
    if (!declared) fail(`Verified boundary-policy gate ${policyGate.id} has no declared command`);
    if (declared.kind !== policyGate.kind || declared.mandatory !== policyGate.mandatory) fail(`Gate ${policyGate.id} command declaration changed verified boundary-policy kind or mandatory semantics`);
  }
  const selected = new Set([...invalidated, ...normalized.filter((gate) => gate.mandatory || gate.kind === "security" || gate.kind === "release").map((gate) => gate.id)]);
  return normalized.filter((gate) => selected.has(gate.id)).sort((left, right) => left.id.localeCompare(right.id));
}

function requiredAnalyzerForPath(relative) {
  const normalized = relative.toLowerCase();
  const base = path.posix.basename(normalized);
  if (/^\.github\/workflows\/[^/]+\.(?:json|ya?ml)$/u.test(normalized)) return "github-actions";
  if (base === "dockerfile" || base.startsWith("dockerfile.") || /(?:^|\/)(?:oci|image)[^/]*inspection[^/]*\.json$/u.test(normalized)) return "oci";
  if (/(?:^|[._-])openapi(?:[._-]|$)/u.test(base) && /\.(?:json|ya?ml)$/u.test(base)) return "openapi";
  if ((/(?:^|[._-])cloudformation(?:[._-]|$)/u.test(base) || /(?:^|\.)template\.(?:json|ya?ml)$/u.test(base)) && /\.(?:json|ya?ml)$/u.test(base)) return "cloudformation-cdk";
  if (/\.(?:ts|tsx|mts|cts|js|jsx|mjs|cjs)$/u.test(normalized)) return "typescript";
  if (/\.py$/u.test(normalized)) return "python";
  if (/\.go$/u.test(normalized)) return "go";
  if (/\.(?:graphql|gql)$/u.test(normalized)) return "graphql";
  if (/\.sql$/u.test(normalized)) return "sql";
  if (/\.tf(?:\.json)?$/u.test(normalized)) return "terraform";
  return null;
}

function witnessEffectPath(effect, label) {
  const relative = effect.domain === "path" ? effect.subject : effect.domain === undefined ? effect.path : null;
  if (relative === null || relative === undefined) return null;
  try { return portableRelativePath(relative, label); } catch (error) { fail(error.message); }
}

function witnessEffectTransition(effect, label) {
  const after = witnessEffectPath(effect, label);
  if (!after) return null;
  const previous = effect.domain === undefined ? effect.previousPath : undefined;
  if (previous === undefined) return { before: after, after };
  let before;
  try { before = portableRelativePath(previous, `${label} previousPath`); } catch (error) { fail(error.message); }
  return { before, after };
}

function gitBlob(repository, revision, relative) {
  const object = `${revision}:${relative}`;
  if (gitOptional(repository, ["cat-file", "-e", object], { absentStatuses: [128] }) === null) return Buffer.alloc(0);
  return gitBuffer(repository, ["show", object]);
}

function worktreeBlob(worktree, relative) {
  if (hasSymlink(worktree, relative)) fail(`Analyzer subject ${relative} crosses a symbolic link`);
  const file = path.join(worktree, ...relative.split("/"));
  if (!fs.existsSync(file)) return Buffer.alloc(0);
  if (!fs.lstatSync(file).isFile()) fail(`Analyzer subject ${relative} is not a regular file`);
  const value = fs.readFileSync(file);
  if (value.length > 256 * 1024) fail(`Analyzer subject ${relative} exceeds the certified 256 KiB source limit`);
  return value;
}

function verifyAnalyzerCoverage(candidates, repository, baseHead, worktree) {
  const records = [];
  for (const candidate of candidates) {
    const transitions = [...new Map(candidate.witness.payload.body.effects.map((effect, index) => witnessEffectTransition(effect, `Bundle ${candidate.id} effect ${index} path`)).filter(Boolean).map((item) => [`${item.before}\0${item.after}`, item])).values()]
      .sort((left, right) => `${left.before}:${left.after}`.localeCompare(`${right.before}:${right.after}`));
    const requiredByKey = new Map();
    for (const transition of transitions) {
      for (const analyzerId of new Set([requiredAnalyzerForPath(transition.before), requiredAnalyzerForPath(transition.after)].filter(Boolean))) {
        requiredByKey.set(`${analyzerId}\0${transition.before}\0${transition.after}`, { analyzerId, before: transition.before, after: transition.after });
      }
      for (const obligation of candidate.analyzerObligations) {
        if (obligation.path === transition.before || obligation.path === transition.after) requiredByKey.set(`${obligation.analyzerId}\0${transition.before}\0${transition.after}`, { analyzerId: obligation.analyzerId, before: transition.before, after: transition.after });
      }
    }
    const required = [...requiredByKey.values()].sort((left, right) => `${left.analyzerId}:${left.before}:${left.after}`.localeCompare(`${right.analyzerId}:${right.before}:${right.after}`));
    const reports = [];
    const reportKeys = new Set();
    for (const [index, rawReport] of candidate.analyzerReports.entries()) {
      let report;
      try { report = validateAnalyzerReport(rawReport); } catch (error) { fail(`Bundle ${candidate.id} analyzer report ${index} is invalid: ${error.message}`); }
      const beforePath = portableRelativePath(report.subject.before.path, `Bundle ${candidate.id} analyzer report ${index} before path`);
      const afterPath = portableRelativePath(report.subject.after.path, `Bundle ${candidate.id} analyzer report ${index} after path`);
      if (!transitions.some((item) => item.before === beforePath && item.after === afterPath)) fail(`Bundle ${candidate.id} analyzer report ${index} is not bound to an exact changed-path transition`);
      const key = `${report.analyzer.id}\0${beforePath}\0${afterPath}`;
      if (reportKeys.has(key)) fail(`Bundle ${candidate.id} has duplicate analyzer coverage for ${report.analyzer.id}:${afterPath}`);
      reportKeys.add(key);
      const beforeBytes = gitBlob(repository, baseHead, beforePath);
      const afterBytes = worktreeBlob(worktree, afterPath);
      const beforeDigest = `sha256:${sha256(beforeBytes)}`;
      const afterDigest = `sha256:${sha256(afterBytes)}`;
      if (report.subject.before.digest !== beforeDigest || report.subject.after.digest !== afterDigest) fail(`Bundle ${candidate.id} analyzer report ${report.analyzer.id}:${afterPath} is stale for the target composition context`);
      const beforeSource = beforeBytes.toString("utf8");
      const afterSource = afterBytes.toString("utf8");
      if (!Buffer.from(beforeSource, "utf8").equals(beforeBytes) || !Buffer.from(afterSource, "utf8").equals(afterBytes)) fail(`Bundle ${candidate.id} analyzer subject ${afterPath} is not canonical UTF-8 source`);
      let recomputed;
      try {
        recomputed = analyzeCertifiedChange({
          analyzerId: report.analyzer.id,
          before: { path: beforePath, source: beforeSource },
          after: { path: afterPath, source: afterSource },
        });
      } catch (error) {
        fail(`Bundle ${candidate.id} analyzer ${report.analyzer.id}:${afterPath} could not be recomputed: ${error.message}`);
      }
      if (canonicalJson(recomputed) !== canonicalJson(report)) fail(`Bundle ${candidate.id} analyzer report ${report.analyzer.id}:${afterPath} does not match deterministic target-context recomputation`);
      if (report.status !== "ready" || report.compatibility.verdict !== "compatible") fail(`Bundle ${candidate.id} analyzer report ${report.analyzer.id}:${afterPath} does not authorize composition`);
      reports.push({ analyzerId: report.analyzer.id, before: beforePath, after: afterPath, digest: report.digest });
    }
    for (const item of required) if (!reportKeys.has(`${item.analyzerId}\0${item.before}\0${item.after}`)) fail(`Bundle ${candidate.id} is missing required ${item.analyzerId} analyzer evidence for ${item.before} -> ${item.after}`);
    records.push({ candidateId: candidate.id, required, reports: reports.sort((left, right) => `${left.analyzerId}:${left.before}:${left.after}`.localeCompare(`${right.analyzerId}:${right.before}:${right.after}`)) });
  }
  const body = { schemaVersion: "tugboat.composition-analyzer-coverage.v1", records };
  return { ...body, digest: `sha256:${sha256(canonicalJson(body))}` };
}

function writeComponent(worktree, component, missionRelative) {
  const targetPath = portableRelativePath(component.targetPath, "Component target path");
  if (inside(targetPath, missionRelative)) fail(`Component ${targetPath} targets the canonical mission path`);
  if (hasSymlink(worktree, targetPath)) fail(`Component ${targetPath} crosses a symbolic link`);
  const target = path.join(worktree, ...targetPath.split("/"));
  const contents = Buffer.from(component.content, "base64");
  if (fs.existsSync(target)) {
    if (!fs.lstatSync(target).isFile() || `sha256:${sha256(fs.readFileSync(target))}` !== component.digest) fail(`Component ${targetPath} conflicts with composed state`);
    return false;
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents, { mode: 0o600, flag: "wx" });
  return true;
}

function applyOrder({ repository, baseHead, missionRelative, order, byId, root, index, worktree }) {
    git(repository, ["worktree", "add", "--detach", worktree, baseHead]);
    const applied = [];
    const componentApplications = [];
    for (const bundleId of order) {
      const candidate = byId.get(bundleId);
      for (const { commit, index: patchIndex } of candidate.commits) {
        const patchFile = path.join(root, `${index}-${patchIndex}-${sha256(bundleId).slice(0, 16)}.patch`);
        fs.writeFileSync(patchFile, candidate.verified.patches[patchIndex], { mode: 0o600 });
        try {
          git(worktree, ["am", "--3way", "--keep-cr", patchFile]);
        } catch (error) {
          try { git(worktree, ["am", "--abort"]); } catch { /* cleanup removes the worktree */ }
          fail(`Order ${order.join(" -> ")} could not apply bundle ${bundleId} commit ${commit.sha}: ${error.message}`, {
            counterexample: { code: "order_application_failed", order, bundleId, sourceSha: commit.sha, expected: "every dependency-valid order applies completely", actual: "git-format-patch application failed", witnessPath: order.map((id) => `bundle:${id}`) },
          });
        }
        applied.push({ bundleId, sourceSha: commit.sha, targetSha: git(worktree, ["rev-parse", "HEAD"]) });
      }
      const written = [];
      for (const component of candidate.components) {
        const created = writeComponent(worktree, component, missionRelative);
        componentApplications.push({ bundleId, targetPath: component.targetPath, digest: component.digest, status: created ? "applied" : "reconciled" });
        if (created) written.push(component);
      }
      if (written.length) {
        git(worktree, ["add", "--", ...written.map((item) => item.targetPath)]);
        git(worktree, ["commit", "-m", `feat: compose components from ${bundleId}`]);
      }
      const changed = git(worktree, ["diff", "--name-only", "-z", baseHead, "HEAD"]).split("\0").filter(Boolean);
      if (changed.some((file) => inside(file, missionRelative))) fail(`Order ${order.join(" -> ")} changed the canonical mission path ${missionRelative}`);
    }
    const status = git(worktree, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (status) fail(`Order ${order.join(" -> ")} left a dirty disposable worktree: ${status.replaceAll("\n", ", ")}`);
    const head = git(worktree, ["rev-parse", "HEAD"]);
    return { order, worktree, head, observableTreeDigest: trackedContentDigest(worktree, head, missionRelative), applied, componentApplications };
}

function registeredWorktreePaths(repository, root) {
  const prefix = `${path.resolve(root)}${path.sep}`;
  const output = git(repository, ["worktree", "list", "--porcelain"]);
  return output.split("\n").filter((line) => line.startsWith("worktree ")).map((line) => line.slice("worktree ".length)).filter((item) => path.resolve(item).startsWith(prefix));
}

function removeCompositionWorktree(repository, worktree) {
  if (!fs.existsSync(worktree) && !registeredWorktreePaths(repository, path.dirname(worktree)).includes(path.resolve(worktree))) return;
  git(repository, ["worktree", "remove", "--force", worktree]);
}

function runGates(gates, worktree, missionRelative) {
  const results = [];
  for (const gate of gates) {
    const expectedHead = git(worktree, ["rev-parse", "HEAD"]);
    const expectedTree = trackedContentDigest(worktree, expectedHead, missionRelative);
    const result = runBounded(gate.command[0], gate.command.slice(1), {
      cwd: worktree,
      environment: operatorExecutionEnvironment(),
      timeoutMs: 300_000,
      maxOutputBytes: 4 * 1024 * 1024,
    });
    if (result.timedOut) fail(`Gate ${gate.id} timed out`, { counterexample: { code: "gate_timeout", gateId: gate.id, expected: "gate completes within 300000ms", actual: "timeout", witnessPath: [`gate:${gate.id}`] } });
    if (result.exitCode !== 0) fail(`Gate ${gate.id} failed with exit code ${result.exitCode ?? "none"}`, { counterexample: { code: "gate_failed", gateId: gate.id, expected: "exit code 0", actual: `exit code ${result.exitCode ?? "none"}`, witnessPath: [`gate:${gate.id}`] } });
    const status = git(worktree, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (status) fail(`Gate ${gate.id} caused uncommitted validation mutation: ${status.replaceAll("\n", ", ")}`, { counterexample: { code: "validation_mutation", gateId: gate.id, expected: "clean worktree after validation", actual: status.split("\n"), witnessPath: [`gate:${gate.id}`, "worktree:canonical"] } });
    const actualHead = git(worktree, ["rev-parse", "HEAD"]);
    const actualTree = trackedContentDigest(worktree, actualHead, missionRelative);
    if (actualHead !== expectedHead || actualTree !== expectedTree) fail(`Gate ${gate.id} committed or rewrote validation state`, { counterexample: { code: "validation_history_mutation", gateId: gate.id, expected: { head: expectedHead, observableTreeDigest: expectedTree }, actual: { head: actualHead, observableTreeDigest: actualTree }, witnessPath: [`gate:${gate.id}`, "git:head"] } });
    results.push({ id: gate.id, kind: gate.kind, mandatory: gate.mandatory, commandDigest: `sha256:${sha256(canonicalJson(gate.command))}`, exitCode: result.exitCode, stdoutDigest: result.stdoutDigest, stderrDigest: result.stderrDigest });
  }
  return results;
}

function repositoryIdentity(repository) {
  const remote = gitOptional(repository, ["config", "--get", "remote.origin.url"]);
  const roots = git(repository, ["rev-list", "--max-parents=0", "--all"]).split("\n").filter(Boolean).sort().join(":");
  return `sha256:${sha256(remote || roots)}`;
}

function targetStatus(repository, missionRelative) {
  const args = ["status", "--porcelain=v1", "--untracked-files=all"];
  if (missionRelative) args.push("--", ".", `:(exclude)${missionRelative}/.tugboat-lock`);
  return git(repository, args);
}

function targetSnapshot(repository, state, missionRelative) {
  return {
    head: git(repository, ["rev-parse", "HEAD"]),
    branch: git(repository, ["branch", "--show-current"]),
    status: targetStatus(repository, missionRelative),
    missionRevision: state.revision,
  };
}

function assertTargetUnchanged(repository, missionDir, expected) {
  const currentState = verifySnapshot(missionDir, { reducer: missionReducer });
  const actual = targetSnapshot(repository, currentState, relativeMission(repository, missionDir));
  if (actual.head !== expected.head || actual.branch !== expected.branch || actual.status || actual.missionRevision !== expected.missionRevision) {
    fail(`Target changed after composition preparation; prepared result was not applied (${canonicalJson({ expected, actual })})`, { counterexample: { code: "target_drift", expected, actual, witnessPath: ["target:initial", "composition:prepared", "target:final"] } });
  }
  return { headStable: true, branchStable: true, clean: true, missionRevisionStable: true };
}

function eventCandidates(candidates, canonical) {
  return candidates.map((candidate) => ({
    bundleId: candidate.id,
    digest: candidate.verified.digest,
    sourceRequirementIds: candidate.sourceRequirementIds,
    targetRequirementIds: candidate.targetRequirementIds,
    mappings: candidate.mappings,
    appliedCommits: canonical.applied.filter((item) => item.bundleId === candidate.id).map(({ sourceSha, targetSha }) => ({ sourceSha, targetSha })),
    components: candidate.components.map((component) => {
      const application = canonical.componentApplications.find((item) => item.bundleId === candidate.id && item.targetPath === component.targetPath);
      return { targetPath: component.targetPath, digest: component.digest, type: component.type, status: application?.status ?? "reconciled" };
    }),
    source: candidate.verified.payload.source,
  }));
}

function fsyncDirectory(directory, label) {
  let descriptor;
  try {
    descriptor = fs.openSync(directory, "r");
    fs.fsyncSync(descriptor);
  } catch (error) {
    fail(`Could not durably sync ${label} directory ${directory}: ${error.message}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function stageArtifact(file, value) {
  if (!file) return null;
  const absolute = path.resolve(file);
  const temporary = `${absolute}.tmp-${process.pid}-${randomUUID()}`;
  let descriptor;
  try {
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    descriptor = fs.openSync(temporary, "wx", 0o600);
    if (value !== undefined) fs.writeFileSync(descriptor, `${canonicalJson(value)}\n`);
    fs.fsyncSync(descriptor);
    fsyncDirectory(path.dirname(absolute), "certificate staging");
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
    fail(`Could not durably stage certificate artifact ${absolute}: ${error.message}`);
  }
  const identity = fs.fstatSync(descriptor);
  let closed = false;
  let sealed = value !== undefined;
  const close = () => {
    if (!closed) {
      fs.closeSync(descriptor);
      closed = true;
    }
  };
  const assertIdentity = () => {
    const current = fs.lstatSync(temporary);
    if (!current.isFile() || current.isSymbolicLink() || current.dev !== identity.dev || current.ino !== identity.ino) fail(`Certificate staging inode changed before publication: ${temporary}`);
  };
  return {
    absolute,
    temporary,
    seal(nextValue) {
      if (sealed) fail(`Certificate artifact ${absolute} is already sealed`);
      if (closed) fail(`Certificate artifact ${absolute} staging descriptor is closed`);
      assertIdentity();
      fs.ftruncateSync(descriptor, 0);
      fs.writeFileSync(descriptor, `${canonicalJson(nextValue)}\n`);
      fs.fsyncSync(descriptor);
      sealed = true;
    },
    publish() {
      if (!sealed) fail(`Certificate artifact ${absolute} is not sealed`);
      assertIdentity();
      close();
      fs.linkSync(temporary, absolute);
      fsyncDirectory(path.dirname(absolute), "certificate publication");
      fs.unlinkSync(temporary);
    },
    retain() { assertIdentity(); close(); },
    abort() { close(); fs.rmSync(temporary, { force: true }); },
  };
}

function fastForwardCompareAndSwap(repository, missionRelative, expectedHead, expectedBranch, resultHead, resultTree) {
  const observedHead = git(repository, ["rev-parse", "HEAD"]);
  const observedBranch = git(repository, ["branch", "--show-current"]);
  const observedStatus = targetStatus(repository, missionRelative);
  if (observedHead !== expectedHead || observedBranch !== expectedBranch || observedStatus) fail("Target changed before the compare-and-swap fast-forward", {
    counterexample: { code: "target_drift", expected: { head: expectedHead, branch: expectedBranch, status: "clean" }, actual: { head: observedHead, branch: observedBranch, status: observedStatus }, witnessPath: ["target:final", "git:ref-lock"] },
  });
  try {
    git(repository, ["merge", "--ff-only", resultHead]);
  } catch (error) {
    const actualHead = gitOptional(repository, ["rev-parse", "HEAD"]);
    if (actualHead !== expectedHead) return { head: actualHead, status: "recovery_required", reason: `Fast-forward command failed after target movement: ${error.message}` };
    fail(`Atomic fast-forward from ${expectedHead} to ${resultHead} failed: ${error.message}`, {
      counterexample: { code: "fast_forward_race", expected: { oldHead: expectedHead, newHead: resultHead }, actual: { head: actualHead }, witnessPath: ["git:ref-lock", "target:head"] },
    });
  }
  const actualHead = git(repository, ["rev-parse", "HEAD"]);
  const actualBranch = git(repository, ["branch", "--show-current"]);
  const actualTree = git(repository, ["rev-parse", "HEAD^{tree}"]);
  const status = targetStatus(repository, missionRelative);
  if (actualHead !== resultHead || actualBranch !== expectedBranch || actualTree !== resultTree || status) return {
    head: actualHead,
    status: "recovery_required",
    reason: `Post-fast-forward target divergence: expected ${expectedBranch}@${resultHead}/${resultTree} clean; received ${actualBranch || "detached"}@${actualHead}/${actualTree} ${status || "clean"}`,
  };
  return { head: actualHead, status: "complete", reason: null };
}

function physicalWriteTarget(file) {
  const absolute = path.resolve(file);
  const suffix = [];
  let ancestor = absolute;
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) fail(`Cannot resolve certificate output path ${absolute}`);
    suffix.unshift(path.basename(ancestor));
    ancestor = parent;
  }
  return path.join(fs.realpathSync(ancestor), ...suffix);
}

function assertArtifactTarget(repository, file, label) {
  if (!file) return null;
  const absolute = physicalWriteTarget(file);
  const relative = path.relative(fs.realpathSync(repository), absolute);
  const insideRepository = relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
  if (insideRepository) fail(`${label} must be outside the target repository so certificate emission cannot dirty the merged worktree`);
  if (fs.existsSync(absolute)) fail(`${label} already exists; refusing to overwrite an evidence artifact`);
  return absolute;
}

function runComposition(options, execute) {
  assertCanonicalMissionTree(options.missionDir);
  const state = verifySnapshot(options.missionDir, { reducer: missionReducer });
  if (!state?.metadata) fail(`No Tugboat v2 mission in ${options.missionDir}`);
  const repository = state.metadata.worktree;
  assertHermeticRepositoryConfiguration(repository);
  const missionRelative = relativeMission(repository, options.missionDir);
  const initial = targetSnapshot(repository, state, missionRelative);
  if (initial.status) fail("Target worktree must be clean before composition");
  if (initial.branch !== state.metadata.branch) fail(`Target branch ${initial.branch || "detached"} does not match mission branch ${state.metadata.branch}`);
  if (!Array.isArray(options.candidates) || options.candidates.length < 2 || options.candidates.length > MAX_CANDIDATES) fail(`Composition needs 2 to ${MAX_CANDIDATES} candidates so every valid order can be proven`);
  if (!options.actor || typeof options.actor !== "object" || typeof options.actor.name !== "string" || !options.actor.name || typeof options.actor.kind !== "string" || !options.actor.kind || typeof options.actor.runtime !== "string" || !options.actor.runtime) fail("Composition requires an attributed actor with name, kind, and runtime");
  const rollbackAdmission = options.rollbackAdmission ?? { required: false };
  exactKeys(rollbackAdmission, "composition rollbackAdmission", rollbackAdmission.required === true ? ["required", "boundary", "policy", "runtimeEffects"] : ["required"]);
  if (typeof rollbackAdmission.required !== "boolean") fail("Composition rollbackAdmission.required must be a boolean");
  const compositionCertificatePath = assertArtifactTarget(repository, options.compositionCertificatePath, "Composition certificate path");
  const mergeCertificatePath = assertArtifactTarget(repository, options.mergeCertificatePath, "Merge certificate path");
  if (compositionCertificatePath && mergeCertificatePath && compositionCertificatePath === mergeCertificatePath) fail("Composition and merge certificate paths must be different");
  const candidates = options.candidates.map((input) => {
    const verified = readBundle(path.resolve(input.bundlePath), { publicKey: input.publicKey ?? options.publicKey, requireSignature: input.requireSignature ?? options.requireSignature === true });
    return candidateRecord(input, verified, state);
  }).sort((left, right) => left.id.localeCompare(right.id));
  if (new Set(candidates.map((candidate) => candidate.id)).size !== candidates.length) fail("Composition candidate bundle IDs must be unique");
  const policyGates = candidates[0].policyGates;
  for (const candidate of candidates.slice(1)) if (canonicalJson(candidate.policyGates) !== canonicalJson(policyGates)) fail("Composition candidates disagree on the verified boundary-policy gate set or semantics");
  const targetIds = candidates.flatMap((candidate) => candidate.targetRequirementIds);
  if (new Set(targetIds).size !== targetIds.length) fail("Composition candidates may not invalidate the same target requirement");
  const priorBundles = new Set((state.compositions ?? []).flatMap((item) => item.candidates.map((candidate) => candidate.bundleId)));
  for (const promotion of state.promotions ?? []) priorBundles.add(promotion.bundleId);
  for (const candidate of candidates) if (priorBundles.has(candidate.id)) fail(`Bundle ${candidate.id} was already composed into this mission`);
  const algebra = compileBundleAlgebra({ candidates: candidates.map((candidate) => ({ bundle: candidate.verified, witness: candidate.witness, analyzerReports: candidate.analyzerReports })) });
  if (algebra.status !== "ready") fail(`Bundle algebra blocks composition: ${algebra.hazards.map((item) => `${item.code}:${item.subjectIds.join(",")}`).join("; ")}`, { algebra });
  const orders = validOrders(candidates);
  if (!orders.length) fail("Composition has no dependency-valid candidate order");
  const applicationOperationsPerOrder = candidates.reduce((sum, candidate) => sum + candidate.commits.length + candidate.components.length, 0);
  const plannedApplicationOperations = orders.length * applicationOperationsPerOrder;
  if (plannedApplicationOperations > MAX_APPLICATION_OPERATIONS) fail(`Composition requires ${plannedApplicationOperations} application operations, exceeding the ${MAX_APPLICATION_OPERATIONS} operation budget`, {
    resourceUsage: { validOrderCount: orders.length, applicationOperationsPerOrder, plannedApplicationOperations, maxApplicationOperations: MAX_APPLICATION_OPERATIONS },
  });
  const canonicalOrder = algebra.canonicalOrder;
  if (!orders.some((order) => canonicalJson(order) === canonicalJson(canonicalOrder))) fail("Algebra canonical order is not dependency-valid");
  const invalidatedGateIds = [...new Set(candidates.flatMap((candidate) => candidate.invalidation.invalidated.filter((item) => item.kind === "gate").map((item) => item.id)))].sort();
  const gates = selectedGates(options.gates ?? [], invalidatedGateIds, policyGates);
  const generatedAt = normalizeObservedAt(options.generatedAt ?? new Date().toISOString());
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-compose-"));
  const prepared = [];
  const activeWorktrees = new Set();
  let peakConcurrentWorktrees = 0;
  let primaryError;
  let completedOutcome;
  try {
    const byId = new Map(candidates.map((candidate) => [candidate.id, candidate]));
    const executionOrders = [
      ...orders.filter((order) => canonicalJson(order) !== canonicalJson(canonicalOrder)),
      canonicalOrder,
    ];
    let canonical;
    for (let index = 0; index < executionOrders.length; index += 1) {
      const order = executionOrders[index];
      const worktree = path.join(root, `order-${index}`);
      activeWorktrees.add(worktree);
      peakConcurrentWorktrees = Math.max(peakConcurrentWorktrees, activeWorktrees.size);
      const item = applyOrder({ repository, baseHead: initial.head, missionRelative, order, byId, root, index, worktree });
      prepared.push(item);
      if (canonicalJson(order) === canonicalJson(canonicalOrder)) canonical = item;
      else {
        removeCompositionWorktree(repository, worktree);
        activeWorktrees.delete(worktree);
      }
    }
    if (!canonical) fail("Composition did not retain its canonical prepared order");
    const observed = new Set(prepared.map((item) => item.observableTreeDigest));
    if (observed.size !== 1) fail(`Candidate orders diverge in observable state: ${prepared.map((item) => `${item.order.join("->")}:${item.observableTreeDigest}`).join("; ")}`, {
      counterexample: { code: "order_divergence", expected: "one observable tree digest for every dependency-valid order", actual: prepared.map((item) => ({ order: item.order, observableTreeDigest: item.observableTreeDigest })), witnessPath: prepared.map((item) => `order:${item.order.join("->")}`) },
    });
    const analyzerCoverage = verifyAnalyzerCoverage(candidates, repository, initial.head, canonical.worktree);
    const gateResults = runGates(gates, canonical.worktree, missionRelative);
    const raceChecks = assertTargetUnchanged(repository, options.missionDir, initial);
    let rollbackEvidence = null;
    if (rollbackAdmission.required) {
      const forwardCommits = git(repository, ["rev-list", "--reverse", `${initial.head}..${canonical.head}`]).split("\n").filter(Boolean);
      if (!forwardCommits.length || forwardCommits.at(-1) !== canonical.head) fail("Canonical composition did not produce a rollback-provable linear forward range");
      const rollbackProof = proveRollbackEquivalence({
        repository,
        baseRef: initial.head,
        forwardCommits,
        rollback: { mode: "exact_inverse", commits: [] },
        boundary: rollbackAdmission.boundary,
        policy: rollbackAdmission.policy,
        runtimeEffects: rollbackAdmission.runtimeEffects,
        producer: options.actor,
        generatedAt,
      });
      if (rollbackProof.status !== "equivalent") fail(`Rollback-required composition is not admissible: ${rollbackProof.status}`, { rollbackCertificate: rollbackProof.certificate });
      rollbackEvidence = {
        certificate: rollbackProof.certificate,
        digest: rollbackProof.certificate.digest,
        status: rollbackProof.status,
        baseHead: initial.head,
        forwardCommits,
        forwardTip: canonical.head,
        changeDigest: rollbackProof.certificate.payload.body.changeDigest,
      };
    }
    const compositionId = `certificate:composition-${sha256(`${initial.head}:${candidates.map((item) => item.verified.digest).join(":")}`).slice(0, 32)}`;
    const composedFootprint = candidates.flatMap((candidate) => candidate.witness.payload.body.effects.map((effect) => ({ bundleId: candidate.id, ...effect })))
      .sort((left, right) => `${left.bundleId}:${left.id}`.localeCompare(`${right.bundleId}:${right.id}`));
    const mandatoryGateIds = gates.filter((gate) => gate.mandatory || gate.kind === "security" || gate.kind === "release").map((gate) => gate.id).sort();
    const compositionCertificate = createCertifiedEnvelope({
      format: COMPOSITION_SCHEMA,
      payload: {
        id: compositionId,
        generatedAt,
        verdict: "ready",
        subjects: candidates.map((candidate) => ({ kind: "bundle", id: `bundle:${candidate.id}`, digest: candidate.verified.digest })),
        inputs: [
          { kind: "bundle_algebra", id: `algebra:${algebra.digest.slice("sha256:".length, "sha256:".length + 32)}`, digest: algebra.digest },
          { kind: "analyzer_coverage", id: `analyzer-coverage:${analyzerCoverage.digest.slice("sha256:".length, "sha256:".length + 32)}`, digest: analyzerCoverage.digest },
          ...candidates.flatMap((candidate) => [
            { kind: "non_interference_witness", id: `witness:${candidate.id}`, digest: candidate.witness.digest },
            { kind: "proof_invalidation", id: `invalidation:${candidate.id}`, digest: candidate.invalidation.digest },
          ]),
          ...(rollbackEvidence ? [{ kind: "rollback_certificate", id: rollbackEvidence.certificate.payload.id, digest: rollbackEvidence.digest }] : []),
        ],
        producer: options.actor,
        claims: [{
          id: `claim:composition-${compositionId.split("-").at(-1)}`,
          type: "commutativity",
          status: "passed",
          subjectIds: candidates.map((candidate) => `bundle:${candidate.id}`),
          summary: `${prepared.length} dependency-valid order${prepared.length === 1 ? "" : "s"} produced one observable tree and every selected gate passed.`,
        }],
        counterexamples: [],
        body: {
          repositoryIdentity: repositoryIdentity(repository),
          branch: initial.branch,
          baseHead: initial.head,
          missionId: state.metadata.id,
          missionRevision: state.revision,
          algebraDigest: algebra.digest,
          analyzerCoverageDigest: analyzerCoverage.digest,
          candidateDigests: candidates.map((candidate) => ({ id: candidate.id, digest: candidate.verified.digest, witnessDigest: candidate.witness.digest, invalidationDigest: candidate.invalidation.digest })),
          canonicalOrder,
          dependencyDag: candidates.map((candidate) => ({ id: candidate.id, dependencies: [...candidate.dependencies].sort() })),
          pairwiseMatrix: algebra.pairwiseMatrix,
          transitiveHazards: algebra.hazards.filter((hazard) => hazard.code.startsWith("transitive_")),
          composedFootprint,
          canonicalApplications: { commits: canonical.applied, components: canonical.componentApplications },
          orders: orders.map((order) => {
            const item = prepared.find((preparedOrder) => canonicalJson(preparedOrder.order) === canonicalJson(order));
            return { order: item.order, head: item.head, observableTreeDigest: item.observableTreeDigest };
          }),
          observableTreeDigest: prepared[0].observableTreeDigest,
          gates: gateResults,
          invalidatedGateIds,
          mandatoryGateIds,
          rollbackRequired: rollbackAdmission.required,
          rollbackEvidence,
          proofBasis: { everyDependencyValidOrderExecuted: true, orderCount: prepared.length, exactObservableTreeComparison: true, analyzerCoverageComplete: true, invalidatedAndMandatoryGatesPassed: true, targetMutationBeforeAuthorization: false },
          executionAuthorized: true,
        },
      },
    });
    verifyCompositionCertificate(compositionCertificate, { repository });
    const resourceUsage = {
      validOrderCount: prepared.length,
      peakConcurrentWorktrees,
      applicationOperationsPerOrder,
      plannedApplicationOperations,
      maxApplicationOperations: MAX_APPLICATION_OPERATIONS,
    };
    if (!execute) {
      completedOutcome = { dryRun: true, algebra, certificate: compositionCertificate, resourceUsage };
      return completedOutcome;
    }

    const temporaryMission = path.join(canonical.worktree, ...missionRelative.split("/"));
    assertCanonicalMissionTree(temporaryMission);
    const eventPayload = {
      compositionId: compositionCertificate.payload.id,
      certificateDigest: compositionCertificate.digest,
      canonicalOrder,
      candidates: eventCandidates(candidates, canonical),
      targetContentDigest: canonical.observableTreeDigest,
      gates: gateResults,
      ...(rollbackEvidence ? { rollbackEvidence: { digest: rollbackEvidence.digest, status: rollbackEvidence.status, changeDigest: rollbackEvidence.changeDigest, baseHead: rollbackEvidence.baseHead, forwardTip: rollbackEvidence.forwardTip } } : {}),
      sliceProgressionVersion: 1,
    };
    const appended = appendEvent(temporaryMission, {
      type: "COMPOSITION_MERGED",
      actor: options.actor,
      timestamp: generatedAt,
      payload: eventPayload,
    }, { reducer: missionReducer, expectedRevision: state.revision, currentHead: canonical.head });
    renderMission(temporaryMission, appended.state);
    git(canonical.worktree, ["add", "--", missionRelative]);
    git(canonical.worktree, [
      "commit",
      "-m", `chore(tugboat): record composition ${compositionCertificate.payload.id}`,
      "-m", `Tugboat-Composition: ${compositionCertificate.digest}\nTugboat-Event: ${appended.event.hash}`,
    ]);
    const resultHead = git(canonical.worktree, ["rev-parse", "HEAD"]);
    const resultParentHead = git(canonical.worktree, ["rev-parse", "HEAD^"]);
    if (resultParentHead !== canonical.head) fail("Composition mission commit is not a single child of the canonical prepared order");
    const resultTree = git(canonical.worktree, ["rev-parse", "HEAD^{tree}"]);
    const resultTreeDigest = `sha256:${sha256(resultTree)}`;
    const gitObjectProof = buildGitObjectProof(canonical.worktree, resultHead);
    completedOutcome = withMissionLock(options.missionDir, () => {
      const finalRaceChecks = assertTargetUnchanged(repository, options.missionDir, initial);
      const mergeSuffix = sha256(`${compositionCertificate.digest}:${resultHead}`).slice(0, 32);
      const compositionVerification = verifyCompositionCertificate(compositionCertificate, { repository });
      const proofGraphDigest = proofGraphDigestFor(compositionVerification);
      const mergeEnvelopeInput = (authorized) => ({
        format: MERGE_SCHEMA,
        payload: {
          id: `certificate:merge-${mergeSuffix}`,
          generatedAt,
          verdict: authorized ? "ready" : "insufficient_evidence",
          subjects: [{ kind: "git_tree", id: `git_tree:${resultTree}`, digest: resultTreeDigest }],
          inputs: [{ kind: "composition_certificate", id: compositionCertificate.payload.id, digest: compositionCertificate.digest }],
          producer: options.actor,
          claims: [{ id: `claim:merge-${mergeSuffix}`, type: "merge_integrity", status: authorized ? "passed" : "indeterminate", subjectIds: [`git_tree:${resultTree}`], summary: authorized ? "The admitted composition passed target-context gates and advanced the target by exactly one fast-forward." : "Certificate size and structure preflight only; no target advancement is claimed." }],
          counterexamples: [],
          body: {
            compositionCertificateDigest: compositionCertificate.digest,
            baseHead: initial.head,
            resultHead,
            resultTree,
            resultTreeDigest,
            branch: initial.branch,
            missionRevisionBefore: state.revision,
            missionRevisionAfter: appended.state.revision,
            canonicalPreparedHead: canonical.head,
            resultParentHead,
            missionPath: missionRelative,
            missionEvent: appended.event,
            gitObjectProof,
            fastForwardOnly: true,
            raceChecks: { ...raceChecks, ...finalRaceChecks, resultHeadMatched: authorized },
            eventType: "COMPOSITION_MERGED",
            gateOutputs: gateResults,
            proofGraphDigest,
            executionAuthorized: authorized,
          },
        },
      });
      createCertifiedEnvelope(mergeEnvelopeInput(false));
      const stagedArtifacts = [];
      try {
        const stagedComposition = stageArtifact(compositionCertificatePath, compositionCertificate);
        if (stagedComposition) stagedArtifacts.push({ kind: "composition", artifact: stagedComposition });
        const stagedMerge = stageArtifact(mergeCertificatePath, undefined);
        if (stagedMerge) stagedArtifacts.push({ kind: "merge", artifact: stagedMerge });
      } catch (error) {
        for (const item of stagedArtifacts) item.artifact.abort();
        throw error;
      }
      let targetAdvance;
      try {
        targetAdvance = fastForwardCompareAndSwap(repository, missionRelative, initial.head, initial.branch, resultHead, resultTree);
      } catch (error) {
        for (const item of stagedArtifacts) item.artifact.abort();
        throw error;
      }
      if (targetAdvance.status !== "complete") {
        const artifacts = [];
        for (const item of stagedArtifacts) {
          if (item.kind === "merge") item.artifact.abort();
          else {
            item.artifact.retain();
            artifacts.push({ kind: item.kind, path: item.artifact.absolute, status: "staged", recoveryPath: item.artifact.temporary });
          }
        }
        return {
          dryRun: false,
          status: "recovery_required",
          baseHead: initial.head,
          head: targetAdvance.head,
          canonicalOrder,
          compositionCertificate,
          mergeCertificate: null,
          gates: gateResults,
          resourceUsage,
          evidenceEmission: { status: "recovery_required", reason: targetAdvance.reason, artifacts },
        };
      }
      let mergeCertificate;
      try {
        mergeCertificate = createCertifiedEnvelope(mergeEnvelopeInput(true));
        verifyMergeCertificate(mergeCertificate, { compositionCertificate, repository });
        stagedArtifacts.find((item) => item.kind === "merge")?.artifact.seal(mergeCertificate);
      } catch (error) {
        const artifacts = [];
        for (const item of stagedArtifacts) {
          if (item.kind === "merge") item.artifact.abort();
          else {
            item.artifact.retain();
            artifacts.push({ kind: item.kind, path: item.artifact.absolute, status: "staged", recoveryPath: item.artifact.temporary });
          }
        }
        return {
          dryRun: false,
          status: "recovery_required",
          baseHead: initial.head,
          head: targetAdvance.head,
          canonicalOrder,
          compositionCertificate,
          mergeCertificate: null,
          gates: gateResults,
          resourceUsage,
          evidenceEmission: { status: "recovery_required", reason: `Merge certificate finalization failed after target advancement: ${error.message}`, artifacts },
        };
      }
      const evidenceEmission = { status: "complete", artifacts: [] };
      for (const item of stagedArtifacts) {
        try {
          item.artifact.publish();
          evidenceEmission.artifacts.push({ kind: item.kind, path: item.artifact.absolute, status: "published" });
        } catch (error) {
          evidenceEmission.status = "recovery_required";
          evidenceEmission.artifacts.push({ kind: item.kind, path: item.artifact.absolute, status: "staged", recoveryPath: item.artifact.temporary, error: error.message });
        }
      }
      return {
        dryRun: false,
        status: evidenceEmission.status,
        baseHead: initial.head,
        head: targetAdvance.head,
        canonicalOrder,
        compositionCertificate,
        mergeCertificate,
        gates: gateResults,
        resourceUsage,
        evidenceEmission,
      };
    });
    return completedOutcome;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    const cleanupErrors = [];
    let registered = [];
    try { registered = registeredWorktreePaths(repository, root); } catch (error) { cleanupErrors.push(`list worktrees before cleanup: ${error.message}`); }
    const cleanupPaths = new Set([...activeWorktrees, ...registered]);
    for (const worktree of cleanupPaths) {
      try { removeCompositionWorktree(repository, worktree); } catch (error) { cleanupErrors.push(`remove ${worktree}: ${error.message}`); }
    }
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (error) { cleanupErrors.push(`remove temporary root ${root}: ${error.message}`); }
    try { git(repository, ["worktree", "prune"]); } catch (error) { cleanupErrors.push(`prune worktrees: ${error.message}`); }
    let unresolved = [];
    try { unresolved = registeredWorktreePaths(repository, root); } catch (error) { cleanupErrors.push(`list worktrees after cleanup: ${error.message}`); }
    if (fs.existsSync(root)) cleanupErrors.push(`temporary root still exists: ${root}`);
    if (unresolved.length) cleanupErrors.push(`stale worktree registrations: ${unresolved.join(", ")}`);
    if (cleanupErrors.length) {
      const details = { cleanupFailures: cleanupErrors, recoveryRequired: true };
      if (primaryError) primaryError.details = { ...(primaryError.details ?? {}), ...details };
      else if (completedOutcome && !completedOutcome.dryRun) {
        completedOutcome.status = "recovery_required";
        completedOutcome.evidenceEmission = {
          ...(completedOutcome.evidenceEmission ?? {}),
          status: "recovery_required",
          reason: `Composition result is preserved at ${completedOutcome.head ?? "unknown head"}, but disposable-worktree cleanup needs operator recovery.`,
          cleanupFailures: cleanupErrors,
        };
      } else fail("Composition cleanup was incomplete; operator recovery is required", {
        ...details,
        phase: "post-proof cleanup",
        certificateDigest: completedOutcome?.certificate?.digest ?? null,
      });
    }
  }
}

export function planComposition(options) {
  return runComposition(options, false);
}

export function composeBundles(options) {
  return runComposition(options, true);
}
