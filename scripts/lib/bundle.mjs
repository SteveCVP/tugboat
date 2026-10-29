import { execFileSync } from "node:child_process";
import { createPublicKey, randomUUID, sign, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { assertNoSecrets, assertNoSecretsInBuffer } from "./security.mjs";
import { readState } from "./store.mjs";

export const BUNDLE_LIMITS = Object.freeze({
  maxComponentBytes: 25 * 1024 * 1024,
  maxBundleBytes: 50 * 1024 * 1024,
  maxEnvelopeBytes: 80 * 1024 * 1024,
  maxCommits: 64,
  maxComponents: 128,
});

const COMPONENT_TYPES = new Set([
  "code", "ui", "image", "document", "schema", "infrastructure", "prompt", "evaluation",
  "browser-evidence", "deployment-attestation",
]);

export class BundleValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "BundleValidationError";
    this.exitCode = 3;
  }
}

function fail(message) {
  throw new BundleValidationError(message);
}

function assertBundleNoSecrets(value, label) {
  try {
    assertNoSecrets(value, label);
  } catch (error) {
    fail(error.message);
  }
}

function assertBundleNoSecretsInBuffer(value, label) {
  try {
    assertNoSecretsInBuffer(value, label);
  } catch (error) {
    fail(error.message);
  }
}

function nonEmptyString(value, label) {
  if (typeof value !== "string" || !value.trim()) fail(`${label} must be a non-empty string`);
  return value;
}

function stringList(value, label, { allowEmpty = true } = {}) {
  if (!Array.isArray(value) || (!allowEmpty && !value.length)) fail(`${label} must be ${allowEmpty ? "an array" : "a non-empty array"}`);
  for (const item of value) nonEmptyString(item, `${label} item`);
  if (new Set(value).size !== value.length) fail(`${label} must not contain duplicates`);
  return value;
}

function objectValue(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

function digestValue(value, label) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value)) fail(`${label} must be a SHA-256 digest`);
  return value;
}

function gitOid(value, label) {
  if (typeof value !== "string" || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value)) fail(`${label} must be a full Git object ID`);
  return value;
}

function git(cwd, args, { buffer = false } = {}) {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: buffer ? null : "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 128 * 1024 * 1024,
    });
  } catch (error) {
    const detail = error.stderr?.toString().trim() || error.message;
    fail(`Git command failed: git ${args.join(" ")}: ${detail}`);
  }
}

function fullCommit(repo, value) {
  return git(repo, ["rev-parse", "--verify", `${value}^{commit}`]).trim();
}

function normalizedRelative(value, label = "component path") {
  if (typeof value !== "string" || !value.trim()) fail(`${label} must be a non-empty relative path`);
  if (/[\u0000-\u001f\u007f]/.test(value)) fail(`${label} may not contain control characters`);
  const portable = value.replaceAll("\\", "/");
  if (path.isAbsolute(value) || /^[A-Za-z]:\//.test(portable) || portable.startsWith("/")) fail(`${label} must be relative`);
  const segments = portable.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) fail(`${label} is unsafe: ${value}`);
  if (segments.some((segment) => segment.toLowerCase() === ".git")) fail(`${label} may not target Git internals`);
  return segments.join("/");
}

function decodeBase64(value, label) {
  if (typeof value !== "string") fail(`${label} content is not base64 text`);
  const buffer = Buffer.from(value, "base64");
  if (buffer.toString("base64") !== value) fail(`${label} content is not canonical base64`);
  return buffer;
}

function sourcePathLabel(repo, absolute) {
  const relative = path.relative(repo, absolute);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative.replaceAll(path.sep, "/") : path.basename(absolute);
}

function componentFromInput(repo, input, selectedIds, limits) {
  if (!COMPONENT_TYPES.has(input.type)) fail(`Unsupported component type ${input.type}`);
  const targetPath = normalizedRelative(input.targetPath);
  const sourcePath = path.resolve(repo, input.sourcePath);
  let stat;
  try {
    stat = fs.lstatSync(sourcePath);
  } catch {
    fail(`Component source does not exist: ${input.sourcePath}`);
  }
  if (stat.isSymbolicLink()) fail(`Component source may not be a symbolic link: ${input.sourcePath}`);
  if (!stat.isFile()) fail(`Component source is not a file: ${input.sourcePath}`);
  if (stat.size > limits.maxComponentBytes) fail(`Component exceeds ${limits.maxComponentBytes} bytes: ${input.sourcePath}`);
  const requirementIds = [...new Set(input.requirementIds ?? [])].sort();
  if (!requirementIds.length) fail(`Component ${targetPath} needs requirement IDs`);
  for (const id of requirementIds) if (!selectedIds.has(id)) fail(`Component ${targetPath} references unselected requirement ${id}`);
  const contents = fs.readFileSync(sourcePath);
  assertBundleNoSecretsInBuffer(contents, `component ${targetPath}`);
  return {
    type: input.type,
    label: input.label ?? path.basename(targetPath),
    sourcePath: sourcePathLabel(repo, sourcePath),
    targetPath,
    requirementIds,
    encoding: "base64",
    size: contents.length,
    digest: `sha256:${sha256(contents)}`,
    content: contents.toString("base64"),
  };
}

function commitMetadata(repo, sha) {
  const fields = git(repo, ["show", "-s", "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%s", sha]).trimEnd().split("\0");
  return {
    sha: fields[0],
    parents: fields[1].split(" ").filter(Boolean),
    author: { name: fields[2], email: fields[3] },
    authoredAt: fields[4],
    subject: fields.slice(5).join("\0"),
  };
}

function orderedCommits(repo, values) {
  const commits = (values ?? []).map((value) => commitMetadata(repo, fullCommit(repo, value)));
  for (const item of commits) if (item.parents.length !== 1) fail(`Bundle commits must be linear non-merge commits: ${item.sha}`);
  for (let index = 1; index < commits.length; index += 1) {
    if (commits[index].parents[0] !== commits[index - 1].sha) fail("Bundle commits must be supplied in linear parent order");
  }
  return commits;
}

function patchForCommit(repo, commit, excludedPath) {
  const args = ["format-patch", "--stdout", "--binary", "--no-stat", "--full-index", `${commit.parents[0]}..${commit.sha}`, "--", "."];
  if (excludedPath) args.push(`:(exclude)${excludedPath}`);
  return git(repo, args, { buffer: true });
}

function associateCommits(repo, commits, mapping, selectedRequirementIds) {
  if (!mapping) return commits.map((item) => ({ ...item, requirementIds: [...selectedRequirementIds] }));
  const resolved = new Map();
  for (const [commit, requirementIds] of Object.entries(mapping)) resolved.set(fullCommit(repo, commit), requirementIds);
  for (const sha of resolved.keys()) if (!commits.some((item) => item.sha === sha)) fail(`Commit requirement map references unselected commit ${sha}`);
  if (commits.some((item) => !resolved.has(item.sha))) fail("Commit requirement map must map every commit");
  return commits.map((item) => {
    const requirementIds = [...new Set(resolved.get(item.sha) ?? [])].sort();
    if (!requirementIds.length) fail(`Commit ${item.sha} needs at least one requirement ID`);
    for (const id of requirementIds) if (!selectedRequirementIds.includes(id)) fail(`Commit ${item.sha} references unselected requirement ${id}`);
    return { ...item, requirementIds };
  });
}

function evidenceSummary(evidence, selectedIds) {
  return {
    id: evidence.id,
    kind: evidence.kind,
    requirementIds: [...evidence.requirementIds].filter((id) => selectedIds.has(id)).sort(),
    capturedAt: evidence.capturedAt,
    git: evidence.git,
    verification: evidence.verification,
    digest: `sha256:${sha256(canonicalJson(evidence))}`,
  };
}

function fingerprint(publicKey) {
  const key = publicKey?.type === "public" ? publicKey : createPublicKey(publicKey);
  const der = key.export({ type: "spki", format: "der" });
  return `sha256:${sha256(der)}`;
}

function writeAtomic(file, contents) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.tmp-${process.pid}-${randomUUID()}`;
  try {
    fs.writeFileSync(temp, contents, { mode: 0o600, flag: "wx" });
    fs.renameSync(temp, file);
  } finally {
    fs.rmSync(temp, { force: true });
  }
}

export function trackedContentDigest(repo, ref, excludedPath) {
  const excluded = excludedPath ? normalizedRelative(excludedPath, "excluded path") : null;
  const lines = git(repo, ["ls-tree", "-r", "--full-tree", fullCommit(repo, ref)]).trimEnd().split("\n").filter(Boolean);
  const retained = lines.filter((line) => {
    const file = line.slice(line.indexOf("\t") + 1);
    return !excluded || (file !== excluded && !file.startsWith(`${excluded}/`));
  });
  return `sha256:${sha256(retained.join("\n"))}`;
}

export function createBundle(options) {
  const state = readState(options.missionDir);
  if (!state?.metadata) fail(`No Tugboat v2 mission in ${options.missionDir}`);
  const repo = state.metadata.worktree;
  const missionRelative = normalizedRelative(path.relative(repo, options.missionDir).replaceAll(path.sep, "/"), "mission path");
  const requirementIds = [...new Set(options.requirementIds ?? [])].sort();
  if (!requirementIds.length) fail("Bundle needs at least one requirement ID");
  for (const id of requirementIds) if (!state.requirements[id]) fail(`Unknown requirement ${id}`);
  const selectedIds = new Set(requirementIds);
  const limits = { ...BUNDLE_LIMITS, ...(options.limits ?? {}) };
  if ((options.commitShas ?? []).length > limits.maxCommits) fail(`Bundle exceeds ${limits.maxCommits} commits`);
  if ((options.components ?? []).length > limits.maxComponents) fail(`Bundle exceeds ${limits.maxComponents} components`);
  const commits = associateCommits(repo, orderedCommits(repo, options.commitShas), options.commitRequirements, requirementIds);
  if (!commits.length && !(options.components ?? []).length) fail("Bundle needs commits or components");
  const baseSha = commits[0]?.parents[0] ?? fullCommit(repo, "HEAD");
  const tipSha = commits.at(-1)?.sha ?? baseSha;
  const patches = commits.map((commit) => {
    const contents = patchForCommit(repo, commit, missionRelative);
    assertBundleNoSecretsInBuffer(contents, `bundle patch ${commit.sha}`);
    return {
      sourceSha: commit.sha,
      requirementIds: [...commit.requirementIds],
      format: "git-format-patch",
      encoding: "base64",
      size: contents.length,
      digest: `sha256:${sha256(contents)}`,
      content: contents.toString("base64"),
    };
  });
  const components = (options.components ?? []).map((item) => componentFromInput(repo, item, selectedIds, limits));
  const totalBytes = patches.reduce((sum, item) => sum + item.size, 0) + components.reduce((sum, item) => sum + item.size, 0);
  if (totalBytes > limits.maxBundleBytes) fail(`Bundle exceeds ${limits.maxBundleBytes} bytes of decoded content`);
  const evidence = Object.values(state.evidence)
    .filter((item) => item.requirementIds.some((id) => selectedIds.has(id)))
    .map((item) => evidenceSummary(item, selectedIds))
    .sort((left, right) => left.id.localeCompare(right.id));
  const slices = Object.values(state.slices).filter((slice) => slice.requirementIds.some((id) => selectedIds.has(id)));
  const payload = {
    id: options.id,
    createdAt: options.createdAt ?? new Date().toISOString(),
    actor: options.actor,
    source: {
      missionId: state.metadata.id,
      protocolVersion: state.protocolVersion,
      missionRevision: state.revision,
      branch: state.metadata.branch,
      sourceDigest: state.metadata.source.digest,
      baseSha,
      tipSha,
      contentDigest: trackedContentDigest(repo, tipSha, missionRelative),
    },
    selection: {
      requirements: requirementIds.map((id) => ({ ...state.requirements[id] })),
      preservations: Object.values(state.preservations).map((item) => ({ ...item })),
      sliceDependencies: [...new Set(slices.flatMap((slice) => slice.dependencies ?? []))].sort(),
      bundleDependencies: [...new Set(options.dependsOn ?? [])].sort(),
    },
    commits,
    patches,
    components,
    evidence,
  };
  if (!payload.id || !payload.actor?.name) fail("Bundle needs an ID and actor");
  assertBundleNoSecrets({ ...payload, patches: payload.patches.map((item) => ({ ...item, content: "[BODY]" })), components: payload.components.map((item) => ({ ...item, content: "[BODY]" })) }, "bundle manifest");
  const body = canonicalJson(payload);
  const envelope = {
    schemaVersion: 1,
    format: "tugboat.bundle",
    payload,
    digest: `sha256:${sha256(body)}`,
  };
  if (options.privateKey) {
    const publicKey = createPublicKey(options.privateKey);
    envelope.signature = {
      algorithm: "ed25519",
      keyFingerprint: fingerprint(publicKey),
      value: sign(null, Buffer.from(body), options.privateKey).toString("base64"),
    };
  }
  validateEnvelope(envelope, { limits });
  if (options.outputPath) writeAtomic(path.resolve(options.outputPath), `${canonicalJson(envelope)}\n`);
  return envelope;
}

function validateEnvelope(envelope, policy = {}) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) fail("Bundle envelope must be an object");
  if (envelope.schemaVersion !== 1 || envelope.format !== "tugboat.bundle") fail("Unsupported bundle schema or format");
  const payload = objectValue(envelope.payload, "Bundle payload");
  nonEmptyString(payload.id, "Bundle ID");
  if (typeof payload.createdAt !== "string" || Number.isNaN(Date.parse(payload.createdAt))) fail("Bundle createdAt must be an ISO-compatible timestamp");
  const actor = objectValue(payload.actor, "Bundle actor");
  nonEmptyString(actor.name, "Bundle actor name");
  const source = objectValue(payload.source, "Bundle source");
  nonEmptyString(source.missionId, "Bundle source missionId");
  nonEmptyString(source.protocolVersion, "Bundle source protocolVersion");
  if (!Number.isInteger(source.missionRevision) || source.missionRevision < 1) fail("Bundle source missionRevision must be a positive integer");
  nonEmptyString(source.branch, "Bundle source branch");
  digestValue(source.sourceDigest, "Bundle source digest");
  gitOid(source.baseSha, "Bundle source baseSha");
  gitOid(source.tipSha, "Bundle source tipSha");
  digestValue(source.contentDigest, "Bundle source contentDigest");
  const selection = objectValue(payload.selection, "Bundle selection");
  if (!Array.isArray(selection.requirements) || !selection.requirements.length) fail("Bundle selection requirements must be a non-empty array");
  const selectedRequirementIds = selection.requirements.map((item, index) => nonEmptyString(objectValue(item, `Bundle requirement ${index}`).id, `Bundle requirement ${index} ID`));
  if (new Set(selectedRequirementIds).size !== selectedRequirementIds.length) fail("Bundle requirement IDs must be unique");
  const selectedIds = new Set(selectedRequirementIds);
  if (!Array.isArray(selection.preservations)) fail("Bundle selection preservations must be an array");
  const preservationIds = selection.preservations.map((item, index) => nonEmptyString(objectValue(item, `Bundle preservation ${index}`).id, `Bundle preservation ${index} ID`));
  if (new Set(preservationIds).size !== preservationIds.length) fail("Bundle preservation IDs must be unique");
  stringList(selection.sliceDependencies, "Bundle slice dependencies");
  stringList(selection.bundleDependencies, "Bundle dependencies");
  if (!Array.isArray(payload.commits) || !Array.isArray(payload.patches) || !Array.isArray(payload.components) || !Array.isArray(payload.evidence)) fail("Bundle payload commit, patch, component, and evidence collections must be arrays");
  const body = canonicalJson(payload);
  if (envelope.digest !== `sha256:${sha256(body)}`) fail("Bundle payload digest mismatch");
  const limits = { ...BUNDLE_LIMITS, ...(policy.limits ?? {}) };
  if (payload.commits.length > limits.maxCommits) fail(`Bundle exceeds ${limits.maxCommits} commits`);
  if (payload.components.length > limits.maxComponents) fail(`Bundle exceeds ${limits.maxComponents} components`);
  if (payload.patches.length !== payload.commits.length) fail("Bundle needs exactly one patch per commit");
  payload.commits.forEach((item, index) => {
    objectValue(item, `Bundle commit ${index}`);
    gitOid(item.sha, `Bundle commit ${index} SHA`);
    const parents = stringList(item.parents, `Bundle commit ${item.sha} parents`, { allowEmpty: false });
    if (parents.length !== 1) fail(`Bundle commit ${item.sha} must have exactly one parent`);
    gitOid(parents[0], `Bundle commit ${item.sha} parent`);
    if (index > 0 && parents[0] !== payload.commits[index - 1].sha) fail("Bundle commits must be in linear parent order");
    const requirementIds = stringList(item.requirementIds, `Bundle commit ${item.sha} requirement IDs`, { allowEmpty: false });
    for (const id of requirementIds) if (!selectedIds.has(id)) fail(`Bundle commit ${item.sha} references unselected requirement ${id}`);
  });
  let totalBytes = 0;
  const patches = payload.patches.map((item, index) => {
    objectValue(item, `Bundle patch ${index}`);
    const commit = payload.commits[index];
    if (item.sourceSha !== commit?.sha) fail("Bundle patches must match commit order");
    if (item.format !== "git-format-patch" || item.encoding !== "base64") fail(`Bundle patch ${item.sourceSha} has unsupported format or encoding`);
    const patchRequirementIds = stringList(item.requirementIds, `Bundle patch ${item.sourceSha} requirement IDs`, { allowEmpty: false });
    if (canonicalJson(patchRequirementIds) !== canonicalJson(commit.requirementIds)) fail(`Bundle patch requirement IDs do not match commit ${item.sourceSha}`);
    const patch = decodeBase64(item.content, `patch ${item.sourceSha}`);
    if (item.size !== patch.length || item.digest !== `sha256:${sha256(patch)}`) fail(`Bundle patch digest or size mismatch: ${item.sourceSha}`);
    assertBundleNoSecretsInBuffer(patch, `bundle patch ${item.sourceSha}`);
    totalBytes += patch.length;
    return patch;
  });
  const componentTargets = new Set();
  for (const [index, item] of payload.components.entries()) {
    objectValue(item, `Bundle component ${index}`);
    if (!COMPONENT_TYPES.has(item.type)) fail(`Unsupported component type ${item.type}`);
    const targetPath = normalizedRelative(item.targetPath);
    if (componentTargets.has(targetPath)) fail(`Bundle component target paths must be unique; duplicate target ${targetPath}`);
    componentTargets.add(targetPath);
    const requirementIds = stringList(item.requirementIds, `Bundle component ${targetPath} requirement IDs`, { allowEmpty: false });
    for (const id of requirementIds) if (!selectedIds.has(id)) fail(`Bundle component ${targetPath} references unselected requirement ${id}`);
    if (item.encoding !== "base64") fail(`Bundle component ${targetPath} has unsupported encoding`);
    const contents = decodeBase64(item.content, `component ${item.targetPath}`);
    if (contents.length > limits.maxComponentBytes) fail(`Component exceeds ${limits.maxComponentBytes} bytes: ${item.targetPath}`);
    if (item.size !== contents.length || item.digest !== `sha256:${sha256(contents)}`) fail(`Component digest or size mismatch: ${item.targetPath}`);
    assertBundleNoSecretsInBuffer(contents, `component ${item.targetPath}`);
    totalBytes += contents.length;
  }
  if (totalBytes > limits.maxBundleBytes) fail(`Bundle exceeds ${limits.maxBundleBytes} bytes of decoded content`);
  for (const [index, item] of payload.evidence.entries()) {
    objectValue(item, `Bundle evidence ${index}`);
    nonEmptyString(item.id, `Bundle evidence ${index} ID`);
    nonEmptyString(item.kind, `Bundle evidence ${item.id} kind`);
    const requirementIds = stringList(item.requirementIds, `Bundle evidence ${item.id} requirement IDs`, { allowEmpty: false });
    for (const id of requirementIds) if (!selectedIds.has(id)) fail(`Bundle evidence ${item.id} references unselected requirement ${id}`);
    objectValue(item.verification, `Bundle evidence ${item.id} verification`);
    nonEmptyString(item.verification.status, `Bundle evidence ${item.id} verification status`);
    digestValue(item.digest, `Bundle evidence ${item.id} digest`);
  }
  assertBundleNoSecrets({ ...payload, patches: payload.patches.map((item) => ({ ...item, content: "[BODY]" })), components: payload.components.map((item) => ({ ...item, content: "[BODY]" })) }, "bundle manifest");
  let signatureStatus = envelope.signature ? "unverified" : "unsigned";
  if (envelope.signature && envelope.signature.algorithm !== "ed25519") fail(`Unsupported signature algorithm ${envelope.signature.algorithm}`);
  if (envelope.signature) {
    digestValue(envelope.signature.keyFingerprint, "Bundle signature key fingerprint");
    decodeBase64(envelope.signature.value, "signature");
  }
  if (policy.publicKey) {
    if (!envelope.signature) fail("Bundle signature is required for public-key verification");
    if (envelope.signature.keyFingerprint !== fingerprint(policy.publicKey)) fail("Bundle signature key fingerprint does not match the trusted key");
    const valid = verify(null, Buffer.from(body), policy.publicKey, decodeBase64(envelope.signature.value, "signature"));
    if (!valid) fail("Bundle signature verification failed");
    signatureStatus = "verified";
  }
  if (policy.requireSignature && signatureStatus !== "verified") fail("Bundle requires a signature verified by an explicit trusted public key");
  return { envelope, payload, digest: envelope.digest, signatureStatus, patches };
}

export function verifyBundleEnvelope(envelope, policy = {}) {
  return validateEnvelope(envelope, policy);
}

export function readBundle(file, policy = {}) {
  let envelope;
  try {
    const limits = { ...BUNDLE_LIMITS, ...(policy.limits ?? {}) };
    if (fs.statSync(file).size > limits.maxEnvelopeBytes) fail(`Bundle envelope exceeds ${limits.maxEnvelopeBytes} bytes`);
    envelope = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    if (error instanceof BundleValidationError) throw error;
    fail(`Cannot read bundle ${file}: ${error.message}`);
  }
  return { ...validateEnvelope(envelope, policy), file: path.resolve(file) };
}

export function inspectBundle(verified) {
  const payload = verified.payload;
  const componentTypes = {};
  for (const item of payload.components) componentTypes[item.type] = (componentTypes[item.type] ?? 0) + 1;
  return {
    id: payload.id,
    digest: verified.digest,
    createdAt: payload.createdAt,
    actor: payload.actor,
    source: payload.source,
    requirementIds: payload.selection.requirements.map((item) => item.id),
    preservationIds: payload.selection.preservations.map((item) => item.id),
    sliceDependencies: payload.selection.sliceDependencies,
    dependencies: payload.selection.bundleDependencies,
    commits: payload.commits.map(({ sha, parents, author, authoredAt, subject }) => ({ sha, parents, author, authoredAt, subject })),
    components: payload.components.map(({ type, label, sourcePath, targetPath, requirementIds, size, digest }) => ({ type, label, sourcePath, targetPath, requirementIds, size, digest })),
    componentTypes: Object.fromEntries(Object.entries(componentTypes).sort(([left], [right]) => left.localeCompare(right))),
    evidence: payload.evidence.map(({ id, kind, requirementIds, capturedAt, git, verification, digest }) => ({ id, kind, requirementIds, capturedAt, git, verification, digest })),
    signature: { status: verified.signatureStatus, keyFingerprint: verified.envelope.signature?.keyFingerprint ?? null },
  };
}

function groupedRows(items, keyOf, ownerOf, rowOf) {
  const groups = new Map();
  for (const item of items) {
    const key = keyOf(item);
    const group = groups.get(key) ?? [];
    group.push({ owner: ownerOf(item), value: rowOf(item) });
    groups.set(key, group);
  }
  return [...groups.entries()].sort(([left], [right]) => left.localeCompare(right));
}

export function compareBundles(verifiedBundles) {
  if (!Array.isArray(verifiedBundles) || verifiedBundles.length < 2) fail("Bundle comparison needs at least two candidates");
  const summaries = verifiedBundles.map(inspectBundle).sort((left, right) => left.id.localeCompare(right.id));
  if (new Set(summaries.map((item) => item.id)).size !== summaries.length) fail("Bundle comparison requires unique candidate IDs");
  const requirements = groupedRows(
    summaries.flatMap((summary) => summary.requirementIds.map((id) => ({ id, owner: summary.id }))),
    (item) => item.id,
    (item) => item.owner,
    () => null,
  ).map(([id, rows]) => ({ id, candidates: rows.map((item) => item.owner).sort() }));
  const dependencies = groupedRows(
    summaries.flatMap((summary) => summary.dependencies.map((id) => ({ id, owner: summary.id }))),
    (item) => item.id,
    (item) => item.owner,
    () => null,
  ).map(([id, rows]) => ({ id, requiredBy: rows.map((item) => item.owner).sort() }));
  const components = groupedRows(
    summaries.flatMap((summary) => summary.components.map((component) => ({ ...component, owner: summary.id }))),
    (item) => item.targetPath,
    (item) => item.owner,
    (item) => ({ id: item.owner, type: item.type, digest: item.digest, requirementIds: item.requirementIds }),
  ).map(([targetPath, rows]) => {
    const candidates = rows.map((item) => item.value).sort((left, right) => left.id.localeCompare(right.id));
    return { targetPath, conflict: new Set(candidates.map((item) => `${item.type}:${item.digest}`)).size > 1, candidates };
  });
  return {
    candidateCount: summaries.length,
    candidates: summaries.map(({ id, digest, createdAt, actor, source, requirementIds, componentTypes, sliceDependencies, dependencies: candidateDependencies, evidence }) => ({ id, digest, createdAt, actor, source, requirementIds, componentTypes, sliceDependencies, dependencies: candidateDependencies, evidence })),
    requirements,
    components,
    dependencies,
    signatures: summaries.map((summary) => ({ id: summary.id, ...summary.signature })),
  };
}
