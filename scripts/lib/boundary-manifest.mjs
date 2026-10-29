import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { portableSubjectId } from "./certified-changeset.mjs";
import { assertNoSecrets } from "./security.mjs";

export const BOUNDARY_MANIFEST_LIMITS = Object.freeze({
  maxManifestBytes: 2 * 1024 * 1024,
  maxReferencedFileBytes: 16 * 1024 * 1024,
  maxComponents: 512,
  maxPathsPerComponent: 512,
  maxInterfacesPerComponent: 512,
  maxSources: 512,
  maxInvariants: 1024,
  maxGates: 1024,
  maxReferences: 1024,
  maxTextBytes: 16 * 1024,
});

const DISCLOSURES = new Set(["public", "internal", "confidential", "restricted"]);
const TOKEN = /^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*$/;
const REQUIREMENT_ID = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

export class BoundaryManifestError extends Error {
  constructor(message) {
    super(message);
    this.name = "BoundaryManifestError";
    this.exitCode = 2;
  }
}

function fail(message) {
  throw new BoundaryManifestError(message);
}

function exactObject(value, label, allowed, required = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`Unknown ${label} field ${key}`);
  for (const key of required) if (value[key] === undefined || value[key] === null || value[key] === "") fail(`${label} is missing ${key}`);
  return value;
}

function boundedText(value, label, limits, { token = false } = {}) {
  if (typeof value !== "string" || !value || Buffer.byteLength(value) > limits.maxTextBytes || /[\u0000-\u001f\u007f]/.test(value)) {
    fail(`${label} must be bounded non-empty text without control characters`);
  }
  if (token && !TOKEN.test(value)) fail(`${label} must be a stable lowercase token`);
  return value;
}

function boundedArray(value, label, maximum, { allowEmpty = true } = {}) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  if (!allowEmpty && value.length === 0) fail(`${label} must not be empty`);
  if (value.length > maximum) fail(`${label} exceeds ${maximum} items`);
  return value;
}

function noDuplicate(values, label) {
  if (new Set(values).size !== values.length) fail(`duplicate ${label}`);
}

function uniqueSorted(values, label) {
  noDuplicate(values, label);
  return [...values].sort((left, right) => left.localeCompare(right));
}

function disclosure(value, label) {
  if (!DISCLOSURES.has(value)) fail(`${label} disclosure must be public, internal, confidential, or restricted`);
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail(`${label} must be a sha256 digest`);
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || !/^\d{4}-\d{2}-\d{2}T/.test(value)) fail(`${label} must be an ISO timestamp`);
  return value;
}

function secretScan(value, label) {
  try {
    assertNoSecrets(value, label);
  } catch (error) {
    fail(error.message);
  }
}

function limitsFrom(overrides = {}) {
  exactObject(overrides, "boundary limits", Object.keys(BOUNDARY_MANIFEST_LIMITS));
  const limits = { ...BOUNDARY_MANIFEST_LIMITS };
  for (const [key, value] of Object.entries(overrides)) {
    if (!Number.isInteger(value) || value < 1 || value > BOUNDARY_MANIFEST_LIMITS[key]) fail(`${key} may only lower the boundary manifest limit`);
    limits[key] = value;
  }
  return limits;
}

function portablePath(value, label) {
  if (typeof value !== "string" || !value || value.includes("\\") || path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || /[\u0000-\u001f\u007f]/.test(value)) {
    fail(`${label} must be a portable path scope`);
  }
  const parts = value.split("/");
  if (parts.some((part) => !part || part === "." || part === "..")) fail(`${label} must be a portable path scope`);
  if (parts.includes(".git")) fail(`${label} is an unsafe Git-internal path`);
  return value;
}

function pathScope(value, label) {
  if (typeof value !== "string") fail(`${label} must be a portable path scope`);
  const suffix = value.endsWith("/**") ? "/**" : "";
  const base = suffix ? value.slice(0, -3) : value;
  if (base.includes("*")) fail(`${label} must be a portable path scope`);
  portablePath(base, label);
  return `${base}${suffix}`;
}

function requirementId(value, label) {
  if (typeof value !== "string" || !REQUIREMENT_ID.test(value)) fail(`${label} must be a stable requirement ID`);
  return value;
}

function filePath(value, label) {
  if (typeof value === "string" && value.includes("*")) fail(`${label} must be a portable path scope`);
  return portablePath(value, label);
}

function scopeBase(scope) {
  return scope.endsWith("/**") ? scope.slice(0, -3) : scope;
}

function scopeContains(scope, candidate) {
  const base = scopeBase(scope);
  return scope.endsWith("/**") ? candidate === base || candidate.startsWith(`${base}/`) : candidate === base;
}

function scopesOverlap(left, right) {
  const leftBase = scopeBase(left);
  const rightBase = scopeBase(right);
  return scopeContains(left, rightBase) || scopeContains(right, leftBase);
}

function sourceDescriptor(value, label, limits) {
  exactObject(value, label, ["id", "path", "digest", "disclosure"], ["id", "path", "digest", "disclosure"]);
  return {
    id: portableSubjectId(value.id, `${label} ID`),
    path: filePath(value.path, `${label} path`),
    digest: digest(value.digest, `${label} digest`),
    disclosure: disclosure(value.disclosure, label),
  };
}

function interfaceDescriptor(value, label, limits) {
  exactObject(value, label, ["id", "kind", "path", "digest", "disclosure"], ["id", "kind", "path", "digest", "disclosure"]);
  return {
    id: portableSubjectId(value.id, `${label} ID`),
    kind: boundedText(value.kind, `${label} kind`, limits, { token: true }),
    path: filePath(value.path, `${label} path`),
    digest: digest(value.digest, `${label} digest`),
    disclosure: disclosure(value.disclosure, label),
  };
}

function component(value, index, limits) {
  const label = `component ${index}`;
  exactObject(
    value,
    label,
    ["id", "owner", "disclosure", "paths", "requirementIds", "dependencies", "interfaces", "invariantIds", "gateIds"],
    ["id", "owner", "disclosure", "paths", "requirementIds", "dependencies", "interfaces", "invariantIds", "gateIds"],
  );
  const paths = boundedArray(value.paths, `${label} paths`, limits.maxPathsPerComponent, { allowEmpty: false })
    .map((item) => pathScope(item, `${label} path`));
  const interfaces = boundedArray(value.interfaces, `${label} interfaces`, limits.maxInterfacesPerComponent)
    .map((item, interfaceIndex) => interfaceDescriptor(item, `${label} interface ${interfaceIndex}`, limits))
    .sort((left, right) => left.id.localeCompare(right.id));
  noDuplicate(interfaces.map((item) => item.id), "interface ID");
  return {
    id: portableSubjectId(value.id, `${label} ID`),
    owner: portableSubjectId(value.owner, `${label} owner`),
    disclosure: disclosure(value.disclosure, label),
    paths: uniqueSorted(paths, `${label} path scope`),
    requirementIds: uniqueSorted(
      boundedArray(value.requirementIds, `${label} requirementIds`, limits.maxReferences, { allowEmpty: false }).map((item) => requirementId(item, `${label} requirement ID`)),
      `${label} requirement ID`,
    ),
    dependencies: uniqueSorted(
      boundedArray(value.dependencies, `${label} dependencies`, limits.maxReferences).map((item) => portableSubjectId(item, `${label} dependency`)),
      `${label} dependency`,
    ),
    interfaces,
    invariantIds: uniqueSorted(
      boundedArray(value.invariantIds, `${label} invariantIds`, limits.maxReferences).map((item) => portableSubjectId(item, `${label} invariant ID`)),
      `${label} invariant ID`,
    ),
    gateIds: uniqueSorted(
      boundedArray(value.gateIds, `${label} gateIds`, limits.maxReferences).map((item) => portableSubjectId(item, `${label} gate ID`)),
      `${label} gate ID`,
    ),
  };
}

function invariant(value, index, limits) {
  const label = `invariant ${index}`;
  exactObject(value, label, ["id", "kind", "description", "subjectIds", "gateIds"], ["id", "kind", "description", "subjectIds", "gateIds"]);
  return {
    id: portableSubjectId(value.id, `${label} ID`),
    kind: boundedText(value.kind, `${label} kind`, limits, { token: true }),
    description: boundedText(value.description, `${label} description`, limits),
    subjectIds: uniqueSorted(
      boundedArray(value.subjectIds, `${label} subjectIds`, limits.maxReferences, { allowEmpty: false }).map((item) => portableSubjectId(item, `${label} subject ID`)),
      `${label} subject ID`,
    ),
    gateIds: uniqueSorted(
      boundedArray(value.gateIds, `${label} gateIds`, limits.maxReferences, { allowEmpty: false }).map((item) => portableSubjectId(item, `${label} gate ID`)),
      `${label} gate ID`,
    ),
  };
}

function gate(value, index, limits) {
  const label = `gate ${index}`;
  exactObject(value, label, ["id", "kind", "description", "subjectIds", "mandatory"], ["id", "kind", "description", "subjectIds", "mandatory"]);
  if (typeof value.mandatory !== "boolean") fail(`${label} mandatory must be a boolean`);
  return {
    id: portableSubjectId(value.id, `${label} ID`),
    kind: boundedText(value.kind, `${label} kind`, limits, { token: true }),
    description: boundedText(value.description, `${label} description`, limits),
    subjectIds: uniqueSorted(
      boundedArray(value.subjectIds, `${label} subjectIds`, limits.maxReferences, { allowEmpty: false }).map((item) => portableSubjectId(item, `${label} subject ID`)),
      `${label} subject ID`,
    ),
    mandatory: value.mandatory,
  };
}

function findCycle(components) {
  const graph = new Map(components.map((item) => [item.id, item.dependencies]));
  const visited = new Set();
  const active = new Set();
  const stack = [];
  function visit(id) {
    if (active.has(id)) {
      const start = stack.indexOf(id);
      return [...stack.slice(start), id];
    }
    if (visited.has(id)) return null;
    active.add(id);
    stack.push(id);
    for (const dependency of graph.get(id) ?? []) {
      const cycle = visit(dependency);
      if (cycle) return cycle;
    }
    stack.pop();
    active.delete(id);
    visited.add(id);
    return null;
  }
  for (const id of [...graph.keys()].sort()) {
    const cycle = visit(id);
    if (cycle) return cycle;
  }
  return null;
}

function normalizeManifest(value, limits) {
  exactObject(
    value,
    "boundary manifest",
    ["id", "generatedAt", "disclosure", "sources", "components", "invariants", "gates"],
    ["id", "generatedAt", "disclosure", "sources", "components", "invariants", "gates"],
  );
  const sources = boundedArray(value.sources, "boundary manifest sources", limits.maxSources)
    .map((item, index) => sourceDescriptor(item, `source ${index}`, limits))
    .sort((left, right) => left.id.localeCompare(right.id));
  const components = boundedArray(value.components, "boundary manifest components", limits.maxComponents, { allowEmpty: false })
    .map((item, index) => component(item, index, limits))
    .sort((left, right) => left.id.localeCompare(right.id));
  const invariants = boundedArray(value.invariants, "boundary manifest invariants", limits.maxInvariants, { allowEmpty: false })
    .map((item, index) => invariant(item, index, limits))
    .sort((left, right) => left.id.localeCompare(right.id));
  const gates = boundedArray(value.gates, "boundary manifest gates", limits.maxGates, { allowEmpty: false })
    .map((item, index) => gate(item, index, limits))
    .sort((left, right) => left.id.localeCompare(right.id));

  noDuplicate(sources.map((item) => item.id), "source ID");
  noDuplicate(components.map((item) => item.id), "component ID");
  noDuplicate(invariants.map((item) => item.id), "invariant ID");
  noDuplicate(gates.map((item) => item.id), "gate ID");
  const interfaces = components.flatMap((item) => item.interfaces);
  noDuplicate(interfaces.map((item) => item.id), "interface ID");
  const allIds = [...sources, ...components, ...interfaces, ...invariants, ...gates].map((item) => item.id);
  noDuplicate(allIds, "stable ID");

  const componentIds = new Set(components.map((item) => item.id));
  const invariantIds = new Set(invariants.map((item) => item.id));
  const gateIds = new Set(gates.map((item) => item.id));
  const subjectIds = new Set([...sources, ...components, ...interfaces].map((item) => item.id));
  for (const item of components) {
    for (const dependency of item.dependencies) if (!componentIds.has(dependency)) fail(`${item.id} references unknown dependency ${dependency}`);
    for (const invariantId of item.invariantIds) if (!invariantIds.has(invariantId)) fail(`${item.id} references unknown invariant ${invariantId}`);
    for (const gateId of item.gateIds) if (!gateIds.has(gateId)) fail(`${item.id} references unknown gate ${gateId}`);
    for (const contract of item.interfaces) {
      if (!item.paths.some((scope) => scopeContains(scope, contract.path))) fail(`${contract.path} is not owned by ${item.id}`);
    }
  }
  for (const item of invariants) {
    for (const subjectId of item.subjectIds) if (!subjectIds.has(subjectId)) fail(`${item.id} references unknown subject ${subjectId}`);
    for (const gateId of item.gateIds) if (!gateIds.has(gateId)) fail(`${item.id} references unknown gate ${gateId}`);
  }
  for (const item of gates) for (const subjectId of item.subjectIds) if (!subjectIds.has(subjectId)) fail(`${item.id} references unknown subject ${subjectId}`);

  const ownership = components.flatMap((item) => item.paths.map((scope) => ({ scope, componentId: item.id })));
  for (let left = 0; left < ownership.length; left += 1) {
    for (let right = left + 1; right < ownership.length; right += 1) {
      if (ownership[left].componentId !== ownership[right].componentId && scopesOverlap(ownership[left].scope, ownership[right].scope)) {
        fail(`Boundary ownership overlap: ${ownership[left].scope} (${ownership[left].componentId}) and ${ownership[right].scope} (${ownership[right].componentId})`);
      }
    }
  }
  const cycle = findCycle(components);
  if (cycle) fail(`Component dependency cycle: ${cycle.join(" -> ")}`);

  const manifest = {
    id: portableSubjectId(value.id, "Boundary manifest ID"),
    generatedAt: timestamp(value.generatedAt, "boundary manifest generatedAt"),
    disclosure: disclosure(value.disclosure, "boundary manifest"),
    sources,
    components,
    invariants,
    gates,
  };
  secretScan(manifest, "Boundary manifest");
  return manifest;
}

function walkWithoutSymlinks(root, relative, label) {
  const realRoot = fs.realpathSync(root);
  let current = realRoot;
  for (const segment of relative.split("/")) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) continue;
    if (fs.lstatSync(current).isSymbolicLink()) fail(`${label} crosses a symbolic link: ${relative}`);
  }
  const relation = path.relative(realRoot, current);
  if (relation.startsWith("..") || path.isAbsolute(relation)) fail(`${label} escapes the boundary root: ${relative}`);
  return current;
}

function verifyFile(root, descriptor, limits) {
  const file = walkWithoutSymlinks(root, descriptor.path, descriptor.id);
  let stat;
  try {
    stat = fs.statSync(file);
  } catch (error) {
    fail(`Missing boundary source ${descriptor.id} at ${descriptor.path}: ${error.message}`);
  }
  if (!stat.isFile()) fail(`Boundary source ${descriptor.id} is not a regular file: ${descriptor.path}`);
  if (stat.size > limits.maxReferencedFileBytes) fail(`Boundary source ${descriptor.id} exceeds ${limits.maxReferencedFileBytes} bytes`);
  const actual = `sha256:${sha256(fs.readFileSync(file))}`;
  if (actual !== descriptor.digest) fail(`Boundary source stale digest for ${descriptor.id}: expected ${descriptor.digest}, received ${actual}`);
  return { id: descriptor.id, path: descriptor.path, digest: actual, status: "verified" };
}

function resultFrom(manifest, envelopeDigest, sourceVerification) {
  const components = manifest.components.map((item) => ({
    id: item.id,
    owner: item.owner,
    disclosure: item.disclosure,
    paths: [...item.paths],
    requirementIds: [...item.requirementIds],
    dependencies: [...item.dependencies],
    interfaceIds: item.interfaces.map((contract) => contract.id),
    invariantIds: [...item.invariantIds],
    gateIds: [...item.gateIds],
  }));
  return {
    status: "ready",
    id: manifest.id,
    digest: envelopeDigest,
    disclosure: manifest.disclosure,
    componentCount: components.length,
    components,
    ownership: manifest.components.flatMap((item) => item.paths.map((scope) => ({ path: scope, componentId: item.id, owner: item.owner })))
      .sort((left, right) => left.path.localeCompare(right.path) || left.componentId.localeCompare(right.componentId)),
    interfaces: Object.fromEntries(manifest.components.flatMap((item) => item.interfaces).sort((left, right) => left.id.localeCompare(right.id)).map((item) => [item.id, item])),
    invariants: Object.fromEntries(manifest.invariants.map((item) => [item.id, item])),
    gates: Object.fromEntries(manifest.gates.map((item) => [item.id, item])),
    sourceVerification,
  };
}

export function createBoundaryManifest(input, options = {}) {
  const limits = limitsFrom(options.limits);
  const manifest = normalizeManifest(input, limits);
  const envelope = {
    schemaVersion: 1,
    format: "tugboat.boundary-manifest.v1",
    manifest,
    digest: `sha256:${sha256(canonicalJson(manifest))}`,
  };
  if (Buffer.byteLength(canonicalJson(envelope)) > limits.maxManifestBytes) fail(`Boundary manifest exceeds ${limits.maxManifestBytes} bytes`);
  return envelope;
}

export function verifyBoundaryManifest(envelope, options = {}) {
  const limits = limitsFrom(options.limits);
  exactObject(envelope, "boundary manifest envelope", ["schemaVersion", "format", "manifest", "digest"], ["schemaVersion", "format", "manifest", "digest"]);
  if (envelope.schemaVersion !== 1 || envelope.format !== "tugboat.boundary-manifest.v1") fail("Unsupported boundary manifest schema or format");
  const manifest = normalizeManifest(envelope.manifest, limits);
  const expected = `sha256:${sha256(canonicalJson(manifest))}`;
  if (envelope.digest !== expected) fail("Boundary manifest digest mismatch");
  let sourceVerification = [
    ...manifest.sources,
    ...manifest.components.flatMap((item) => item.interfaces),
  ].sort((left, right) => left.id.localeCompare(right.id)).map((item) => ({ id: item.id, path: item.path, digest: item.digest, status: "not_checked" }));
  if (options.rootDir !== undefined) {
    const root = fs.realpathSync(options.rootDir);
    for (const item of manifest.components) for (const scope of item.paths) walkWithoutSymlinks(root, scopeBase(scope), item.id);
    sourceVerification = [
      ...manifest.sources,
      ...manifest.components.flatMap((item) => item.interfaces),
    ].sort((left, right) => left.id.localeCompare(right.id)).map((item) => verifyFile(root, item, limits));
  }
  return resultFrom(manifest, expected, sourceVerification);
}

export function loadBoundaryManifest(file, options = {}) {
  const limits = limitsFrom(options.limits);
  let contents;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) fail(`Boundary manifest path is not a regular file: ${file}`);
    if (stat.size > limits.maxManifestBytes) fail(`Boundary manifest exceeds ${limits.maxManifestBytes} bytes`);
    contents = fs.readFileSync(file, "utf8");
  } catch (error) {
    if (error instanceof BoundaryManifestError) throw error;
    fail(`Cannot read boundary manifest ${file}: ${error.message}`);
  }
  let envelope;
  try {
    envelope = JSON.parse(contents);
  } catch (error) {
    fail(`Cannot parse boundary manifest ${file}: ${error.message}`);
  }
  return { envelope, verification: verifyBoundaryManifest(envelope, options) };
}

export function readBoundaryManifest(file, options = {}) {
  return loadBoundaryManifest(file, options).verification;
}

export function writeBoundaryManifest(file, envelope, options = {}) {
  const limits = limitsFrom(options.limits);
  verifyBoundaryManifest(envelope, { limits });
  const output = `${canonicalJson(envelope)}\n`;
  if (Buffer.byteLength(output) > limits.maxManifestBytes) fail(`Boundary manifest exceeds ${limits.maxManifestBytes} bytes`);
  const target = path.resolve(file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.tmp-${process.pid}-${randomUUID()}`;
  try {
    fs.writeFileSync(temporary, output, { flag: "wx", mode: 0o600 });
    fs.renameSync(temporary, target);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
  return target;
}
