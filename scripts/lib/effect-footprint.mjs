import { canonicalJson, sha256 } from "./canonical.mjs";
import { verifyBoundaryManifest } from "./boundary-manifest.mjs";
import { createCertifiedEnvelope } from "./certified-changeset.mjs";

const MAX_PATCH_BYTES = 64 * 1024 * 1024;
const MAX_EFFECTS = 8192;

export class EffectFootprintError extends Error {
  constructor(message) {
    super(message);
    this.name = "EffectFootprintError";
    this.exitCode = 2;
  }
}

function fail(message) {
  throw new EffectFootprintError(message);
}

function portablePath(value, label = "Patch path") {
  if (typeof value !== "string" || !value || value.includes("\\") || value.startsWith("/") || /^[A-Za-z]:\//.test(value) || /[\u0000-\u001f\u007f]/.test(value)) {
    fail(`${label} is not a portable relative path`);
  }
  const parts = value.split("/");
  if (parts.some((part) => !part || part === "." || part === "..") || parts.some((part) => part.toLowerCase() === ".git")) {
    fail(`${label} is not a portable relative path`);
  }
  return value;
}

function parseQuotedToken(text, offset) {
  let index = offset;
  while (text[index] === " ") index += 1;
  if (index >= text.length) return null;
  if (text[index] !== '"') {
    const end = text.indexOf(" ", index);
    return { value: text.slice(index, end < 0 ? text.length : end), next: end < 0 ? text.length : end };
  }
  index += 1;
  const bytes = [];
  while (index < text.length) {
    const character = text[index++];
    if (character === '"') return { value: Buffer.from(bytes).toString("utf8"), next: index };
    if (character !== "\\") {
      bytes.push(...Buffer.from(character));
      continue;
    }
    if (index >= text.length) return null;
    const escaped = text[index++];
    const simple = { '"': 34, "\\": 92, t: 9, n: 10, r: 13, b: 8, f: 12, v: 11, a: 7 };
    if (simple[escaped] !== undefined) bytes.push(simple[escaped]);
    else if (/[0-7]/.test(escaped)) {
      let octal = escaped;
      while (octal.length < 3 && /[0-7]/.test(text[index] ?? "")) octal += text[index++];
      bytes.push(Number.parseInt(octal, 8));
    } else return null;
  }
  return null;
}

function parseDiffHeader(line) {
  const text = line.slice("diff --git ".length);
  const left = parseQuotedToken(text, 0);
  const right = left ? parseQuotedToken(text, left.next) : null;
  if (!left || !right || text.slice(right.next).trim()) return null;
  if (!left.value.startsWith("a/") || !right.value.startsWith("b/")) return null;
  return {
    previousPath: portablePath(left.value.slice(2)),
    path: portablePath(right.value.slice(2)),
  };
}

function parseMetadataPath(line, prefix) {
  const raw = line.slice(prefix.length);
  const token = parseQuotedToken(raw, 0);
  if (!token || raw.slice(token.next).trim()) return null;
  return portablePath(token.value, prefix.trim());
}

function effectRecord(input) {
  const body = {
    level: "file",
    operation: input.operation,
    path: portablePath(input.path),
    ...(input.previousPath ? { previousPath: portablePath(input.previousPath, "Previous patch path") } : {}),
    ...(input.oldMode ? { oldMode: input.oldMode } : {}),
    ...(input.newMode ? { newMode: input.newMode } : {}),
    bundleId: input.bundleId,
    sourceKind: input.sourceKind,
    sourceId: input.sourceId,
    sourceDigest: input.sourceDigest,
    requirementIds: [...new Set(input.requirementIds ?? [])].sort(),
  };
  return { id: `effect:${sha256(canonicalJson(body))}`, ...body };
}

function uncertainty(input) {
  return {
    code: input.code,
    message: input.message,
    sourceId: input.sourceId,
    sourceDigest: input.sourceDigest,
    requirementIds: [...new Set(input.requirementIds ?? [])].sort(),
  };
}

function parsePatch(patch, metadata, bundleId) {
  if (!Buffer.isBuffer(patch)) fail(`Bundle patch ${metadata.sourceSha} is not a buffer`);
  if (patch.length > MAX_PATCH_BYTES) fail(`Bundle patch ${metadata.sourceSha} exceeds ${MAX_PATCH_BYTES} bytes`);
  const actualDigest = `sha256:${sha256(patch)}`;
  if (metadata.digest !== actualDigest) fail(`Bundle patch ${metadata.sourceSha} digest mismatch`);
  const text = patch.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(patch)) {
    return { effects: [], uncertainty: [uncertainty({ code: "unsupported_patch_encoding", message: "Patch is not canonical UTF-8 text.", sourceId: metadata.sourceSha, sourceDigest: actualDigest, requirementIds: metadata.requirementIds })] };
  }
  const lines = text.split("\n");
  const starts = [];
  for (let index = 0; index < lines.length; index += 1) if (lines[index].startsWith("diff --git ")) starts.push(index);
  if (!starts.length) {
    return { effects: [], uncertainty: [uncertainty({ code: "unsupported_patch", message: "Patch contains no supported diff sections.", sourceId: metadata.sourceSha, sourceDigest: actualDigest, requirementIds: metadata.requirementIds })] };
  }
  starts.push(lines.length);
  const effects = [];
  const gaps = [];
  for (let sectionIndex = 0; sectionIndex < starts.length - 1; sectionIndex += 1) {
    const section = lines.slice(starts[sectionIndex], starts[sectionIndex + 1]);
    const header = parseDiffHeader(section[0]);
    if (!header) {
      gaps.push(uncertainty({ code: "unsupported_patch_header", message: `Cannot parse diff header ${section[0]}`, sourceId: metadata.sourceSha, sourceDigest: actualDigest, requirementIds: metadata.requirementIds }));
      continue;
    }
    const newMode = section.find((line) => line.startsWith("new file mode "))?.slice("new file mode ".length)
      ?? section.find((line) => line.startsWith("new mode "))?.slice("new mode ".length);
    const deletedMode = section.find((line) => line.startsWith("deleted file mode "))?.slice("deleted file mode ".length);
    const oldMode = section.find((line) => line.startsWith("old mode "))?.slice("old mode ".length);
    const renameFromLine = section.find((line) => line.startsWith("rename from "));
    const renameToLine = section.find((line) => line.startsWith("rename to "));
    const copyLine = section.find((line) => line.startsWith("copy from ") || line.startsWith("copy to "));
    if (copyLine) {
      gaps.push(uncertainty({ code: "unsupported_copy_effect", message: `Copy effects require a semantic analyzer: ${copyLine}`, sourceId: metadata.sourceSha, sourceDigest: actualDigest, requirementIds: metadata.requirementIds }));
      continue;
    }
    const contentChanged = section.some((line) => line.startsWith("@@ ") || line === "GIT binary patch" || line.startsWith("Binary files "));
    const common = { bundleId, sourceKind: "patch", sourceId: metadata.sourceSha, sourceDigest: actualDigest, requirementIds: metadata.requirementIds };
    if (renameFromLine || renameToLine) {
      const previousPath = renameFromLine ? parseMetadataPath(renameFromLine, "rename from ") : null;
      const currentPath = renameToLine ? parseMetadataPath(renameToLine, "rename to ") : null;
      if (!previousPath || !currentPath) {
        gaps.push(uncertainty({ code: "unsupported_rename", message: `Rename metadata is incomplete for ${header.previousPath}`, ...common }));
        continue;
      }
      effects.push(effectRecord({ operation: "rename", path: currentPath, previousPath, ...common }));
      if (contentChanged) effects.push(effectRecord({ operation: "modify", path: currentPath, ...common }));
      if (oldMode || newMode) effects.push(effectRecord({ operation: "mode_change", path: currentPath, oldMode, newMode, ...common }));
      continue;
    }
    if (header.previousPath !== header.path) {
      gaps.push(uncertainty({ code: "unsupported_path_transition", message: `Path changed without rename metadata: ${header.previousPath} -> ${header.path}`, ...common }));
      continue;
    }
    if (deletedMode) {
      effects.push(effectRecord({ operation: "delete", path: header.previousPath, oldMode: deletedMode, ...common }));
      continue;
    }
    if (section.some((line) => line.startsWith("new file mode "))) {
      effects.push(effectRecord({ operation: "create", path: header.path, newMode, ...common }));
      continue;
    }
    if (oldMode || newMode) effects.push(effectRecord({ operation: "mode_change", path: header.path, oldMode, newMode, ...common }));
    if (contentChanged) effects.push(effectRecord({ operation: "modify", path: header.path, ...common }));
    if (!contentChanged && !oldMode && !newMode) {
      gaps.push(uncertainty({ code: "unsupported_empty_effect", message: `Diff section has no recognized effect: ${header.path}`, ...common }));
    }
  }
  return { effects, uncertainty: gaps };
}

export function extractBundleEffects(verifiedBundle) {
  if (!verifiedBundle?.payload || typeof verifiedBundle.digest !== "string" || !Array.isArray(verifiedBundle.payload.patches) || !Array.isArray(verifiedBundle.patches)) {
    fail("Effect extraction requires a verified bundle result");
  }
  if (verifiedBundle.payload.patches.length !== verifiedBundle.patches.length) fail("Verified bundle patch metadata does not match decoded patches");
  const effects = [];
  const gaps = [];
  for (let index = 0; index < verifiedBundle.patches.length; index += 1) {
    const parsed = parsePatch(verifiedBundle.patches[index], verifiedBundle.payload.patches[index], verifiedBundle.payload.id);
    effects.push(...parsed.effects);
    gaps.push(...parsed.uncertainty);
  }
  for (const component of verifiedBundle.payload.components ?? []) {
    effects.push(effectRecord({
      operation: "create",
      path: component.targetPath,
      bundleId: verifiedBundle.payload.id,
      sourceKind: "component",
      sourceId: component.targetPath,
      sourceDigest: component.digest,
      requirementIds: component.requirementIds,
    }));
  }
  if (effects.length > MAX_EFFECTS) fail(`Bundle effects exceed ${MAX_EFFECTS} items`);
  const orderedEffects = effects.sort((left, right) => left.operation.localeCompare(right.operation) || left.path.localeCompare(right.path) || left.id.localeCompare(right.id));
  const duplicateIds = orderedEffects.map((item) => item.id).filter((id, index, values) => values.indexOf(id) !== index);
  if (duplicateIds.length) gaps.push(uncertainty({ code: "duplicate_effect", message: `The same effect was declared more than once: ${duplicateIds[0]}`, sourceId: verifiedBundle.payload.id, sourceDigest: verifiedBundle.digest, requirementIds: [] }));
  return {
    effects: orderedEffects,
    uncertainty: gaps.sort((left, right) => `${left.code}:${left.sourceId}`.localeCompare(`${right.code}:${right.sourceId}`)),
  };
}

function scopeContains(scope, candidate) {
  const recursive = scope.endsWith("/**");
  const base = recursive ? scope.slice(0, -3) : scope;
  return recursive ? candidate === base || candidate.startsWith(`${base}/`) : candidate === base;
}

function owningComponent(components, file) {
  return components.find((item) => item.paths.some((scope) => scopeContains(scope, file))) ?? null;
}

function dependencyPath(component, target, byId, seen = new Set()) {
  if (component.id === target) return [target];
  if (seen.has(component.id)) return null;
  const nextSeen = new Set(seen).add(component.id);
  for (const dependency of component.dependencies) {
    if (dependency === target) return [component.id, target];
    const nested = dependencyPath(byId.get(dependency), target, byId, nextSeen);
    if (nested) return [component.id, ...nested];
  }
  return null;
}

export function compileEffectFootprint({ bundle, boundary, rootDir, producer, generatedAt }) {
  const boundaryResult = verifyBoundaryManifest(boundary, { rootDir });
  const extracted = extractBundleEffects(bundle);
  const components = boundaryResult.components;
  const byId = new Map(components.map((item) => [item.id, item]));
  const gaps = [...extracted.uncertainty];
  const mappedEffects = extracted.effects.map((effect) => {
    const owner = owningComponent(components, effect.path);
    const previousOwner = effect.previousPath ? owningComponent(components, effect.previousPath) : owner;
    if (!owner) {
      gaps.push(uncertainty({ code: "unowned_path", message: `No component owns ${effect.path}`, sourceId: effect.id, sourceDigest: effect.sourceDigest, requirementIds: effect.requirementIds }));
      return { ...effect, componentId: null, owner: null };
    }
    if (previousOwner && previousOwner.id !== owner.id) {
      gaps.push(uncertainty({ code: "cross_boundary_rename", message: `Rename crosses ${previousOwner.id} -> ${owner.id}`, sourceId: effect.id, sourceDigest: effect.sourceDigest, requirementIds: effect.requirementIds }));
    }
    return { ...effect, componentId: owner.id, owner: owner.owner };
  });
  const directlyAffected = [...new Set(mappedEffects.map((item) => item.componentId).filter(Boolean))].sort();
  const hazards = [];
  const transitive = new Set();
  for (const reader of components) {
    if (directlyAffected.includes(reader.id)) continue;
    for (const writer of directlyAffected) {
      const path = dependencyPath(reader, writer, byId);
      if (!path) continue;
      transitive.add(reader.id);
      hazards.push({ writerComponentId: writer, readerComponentId: reader.id, dependencyPath: path });
      break;
    }
  }
  const transitivelyAffected = [...transitive].sort();
  const affected = new Set([...directlyAffected, ...transitivelyAffected]);
  const unaffected = components.map((item) => item.id).filter((id) => !affected.has(id)).sort();
  const verdict = gaps.length ? "insufficient_evidence" : "ready";
  const claimStatus = gaps.length ? "indeterminate" : "passed";
  return createCertifiedEnvelope({
    format: "tugboat.effect-footprint.v1",
    payload: {
      id: `certificate:effects-${bundle.payload.id}`,
      generatedAt,
      verdict,
      subjects: [{ kind: "bundle", id: `bundle:${bundle.payload.id}`, digest: bundle.digest }],
      inputs: [{ kind: "boundary_manifest", id: boundaryResult.id, digest: boundaryResult.digest }],
      producer,
      claims: [{
        id: `claim:effects-${bundle.payload.id}`,
        type: "effect_extraction",
        status: claimStatus,
        subjectIds: [`bundle:${bundle.payload.id}`],
        summary: gaps.length ? `${gaps.length} effect classification gaps require review.` : `${mappedEffects.length} deterministic file effects were classified.`,
      }],
      counterexamples: [],
      body: {
        bundleId: bundle.payload.id,
        bundleDigest: bundle.digest,
        boundaryManifestId: boundaryResult.id,
        boundaryManifestDigest: boundaryResult.digest,
        effects: mappedEffects,
        uncertainty: gaps.sort((left, right) => `${left.code}:${left.sourceId}`.localeCompare(`${right.code}:${right.sourceId}`)),
        directlyAffectedComponentIds: directlyAffected,
        transitivelyAffectedComponentIds: transitivelyAffected,
        provenUnaffectedComponentIds: unaffected,
        readWriteHazards: hazards.sort((left, right) => left.readerComponentId.localeCompare(right.readerComponentId) || left.writerComponentId.localeCompare(right.writerComponentId)),
      },
    },
  });
}
