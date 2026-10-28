import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { canonicalReport } from "./intelligence-core.mjs";
import { assertNoSecrets } from "./security.mjs";
import { canonicalDigest, describeFile, exactObject, portableRelativePath, resolvePortable, runBounded } from "./proof-runtime.mjs";

const MANIFEST_FIELDS = ["schemaVersion", "id", "runtime", "entrypoint", "entrypointDigest", "inputSchema", "outputSchema", "capabilities", "allowedInputPaths", "environment", "timeoutMs", "maxOutputBytes", "isolation"];
const JSON_TYPES = new Set(["array", "boolean", "integer", "number", "object", "string"]);

function validateSchema(schema, label) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema) || !JSON_TYPES.has(schema.type)) throw new Error(`${label} must declare a supported JSON type`);
  const allowed = schema.type === "object" ? ["type", "properties", "required", "additionalProperties"] : ["type"];
  for (const key of Object.keys(schema)) if (!allowed.includes(key)) throw new Error(`${label} uses unsupported schema keyword ${key}`);
  if (schema.type === "object") {
    if (!schema.properties || typeof schema.properties !== "object" || Array.isArray(schema.properties)) throw new Error(`${label}.properties must be an object`);
    if (!Array.isArray(schema.required) || schema.required.some((name) => !Object.hasOwn(schema.properties, name))) throw new Error(`${label}.required is invalid`);
    if (typeof schema.additionalProperties !== "boolean") throw new Error(`${label}.additionalProperties must be boolean`);
    for (const [name, property] of Object.entries(schema.properties)) {
      if (!property || typeof property !== "object" || !JSON_TYPES.has(property.type) || Object.keys(property).some((key) => key !== "type")) throw new Error(`${label}.properties.${name} is invalid`);
    }
  }
  if (Buffer.byteLength(JSON.stringify(schema)) > 64 * 1024) throw new Error(`${label} exceeds 64 KiB`);
}

function assertSchemaValue(value, schema, label) {
  const typeMatches = schema.type === "array" ? Array.isArray(value)
    : schema.type === "object" ? value !== null && typeof value === "object" && !Array.isArray(value)
      : schema.type === "integer" ? Number.isInteger(value)
        : schema.type === "number" ? typeof value === "number" && Number.isFinite(value)
          : typeof value === schema.type;
  if (!typeMatches) throw new Error(`${label} must match ${schema.type} schema`);
  if (schema.type !== "object") return;
  for (const name of schema.required) if (!Object.hasOwn(value, name)) throw new Error(`${label} is missing ${name}`);
  for (const [name, item] of Object.entries(value)) {
    const property = schema.properties[name];
    if (!property) {
      if (!schema.additionalProperties) throw new Error(`${label} has unknown field ${name}`);
      continue;
    }
    assertSchemaValue(item, property, `${label}.${name}`);
  }
}

function validateManifest(manifest, manifestDir) {
  exactObject(manifest, "adapter manifest", MANIFEST_FIELDS, MANIFEST_FIELDS);
  if (manifest.schemaVersion !== "tugboat.adapter-manifest.v1") throw new Error("Unsupported adapter manifest schemaVersion");
  if (!/^[a-zA-Z0-9._-]{1,128}$/.test(manifest.id)) throw new Error("Adapter id is invalid");
  if (manifest.runtime !== "node20") throw new Error("Built-in adapter runtime must be node20");
  validateSchema(manifest.inputSchema, "Adapter inputSchema");
  validateSchema(manifest.outputSchema, "Adapter outputSchema");
  portableRelativePath(manifest.entrypoint, "Adapter entrypoint");
  if (!/^sha256:[0-9a-f]{64}$/.test(manifest.entrypointDigest)) throw new Error("Adapter entrypointDigest is invalid");
  for (const [label, values] of [["capabilities", manifest.capabilities], ["allowedInputPaths", manifest.allowedInputPaths], ["environment", manifest.environment]]) {
    if (!Array.isArray(values) || values.length > 128 || new Set(values).size !== values.length || values.some((value) => typeof value !== "string" || !value)) throw new Error(`Adapter ${label} are invalid`);
  }
  manifest.allowedInputPaths.forEach((value) => portableRelativePath(value, "Allowed input path"));
  if (manifest.environment.some((value) => !/^[A-Z][A-Z0-9_]{0,63}$/.test(value))) throw new Error("Adapter environment name is invalid");
  if (!Number.isInteger(manifest.timeoutMs) || manifest.timeoutMs < 1 || manifest.timeoutMs > 300_000) throw new Error("Adapter timeoutMs is invalid");
  if (!Number.isInteger(manifest.maxOutputBytes) || manifest.maxOutputBytes < 64 || manifest.maxOutputBytes > 16 * 1024 * 1024) throw new Error("Adapter maxOutputBytes is invalid");
  if (!["brokered", "wasi", "container"].includes(manifest.isolation)) throw new Error("Adapter isolation is invalid");
  const entrypoint = describeFile(manifestDir, manifest.entrypoint);
  if (entrypoint.digest !== manifest.entrypointDigest) throw new Error("Adapter entrypoint digest mismatch");
  return entrypoint;
}

export function inspectAdapter(manifest, { manifestDir }) {
  const entrypoint = validateManifest(manifest, manifestDir);
  const limitations = manifest.isolation === "brokered"
    ? ["Brokered execution strips ambient inputs but is not an OS sandbox; use a pinned WASI or container runtime for kernel-enforced isolation."]
    : ["The declared external isolation runtime must be independently pinned and verified by the operator."];
  return canonicalReport("tugboat.adapter-inspection.v1", {
    status: "ready",
    adapter: { id: manifest.id, isolation: manifest.isolation, capabilities: [...manifest.capabilities].sort(), entrypointDigest: entrypoint.digest },
    limitations,
  });
}

export function runAdapter({ manifest, manifestDir, inputRoot, inputPaths = [], input = {}, environment = {} }) {
  validateManifest(manifest, manifestDir);
  if (manifest.isolation !== "brokered") throw new Error(`${manifest.isolation} adapter execution requires a separately pinned external runtime`);
  assertNoSecrets({ input, environment }, "Adapter invocation");
  assertSchemaValue(input, manifest.inputSchema, "Adapter input");
  for (const name of Object.keys(environment)) if (!manifest.environment.includes(name)) throw new Error(`Adapter environment ${name} is not declared`);
  for (const name of manifest.environment) if (environment[name] !== undefined && typeof environment[name] !== "string") throw new Error(`Adapter environment ${name} must be a string`);
  if (!Array.isArray(inputPaths) || inputPaths.length > 128) throw new Error("Adapter input paths are invalid");
  const allowed = new Set(manifest.allowedInputPaths);
  for (const relative of inputPaths) {
    portableRelativePath(relative, "Adapter input path");
    if (!allowed.has(relative)) throw new Error(`Adapter input path is not allowed: ${relative}`);
  }
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-adapter-run-"));
  try {
    const entrypointSource = resolvePortable(manifestDir, manifest.entrypoint, { regularFile: true });
    const entrypointTarget = path.join(stage, "adapter.mjs");
    fs.copyFileSync(entrypointSource, entrypointTarget);
    fs.mkdirSync(path.join(stage, "inputs"), { recursive: true });
    const files = [];
    for (const relative of [...new Set(inputPaths)].sort()) {
      const descriptor = describeFile(inputRoot, relative);
      const source = resolvePortable(inputRoot, relative, { regularFile: true });
      const target = path.join(stage, "inputs", ...relative.split("/"));
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(source, target);
      files.push(descriptor);
    }
    const environmentEvidence = Object.keys(environment).sort().map((name) => ({ name, valueDigest: canonicalDigest(environment[name]) }));
    const request = { protocolVersion: "tugboat.adapter.v1", input, files, environment: environmentEvidence };
    const execution = runBounded(process.execPath, ["adapter.mjs"], {
      cwd: stage,
      input: JSON.stringify(request),
      environment: Object.fromEntries(Object.entries(environment).filter(([name]) => manifest.environment.includes(name))),
      timeoutMs: manifest.timeoutMs,
      maxOutputBytes: manifest.maxOutputBytes,
    });
    if (execution.timedOut) throw new Error("Adapter execution timed out");
    if (execution.exitCode !== 0) throw new Error(`Adapter execution failed with exit code ${execution.exitCode}`);
    let output;
    try { output = JSON.parse(execution.stdout); } catch { throw new Error("Adapter output is not valid JSON"); }
    if (!output || typeof output !== "object" || Array.isArray(output)) throw new Error("Adapter output must be a JSON object");
    assertNoSecrets(output, "Adapter output");
    assertSchemaValue(output, manifest.outputSchema, "Adapter output");
    return canonicalReport("tugboat.adapter-result.v1", {
      status: "ready",
      adapter: { id: manifest.id, isolation: manifest.isolation, entrypointDigest: manifest.entrypointDigest },
      requestDigest: canonicalDigest(request),
      output,
      outputDigest: canonicalDigest(output),
      limitations: inspectAdapter(manifest, { manifestDir }).limitations,
    });
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
}

export function conformAdapter(options, cases) {
  if (!Array.isArray(cases) || cases.length < 1 || cases.length > 64) throw new Error("Adapter conformance needs 1 to 64 cases");
  const results = cases.map((item) => {
    const first = runAdapter({ ...options, input: item.input, inputPaths: item.inputPaths ?? [] });
    const second = runAdapter({ ...options, input: item.input, inputPaths: item.inputPaths ?? [] });
    return { id: item.id, deterministic: first.outputDigest === second.outputDigest, outputDigest: first.outputDigest };
  }).sort((left, right) => left.id.localeCompare(right.id));
  const boundaryChecks = {
    entrypointPinned: true,
    inputSchemaEnforced: true,
    outputSchemaEnforced: true,
    ambientEnvironmentStripped: true,
    declaredInputsOnly: true,
    timeoutBounded: true,
    outputBounded: true,
    shellDisabled: true,
    osSandboxClaimed: false,
  };
  return canonicalReport("tugboat.adapter-conformance.v1", { status: results.every((item) => item.deterministic) ? "ready" : "blocked", results, boundaryChecks });
}
