import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { sha256 } from "./canonical.mjs";
import { canonicalReport } from "./intelligence-core.mjs";
import { assertNoSecrets, assertNoSecretsInBuffer } from "./security.mjs";
import { canonicalDigest, describeFile, exactObject, portableRelativePath, resolvePortable, runBounded } from "./proof-runtime.mjs";

const PROFILE_FIELDS = ["schemaVersion", "id", "kind", "runtime", "artifact", "allowedInputPaths", "capabilities", "limits", "isolation", "digest"];
const SHA256 = /^sha256:[0-9a-f]{64}$/;

function regularFileDescriptor(file, label) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new Error(`${label} path must be explicit and absolute`);
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${label} must be a regular non-symbolic file`);
  const bytes = fs.readFileSync(file);
  if (bytes.length > 512 * 1024 * 1024) throw new Error(`${label} exceeds 512 MiB`);
  if (label.includes("artifact")) assertNoSecretsInBuffer(bytes, label);
  return { name: path.basename(file), digest: `sha256:${sha256(bytes)}`, bytes: bytes.length };
}

function positiveInteger(value, label, maximum) {
  if (!Number.isInteger(value) || value < 1 || value > maximum) throw new Error(`${label} is invalid`);
}

export function validateRunnerProfile(profile) {
  exactObject(profile, "hermetic runner profile", PROFILE_FIELDS, PROFILE_FIELDS);
  if (profile.schemaVersion !== "tugboat.hermetic-runner-profile.v1") throw new Error("Unsupported hermetic runner profile schemaVersion");
  if (!/^[a-zA-Z0-9._-]{1,128}$/u.test(profile.id)) throw new Error("Hermetic runner profile id is invalid");
  if (!["wasi", "oci"].includes(profile.kind)) throw new Error("Hermetic runner profile kind must be wasi or oci");
  for (const [label, value] of [["runtime", profile.runtime], ["artifact", profile.artifact]]) {
    exactObject(value, `hermetic runner ${label}`, ["name", "digest", "bytes"], ["name", "digest", "bytes"]);
    portableRelativePath(value.name, `Hermetic runner ${label} name`);
    if (!SHA256.test(value.digest)) throw new Error(`Hermetic runner ${label} digest is invalid`);
    positiveInteger(value.bytes, `Hermetic runner ${label} bytes`, 512 * 1024 * 1024);
  }
  if (!Array.isArray(profile.allowedInputPaths) || profile.allowedInputPaths.length > 128 || new Set(profile.allowedInputPaths).size !== profile.allowedInputPaths.length) throw new Error("Hermetic runner allowedInputPaths are invalid");
  profile.allowedInputPaths.forEach((value) => portableRelativePath(value, "Hermetic runner allowed input"));
  exactObject(profile.capabilities, "hermetic runner capabilities", ["filesystem", "environment", "network", "clock"], ["filesystem", "environment", "network", "clock"]);
  if (profile.capabilities.filesystem !== "declared-read-only" || profile.capabilities.environment !== "none" || profile.capabilities.network !== "none" || profile.capabilities.clock !== "none") throw new Error("Hermetic runner capabilities must be default deny");
  exactObject(profile.limits, "hermetic runner limits", ["timeoutMs", "maxOutputBytes", "memoryBytes", "cpuMilliseconds"], ["timeoutMs", "maxOutputBytes", "memoryBytes", "cpuMilliseconds"]);
  positiveInteger(profile.limits.timeoutMs, "Hermetic runner timeoutMs", 300_000);
  positiveInteger(profile.limits.maxOutputBytes, "Hermetic runner maxOutputBytes", 16 * 1024 * 1024);
  if (profile.limits.maxOutputBytes < 64) throw new Error("Hermetic runner maxOutputBytes must be at least 64");
  positiveInteger(profile.limits.memoryBytes, "Hermetic runner memoryBytes", 16 * 1024 * 1024 * 1024);
  positiveInteger(profile.limits.cpuMilliseconds, "Hermetic runner cpuMilliseconds", 300_000);
  exactObject(profile.isolation, "hermetic runner isolation", ["enforcement", "kernelIsolationSuppliedBy", "runtimeInterface"], ["enforcement", "kernelIsolationSuppliedBy", "runtimeInterface"]);
  if (profile.isolation.enforcement !== "pinned_external_runtime" || profile.isolation.kernelIsolationSuppliedBy !== "configured-runtime" || profile.isolation.runtimeInterface !== "artifact-as-first-argument.v1") throw new Error("Hermetic runner isolation declaration is invalid");
  if (!SHA256.test(profile.digest)) throw new Error("Hermetic runner profile digest is invalid");
  const { digest: claimed, ...body } = profile;
  if (claimed !== canonicalDigest(body)) throw new Error("Hermetic runner profile digest mismatch");
  return profile;
}

export function createPinnedRunnerProfile({ id, kind, runtimePath, artifactPath, allowedInputPaths = [], timeoutMs = 30_000, maxOutputBytes = 1024 * 1024, memoryBytes = 512 * 1024 * 1024, cpuMilliseconds = 30_000 }) {
  const body = {
    schemaVersion: "tugboat.hermetic-runner-profile.v1",
    id,
    kind,
    runtime: regularFileDescriptor(runtimePath, "Hermetic runtime"),
    artifact: regularFileDescriptor(artifactPath, "Hermetic artifact"),
    allowedInputPaths: [...allowedInputPaths].sort(),
    capabilities: { filesystem: "declared-read-only", environment: "none", network: "none", clock: "none" },
    limits: { timeoutMs, maxOutputBytes, memoryBytes, cpuMilliseconds },
    isolation: { enforcement: "pinned_external_runtime", kernelIsolationSuppliedBy: "configured-runtime", runtimeInterface: "artifact-as-first-argument.v1" },
  };
  return validateRunnerProfile({ ...body, digest: canonicalDigest(body) });
}

function verifyConfiguredFiles(profile, runtimePath, artifactPath) {
  const runtime = regularFileDescriptor(runtimePath, "Hermetic runtime");
  const artifact = regularFileDescriptor(artifactPath, "Hermetic artifact");
  if (runtime.digest !== profile.runtime.digest || runtime.bytes !== profile.runtime.bytes) throw new Error("Hermetic runtime digest mismatch");
  if (artifact.digest !== profile.artifact.digest || artifact.bytes !== profile.artifact.bytes) throw new Error("Hermetic artifact digest mismatch");
  return { runtime, artifact };
}

export function inspectHermeticRunner({ profile, runtimePath, artifactPath }) {
  validateRunnerProfile(profile);
  try {
    verifyConfiguredFiles(profile, runtimePath, artifactPath);
    return canonicalReport("tugboat.hermetic-runner-inspection.v1", {
      status: "ready",
      available: true,
      profileDigest: profile.digest,
      kind: profile.kind,
      isolation: profile.isolation,
      uncertainty: null,
      limitations: ["Kernel isolation is supplied by the explicitly configured, digest-pinned external runtime and must be trusted only after its independent conformance review."],
    });
  } catch {
    return canonicalReport("tugboat.hermetic-runner-inspection.v1", {
      status: "insufficient_evidence",
      available: false,
      profileDigest: profile.digest,
      kind: profile.kind,
      isolation: profile.isolation,
      uncertainty: { code: "runtime_unavailable", subject: profile.id, message: "The configured runtime or artifact is unavailable or failed digest verification." },
      limitations: ["No hermetic execution claim is made when the configured runtime or artifact cannot be verified."],
    });
  }
}

function validateAttestation(output, capabilityDigest) {
  exactObject(output, "hermetic runner output", ["status", "result", "capabilityAttestation"], ["status", "result", "capabilityAttestation"]);
  if (output.status !== "ready") throw new Error("Hermetic runtime did not return ready status");
  exactObject(output.capabilityAttestation, "hermetic capability attestation", ["capabilityDigest", "declaredInputsOnly", "filesystemDenied", "environmentDenied", "networkDenied", "clockDenied", "resourceLimitsApplied"], ["capabilityDigest", "declaredInputsOnly", "filesystemDenied", "environmentDenied", "networkDenied", "clockDenied", "resourceLimitsApplied"]);
  if (output.capabilityAttestation.capabilityDigest !== capabilityDigest) throw new Error("Hermetic capability attestation digest mismatch");
  for (const field of ["declaredInputsOnly", "filesystemDenied", "environmentDenied", "networkDenied", "clockDenied", "resourceLimitsApplied"]) {
    if (output.capabilityAttestation[field] !== true) throw new Error(`Hermetic capability attestation did not prove ${field}`);
  }
}

export function runHermeticRunner({ profile, runtimePath, artifactPath, inputRoot, inputPaths = [], input = {} }) {
  validateRunnerProfile(profile);
  verifyConfiguredFiles(profile, runtimePath, artifactPath);
  assertNoSecrets(input, "Hermetic runner input");
  if (!Array.isArray(inputPaths) || inputPaths.length > 128) throw new Error("Hermetic runner input paths are invalid");
  const allowed = new Set(profile.allowedInputPaths);
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-hermetic-run-"));
  try {
    const stagedArtifact = path.join(stage, `artifact${path.extname(profile.artifact.name) || ".bin"}`);
    fs.copyFileSync(artifactPath, stagedArtifact);
    const stagedInputRoot = path.join(stage, "inputs");
    fs.mkdirSync(stagedInputRoot);
    const inputs = [];
    for (const relative of [...new Set(inputPaths)].sort()) {
      portableRelativePath(relative, "Hermetic runner input path");
      if (!allowed.has(relative)) throw new Error(`Hermetic runner input path is not allowed: ${relative}`);
      const descriptor = describeFile(inputRoot, relative);
      const source = resolvePortable(inputRoot, relative, { regularFile: true });
      const target = path.join(stagedInputRoot, ...relative.split("/"));
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(source, target);
      inputs.push(descriptor);
    }
    const capabilityDigest = canonicalDigest({ capabilities: profile.capabilities, limits: profile.limits, inputDigests: inputs.map(({ path: inputPath, digest }) => ({ path: inputPath, digest })) });
    const request = { protocolVersion: "tugboat.hermetic-runner.v1", runnerKind: profile.kind, profileDigest: profile.digest, capabilityDigest, inputs, input, limits: profile.limits };
    const execution = runBounded(runtimePath, [stagedArtifact], { cwd: stage, input: JSON.stringify(request), environment: {}, timeoutMs: profile.limits.timeoutMs, maxOutputBytes: profile.limits.maxOutputBytes });
    if (execution.timedOut) throw new Error("Hermetic runner timed out");
    if (execution.exitCode !== 0) throw new Error(`Hermetic runner failed with exit code ${execution.exitCode}`);
    let output;
    try { output = JSON.parse(execution.stdout); } catch { throw new Error("Hermetic runner output is not valid JSON"); }
    assertNoSecrets(output, "Hermetic runner output");
    validateAttestation(output, capabilityDigest);
    return canonicalReport("tugboat.hermetic-runner-result.v1", {
      status: "ready",
      profileDigest: profile.digest,
      requestDigest: canonicalDigest(request),
      isolation: {
        kind: profile.kind,
        enforcement: profile.isolation.enforcement,
        kernelIsolationSuppliedBy: profile.isolation.kernelIsolationSuppliedBy,
        hermetic: "externally_attested",
        denied: ["clock", "environment", "filesystem", "network"],
      },
      inputs,
      output: { status: output.status, result: output.result },
      outputDigest: canonicalDigest(output),
      limits: { ...profile.limits, enforcedBy: "configured-runtime" },
      limitations: ["The certificate verifies a pinned runtime plus a complete denial attestation; Tugboat does not relabel brokered Node adapters as hermetic."],
    });
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
}
