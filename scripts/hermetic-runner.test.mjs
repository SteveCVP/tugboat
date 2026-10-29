import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createPinnedRunnerProfile,
  inspectHermeticRunner,
  runHermeticRunner,
  validateRunnerProfile,
} from "./lib/hermetic-runner.mjs";
import { canonicalDigest } from "./lib/proof-runtime.mjs";

const runtimeSource = `let encoded="";for await(const chunk of process.stdin)encoded+=chunk;const request=JSON.parse(encoded);if(request.input.mode==="timeout")while(true){}if(request.input.mode==="oversize"){process.stdout.write("x".repeat(10000));process.exit(0);}const output={status:"ready",result:{value:request.input.value??null},capabilityAttestation:{capabilityDigest:request.capabilityDigest,declaredInputsOnly:true,filesystemDenied:true,environmentDenied:process.env.TUGBOAT_UNDECLARED_TEST_VALUE===undefined,networkDenied:true,clockDenied:true,resourceLimitsApplied:true}};process.stdout.write(JSON.stringify(output));\n`;

function runnerFixture(context, kind = "wasi") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-hermetic-fixture-"));
  context.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const runtimePath = process.execPath;
  const artifactPath = path.join(root, "runner-artifact.mjs");
  const inputRoot = path.join(root, "inputs");
  fs.mkdirSync(inputRoot);
  fs.writeFileSync(artifactPath, runtimeSource);
  fs.writeFileSync(path.join(inputRoot, "declared.txt"), "declared only\n");
  const profile = createPinnedRunnerProfile({
    id: `${kind}-fixture`,
    kind,
    runtimePath,
    artifactPath,
    allowedInputPaths: ["declared.txt"],
    timeoutMs: 1000,
    maxOutputBytes: 4096,
    memoryBytes: 64 * 1024 * 1024,
    cpuMilliseconds: 500,
  });
  return { root, runtimePath, artifactPath, inputRoot, profile };
}

for (const kind of ["wasi", "oci"]) {
  test(`${kind} runner pins runtime/artifact and verifies default-deny capability attestation`, (context) => {
    const fixture = runnerFixture(context, kind);
    process.env.TUGBOAT_UNDECLARED_TEST_VALUE = "must-not-cross";
    context.after(() => { delete process.env.TUGBOAT_UNDECLARED_TEST_VALUE; });
    const report = runHermeticRunner({
      ...fixture,
      inputPaths: ["declared.txt"],
      input: { value: 7 },
    });
    assert.equal(report.status, "ready");
    assert.equal(report.isolation.kind, kind);
    assert.equal(report.isolation.enforcement, "pinned_external_runtime");
    assert.equal(report.isolation.hermetic, "externally_attested");
    assert.deepEqual(report.isolation.denied, ["clock", "environment", "filesystem", "network"]);
    assert.equal(report.output.result.value, 7);
    assert.equal(report.inputs[0].path, "declared.txt");
    assert.doesNotMatch(JSON.stringify(report), /must-not-cross/);
  });
}

test("runner rejects undeclared inputs, runtime/artifact drift, and malformed profiles", (context) => {
  const fixture = runnerFixture(context);
  fs.writeFileSync(path.join(fixture.inputRoot, "other.txt"), "other\n");
  assert.throws(() => runHermeticRunner({ ...fixture, inputPaths: ["other.txt"], input: {} }), /not allowed/);
  fs.appendFileSync(fixture.artifactPath, "drift");
  assert.throws(() => runHermeticRunner({ ...fixture, inputPaths: [], input: {} }), /artifact digest mismatch/);
  assert.throws(() => validateRunnerProfile({ ...fixture.profile, surprise: true }), /unknown/i);
});

test("runner enforces timeout and output bounds and removes every staging directory", (context) => {
  const fixture = runnerFixture(context);
  const before = new Set(fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("tugboat-hermetic-run-")));
  assert.throws(() => runHermeticRunner({ ...fixture, inputPaths: [], input: { mode: "timeout" } }), /timed out/);
  const bounded = { ...fixture.profile, limits: { ...fixture.profile.limits, maxOutputBytes: 64 } };
  bounded.digest = canonicalDigest(Object.fromEntries(Object.entries(bounded).filter(([key]) => key !== "digest")));
  assert.throws(() => runHermeticRunner({ ...fixture, profile: bounded, inputPaths: [], input: { mode: "oversize" } }), /output exceeded/);
  const after = new Set(fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("tugboat-hermetic-run-")));
  assert.deepEqual(after, before);
});

test("unavailable runtimes fail closed without leaking local paths", (context) => {
  const fixture = runnerFixture(context);
  const missingRuntime = path.join(fixture.root, "missing-runtime");
  const report = inspectHermeticRunner({ profile: fixture.profile, runtimePath: missingRuntime, artifactPath: fixture.artifactPath });
  assert.equal(report.status, "insufficient_evidence");
  assert.equal(report.available, false);
  assert.equal(report.uncertainty.code, "runtime_unavailable");
  assert.doesNotMatch(JSON.stringify(report), new RegExp(fixture.root.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
});

test("brokered adapters cannot be relabeled as hermetic runner profiles", (context) => {
  const fixture = runnerFixture(context);
  assert.throws(() => validateRunnerProfile({ ...fixture.profile, kind: "brokered" }), /kind/i);
  assert.equal(fixture.profile.isolation.enforcement, "pinned_external_runtime");
  assert.equal(fixture.profile.isolation.kernelIsolationSuppliedBy, "configured-runtime");
});
