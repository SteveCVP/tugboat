import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { captureCommandEvidence, gitSnapshot, recordEvidence, validateEvidence } from "./lib/evidence.mjs";
import { createMission } from "./lib/reducer.mjs";

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-evidence-"));
  execFileSync("git", ["init", "-b", "main"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: dir });
  fs.writeFileSync(path.join(dir, "spec.md"), "# Spec\n");
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "baseline"], { cwd: dir });
  return dir;
}

test("free-form proof and incomplete evidence cannot prove a requirement", () => {
  assert.throws(() => validateEvidence("tests pass"), /structured evidence object/i);
  assert.throws(() => validateEvidence({ id: "E1", kind: "command" }), /schemaVersion|capturedAt|verification/i);
});

test("command evidence records verifiable result, output digests, and Git alignment", () => {
  const cwd = repo();
  const evidence = captureCommandEvidence({
    id: "E-CMD", requirementIds: ["R1"], cwd,
    command: [process.execPath, "-e", "process.stdout.write('verified')"],
    actor: { name: "Codex", kind: "agent", runtime: "codex" },
  });
  assert.deepEqual(validateEvidence(evidence), []);
  assert.equal(evidence.verification.exitCode, 0);
  assert.match(evidence.verification.stdoutDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(evidence.git.clean, true);

  const failed = captureCommandEvidence({ id: "E-FAIL", requirementIds: ["R1"], cwd, command: [process.execPath, "-e", "process.exit(7)"] });
  assert.ok(validateEvidence(failed).some((error) => /did not pass/i.test(error)));
});

test("artifact evidence fails when its file is missing or digest no longer matches", () => {
  const cwd = repo();
  const evidence = {
    schemaVersion: 1, id: "E-ART", kind: "artifact", requirementIds: ["R1"], capturedAt: new Date().toISOString(),
    origin: { actor: { name: "Codex", kind: "agent" }, cwd },
    git: gitSnapshot(cwd),
    verification: { status: "passed", verifier: "tugboat:2.0" },
    artifacts: [{ path: "missing.json", digest: `sha256:${"0".repeat(64)}` }],
  };
  assert.ok(validateEvidence(evidence, { verifyArtifacts: true }).some((error) => /missing artifact/i.test(error)));
});

test("operator evidence requires an observable URL and result", () => {
  const cwd = repo();
  const evidence = {
    schemaVersion: 1, id: "E-OP", kind: "operator", requirementIds: ["R1"], capturedAt: new Date().toISOString(),
    origin: { actor: { name: "Alex", kind: "human" }, cwd }, git: gitSnapshot(cwd),
    verification: { status: "passed", verifier: "human:Alex", url: "https://app.example.test" }, artifacts: [],
  };
  assert.ok(validateEvidence(evidence).some((error) => /observable result/i.test(error)));
});

test("dirty local evidence is bound to the exact patch and secret-bearing evidence is rejected", () => {
  const cwd = repo();
  fs.writeFileSync(path.join(cwd, "change.txt"), "first\n");
  const first = gitSnapshot(cwd);
  assert.equal(first.clean, false);
  assert.match(first.patchDigest, /^sha256:[0-9a-f]{64}$/);
  fs.writeFileSync(path.join(cwd, "change.txt"), "second\n");
  assert.notEqual(gitSnapshot(cwd).patchDigest, first.patchDigest);

  const missionDir = path.join(cwd, "tugboat");
  createMission({
    dir: missionDir, actor: { name: "Alex", kind: "human" },
    metadata: { id: "m", title: "M", owner: "Alex", target: "local", repository: cwd, worktree: cwd, branch: "main", baselineGitSha: first.sha, source: { path: "spec.md", digest: `sha256:${"0".repeat(64)}` }, criticalPath: ["R1"], deployPath: "not requested" },
    requirements: [{ id: "R1", requirement: "Run", source: "spec", material: true, acceptance: "passes", proofTarget: "local" }],
    preservations: [{ id: "P1", instruction: "keep", source: "spec" }],
  });
  const secretEvidence = captureCommandEvidence({ id: "E-SECRET", requirementIds: ["R1"], cwd, command: [process.execPath, "-e", "" ] });
  secretEvidence.note = ["token=gh", "p_123456789012345678901234567890123456"].join("");
  assert.throws(() => recordEvidence(missionDir, secretEvidence), /secret material/i);
});
