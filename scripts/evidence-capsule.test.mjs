import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { captureEvidenceCapsule, replayEvidenceCapsule, verifyEvidenceCapsule } from "./lib/evidence-capsule.mjs";

function repository() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-capsule-"));
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: root });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: root });
  execFileSync("git", ["config", "user.email", "tugboat@example.invalid"], { cwd: root });
  fs.writeFileSync(path.join(root, "input.txt"), "alpha\n");
  fs.writeFileSync(path.join(root, "proof.mjs"), "import fs from 'node:fs'; process.stdout.write(fs.readFileSync('input.txt','utf8'));\n");
  execFileSync("git", ["add", "."], { cwd: root });
  execFileSync("git", ["commit", "-qm", "fixture"], { cwd: root });
  return root;
}

test("capsules capture declared context, verify exact inputs, and replay explicitly", () => {
  const repo = repository();
  const before = execFileSync("git", ["status", "--porcelain=v1"], { cwd: repo, encoding: "utf8" });
  const capsule = captureEvidenceCapsule({ repoDir: repo, inputPaths: ["input.txt", "proof.mjs"], command: [process.execPath, "proof.mjs"], capturedAt: "2026-10-28T12:00:00.000Z" });
  assert.equal(capsule.execution.exitCode, 0);
  assert.match(capsule.digest, /^sha256:/);
  assert.equal(verifyEvidenceCapsule(capsule, { repoDir: repo }).status, "ready");
  const replay = replayEvidenceCapsule(capsule, { repoDir: repo, command: [process.execPath, "proof.mjs"] });
  assert.equal(replay.status, "ready");
  assert.equal(replay.comparison, "exact");
  assert.equal(execFileSync("git", ["status", "--porcelain=v1"], { cwd: repo, encoding: "utf8" }), before);
});

test("capsules detect body tampering, changed inputs, and divergent replay", () => {
  const repo = repository();
  const capsule = captureEvidenceCapsule({ repoDir: repo, inputPaths: ["input.txt"], command: [process.execPath, "-e", "process.stdout.write('ok')"], capturedAt: "2026-10-28T12:00:00.000Z" });
  const tampered = structuredClone(capsule);
  tampered.execution.exitCode = 3;
  assert.throws(() => verifyEvidenceCapsule(tampered), /digest mismatch/);
  const malformed = structuredClone(capsule);
  malformed.unknown = true;
  malformed.digest = (() => { const { digest: _digest, ...body } = malformed; return `sha256:${import.meta.url.length.toString(16).padStart(64, "0")}`; })();
  assert.throws(() => verifyEvidenceCapsule(malformed), /Unknown evidence capsule field/);
  fs.writeFileSync(path.join(repo, "input.txt"), "changed\n");
  assert.equal(verifyEvidenceCapsule(capsule, { repoDir: repo }).status, "blocked");
  execFileSync("git", ["checkout", "--", "input.txt"], { cwd: repo });
  const replay = replayEvidenceCapsule(capsule, { repoDir: repo, command: [process.execPath, "-e", "process.stdout.write('different')"] });
  assert.equal(replay.status, "blocked");
  assert.equal(replay.comparison, "different");
});
