import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { runProofMutations } from "./lib/proof-mutation.mjs";

function repository() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-mutation-"));
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: root });
  execFileSync("git", ["config", "user.name", "Tugboat Test"], { cwd: root });
  execFileSync("git", ["config", "user.email", "tugboat@example.invalid"], { cwd: root });
  fs.writeFileSync(path.join(root, "rule.mjs"), "// unused-marker\nexport const allowed = true;\n");
  fs.writeFileSync(path.join(root, "gate.mjs"), "import { allowed } from './rule.mjs'; if (!allowed) process.exit(7);\n");
  execFileSync("git", ["add", "."], { cwd: root });
  execFileSync("git", ["commit", "-qm", "fixture"], { cwd: root });
  return root;
}

test("proof mutations distinguish killed, survived, and invalid without changing source", () => {
  const repo = repository();
  const before = execFileSync("git", ["status", "--porcelain=v1"], { cwd: repo, encoding: "utf8" });
  const report = runProofMutations({
    repoDir: repo,
    plan: {
      schemaVersion: "tugboat.proof-mutation-plan.v1",
      mutations: [
        { id: "killed", requirementId: "R1", gateId: "unit", path: "rule.mjs", find: "true", replace: "false", expectedOccurrences: 1 },
        { id: "survived", requirementId: "R1", gateId: "unit", path: "rule.mjs", find: "unused-marker", replace: "changed-marker", expectedOccurrences: 1 },
        { id: "invalid", requirementId: "R1", gateId: "unit", path: "rule.mjs", find: "missing", replace: "x", expectedOccurrences: 1 },
      ],
    },
    command: [process.execPath, "gate.mjs"],
  });
  assert.equal(report.status, "blocked");
  assert.deepEqual(report.results.map(({ id, outcome }) => [id, outcome]), [
    ["invalid", "invalid"], ["killed", "killed"], ["survived", "survived"],
  ]);
  assert.equal(execFileSync("git", ["status", "--porcelain=v1"], { cwd: repo, encoding: "utf8" }), before);
  assert.equal(fs.readFileSync(path.join(repo, "rule.mjs"), "utf8"), "// unused-marker\nexport const allowed = true;\n");
});

test("proof mutation rejects traversal, symlinks, duplicate IDs, dirty repositories, and commands in plans", () => {
  const repo = repository();
  const base = { schemaVersion: "tugboat.proof-mutation-plan.v1", mutations: [] };
  assert.throws(() => runProofMutations({ repoDir: repo, plan: { ...base, command: ["sh"] }, command: [process.execPath, "gate.mjs"] }), /Unknown mutation plan field command/);
  assert.throws(() => runProofMutations({ repoDir: repo, plan: { ...base, mutations: [{ id: "x", requirementId: "R1", gateId: "g", path: "../x", find: "a", replace: "b", expectedOccurrences: 1 }] }, command: [process.execPath, "gate.mjs"] }), /portable relative path/);
  fs.writeFileSync(path.join(repo, "dirty.txt"), "dirty");
  const valid = { ...base, mutations: [{ id: "x", requirementId: "R1", gateId: "g", path: "rule.mjs", find: "true", replace: "false", expectedOccurrences: 1 }] };
  assert.throws(() => runProofMutations({ repoDir: repo, plan: valid, command: [process.execPath, "gate.mjs"] }), /clean repository/);
});

test("proof mutation rejects no-op and binary mutations instead of producing misleading survivors", () => {
  const repo = repository();
  const noop = { schemaVersion: "tugboat.proof-mutation-plan.v1", mutations: [{ id: "x", requirementId: "R1", gateId: "g", path: "rule.mjs", find: "true", replace: "true", expectedOccurrences: 1 }] };
  assert.throws(() => runProofMutations({ repoDir: repo, plan: noop, command: [process.execPath, "gate.mjs"] }), /must change content/);
  fs.writeFileSync(path.join(repo, "binary.bin"), Buffer.from([0, 255, 1]));
  execFileSync("git", ["add", "binary.bin"], { cwd: repo });
  execFileSync("git", ["commit", "-qm", "binary"], { cwd: repo });
  const binary = { schemaVersion: "tugboat.proof-mutation-plan.v1", mutations: [{ id: "x", requirementId: "R1", gateId: "g", path: "binary.bin", find: "x", replace: "y", expectedOccurrences: 1 }] };
  assert.throws(() => runProofMutations({ repoDir: repo, plan: binary, command: [process.execPath, "gate.mjs"] }), /text file/);
});
