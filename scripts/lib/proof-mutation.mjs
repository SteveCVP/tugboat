import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { canonicalReport } from "./intelligence-core.mjs";
import { assertArgv, canonicalDigest, exactObject, operatorExecutionEnvironment, portableRelativePath, resolvePortable, runBounded } from "./proof-runtime.mjs";
import { isTextBuffer } from "./security.mjs";

const PLAN_FIELDS = ["schemaVersion", "mutations"];
const MUTATION_FIELDS = ["id", "requirementId", "gateId", "path", "find", "replace", "expectedOccurrences", "rationale"];

function git(repoDir, args) {
  return execFileSync("git", args, { cwd: repoDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function validatePlan(plan) {
  exactObject(plan, "mutation plan", PLAN_FIELDS, PLAN_FIELDS);
  if (plan.schemaVersion !== "tugboat.proof-mutation-plan.v1") throw new Error("Unsupported mutation plan schemaVersion");
  if (!Array.isArray(plan.mutations) || plan.mutations.length < 1 || plan.mutations.length > 128) throw new Error("Mutation plan must contain 1 to 128 mutations");
  const ids = new Set();
  return plan.mutations.map((mutation, index) => {
    exactObject(mutation, `mutation[${index}]`, MUTATION_FIELDS, ["id", "requirementId", "gateId", "path", "find", "replace", "expectedOccurrences"]);
    if (ids.has(mutation.id)) throw new Error(`Duplicate mutation ID ${mutation.id}`);
    ids.add(mutation.id);
    portableRelativePath(mutation.path, `mutation[${index}].path`);
    for (const field of ["id", "requirementId", "gateId", "find", "replace"]) {
      if (typeof mutation[field] !== "string" || !mutation[field] || Buffer.byteLength(mutation[field]) > 16_384) throw new Error(`mutation[${index}].${field} is invalid`);
    }
    if (mutation.find === mutation.replace) throw new Error(`mutation[${index}] must change content`);
    if (!Number.isInteger(mutation.expectedOccurrences) || mutation.expectedOccurrences < 1 || mutation.expectedOccurrences > 1024) {
      throw new Error(`mutation[${index}].expectedOccurrences is invalid`);
    }
    return mutation;
  });
}

function occurrenceCount(contents, find) {
  let count = 0;
  let offset = 0;
  while ((offset = contents.indexOf(find, offset)) >= 0) {
    count += 1;
    offset += Math.max(find.length, 1);
  }
  return count;
}

export function runProofMutations({ repoDir, plan, command, timeoutMs = 30_000, maxOutputBytes = 1024 * 1024 }) {
  const mutations = validatePlan(plan);
  assertArgv(command);
  const repo = fs.realpathSync(repoDir);
  if (git(repo, ["status", "--porcelain=v1"])) throw new Error("Proof mutation requires a clean repository");
  const head = git(repo, ["rev-parse", "HEAD"]);
  const tracked = new Set(git(repo, ["ls-files", "-z"]).split("\0").filter(Boolean));
  const results = [];
  for (const mutation of mutations) {
    if (!tracked.has(mutation.path)) throw new Error(`Mutation path is not tracked: ${mutation.path}`);
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-mutation-run-"));
    const worktree = path.join(parent, "worktree");
    let added = false;
    try {
      git(repo, ["worktree", "add", "--detach", worktree, head]);
      added = true;
      const file = resolvePortable(worktree, mutation.path, { regularFile: true });
      const stat = fs.statSync(file);
      if (stat.size > 4 * 1024 * 1024) throw new Error(`Mutation file is too large: ${mutation.path}`);
      const source = fs.readFileSync(file);
      if (!isTextBuffer(source)) throw new Error(`Mutation path must be a UTF-8 text file: ${mutation.path}`);
      const contents = source.toString("utf8");
      const count = occurrenceCount(contents, mutation.find);
      if (count !== mutation.expectedOccurrences) {
        results.push({ id: mutation.id, requirementId: mutation.requirementId, gateId: mutation.gateId, outcome: "invalid", expectedOccurrences: mutation.expectedOccurrences, actualOccurrences: count });
        continue;
      }
      fs.writeFileSync(file, contents.split(mutation.find).join(mutation.replace));
      const execution = runBounded(command[0], command.slice(1), { cwd: worktree, environment: operatorExecutionEnvironment(), timeoutMs, maxOutputBytes });
      results.push({
        id: mutation.id,
        requirementId: mutation.requirementId,
        gateId: mutation.gateId,
        outcome: execution.exitCode === 0 && !execution.timedOut ? "survived" : "killed",
        exitCode: execution.exitCode,
        timedOut: execution.timedOut,
        stdoutDigest: execution.stdoutDigest,
        stderrDigest: execution.stderrDigest,
      });
    } finally {
      if (added) {
        try { git(repo, ["worktree", "remove", "--force", worktree]); } catch { /* cleanup below */ }
      }
      fs.rmSync(parent, { recursive: true, force: true });
      try { git(repo, ["worktree", "prune"]); } catch { /* best effort after exact cleanup */ }
    }
  }
  results.sort((left, right) => left.id.localeCompare(right.id));
  const hasSurvivor = results.some((result) => result.outcome === "survived");
  const hasInvalid = results.some((result) => result.outcome === "invalid");
  return canonicalReport("tugboat.proof-mutation.v1", {
    status: hasSurvivor ? "blocked" : hasInvalid ? "insufficient_evidence" : "ready",
    source: { head, planDigest: canonicalDigest(plan), commandDigest: canonicalDigest(command) },
    results,
    summary: {
      killed: results.filter((result) => result.outcome === "killed").length,
      survived: results.filter((result) => result.outcome === "survived").length,
      invalid: results.filter((result) => result.outcome === "invalid").length,
    },
  });
}
