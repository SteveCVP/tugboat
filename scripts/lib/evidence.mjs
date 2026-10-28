import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { sha256 } from "./canonical.mjs";
import { missionReducer } from "./reducer.mjs";
import { renderMission } from "./render.mjs";
import { assertNoSecrets } from "./security.mjs";
import { appendEvent, readState } from "./store.mjs";

function git(cwd, args) {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

function relativeExclusions(cwd, excludePaths) {
  return excludePaths.map((item) => path.relative(cwd, path.resolve(item))).filter((item) => item && !item.startsWith(".."));
}

function isExcluded(file, exclusions) {
  return exclusions.some((excluded) => file === excluded || file.startsWith(`${excluded}${path.sep}`) || file.startsWith(`${excluded}/`));
}

export function gitSnapshot(cwd, { excludePaths = [] } = {}) {
  const sha = git(cwd, ["rev-parse", "HEAD"]);
  if (!sha) throw new Error(`Cannot read Git state in ${cwd}`);
  const exclusions = relativeExclusions(cwd, excludePaths);
  const porcelain = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd, encoding: "utf8" }).trimEnd();
  const lines = porcelain.split("\n").filter(Boolean);
  const included = lines.filter((line) => {
    const file = line.slice(3).split(" -> ").at(-1);
    return !isExcluded(file, exclusions);
  });
  if (!included.length) return { sha, clean: true, patchDigest: null, files: [] };
  const trackedDiff = execFileSync("git", ["diff", "--binary", "HEAD", "--", ".", ...exclusions.map((excluded) => `:(exclude)${excluded}`)], { cwd });
  const untracked = included.filter((line) => line.startsWith("?? ")).map((line) => line.slice(3)).sort();
  const untrackedProof = untracked.map((file) => {
    const absolute = path.join(cwd, file);
    return fs.existsSync(absolute) && fs.statSync(absolute).isFile() ? `${file}:${sha256(fs.readFileSync(absolute))}` : `${file}:non-file`;
  }).join("\n");
  const filteredStatus = included.join("\n");
  return {
    sha,
    clean: false,
    patchDigest: `sha256:${sha256(Buffer.concat([Buffer.from(filteredStatus), trackedDiff, Buffer.from(untrackedProof)]))}`,
    files: included.map((line) => line.slice(3)),
  };
}

export function captureCommandEvidence({ id, requirementIds, cwd, command, actor = { name: "unknown", kind: "unknown" }, capturedAt = new Date().toISOString(), excludePaths = [] }) {
  if (!Array.isArray(command) || !command.length) throw new Error("command evidence needs a command array");
  const result = spawnSync(command[0], command.slice(1), { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const exitCode = result.status ?? 1;
  return {
    schemaVersion: 1,
    id,
    kind: "command",
    requirementIds,
    capturedAt,
    origin: { actor, cwd },
    git: gitSnapshot(cwd, { excludePaths }),
    verification: {
      status: exitCode === 0 ? "passed" : "failed",
      verifier: "tugboat:2.0",
      command,
      exitCode,
      stdoutDigest: `sha256:${sha256(result.stdout ?? "")}`,
      stderrDigest: `sha256:${sha256(result.stderr ?? "")}`,
    },
    artifacts: [],
  };
}

export function captureObservationEvidence({ id, kind = "operator", requirementIds, cwd, actor, url, result, viewport, capturedAt = new Date().toISOString(), excludePaths = [] }) {
  if (!["operator", "browser"].includes(kind)) throw new Error(`Unsupported observation kind ${kind}`);
  return {
    schemaVersion: 1,
    id,
    kind,
    requirementIds,
    capturedAt,
    origin: { actor, cwd },
    git: gitSnapshot(cwd, { excludePaths }),
    verification: { status: "passed", verifier: `${kind}:${actor.name}`, url, result, ...(viewport ? { viewport } : {}) },
    artifacts: [],
  };
}

export function validateEvidence(evidence, { verifyArtifacts = false } = {}) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) throw new Error("Proof must be a structured evidence object");
  const missingCore = ["schemaVersion", "id", "kind", "requirementIds", "capturedAt", "origin", "git", "verification"].filter((field) => evidence[field] === undefined || evidence[field] === null || evidence[field] === "");
  if (missingCore.length) throw new Error(`Structured evidence is missing ${missingCore.join(", ")}`);
  const errors = [];
  if (!Array.isArray(evidence.requirementIds) || !evidence.requirementIds.length) errors.push("Evidence needs at least one requirement ID");
  if (evidence.verification?.status !== "passed") errors.push("Evidence verification did not pass");
  if (!evidence.verification?.verifier) errors.push("Evidence is missing verification verifier");
  if (evidence.kind === "command") {
    if (!Array.isArray(evidence.verification?.command) || !evidence.verification.command.length) errors.push("Command evidence is missing command");
    if (evidence.verification?.exitCode !== 0) errors.push("Command evidence did not pass with exit code 0");
  }
  if (evidence.kind === "deployment") {
    if (!evidence.deployment?.provider || !evidence.deployment?.environment || !evidence.deployment?.deployedSha || !evidence.deployment?.source) errors.push("Deployment evidence is missing provider, environment, deployedSha, or source");
  }
  if (["operator", "browser"].includes(evidence.kind)) {
    if (!evidence.origin?.actor?.name) errors.push("Operator/browser evidence is missing the observing actor");
    if (!evidence.verification?.url) errors.push("Operator/browser evidence is missing an observable URL");
    if (!evidence.verification?.result) errors.push("Operator/browser evidence is missing an observable result");
  }
  if (evidence.git && evidence.git.clean === false && !/^sha256:[0-9a-f]{64}$/.test(evidence.git.patchDigest ?? "")) errors.push("Dirty evidence needs an exact patch digest");
  if (verifyArtifacts) {
    for (const artifact of evidence.artifacts ?? []) {
      const absolute = path.resolve(evidence.origin?.cwd ?? process.cwd(), artifact.path);
      if (!fs.existsSync(absolute)) errors.push(`Missing artifact: ${artifact.path}`);
      else if (`sha256:${sha256(fs.readFileSync(absolute))}` !== artifact.digest) errors.push(`Artifact digest changed: ${artifact.path}`);
    }
  }
  return errors;
}

export function recordEvidence(missionDir, evidence, { actor = evidence.origin?.actor } = {}) {
  assertNoSecrets(evidence, "evidence");
  const errors = validateEvidence(evidence, { verifyArtifacts: true });
  if (errors.length) throw new Error(`Invalid evidence:\n- ${errors.join("\n- ")}`);
  const state = readState(missionDir);
  if (!state) throw new Error(`No Tugboat v2 state in ${missionDir}`);
  if (state.evidence[evidence.id]) throw new Error(`Evidence ${evidence.id} already exists`);
  const result = appendEvent(missionDir, { type: "EVIDENCE_RECORDED", actor, payload: { evidence } }, {
    reducer: missionReducer,
    expectedRevision: state.revision,
    currentHead: evidence.git.sha,
  });
  const evidenceDir = path.join(missionDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true });
  const file = path.join(evidenceDir, `${evidence.id}.json`);
  const temp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temp, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temp, file);
  renderMission(missionDir, result.state);
  return result.state;
}

export function checkpointMission(missionDir, { actor, requirementIds = [], preservationIds = [], status, evidenceRefs, result, action, nextAction, nextCheck, blocker }) {
  const state = readState(missionDir);
  if (!state) throw new Error(`No Tugboat v2 state in ${missionDir}`);
  if (!requirementIds.length && !preservationIds.length) throw new Error("Checkpoint needs requirementIds or preservationIds");
  if (!Array.isArray(evidenceRefs) || !evidenceRefs.length) throw new Error("Checkpoint requires structured evidence IDs");
  const implementationSnapshot = gitSnapshot(state.metadata.worktree, { excludePaths: [missionDir] });
  for (const evidenceId of evidenceRefs) {
    const evidence = state.evidence[evidenceId];
    if (!evidence) throw new Error(`Unknown evidence ${evidenceId}`);
    const errors = validateEvidence(evidence, { verifyArtifacts: true });
    if (errors.length) throw new Error(`Evidence ${evidenceId} is invalid:\n- ${errors.join("\n- ")}`);
    for (const id of requirementIds) if (!evidence.requirementIds.includes(id)) throw new Error(`Evidence ${evidenceId} does not cover ${id}`);
    if (!evidence.git.clean && evidence.git.patchDigest !== implementationSnapshot.patchDigest) throw new Error(`Evidence ${evidenceId} patch digest does not match the current implementation patch`);
  }
  if (status?.startsWith("PROVEN(") && requirementIds.length) {
    const evidence = evidenceRefs.map((id) => state.evidence[id]);
    if (!evidence.some((item) => item.kind === "command" && item.verification.status === "passed")) throw new Error("Proof requires passing deterministic command evidence");
    if (!evidence.some((item) => ["operator", "browser"].includes(item.kind) && item.verification.status === "passed")) throw new Error("Proof requires live operator or browser evidence");
  }
  if (status === "PROVEN(production)") {
    if (!implementationSnapshot.clean) throw new Error("Production proof requires a clean implementation tree");
    const evidence = evidenceRefs.map((id) => state.evidence[id]);
    const deployment = evidence.find((item) => item.kind === "deployment" && item.verification.status === "passed");
    if (!deployment) throw new Error("Production proof requires provider-verified deployment evidence");
    if (deployment.deployment.deployedSha !== implementationSnapshot.sha) throw new Error(`Provider deployed SHA ${deployment.deployment.deployedSha} does not match implementation SHA ${implementationSnapshot.sha}`);
    if (!evidence.some((item) => ["operator", "browser"].includes(item.kind) && item.verification.status === "passed")) throw new Error("Production proof requires live operator or browser evidence");
  }
  const event = appendEvent(missionDir, {
    type: "CHECKPOINT_RECORDED",
    actor,
    payload: { requirementIds, preservationIds, status, evidenceRefs, result, action, nextAction, nextCheck, blocker, sliceProgressionVersion: 1 },
  }, { reducer: missionReducer, expectedRevision: state.revision, currentHead: implementationSnapshot.sha });
  renderMission(missionDir, event.state);
  return event.state;
}
