import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./canonical.mjs";
import { inspectContinuity } from "./continuity.mjs";
import { gitSnapshot, validateEvidence } from "./evidence.mjs";
import { missionReducer } from "./reducer.mjs";
import { renderMission } from "./render.mjs";
import { appendEvent, readState, replayEvents } from "./store.mjs";
import { resolveMissionWorkspace } from "./workspace.mjs";

function git(cwd, args) {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

export class MissionValidationError extends Error {
  constructor(report) {
    super(`Tugboat validation failed:\n- ${report.errors.map((error) => `${error.code}: ${error.message}`).join("\n- ")}`);
    this.name = "MissionValidationError";
    this.exitCode = 3;
    this.report = report;
  }
}

export function validateAppendOnlyBaseline(missionDir, baseRef) {
  const state = readState(missionDir);
  if (!state) return [{ code: "state_missing", message: "state.json is missing" }];
  const workspace = resolveMissionWorkspace(missionDir, state);
  const worktree = workspace.worktree;
  const relative = path.relative(worktree, path.join(workspace.missionDir, "events.jsonl"));
  const baseline = git(worktree, ["show", `${baseRef}:${relative}`]);
  if (baseline === null) return [{ code: "baseline_missing", message: `${baseRef} does not contain ${relative}` }];
  const current = fs.readFileSync(path.join(missionDir, "events.jsonl"), "utf8").trimEnd();
  if (current !== baseline && !current.startsWith(`${baseline}\n`)) return [{ code: "baseline_rewritten", message: `Event history from ${baseRef} is not an exact prefix of current history` }];
  return [];
}

function inferredGenesisCommit(state, missionDir) {
  const workspace = resolveMissionWorkspace(missionDir, state);
  const worktree = workspace.worktree;
  const relative = path.relative(worktree, path.join(workspace.missionDir, "events.jsonl"));
  return git(worktree, ["log", "--reverse", "--format=%H", "--", relative])?.split("\n").filter(Boolean)[0] ?? null;
}

function evidenceErrors(state) {
  const errors = [];
  for (const evidence of Object.values(state.evidence)) {
    try {
      for (const message of validateEvidence(evidence, { verifyArtifacts: true })) errors.push({ code: "invalid_evidence", message: `${evidence.id}: ${message}` });
    } catch (error) {
      errors.push({ code: "invalid_evidence", message: `${evidence.id}: ${error.message}` });
    }
  }
  return errors;
}

export function validateMission(missionDir, { baseRef, maxHandoffAgeHours = 24, requireClean = true, requireCompletion = true } = {}) {
  const errors = [];
  let state;
  try {
    const replayed = replayEvents(missionDir, { reducer: missionReducer }).state;
    const stored = readState(missionDir);
    if (!stored || canonicalJson(stored) !== canonicalJson(replayed)) errors.push({ code: "snapshot_mismatch", message: "state.json does not match event replay" });
    state = replayed;
  } catch (error) {
    return { valid: false, errors: [{ code: "event_tampering", message: error.message }], state: null };
  }

  const continuity = inspectContinuity(missionDir, { maxHandoffAgeHours });
  for (const issue of continuity.issues) errors.push(issue);
  const baseline = baseRef ?? inferredGenesisCommit(state, missionDir);
  if (!baseline) errors.push({ code: "baseline_missing", message: "No committed genesis event exists" });
  else errors.push(...validateAppendOnlyBaseline(missionDir, baseline));

  for (const requirement of Object.values(state.requirements)) {
    const acceptable = requirement.proofTarget === "production"
      ? ["PROVEN(production)", "WAIVED(user)"]
      : ["PROVEN(local)", "PROVEN(production)", "WAIVED(user)"];
    if (requireCompletion && requirement.material !== false && !acceptable.includes(requirement.status)) errors.push({ code: "unclosed_requirement", message: `${requirement.id} is ${requirement.status}, target=${requirement.proofTarget}` });
    for (const evidenceId of requirement.evidenceRefs) if (!state.evidence[evidenceId]) errors.push({ code: "missing_evidence", message: `${requirement.id} references missing evidence ${evidenceId}` });
    if (requirement.status.startsWith("PROVEN(")) {
      const evidence = requirement.evidenceRefs.map((id) => state.evidence[id]).filter(Boolean);
      if (!evidence.some((item) => item.kind === "command" && item.verification.status === "passed")) errors.push({ code: "deterministic_proof_missing", message: `${requirement.id} lacks passing command evidence` });
      if (!evidence.some((item) => ["operator", "browser"].includes(item.kind) && item.verification.status === "passed")) errors.push({ code: "operator_proof_missing", message: `${requirement.id} lacks operator/browser evidence` });
    }
    if (requirement.status === "PROVEN(production)") {
      const evidence = requirement.evidenceRefs.map((id) => state.evidence[id]).filter(Boolean);
      if (!evidence.some((item) => item.kind === "deployment" && item.verification.status === "passed")) errors.push({ code: "deployment_proof_missing", message: `${requirement.id} lacks verified deployment evidence` });
      if (!evidence.some((item) => ["operator", "browser"].includes(item.kind) && item.verification.status === "passed")) errors.push({ code: "operator_proof_missing", message: `${requirement.id} lacks live operator/browser evidence` });
    }
  }
  if (requireCompletion) {
    for (const preservation of Object.values(state.preservations)) {
      if (!["PROVEN(local)", "PROVEN(production)", "WAIVED(user)"].includes(preservation.status)) errors.push({ code: "unclosed_preservation", message: `${preservation.id} is ${preservation.status}` });
    }
  }
  for (const amendment of Object.values(state.amendments)) {
    if (!amendment.supersededBy && amendment.conflictsWith.length) errors.push({ code: "scope_conflict", message: `${amendment.id} conflicts with ${amendment.conflictsWith.join(",")}` });
  }
  errors.push(...evidenceErrors(state));
  if (requireClean) {
    const snapshot = gitSnapshot(resolveMissionWorkspace(missionDir, state).worktree);
    if (!snapshot.clean) errors.push({ code: "dirty_worktree", message: `Close/CI requires a clean tree; found ${snapshot.files.join(", ")}` });
  }
  const unique = [...new Map(errors.map((error) => [`${error.code}:${error.message}`, error])).values()];
  return { valid: unique.length === 0, errors: unique, state, baselineRef: baseline };
}

export function closeMission(missionDir, { actor, baseRef } = {}) {
  const report = validateMission(missionDir, { baseRef, requireClean: true });
  if (!report.valid) throw new MissionValidationError(report);
  const head = git(resolveMissionWorkspace(missionDir, report.state).worktree, ["rev-parse", "HEAD"]);
  const result = appendEvent(missionDir, { type: "MISSION_CLOSED", actor, payload: { validationBaseline: report.baselineRef } }, {
    reducer: missionReducer,
    expectedRevision: report.state.revision,
    currentHead: head,
  });
  renderMission(missionDir, result.state);
  return result.state;
}
