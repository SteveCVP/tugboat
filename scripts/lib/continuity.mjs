import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { gitSnapshot } from "./evidence.mjs";
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

export class ContinuityError extends Error {
  constructor(report) {
    super(`Tugboat continuity check failed:\n- ${report.issues.map((issue) => `${issue.code}: ${issue.message}`).join("\n- ")}`);
    this.name = "ContinuityError";
    this.exitCode = 4;
    this.report = report;
  }
}

export function inspectContinuity(missionDir, { now = new Date(), maxHandoffAgeHours = 24 } = {}) {
  const issues = [];
  let state;
  try {
    const replayed = replayEvents(missionDir, { reducer: missionReducer }).state;
    const stored = readState(missionDir);
    if (!stored || canonicalJson(stored) !== canonicalJson(replayed)) {
      issues.push({ code: "snapshot_mismatch", message: "state.json does not match event replay" });
    }
    state = replayed;
  } catch (error) {
    return { state: null, issues: [{ code: "event_tampering", message: error.message }] };
  }
  const workspace = resolveMissionWorkspace(missionDir, state);
  const worktree = workspace.worktree;
  const actualHead = git(worktree, ["rev-parse", "HEAD"]);
  const actualBranch = git(worktree, ["branch", "--show-current"]);
  if (!actualHead) issues.push({ code: "git_unavailable", message: `Cannot read Git HEAD in ${worktree}` });
  if (actualBranch && actualBranch !== state.metadata.branch) issues.push({ code: "branch_drift", message: `Recorded branch ${state.metadata.branch}, actual ${actualBranch}` });
  const relativeEvents = path.relative(worktree, path.join(workspace.missionDir, "events.jsonl"));
  const lastMissionCommit = git(worktree, ["log", "-1", "--format=%H", "--", relativeEvents]);
  if (!lastMissionCommit) issues.push({ code: "mission_uncommitted", message: "Genesis/event history has not been committed" });
  else if (actualHead && lastMissionCommit !== actualHead) {
    const count = git(worktree, ["rev-list", "--count", `${lastMissionCommit}..${actualHead}`]);
    issues.push({ code: "unrecorded_commits", message: `${count ?? "unknown"} commit(s) exist after the latest committed mission event` });
  }
  const snapshot = actualHead ? gitSnapshot(worktree, { excludePaths: [workspace.missionDir] }) : null;
  if (snapshot && !snapshot.clean && snapshot.patchDigest !== state.handoff.allowedPatchDigest) {
    issues.push({ code: "dirty_worktree", message: `Unreconciled implementation patch ${snapshot.patchDigest}` });
  }
  const sourceFile = path.resolve(workspace.repository, state.metadata.source.path);
  if (!fs.existsSync(sourceFile)) issues.push({ code: "source_missing", message: `Source specification is missing: ${sourceFile}` });
  else {
    const digest = `sha256:${sha256(fs.readFileSync(sourceFile))}`;
    if (digest !== state.metadata.source.digest) issues.push({ code: "source_drift", message: `Source digest changed from ${state.metadata.source.digest} to ${digest}`, actualDigest: digest });
  }
  const updated = Date.parse(state.handoff.updatedAt);
  const ageHours = (now.getTime() - updated) / 3_600_000;
  if (!Number.isFinite(updated) || ageHours > maxHandoffAgeHours) issues.push({ code: "stale_handoff", message: `Handoff is ${Number.isFinite(ageHours) ? ageHours.toFixed(1) : "unknown"} hours old` });
  return { state, issues, git: { actualHead, actualBranch, lastMissionCommit, snapshot } };
}

export function assertContinuity(missionDir, options) {
  const report = inspectContinuity(missionDir, options);
  if (report.issues.length) throw new ContinuityError(report);
  return report;
}

export function reconcileMission(missionDir, { actor, reason, issueCodes, allowCurrentPatch = false, acceptSourceDrift = false, nextAction }) {
  const report = inspectContinuity(missionDir, { maxHandoffAgeHours: Number.POSITIVE_INFINITY });
  const state = report.state;
  if (!state) throw new ContinuityError(report);
  const actualCodes = new Set(report.issues.map((issue) => issue.code));
  for (const code of issueCodes) if (!actualCodes.has(code)) throw new Error(`Cannot reconcile absent issue ${code}`);
  if (allowCurrentPatch && !issueCodes.includes("dirty_worktree")) throw new Error("dirty_worktree must be explicitly named when allowing the current patch");
  if (acceptSourceDrift && !issueCodes.includes("source_drift")) throw new Error("source_drift must be explicitly named when accepting source drift");
  const sourceIssue = report.issues.find((issue) => issue.code === "source_drift");
  const result = appendEvent(missionDir, {
    type: "RECONCILED",
    actor,
    payload: {
      reason,
      issueCodes,
      allowedPatchDigest: allowCurrentPatch ? report.git?.snapshot?.patchDigest : null,
      sourceDigest: acceptSourceDrift ? sourceIssue?.actualDigest : null,
      nextAction,
    },
  }, { reducer: missionReducer, expectedRevision: state.revision, currentHead: report.git?.actualHead });
  renderMission(missionDir, result.state);
  return result.state;
}
