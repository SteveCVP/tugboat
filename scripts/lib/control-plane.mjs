import { canonicalJson, sha256 } from "./canonical.mjs";
import { gitSnapshot } from "./evidence.mjs";
import { activeRequirementIds, missionReducer } from "./reducer.mjs";
import { renderMission } from "./render.mjs";
import { appendEvent, readState, replayEvents } from "./store.mjs";

const OPEN_STATUSES = new Set(["PENDING", "IN_PROGRESS", "BLOCKED"]);

function timestamp(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error(`${label} must be an ISO-8601 timestamp`);
  return milliseconds;
}

function safeClaim(claim) {
  return {
    id: claim.id,
    holder: claim.holder,
    requirementIds: [...claim.requirementIds],
    acquiredAt: claim.acquiredAt,
    expiresAt: claim.expiresAt,
  };
}

export function activeClaims(state, observedAt) {
  const observed = timestamp(observedAt, "observedAt");
  return Object.values(state.claims ?? {})
    .filter((claim) => claim.status === "ACTIVE" && timestamp(claim.expiresAt, `claim ${claim.id} expiresAt`) > observed)
    .sort((left, right) => left.id.localeCompare(right.id))
    .map(safeClaim);
}

function passingEvidence(state, requirement) {
  return (requirement.evidenceRefs ?? [])
    .map((id) => state.evidence?.[id])
    .filter((evidence) => evidence?.verification?.status === "passed");
}

function proofGaps(state, requirement) {
  const evidence = passingEvidence(state, requirement);
  const gaps = [];
  if (!evidence.some((item) => item.kind === "command")) gaps.push("deterministic");
  if (!evidence.some((item) => item.kind === "operator" || item.kind === "browser")) gaps.push("operator");
  if (requirement.proofTarget === "production" && !evidence.some((item) => item.kind === "deployment")) gaps.push("deployment");
  return gaps;
}

function requirementView(state, requirement) {
  return {
    id: requirement.id,
    requirement: requirement.requirement,
    acceptance: requirement.acceptance,
    proofTarget: requirement.proofTarget,
    status: requirement.status,
    proofGaps: proofGaps(state, requirement),
  };
}

export function compileExecutionPacket(state, { observedAt, git = null }) {
  if (!state?.metadata?.id) throw new Error("Execution packet needs replayed Tugboat mission state");
  timestamp(observedAt, "observedAt");
  const slice = state.slices?.[state.activeSliceId] ?? null;
  const claims = activeClaims(state, observedAt);
  const claimByRequirement = new Map(claims.flatMap((claim) => claim.requirementIds.map((id) => [id, claim])));
  const unmetDependencyIds = slice ? [...new Set((slice.dependencies ?? []).flatMap((dependency) => state.slices[dependency]?.requirementIds ?? []))]
    .filter((id) => OPEN_STATUSES.has(state.requirements[id]?.status)) : [];
  const activeIds = state.status === "COMPLETE" ? [] : activeRequirementIds(state);
  const ready = [];
  const blocked = [];
  const claimed = [];

  for (const id of activeIds) {
    const requirement = state.requirements[id];
    if (!requirement || !OPEN_STATUSES.has(requirement.status)) continue;
    const view = requirementView(state, requirement);
    const claim = claimByRequirement.get(id);
    if (claim) claimed.push({ ...view, claim });
    else if (requirement.status === "BLOCKED") blocked.push({ ...view, reason: "requirement_status" });
    else ready.push(view);
  }

  if (state.status !== "COMPLETE" && slice && unmetDependencyIds.length) {
    for (const id of slice.requirementIds) {
      const requirement = state.requirements[id];
      if (requirement && OPEN_STATUSES.has(requirement.status)) {
        blocked.push({ ...requirementView(state, requirement), reason: "slice_dependency", blockedBy: unmetDependencyIds });
      }
    }
  }

  const body = {
    schemaVersion: "tugboat.execution-packet.v1",
    mission: {
      id: state.metadata.id,
      status: state.status,
      revision: state.revision,
      protocolVersion: state.protocolVersion,
    },
    observation: {
      observedAt,
      git: git ? {
        head: git.head ?? git.sha ?? null,
        branch: git.branch ?? null,
        dirty: git.dirty ?? (git.clean === undefined ? null : !git.clean),
        ...(git.patchDigest ? { patchDigest: git.patchDigest } : {}),
      } : null,
    },
    activeSlice: slice ? {
      id: slice.id,
      name: slice.name,
      operatorJourney: slice.operatorJourney,
      dependencies: [...(slice.dependencies ?? [])],
    } : null,
    ready,
    blocked,
    claimed,
    preservations: Object.values(state.preservations ?? {})
      .filter((item) => !item.status.startsWith("PROVEN(") && item.status !== "WAIVED(user)")
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((item) => ({ id: item.id, instruction: item.instruction, regressionProofTarget: item.regressionProofTarget, status: item.status })),
    next: {
      action: state.handoff?.nextAction ?? null,
      check: state.handoff?.nextCheck ?? null,
      blocker: state.handoff?.blocker ?? null,
    },
  };
  return { ...body, packetDigest: `sha256:${sha256(canonicalJson(body))}` };
}

function missionState(dir) {
  const replayed = replayEvents(dir, { reducer: missionReducer }).state;
  const stored = readState(dir);
  if (!stored?.metadata) throw new Error(`No Tugboat v2 state in ${dir}`);
  if (stored.revision !== replayed.revision || stored.lastEventHash !== replayed.lastEventHash) {
    throw new Error("state.json does not match event replay");
  }
  return replayed;
}

function currentHead(state, dir) {
  return gitSnapshot(state.metadata.worktree, { excludePaths: [dir] }).sha;
}

export function claimRequirements(dir, {
  id,
  holder,
  requirementIds,
  ttlSeconds = 900,
  actor,
  now = new Date().toISOString(),
  expectedRevision,
  expectedHead,
}) {
  if (!id || !holder || !Array.isArray(requirementIds) || !requirementIds.length) {
    throw new Error("Work claim needs id, holder, and requirementIds");
  }
  if (new Set(requirementIds).size !== requirementIds.length) throw new Error("Work claim requirement IDs must be unique");
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 14_400) {
    throw new Error("Claim TTL must be an integer from 30 to 14400 seconds");
  }
  const acquiredAt = timestamp(now, "now");
  const state = missionState(dir);
  const head = currentHead(state, dir);
  const result = appendEvent(dir, {
    timestamp: new Date(acquiredAt).toISOString(),
    type: "WORK_CLAIMED",
    actor,
    payload: {
      claim: {
        id,
        holder,
        requirementIds: [...requirementIds],
        expiresAt: new Date(acquiredAt + ttlSeconds * 1000).toISOString(),
      },
    },
  }, {
    reducer: missionReducer,
    expectedRevision: expectedRevision ?? state.revision,
    expectedHead,
    currentHead: head,
  });
  renderMission(dir, result.state);
  return { ...result, claim: result.state.claims[id] };
}

export function releaseClaim(dir, {
  claimId,
  holder,
  actor,
  now = new Date().toISOString(),
  expectedRevision,
  expectedHead,
}) {
  if (!claimId || !holder) throw new Error("Work release needs claimId and holder");
  const releasedAt = timestamp(now, "now");
  const state = missionState(dir);
  const head = currentHead(state, dir);
  const result = appendEvent(dir, {
    timestamp: new Date(releasedAt).toISOString(),
    type: "WORK_RELEASED",
    actor,
    payload: { claimId, holder },
  }, {
    reducer: missionReducer,
    expectedRevision: expectedRevision ?? state.revision,
    expectedHead,
    currentHead: head,
  });
  renderMission(dir, result.state);
  return { ...result, claim: result.state.claims[claimId] };
}
