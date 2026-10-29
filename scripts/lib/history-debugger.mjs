import { canonicalDigest } from "./proof-runtime.mjs";
import { missionReducer } from "./reducer.mjs";
import { verifyRollbackCertificate } from "./rollback-equivalence.mjs";
import { replayEvents } from "./store.mjs";

function replaySubset(events, revision) {
  let state = { schemaVersion: 2, revision: 0, lastEventHash: "0".repeat(64) };
  for (const event of events.slice(0, revision)) {
    state = missionReducer(state, event);
    state = { ...state, schemaVersion: state.schemaVersion ?? 2, revision: event.sequence, lastEventHash: event.hash, updatedAt: event.timestamp, ...(event.gitHead !== undefined ? { currentHead: event.gitHead } : {}) };
  }
  return state;
}

function snapshot(state, requirementId) {
  const requirement = requirementId ? state.requirements?.[requirementId] : null;
  if (requirementId && !requirement) throw new Error(`Unknown requirement ${requirementId}`);
  return {
    revision: state.revision,
    status: state.status,
    activeSliceId: state.activeSliceId ?? null,
    evidenceIds: Object.keys(state.evidence ?? {}).sort(),
    deploymentIds: Object.keys(state.deployments ?? {}).sort(),
    amendmentIds: Object.keys(state.amendments ?? {}).sort(),
    claims: Object.values(state.claims ?? {}).map((claim) => ({ id: claim.id, holder: claim.holder, requirementIds: [...claim.requirementIds].sort(), status: claim.status, expiresAt: claim.expiresAt })).sort((left, right) => left.id.localeCompare(right.id)),
    ...(requirement ? { requirement: { id: requirement.id, status: requirement.status, evidenceRefs: [...requirement.evidenceRefs], amendedBy: [...requirement.amendedBy], result: requirement.result } } : {}),
  };
}

function affectedIds(event) {
  const ids = new Set();
  const payload = event.payload ?? {};
  if (event.type === "GENESIS") for (const requirement of payload.requirements ?? []) ids.add(requirement.id);
  if (payload.requirementId) ids.add(payload.requirementId);
  for (const field of ["requirementIds", "affectedIds"]) for (const id of payload[field] ?? []) ids.add(id);
  for (const id of payload.evidence?.requirementIds ?? []) ids.add(id);
  for (const candidate of payload.candidates ?? []) {
    for (const id of candidate.targetRequirementIds ?? []) ids.add(id);
  }
  return [...ids].sort();
}

export function explainMissionHistory(dir, { revision, requirementId } = {}) {
  const replayed = replayEvents(dir, { reducer: missionReducer });
  const currentRevision = replayed.state.revision;
  const selectedRevision = revision ?? currentRevision;
  if (!Number.isInteger(selectedRevision) || selectedRevision < 1 || selectedRevision > currentRevision) throw new Error(`Selected revision must be between 1 and ${currentRevision}`);
  const selectedState = replaySubset(replayed.events, selectedRevision);
  const causalPath = replayed.events.slice(0, selectedRevision).filter((event) => !requirementId || affectedIds(event).includes(requirementId)).map((event) => ({
    sequence: event.sequence,
    timestamp: event.timestamp,
    type: event.type,
    actor: event.actor?.name ?? String(event.actor ?? "unknown"),
    affectedRequirementIds: affectedIds(event),
    eventHash: event.hash,
  }));
  const body = {
    mission: replayed.state.metadata.id,
    selected: snapshot(selectedState, requirementId),
    current: snapshot(replayed.state, requirementId),
    causalPath,
    changedSince: replayed.events.slice(selectedRevision).map((event) => ({ sequence: event.sequence, type: event.type, affectedRequirementIds: affectedIds(event) })),
  };
  return { schemaVersion: "tugboat.history-explanation.v1", status: "ready", ...body, digest: canonicalDigest(body) };
}

export function explainRollbackHistory(certificate, { repository } = {}) {
  const verified = verifyRollbackCertificate(certificate, { repository });
  const body = {
    certificateDigest: verified.digest,
    policy: {
      id: verified.body.policy.id,
      digest: verified.body.policy.digest,
      requiredStatus: verified.body.policy.requiredStatus,
    },
    rollback: verified.body.rollback,
    mismatches: verified.body.mismatches,
    effectAssessments: verified.body.effectAssessments,
    summary: verified.status === "equivalent"
      ? "Rollback is boundary-observable equivalent to the exact base."
      : verified.status === "not_equivalent"
        ? "Rollback is not boundary-observable equivalent to the exact base."
        : "Rollback equivalence has insufficient evidence.",
  };
  return {
    schemaVersion: "tugboat.rollback-history-explanation.v1",
    status: verified.status,
    ...body,
    digest: canonicalDigest(body),
  };
}
