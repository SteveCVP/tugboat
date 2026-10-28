import fs from "node:fs";
import path from "node:path";

import { renderMission } from "./render.mjs";
import { appendEvent } from "./store.mjs";

const OPEN_STATUSES = new Set(["PENDING", "IN_PROGRESS", "BLOCKED"]);
const SLICE_PROGRESSION_VERSION = 1;

function objectById(items, decorate) {
  return Object.fromEntries((items ?? []).map((item) => [item.id, decorate(item)]));
}

function auditEntry(event, ids = [], reason = "") {
  return {
    eventId: event.id,
    sequence: event.sequence,
    timestamp: event.timestamp,
    actor: event.actor,
    type: event.type,
    ids,
    reason,
  };
}

function versionedSliceProgression(state, requirements, version) {
  if (version === undefined) return { activeSliceId: state.activeSliceId, slices: state.slices };
  if (version !== SLICE_PROGRESSION_VERSION) throw new Error(`Unsupported slice progression version ${version}`);

  const slices = Object.fromEntries(Object.entries(state.slices).map(([id, slice]) => {
    const materialIds = slice.requirementIds.filter((requirementId) => {
      const requirement = requirements[requirementId];
      if (!requirement) throw new Error(`Slice ${id} references unknown requirement ${requirementId}`);
      return requirement.material !== false;
    });
    const complete = materialIds.every((requirementId) => !OPEN_STATUSES.has(requirements[requirementId].status));
    return [id, { ...slice, status: complete ? "COMPLETE" : "PENDING" }];
  }));
  const ready = Object.values(slices).filter((slice) =>
    slice.status === "PENDING" && (slice.dependencies ?? []).every((dependencyId) => slices[dependencyId]?.status === "COMPLETE"));
  const active = ready.find(({ id }) => id === state.activeSliceId) ?? ready[0] ?? null;
  if (active) slices[active.id] = { ...slices[active.id], status: "ACTIVE" };
  return { activeSliceId: active?.id ?? null, slices };
}

export function missionReducer(state, event) {
  if (event.type === "GENESIS") {
    const payload = event.payload;
    return {
      schemaVersion: 2,
      protocolVersion: "2.0",
      status: "ACTIVE",
      metadata: payload.metadata,
      genesisEventHash: event.hash,
      requirements: objectById(payload.requirements, (item) => ({ ...item, status: "PENDING", evidenceRefs: [], result: null, amendedBy: [] })),
      preservations: objectById(payload.preservations, (item) => ({ ...item, status: "PENDING", evidenceRefs: [] })),
      slices: objectById(payload.slices, (item) => ({ ...item })),
      activeSliceId: payload.slices.find((slice) => slice.status === "ACTIVE")?.id ?? payload.slices[0]?.id ?? null,
      amendments: {},
      evidence: {},
      deployments: {},
      bundleImports: {},
      promotions: [],
      claims: {},
      reconciliations: [],
      audit: [auditEntry(event, Object.keys(objectById(payload.requirements, (item) => item)), "mission initialized")],
      handoff: {
        updatedAt: event.timestamp,
        recordedGitSha: payload.metadata.baselineGitSha,
        nextAction: `start ${payload.slices.find((slice) => slice.status === "ACTIVE")?.id ?? payload.metadata.criticalPath.join(",")}`,
        nextCheck: "capture structured evidence for the active slice",
        blocker: null,
      },
    };
  }

  if (!state?.metadata) throw new Error(`${event.type} cannot precede GENESIS`);

  if (event.type === "WORK_CLAIMED") {
    const claim = event.payload?.claim;
    if (!claim?.id || !claim?.holder || !Array.isArray(claim.requirementIds) || !claim.requirementIds.length) {
      throw new Error("Work claim needs id, holder, and requirementIds");
    }
    if (new Set(claim.requirementIds).size !== claim.requirementIds.length) {
      throw new Error("Work claim requirement IDs must be unique");
    }
    const acquiredAt = Date.parse(event.timestamp);
    const expiresAt = Date.parse(claim.expiresAt);
    const ttlSeconds = (expiresAt - acquiredAt) / 1000;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 14_400) {
      throw new Error("Claim TTL must be an integer from 30 to 14400 seconds");
    }
    const claims = Object.fromEntries(Object.entries(state.claims ?? {}).map(([id, existing]) => [id,
      existing.status === "ACTIVE" && Date.parse(existing.expiresAt) <= acquiredAt
        ? { ...existing, status: "EXPIRED", expiredAt: event.timestamp }
        : existing,
    ]));
    if (claims[claim.id]) throw new Error(`Claim ${claim.id} already exists`);
    const activeIds = new Set(activeRequirementIds(state));
    for (const requirementId of claim.requirementIds) {
      const requirement = state.requirements[requirementId];
      if (!requirement) throw new Error(`Unknown requirement ${requirementId}`);
      if (!OPEN_STATUSES.has(requirement.status)) throw new Error(`Requirement ${requirementId} must be open before it can be claimed`);
      if (!activeIds.has(requirementId)) throw new Error(`Requirement ${requirementId} is not executable in the active slice dependency closure`);
      const conflict = Object.values(claims).find((existing) => existing.status === "ACTIVE" && existing.requirementIds.includes(requirementId));
      if (conflict) throw new Error(`Requirement ${requirementId} is already claimed by ${conflict.id}`);
    }
    claims[claim.id] = { ...claim, acquiredAt: event.timestamp, status: "ACTIVE" };
    return {
      ...state,
      claims,
      audit: [...state.audit, auditEntry(event, claim.requirementIds, `claimed by ${claim.holder} as ${claim.id} until ${claim.expiresAt}`)],
      handoff: { ...state.handoff, updatedAt: event.timestamp, recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha },
    };
  }

  if (event.type === "WORK_RELEASED") {
    const { claimId, holder } = event.payload ?? {};
    if (!claimId || !holder) throw new Error("Work release needs claimId and holder");
    const existing = state.claims?.[claimId];
    if (!existing) throw new Error(`Unknown claim ${claimId}`);
    if (existing.status !== "ACTIVE" || Date.parse(existing.expiresAt) <= Date.parse(event.timestamp)) {
      throw new Error(`Claim ${claimId} is not active`);
    }
    if (existing.holder !== holder) throw new Error(`Claim ${claimId} holder is ${existing.holder}; ${holder} cannot release it`);
    return {
      ...state,
      claims: { ...state.claims, [claimId]: { ...existing, status: "RELEASED", releasedAt: event.timestamp } },
      audit: [...state.audit, auditEntry(event, existing.requirementIds, `released ${claimId} by ${holder}`)],
      handoff: { ...state.handoff, updatedAt: event.timestamp, recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha },
    };
  }

  if (event.type === "REQUIREMENT_PROVEN" || event.type === "REQUIREMENT_UPDATED") {
    const id = event.payload.requirementId;
    if (!state.requirements[id]) throw new Error(`Unknown requirement ${id}`);
    return {
      ...state,
      requirements: {
        ...state.requirements,
        [id]: {
          ...state.requirements[id],
          status: event.payload.status,
          evidenceRefs: [...(event.payload.evidenceRefs ?? [])],
          result: event.payload.result ?? state.requirements[id].result,
        },
      },
      audit: [...state.audit, auditEntry(event, [id], event.payload.result ?? event.payload.status)],
      handoff: { ...state.handoff, updatedAt: event.timestamp, recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha },
    };
  }

  if (event.type === "EVIDENCE_RECORDED") {
    const evidence = event.payload.evidence;
    return {
      ...state,
      evidence: { ...state.evidence, [evidence.id]: evidence },
      audit: [...state.audit, auditEntry(event, evidence.requirementIds, `recorded ${evidence.kind} evidence ${evidence.id}`)],
      handoff: { ...state.handoff, updatedAt: event.timestamp, recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha },
    };
  }

  if (event.type === "CHECKPOINT_RECORDED") {
    const requirements = { ...state.requirements };
    const preservations = { ...state.preservations };
    for (const id of event.payload.requirementIds ?? []) {
      if (!requirements[id]) throw new Error(`Unknown requirement ${id}`);
      requirements[id] = {
        ...requirements[id],
        status: event.payload.status,
        evidenceRefs: [...event.payload.evidenceRefs],
        result: event.payload.result ?? requirements[id].result,
      };
    }
    for (const id of event.payload.preservationIds ?? []) {
      if (!preservations[id]) throw new Error(`Unknown preservation ${id}`);
      preservations[id] = { ...preservations[id], status: event.payload.status, evidenceRefs: [...event.payload.evidenceRefs] };
    }
    const ids = [...(event.payload.requirementIds ?? []), ...(event.payload.preservationIds ?? [])];
    const sliceProgression = versionedSliceProgression(state, requirements, event.payload.sliceProgressionVersion);
    return {
      ...state,
      requirements,
      preservations,
      ...sliceProgression,
      audit: [...state.audit, auditEntry(event, ids, event.payload.action)],
      handoff: {
        ...state.handoff,
        updatedAt: event.timestamp,
        recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha,
        nextAction: event.payload.nextAction,
        nextCheck: event.payload.nextCheck ?? event.payload.nextAction,
        blocker: event.payload.blocker ?? null,
      },
    };
  }

  if (event.type === "RECONCILED") {
    const source = event.payload.sourceDigest
      ? { ...state.metadata.source, digest: event.payload.sourceDigest }
      : state.metadata.source;
    return {
      ...state,
      metadata: { ...state.metadata, source },
      reconciliations: [...state.reconciliations, { ...event.payload, eventId: event.id, timestamp: event.timestamp, actor: event.actor }],
      audit: [...state.audit, auditEntry(event, event.payload.issueCodes ?? [], event.payload.reason)],
      handoff: {
        ...state.handoff,
        updatedAt: event.timestamp,
        recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha,
        allowedPatchDigest: event.payload.allowedPatchDigest ?? null,
        nextAction: event.payload.nextAction ?? state.handoff.nextAction,
      },
    };
  }

  if (event.type === "LEGACY_MIGRATED") {
    return {
      ...state,
      legacyImport: event.payload,
      audit: [...state.audit, auditEntry(event, Object.keys(state.requirements), `migrated protocol ${event.payload.protocolVersion} without inheriting prose proof`)],
      handoff: { ...state.handoff, updatedAt: event.timestamp, recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha, nextAction: "capture fresh structured evidence for migrated requirements" },
    };
  }

  if (event.type === "SCOPE_AMENDED") {
    const payload = event.payload;
    if (!payload.id || !payload.reason || !Array.isArray(payload.affectedIds) || !payload.affectedIds.length) {
      throw new Error("Scope amendment needs id, reason, and affectedIds");
    }
    const supersedes = new Set(payload.supersedes ?? []);
    const conflictsWith = Object.values(state.amendments)
      .filter((amendment) => !amendment.supersededBy && amendment.affectedIds.some((id) => payload.affectedIds.includes(id)) && !supersedes.has(amendment.id))
      .map((amendment) => amendment.id);
    const requirements = { ...state.requirements };
    const invalidatedProof = {};
    for (const id of payload.affectedIds) {
      if (!requirements[id]) throw new Error(`Unknown amended requirement ${id}`);
      const previous = requirements[id];
      if (previous.status.startsWith("PROVEN(") || previous.evidenceRefs.length) {
        invalidatedProof[id] = { previousStatus: previous.status, evidenceRefs: previous.evidenceRefs };
      }
      requirements[id] = {
        ...previous,
        ...(payload.replacements?.[id] ?? {}),
        status: "PENDING",
        evidenceRefs: [],
        result: null,
        amendedBy: [...previous.amendedBy, payload.id],
      };
    }
    const amendments = { ...state.amendments };
    for (const id of supersedes) {
      if (!amendments[id]) throw new Error(`Amendment ${payload.id} supersedes unknown amendment ${id}`);
      amendments[id] = { ...amendments[id], supersededBy: payload.id };
    }
    amendments[payload.id] = {
      ...payload,
      actor: event.actor,
      timestamp: event.timestamp,
      conflictsWith,
      invalidatedProof,
      supersededBy: null,
    };
    const sliceProgression = versionedSliceProgression(state, requirements, payload.sliceProgressionVersion);
    return {
      ...state,
      requirements,
      amendments,
      ...sliceProgression,
      audit: [...state.audit, auditEntry(event, payload.affectedIds, payload.reason)],
      handoff: { ...state.handoff, updatedAt: event.timestamp, recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha, nextAction: `re-prove ${payload.affectedIds.join(",")}` },
    };
  }

  if (event.type === "BUNDLE_IMPORTED") {
    const payload = event.payload;
    if (!payload.bundleId || !payload.digest || !payload.source || !Array.isArray(payload.requirementIds)) {
      throw new Error("Bundle import needs bundleId, digest, source, and requirementIds");
    }
    const bundleImports = { ...(state.bundleImports ?? {}) };
    if (bundleImports[payload.bundleId]) throw new Error(`Bundle ${payload.bundleId} is already imported`);
    bundleImports[payload.bundleId] = { ...payload, eventId: event.id, timestamp: event.timestamp, actor: event.actor };
    return {
      ...state,
      bundleImports,
      promotions: state.promotions ?? [],
      audit: [...state.audit, auditEntry(event, payload.requirementIds, `imported bundle ${payload.bundleId}`)],
      handoff: { ...state.handoff, updatedAt: event.timestamp, recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha },
    };
  }

  if (event.type === "BUNDLE_PROMOTED") {
    const payload = event.payload;
    const imported = state.bundleImports?.[payload.bundleId];
    if (!imported) throw new Error(`Bundle ${payload.bundleId} must be imported before promotion`);
    if (imported.digest !== payload.digest) throw new Error(`Bundle ${payload.bundleId} promotion digest does not match the imported bundle`);
    if ((state.promotions ?? []).some((item) => item.bundleId === payload.bundleId)) throw new Error(`Bundle ${payload.bundleId} is already promoted`);
    if (!Array.isArray(payload.targetRequirementIds) || !payload.targetRequirementIds.length) throw new Error("Bundle promotion needs targetRequirementIds");
    const targetIds = [...new Set(payload.targetRequirementIds)];
    if (targetIds.length !== payload.targetRequirementIds.length) throw new Error("Bundle promotion target requirements must be unique");
    const mappedTargets = Object.values(payload.mappings ?? {});
    if (mappedTargets.length !== targetIds.length || targetIds.some((id) => !mappedTargets.includes(id))) throw new Error("Bundle promotion mappings must cover every target requirement exactly once");
    const requirements = { ...state.requirements };
    const invalidatedProof = {};
    for (const id of targetIds) {
      if (!requirements[id]) throw new Error(`Unknown target requirement ${id}`);
      const previous = requirements[id];
      invalidatedProof[id] = { previousStatus: previous.status, evidenceRefs: [...previous.evidenceRefs], result: previous.result };
      requirements[id] = {
        ...previous,
        status: "IN_PROGRESS",
        evidenceRefs: [],
        result: null,
        promotedBy: [...(previous.promotedBy ?? []), payload.bundleId],
      };
    }
    const promotion = { ...payload, invalidatedProof, eventId: event.id, timestamp: event.timestamp, actor: event.actor };
    const sliceProgression = versionedSliceProgression(state, requirements, payload.sliceProgressionVersion);
    return {
      ...state,
      requirements,
      promotions: [...(state.promotions ?? []), promotion],
      ...sliceProgression,
      audit: [...state.audit, auditEntry(event, targetIds, `promoted bundle ${payload.bundleId}; target proof reopened`)],
      handoff: {
        ...state.handoff,
        updatedAt: event.timestamp,
        recordedGitSha: event.gitHead ?? state.handoff.recordedGitSha,
        nextAction: `re-prove ${targetIds.join(",")} after bundle ${payload.bundleId}`,
        nextCheck: `capture fresh target evidence for ${targetIds.join(",")}`,
        blocker: null,
      },
    };
  }

  if (event.type === "SLICE_ACTIVATED") {
    const id = event.payload.sliceId;
    if (!state.slices[id]) throw new Error(`Unknown slice ${id}`);
    const slices = Object.fromEntries(Object.entries(state.slices).map(([sliceId, slice]) => [sliceId, { ...slice, status: sliceId === id ? "ACTIVE" : slice.status === "ACTIVE" ? "PENDING" : slice.status }]));
    return { ...state, slices, activeSliceId: id, audit: [...state.audit, auditEntry(event, state.slices[id].requirementIds, `activated ${id}`)] };
  }

  if (event.type === "MISSION_CLOSED") {
    return { ...state, status: "COMPLETE", audit: [...state.audit, auditEntry(event, Object.keys(state.requirements), "mission closed")], handoff: { ...state.handoff, updatedAt: event.timestamp, nextAction: "stop; mission complete", nextCheck: "none", blocker: null } };
  }

  return { ...state, audit: [...state.audit, auditEntry(event, [], event.payload?.reason ?? "recorded")] };
}

export function activeRequirementIds(state) {
  const slice = state.slices[state.activeSliceId];
  if (!slice) return [];
  const dependencyRequirements = [...new Set((slice.dependencies ?? []).flatMap((dependency) => state.slices[dependency]?.requirementIds ?? []))]
    .filter((id) => OPEN_STATUSES.has(state.requirements[id]?.status));
  if (dependencyRequirements.length) return dependencyRequirements;
  return [...new Set(slice.requirementIds)].filter((id) => OPEN_STATUSES.has(state.requirements[id]?.status));
}

function normalizedSlices(input) {
  if (input.slices?.length) return input.slices;
  const ids = input.metadata.criticalPath?.length ? input.metadata.criticalPath : input.requirements.map((item) => item.id);
  return [{ id: "S1", name: "Critical path", requirementIds: ids, dependencies: [], status: "ACTIVE", operatorJourney: "Complete the approved critical path" }];
}

export function createMission(input) {
  const { dir } = input;
  if (fs.existsSync(dir) && fs.readdirSync(dir).length) throw new Error(`Mission directory is not empty: ${dir}`);
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  const stage = fs.mkdtempSync(path.join(path.dirname(dir), ".tugboat-v2-init-"));
  try {
    const result = appendEvent(stage, {
      type: "GENESIS",
      actor: input.actor,
      payload: {
        metadata: input.metadata,
        requirements: input.requirements,
        preservations: input.preservations,
        slices: normalizedSlices(input),
      },
    }, { reducer: missionReducer, initialState: { schemaVersion: 2 }, currentHead: input.metadata.baselineGitSha });
    renderMission(stage, result.state);
    if (fs.existsSync(dir)) fs.rmdirSync(dir);
    fs.renameSync(stage, dir);
    return result.state;
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
}
