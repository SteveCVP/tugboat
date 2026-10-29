import { canonicalJson, sha256 } from "./canonical.mjs";
import { compileExecutionPacket } from "./control-plane.mjs";
import {
  boundedList,
  canonicalReport,
  missionSummary,
  normalizeObservedAt,
  validateObject,
} from "./intelligence-core.mjs";

const CATALOG_FIELDS = ["workers"];
const WORKER_FIELDS = ["activeAssignments", "attestations", "capacity", "costUnits", "id", "latencyUnits", "maxClassification", "trustLevel", "trustNodeId"];
const ATTESTATION_FIELDS = ["capability", "evidenceDigest", "expiresAt", "issuedAt", "issuer"];
const PROFILE_FIELDS = ["classifications", "packets", "trustedIssuers", "trustLevels"];
const PACKET_FIELDS = ["capabilities", "classification", "minTrust"];

function fail(message) {
  throw new Error(message);
}

function valuesById(value) {
  return Array.isArray(value) ? value : Object.values(value ?? {});
}

function strings(value, label, max = 64, { preserveOrder = false } = {}) {
  const items = boundedList(value ?? [], label, max);
  for (const item of items) if (typeof item !== "string" || item.length === 0) fail(`${label} values must be non-empty strings`);
  if (new Set(items).size !== items.length) {
    const duplicate = items.find((item, index) => items.indexOf(item) !== index);
    fail(`Duplicate ${label} value ${duplicate}`);
  }
  return preserveOrder ? [...items] : [...items].sort((left, right) => left.localeCompare(right));
}

function nonNegativeNumber(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1_000_000) fail(`${label} must be a non-negative number no greater than 1000000`);
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isInteger(value) || value <= 0 || value > 10_000) fail(`${label} must be a positive integer no greater than 10000`);
  return value;
}

function validateDigest(value, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? "")) fail(`${label} must be a SHA-256 digest`);
  return value;
}

function requirementMap(state) {
  const requirements = new Map(valuesById(state?.requirements).map((item) => [item.id, item]));
  if (!requirements.size) fail("Execution routing needs mission requirements");
  return requirements;
}

function validateProfile(state, input) {
  validateObject(input, { label: "routing profile", allowed: PROFILE_FIELDS, required: PROFILE_FIELDS });
  const trustLevels = strings(input.trustLevels, "trustLevels", 16, { preserveOrder: true });
  const classifications = strings(input.classifications, "classifications", 16, { preserveOrder: true });
  const trustedIssuers = strings(input.trustedIssuers, "trustedIssuers", 64);
  if (!trustedIssuers.length) fail("trustedIssuers needs at least one issuer");
  const requirements = requirementMap(state);
  const packetsInput = input.packets;
  if (!packetsInput || typeof packetsInput !== "object" || Array.isArray(packetsInput)) fail("routing packets must be an object");
  const packets = {};
  for (const requirementId of Object.keys(packetsInput).sort()) {
    if (!requirements.has(requirementId)) fail(`Routing packets reference unknown requirement ${requirementId}`);
    const packet = packetsInput[requirementId];
    validateObject(packet, { label: "routing packet", allowed: PACKET_FIELDS, required: PACKET_FIELDS });
    if (!trustLevels.includes(packet.minTrust)) fail(`Routing packet ${requirementId} has unknown minTrust ${packet.minTrust}`);
    if (!classifications.includes(packet.classification)) fail(`Routing packet ${requirementId} has unknown classification ${packet.classification}`);
    packets[requirementId] = {
      capabilities: strings(packet.capabilities, `routing packet ${requirementId} capabilities`),
      classification: packet.classification,
      minTrust: packet.minTrust,
    };
    if (!packets[requirementId].capabilities.length) fail(`Routing packet ${requirementId} needs at least one capability`);
  }
  return { classifications, packets, requirements, trustedIssuers, trustLevels };
}

function validateWorkers(input, profile) {
  validateObject(input, { label: "worker catalog", allowed: CATALOG_FIELDS, required: CATALOG_FIELDS });
  const workers = boundedList(input.workers, "workers", 128, { uniqueBy: "id" }).map((worker) => {
    validateObject(worker, { label: "worker", allowed: WORKER_FIELDS, required: WORKER_FIELDS });
    if (!profile.trustLevels.includes(worker.trustLevel)) fail(`Worker ${worker.id} has unknown trustLevel ${worker.trustLevel}`);
    if (!profile.classifications.includes(worker.maxClassification)) fail(`Worker ${worker.id} has unknown maxClassification ${worker.maxClassification}`);
    if (typeof worker.trustNodeId !== "string" || worker.trustNodeId.length === 0) fail(`Worker ${worker.id} trustNodeId must be a non-empty string`);
    const capacity = positiveInteger(worker.capacity, `Worker ${worker.id} capacity`);
    if (!Number.isInteger(worker.activeAssignments) || worker.activeAssignments < 0 || worker.activeAssignments > capacity) {
      fail(`Worker ${worker.id} activeAssignments must be an integer from 0 to capacity`);
    }
    const attestations = boundedList(worker.attestations, `worker ${worker.id} attestations`, 128).map((attestation) => {
      validateObject(attestation, { label: "capability attestation", allowed: ATTESTATION_FIELDS, required: ATTESTATION_FIELDS });
      const issuedAt = normalizeObservedAt(attestation.issuedAt);
      const expiresAt = normalizeObservedAt(attestation.expiresAt);
      if (Date.parse(expiresAt) <= Date.parse(issuedAt)) fail(`Worker ${worker.id} attestation ${attestation.capability} must expire after issuance`);
      return {
        capability: attestation.capability,
        evidenceDigest: validateDigest(attestation.evidenceDigest, `Worker ${worker.id} evidenceDigest`),
        expiresAt,
        issuedAt,
        issuer: attestation.issuer,
      };
    }).sort((left, right) => left.capability.localeCompare(right.capability) || left.issuer.localeCompare(right.issuer));
    return {
      activeAssignments: worker.activeAssignments,
      attestations,
      capacity,
      costUnits: nonNegativeNumber(worker.costUnits, `Worker ${worker.id} costUnits`),
      id: worker.id,
      latencyUnits: nonNegativeNumber(worker.latencyUnits, `Worker ${worker.id} latencyUnits`),
      maxClassification: worker.maxClassification,
      trustLevel: worker.trustLevel,
      trustNodeId: worker.trustNodeId,
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
  const trustNodeIds = new Set();
  for (const worker of workers) {
    if (trustNodeIds.has(worker.trustNodeId)) fail(`Duplicate worker trustNodeId ${worker.trustNodeId}`);
    trustNodeIds.add(worker.trustNodeId);
  }
  return workers;
}

function verifyTrustReport(report, missionId) {
  if (report === undefined) return null;
  if (!report || typeof report !== "object" || Array.isArray(report) || report.schemaVersion !== "tugboat.trust-taint.v1") fail("Trust report must use tugboat.trust-taint.v1");
  const { digest, ...body } = report;
  if (digest !== `sha256:${sha256(canonicalJson(body))}`) fail("Trust report digest does not match its contents");
  if (report.mission?.id && report.mission.id !== missionId) fail(`Trust report mission ${report.mission.id} does not match ${missionId}`);
  return report;
}

function capabilityFailure(worker, capability, observedMilliseconds, trustedIssuers) {
  const matching = worker.attestations.filter((item) => item.capability === capability);
  if (!matching.length) return `capability:${capability}:not_attested`;
  const thirdParty = matching.filter((item) => item.issuer !== worker.id);
  if (!thirdParty.length) return `capability:${capability}:self_attested`;
  const trusted = thirdParty.filter((item) => trustedIssuers.has(item.issuer));
  if (!trusted.length) return `capability:${capability}:untrusted_issuer`;
  const issued = trusted.filter((item) => Date.parse(item.issuedAt) <= observedMilliseconds);
  if (!issued.length) return `capability:${capability}:not_yet_valid`;
  const current = issued.filter((item) => Date.parse(item.expiresAt) > observedMilliseconds);
  if (!current.length) return `capability:${capability}:expired`;
  return null;
}

function workerTrustFailure(worker, trustReport) {
  if (!trustReport) return null;
  const node = (trustReport.nodes ?? []).find((item) => item.id === worker.trustNodeId);
  if (!node) return "trust_node_missing";
  if (node.type !== "worker") return "trust_node_not_worker";
  const violated = (trustReport.violations ?? []).some((violation) =>
    violation.nodeId === worker.trustNodeId || (violation.witnessPath ?? []).includes(worker.trustNodeId));
  return violated ? "trust_policy_violation" : null;
}

function evaluate(worker, packet, requirementId, profile, observedMilliseconds, assignedCount, trustReport) {
  const failedConstraints = [];
  for (const capability of packet.capabilities) {
    const failure = capabilityFailure(worker, capability, observedMilliseconds, new Set(profile.trustedIssuers));
    if (failure) failedConstraints.push(failure);
  }
  if (profile.trustLevels.indexOf(worker.trustLevel) < profile.trustLevels.indexOf(packet.minTrust)) failedConstraints.push("trust_level");
  if (profile.classifications.indexOf(worker.maxClassification) < profile.classifications.indexOf(packet.classification)) failedConstraints.push("classification_clearance");
  if (worker.activeAssignments + assignedCount >= worker.capacity) failedConstraints.push("capacity");
  const trustFailure = workerTrustFailure(worker, trustReport);
  if (trustFailure) failedConstraints.push(trustFailure);
  failedConstraints.sort();
  return { eligible: failedConstraints.length === 0, failedConstraints, requirementId, workerId: worker.id };
}

function rankWorkers(left, right) {
  return left.costUnits - right.costUnits || left.latencyUnits - right.latencyUnits || left.id.localeCompare(right.id);
}

export function compileExecutionRouting(state, workersInput, profileInput, observedAtInput, trustReportInput) {
  const observedAt = normalizeObservedAt(observedAtInput);
  const observedMilliseconds = Date.parse(observedAt);
  const profile = validateProfile(state, profileInput);
  const workers = validateWorkers(workersInput, profile);
  const trustReport = verifyTrustReport(trustReportInput, state.metadata.id);
  const packet = compileExecutionPacket(state, { observedAt, git: null });
  const assignedCount = new Map(workers.map(({ id }) => [id, 0]));
  const assignments = [];
  const evaluations = [];
  const unassigned = [];
  let missingProfile = false;

  for (const requirement of [...packet.ready].sort((left, right) => left.id.localeCompare(right.id))) {
    const route = profile.packets[requirement.id];
    if (!route) {
      missingProfile = true;
      unassigned.push({ requirementId: requirement.id, reasons: ["profile_missing"] });
      continue;
    }
    const currentEvaluations = workers.map((worker) => evaluate(
      worker,
      route,
      requirement.id,
      profile,
      observedMilliseconds,
      assignedCount.get(worker.id),
      trustReport,
    ));
    evaluations.push(...currentEvaluations);
    const eligible = workers.filter((worker) => currentEvaluations.find((item) => item.workerId === worker.id).eligible).sort(rankWorkers);
    if (!eligible.length) {
      unassigned.push({ requirementId: requirement.id, reasons: ["no_eligible_worker"] });
      continue;
    }
    const selected = eligible[0];
    assignedCount.set(selected.id, assignedCount.get(selected.id) + 1);
    assignments.push({
      capabilities: route.capabilities,
      rank: { costUnits: selected.costUnits, latencyUnits: selected.latencyUnits, tieBreak: selected.id },
      requirementId: requirement.id,
      workerId: selected.id,
    });
  }
  evaluations.sort((left, right) => left.requirementId.localeCompare(right.requirementId) || left.workerId.localeCompare(right.workerId));
  unassigned.sort((left, right) => left.requirementId.localeCompare(right.requirementId));
  return canonicalReport("tugboat.execution-routing.v1", {
    status: missingProfile ? "insufficient_evidence" : unassigned.length ? "blocked" : "ready",
    mission: missionSummary(state),
    observedAt,
    executionPacketDigest: packet.packetDigest,
    trustReportDigest: trustReport?.digest ?? null,
    assignments,
    dispatchPerformed: false,
    evaluations,
    unassigned,
  });
}
