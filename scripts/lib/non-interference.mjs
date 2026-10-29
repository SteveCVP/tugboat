import {
  createCertifiedEnvelope,
  createCounterexample,
  readCertifiedEnvelope,
  verifyCertifiedEnvelope,
  writeCertifiedEnvelope,
} from "./certified-changeset.mjs";
import { compileEffectFootprint } from "./effect-footprint.mjs";
import { verifyBoundaryManifest } from "./boundary-manifest.mjs";
import { canonicalJson, sha256 } from "./canonical.mjs";

export class NonInterferenceError extends Error {
  constructor(message) {
    super(message);
    this.name = "NonInterferenceError";
    this.exitCode = 2;
  }
}

function fail(message) {
  throw new NonInterferenceError(message);
}

function sensitivePath(file) {
  return /(^|\/)(?:\.env(?:\.|$)|[^/]*(?:secret|credential|private[_-]?key)[^/]*)/i.test(file);
}

function evidenceFor(effect) {
  return [{ id: `evidence:${sha256(effect.id ?? effect.sourceId).slice(0, 32)}`, digest: effect.sourceDigest }];
}

function crossBoundaryCounterexample(effect, component) {
  return createCounterexample({
    code: "cross_boundary_write",
    invariantId: "invariant:declared-boundary",
    message: `Requirements ${effect.requirementIds.join(",")} are not authorized to write ${component.id}.`,
    expected: `${component.id} writes require one of ${component.requirementIds.join(",")}`,
    actual: `${effect.requirementIds.join(",")} wrote ${effect.path} owned by ${component.id}; allowed ${component.requirementIds.join(",")}`,
    subjectIds: [`bundle:${effect.bundleId}`, `file:${effect.path}`, component.id, effect.id],
    witnessPath: [`bundle:${effect.bundleId}`, effect.id, `file:${effect.path}`, component.id, "invariant:declared-boundary"],
    evidence: evidenceFor(effect),
  });
}

function sensitivePathCounterexample(effect) {
  return createCounterexample({
    code: "sensitive_path_write",
    invariantId: "invariant:no-sensitive-path-write",
    message: "Certified changesets cannot write a path that appears to hold secrets or credentials.",
    expected: "no writes to sensitive paths",
    actual: `bundle ${effect.bundleId} writes ${effect.path}`,
    subjectIds: [`bundle:${effect.bundleId}`, `file:${effect.path}`, effect.id, "invariant:no-sensitive-path-write"],
    witnessPath: [`bundle:${effect.bundleId}`, effect.id, `file:${effect.path}`, "invariant:no-sensitive-path-write"],
    evidence: evidenceFor(effect),
  });
}

function uncertaintyCounterexample(gap, bundleId, bundleDigest, manifestId) {
  const sourceSubject = gap.sourceId?.startsWith("effect:") ? gap.sourceId : `evidence:${sha256(gap.sourceId).slice(0, 32)}`;
  return createCounterexample({
    code: gap.code,
    invariantId: "invariant:complete-effect-classification",
    message: gap.message,
    expected: "every changeset effect is deterministically classified and owned",
    actual: `${gap.code} at ${gap.sourceId}`,
    subjectIds: [`bundle:${bundleId}`, manifestId, sourceSubject],
    witnessPath: [`bundle:${bundleId}`, sourceSubject, manifestId, "invariant:complete-effect-classification"],
    evidence: [{ id: `evidence:${sha256(`${gap.code}:${gap.sourceId}`).slice(0, 32)}`, digest: gap.sourceDigest ?? bundleDigest }],
  });
}

function summaryFrom(witness, semanticProof, reason) {
  const body = witness.payload.body;
  return {
    status: witness.payload.verdict,
    verdict: witness.payload.verdict,
    digest: witness.digest,
    bundleId: body.bundleId,
    boundaryManifestId: body.boundaryManifestId,
    directlyAffectedComponentIds: body.directlyAffectedComponentIds,
    transitivelyAffectedComponentIds: body.transitivelyAffectedComponentIds,
    provenUnaffectedComponentIds: body.provenUnaffectedComponentIds,
    readWriteHazards: body.readWriteHazards,
    counterexamples: witness.payload.counterexamples,
    semanticProof,
    reason,
    payload: witness.payload,
  };
}

export function certifyBundleNonInterference({ bundle, boundary, rootDir, producer, generatedAt }) {
  const boundaryResult = verifyBoundaryManifest(boundary, { rootDir });
  const footprint = compileEffectFootprint({ bundle, boundary, rootDir, producer, generatedAt });
  const components = new Map(boundaryResult.components.map((item) => [item.id, item]));
  const violations = [];
  for (const effect of footprint.payload.body.effects) {
    if (!effect.componentId) continue;
    const component = components.get(effect.componentId);
    if (effect.requirementIds.some((id) => !component.requirementIds.includes(id))) violations.push(crossBoundaryCounterexample(effect, component));
    if (sensitivePath(effect.path) || (effect.previousPath && sensitivePath(effect.previousPath))) violations.push(sensitivePathCounterexample(effect));
  }
  const gaps = footprint.payload.body.uncertainty;
  const gapCounterexamples = gaps.map((gap) => uncertaintyCounterexample(gap, bundle.payload.id, bundle.digest, boundaryResult.id));
  const verdict = violations.length ? "blocked" : gaps.length ? "insufficient_evidence" : "ready";
  const status = violations.length ? "failed" : gaps.length ? "indeterminate" : "passed";
  const counterexamples = [...violations, ...gapCounterexamples];
  return createCertifiedEnvelope({
    format: "tugboat.non-interference-witness.v1",
    payload: {
      id: `certificate:non-interference-${bundle.payload.id}`,
      generatedAt,
      verdict,
      subjects: [{ kind: "bundle", id: `bundle:${bundle.payload.id}`, digest: bundle.digest }],
      inputs: [
        { kind: "boundary_manifest", id: boundaryResult.id, digest: boundaryResult.digest },
        { kind: "effect_footprint", id: footprint.payload.id, digest: footprint.digest },
      ],
      producer,
      claims: [{
        id: `claim:non-interference-${bundle.payload.id}`,
        type: "non_interference",
        status,
        subjectIds: [`bundle:${bundle.payload.id}`],
        summary: violations.length
          ? `${violations.length} exact invariant violations block admission.`
          : gaps.length
            ? `${gaps.length} unclassified effects prevent non-interference proof.`
            : `${footprint.payload.body.provenUnaffectedComponentIds.length} component boundaries are proven unaffected.`,
      }],
      counterexamples,
      body: {
        bundleId: bundle.payload.id,
        bundleDigest: bundle.digest,
        boundaryManifestId: boundaryResult.id,
        boundaryManifestDigest: boundaryResult.digest,
        effectFootprintDigest: footprint.digest,
        effects: footprint.payload.body.effects,
        uncertainty: gaps,
        directlyAffectedComponentIds: footprint.payload.body.directlyAffectedComponentIds,
        transitivelyAffectedComponentIds: footprint.payload.body.transitivelyAffectedComponentIds,
        provenUnaffectedComponentIds: footprint.payload.body.provenUnaffectedComponentIds,
        readWriteHazards: footprint.payload.body.readWriteHazards,
        violationCodes: [...new Set(violations.map((item) => item.code))].sort(),
      },
    },
  });
}

export function verifyBundleNonInterference(envelope, { bundle, boundary, rootDir }) {
  const integrity = verifyCertifiedEnvelope(envelope, { expectedFormat: "tugboat.non-interference-witness.v1" });
  const expected = certifyBundleNonInterference({
    bundle,
    boundary,
    rootDir,
    producer: integrity.payload.producer,
    generatedAt: integrity.payload.generatedAt,
  });
  if (canonicalJson(expected) !== canonicalJson({
    schemaVersion: integrity.schemaVersion,
    format: integrity.format,
    payload: integrity.payload,
    digest: integrity.digest,
  })) {
    fail("Non-interference witness semantic mismatch; recomputed bundle and boundary effects differ");
  }
  return summaryFrom(expected, true, "integrity and deterministic non-interference semantics recomputed from exact bundle and boundary inputs");
}

export function writeNonInterferenceWitness(file, envelope) {
  verifyCertifiedEnvelope(envelope, { expectedFormat: "tugboat.non-interference-witness.v1" });
  return writeCertifiedEnvelope(file, envelope, { expectedFormat: "tugboat.non-interference-witness.v1" });
}

export function readAndVerifyNonInterferenceWitness(file, inputs) {
  const integrity = readCertifiedEnvelope(file, { expectedFormat: "tugboat.non-interference-witness.v1" });
  const envelope = { schemaVersion: integrity.schemaVersion, format: integrity.format, payload: integrity.payload, digest: integrity.digest };
  return verifyBundleNonInterference(envelope, inputs);
}

export function inspectNonInterferenceWitness(envelope) {
  const integrity = verifyCertifiedEnvelope(envelope, { expectedFormat: "tugboat.non-interference-witness.v1" });
  return summaryFrom({ payload: integrity.payload, digest: integrity.digest }, false, "integrity only; call semantic verification with the exact bundle and boundary manifest");
}
