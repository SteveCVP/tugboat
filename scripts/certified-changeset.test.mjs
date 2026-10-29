import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CERTIFIED_CHANGESET_LIMITS,
  CertificateValidationError,
  createCertifiedEnvelope,
  createCounterexample,
  portableSubjectId,
  readCertifiedEnvelope,
  verifyCertifiedEnvelope,
  writeCertifiedEnvelope,
} from "./lib/certified-changeset.mjs";

const fixtureFile = path.resolve("scripts/fixtures/certified-changesets/confined-candidate.json");
const digest = (character) => `sha256:${character.repeat(64)}`;

function fixture() {
  return JSON.parse(fs.readFileSync(fixtureFile, "utf8"));
}

test("creates a canonical content-addressed certificate independent of input ordering", () => {
  const payload = fixture();
  const reordered = structuredClone(payload);
  reordered.inputs.reverse();
  reordered.claims[0].subjectIds.reverse();

  const first = createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload });
  const second = createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload: reordered });

  assert.deepEqual(second, first);
  assert.match(first.digest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(first.payload.inputs.map((item) => item.id), ["manifest:example", "policy:default"]);
  assert.deepEqual(first.payload.claims[0].subjectIds, ["bundle:confined-candidate", "component:core"]);
  assert.equal(verifyCertifiedEnvelope(first).verdict, "ready");
});

test("uses strict schemas at the envelope and every shared payload boundary", () => {
  const payload = fixture();
  assert.throws(
    () => createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload: { ...payload, trusted: true } }),
    /Unknown certificate payload field trusted/,
  );
  assert.throws(
    () => createCertifiedEnvelope({
      format: "tugboat.non-interference-witness.v1",
      payload: { ...payload, producer: { ...payload.producer, admin: true } },
    }),
    /Unknown producer field admin/,
  );
  assert.throws(
    () => createCertifiedEnvelope({
      format: "tugboat.non-interference-witness.v1",
      payload: { ...payload, subjects: [{ ...payload.subjects[0], mutable: true }] },
    }),
    /Unknown subject .*field mutable/,
  );
  const valid = createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload });
  assert.throws(() => verifyCertifiedEnvelope({ ...valid, admitted: true }), /Unknown certificate envelope field admitted/);
  assert.throws(() => createCertifiedEnvelope({ format: "tugboat.future-proof.v99", payload }), /Unsupported certified format/);
});

test("validates portable stable subject IDs and the closed verdict vocabulary", () => {
  assert.equal(portableSubjectId("file:scripts/lib/example.mjs"), "file:scripts/lib/example.mjs");
  assert.equal(portableSubjectId("requirement:R1"), "requirement:R1");
  for (const invalid of ["scripts/lib/example.mjs", "file:/absolute", "file:../escape", "file:a//b", "File:UPPER", "file:a\\b", "file:a\u0000b"]) {
    assert.throws(() => portableSubjectId(invalid), /portable subject ID/);
  }
  for (const verdict of ["ready", "blocked", "insufficient_evidence"]) {
    assert.equal(createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload: { ...fixture(), verdict } }).payload.verdict, verdict);
  }
  assert.throws(
    () => createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload: { ...fixture(), verdict: "probably_safe" } }),
    /verdict/,
  );
});

test("creates exact bounded counterexamples with canonical subject and evidence sets", () => {
  const counterexample = createCounterexample({
    code: "ownership_conflict",
    invariantId: "invariant:exclusive-ownership",
    message: "The same file is owned by two components.",
    expected: "exactly one owner",
    actual: "component:api and component:worker",
    subjectIds: ["component:worker", "file:scripts/shared.mjs", "component:api"],
    witnessPath: ["bundle:conflict", "file:scripts/shared.mjs", "component:worker"],
    evidence: [
      { id: "evidence:worker-owner", digest: digest("e") },
      { id: "evidence:api-owner", digest: digest("d") },
    ],
  });
  assert.deepEqual(counterexample.subjectIds, ["component:api", "component:worker", "file:scripts/shared.mjs"]);
  assert.deepEqual(counterexample.evidence.map((item) => item.id), ["evidence:api-owner", "evidence:worker-owner"]);
  assert.deepEqual(counterexample.witnessPath, ["bundle:conflict", "file:scripts/shared.mjs", "component:worker"]);
  assert.throws(() => createCounterexample({ ...counterexample, confidence: 0.9 }), /Unknown counterexample field confidence/);
  assert.throws(() => createCounterexample({ ...counterexample, witnessPath: [] }), /witnessPath/);
});

test("rejects oversized collections, secret material, and payload tampering", () => {
  const payload = fixture();
  payload.claims = Array.from({ length: CERTIFIED_CHANGESET_LIMITS.maxClaims + 1 }, (_, index) => ({
    id: `claim:item-${index}`,
    type: "non_interference",
    status: "passed",
    subjectIds: ["bundle:confined-candidate"],
    summary: "Bounded claim.",
  }));
  assert.throws(() => createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload }), /claims exceeds/);
  assert.throws(
    () => createCertifiedEnvelope({
      format: "tugboat.non-interference-witness.v1",
      payload: { ...fixture(), producer: { name: `${["api", "key"].join("_")}=${["abcdefghijkl", "mnop"].join("")}`, kind: "agent", runtime: "test" } },
    }),
    /secret material/,
  );
  const envelope = createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload: fixture() });
  const tampered = structuredClone(envelope);
  tampered.payload.claims[0].summary = "Silently widened claim.";
  assert.throws(() => verifyCertifiedEnvelope(tampered), /digest mismatch/);
});

test("read and write preserve certificate and unrelated source bytes", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-certified-"));
  const source = path.join(root, "source.txt");
  const certificate = path.join(root, "certificate.json");
  fs.writeFileSync(source, "operator source bytes\n");
  const sourceBefore = fs.readFileSync(source);
  const envelope = createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload: fixture() });
  writeCertifiedEnvelope(certificate, envelope);
  const certificateBefore = fs.readFileSync(certificate);

  const verified = readCertifiedEnvelope(certificate, { expectedFormat: "tugboat.non-interference-witness.v1" });

  assert.equal(verified.verdict, "ready");
  assert.deepEqual(fs.readFileSync(source), sourceBefore);
  assert.deepEqual(fs.readFileSync(certificate), certificateBefore);
  assert.throws(() => readCertifiedEnvelope(certificate, { expectedFormat: "tugboat.composition-certificate.v1" }), /format mismatch/);
  fs.writeFileSync(certificate, Buffer.alloc(CERTIFIED_CHANGESET_LIMITS.maxEnvelopeBytes + 1, 0x20));
  assert.throws(() => readCertifiedEnvelope(certificate), /exceeds/);
});

test("format-specific body remains data and never becomes a semantic proof in the shared kernel", () => {
  const payload = fixture();
  payload.body = { claimedByModel: true, confidence: 1, conclusion: "safe" };
  const verified = verifyCertifiedEnvelope(createCertifiedEnvelope({
    format: "tugboat.non-interference-witness.v1",
    payload,
  }));
  assert.equal(verified.verdict, "ready");
  assert.equal(verified.semanticProof, false);
  assert.equal(verified.reason, "shared envelope integrity only; format-specific semantics were not evaluated");
});

test("throws a typed validation error for callers that need fail-closed handling", () => {
  assert.throws(
    () => createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload: { ...fixture(), claims: [] } }),
    (error) => error instanceof CertificateValidationError && error.exitCode === 2,
  );
});
