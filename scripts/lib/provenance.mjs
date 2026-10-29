import { createPublicKey, sign, verify } from "node:crypto";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { assertNoSecrets } from "./security.mjs";
import { canonicalDigest, describeFile, exactObject, portableRelativePath } from "./proof-runtime.mjs";

const PAYLOAD_TYPE = "application/vnd.in-toto+json";

function pae(payloadType, payload) {
  const type = Buffer.from(payloadType, "utf8");
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type, Buffer.from(` ${body.length} `), body]);
}

function publicKeyId(key) {
  const publicKey = key?.type === "public" ? key : createPublicKey(key);
  return `sha256:${sha256(publicKey.export({ type: "spki", format: "der" }))}`;
}

function validateMaterials(materials) {
  if (!Array.isArray(materials) || materials.length > 256) throw new Error("materials must contain at most 256 items");
  return materials.map((material, index) => {
    if (!material || typeof material.uri !== "string" || !material.uri || !material.digest || typeof material.digest.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(material.digest.sha256)) {
      throw new Error(`Material ${index} is invalid`);
    }
    return { uri: material.uri, digest: { sha256: material.digest.sha256 } };
  }).sort((left, right) => left.uri.localeCompare(right.uri));
}

export function createProofProvenance({ rootDir, subjects, materials = [], builderId, invocation = {}, privateKey } = {}) {
  if (!Array.isArray(subjects) || subjects.length < 1 || subjects.length > 256) throw new Error("subjects must contain 1 to 256 paths");
  if (typeof builderId !== "string" || !builderId) throw new Error("builderId is required");
  assertNoSecrets({ builderId, invocation, materials }, "Provenance inputs");
  const subject = [...new Set(subjects)].sort().map((relative) => {
    portableRelativePath(relative, "Subject path");
    const descriptor = describeFile(rootDir, relative);
    return { name: descriptor.path, digest: { sha256: descriptor.digest.slice("sha256:".length) } };
  });
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject,
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://tugboat.invalid/proof-runtime/v4",
        externalParameters: invocation,
        internalParameters: {},
        resolvedDependencies: validateMaterials(materials),
      },
      runDetails: { builder: { id: builderId }, metadata: { invocationId: canonicalDigest({ subject, materials, invocation }) } },
    },
  };
  const payloadBytes = Buffer.from(canonicalJson(statement), "utf8");
  const signatures = privateKey ? [{ keyid: publicKeyId(privateKey), sig: sign(null, pae(PAYLOAD_TYPE, payloadBytes), privateKey).toString("base64") }] : [];
  const envelope = {
    payloadType: PAYLOAD_TYPE,
    payload: payloadBytes.toString("base64"),
    payloadDigest: `sha256:${sha256(payloadBytes)}`,
    signatures,
  };
  assertNoSecrets(envelope, "Provenance envelope");
  return envelope;
}

export function verifyProofProvenance(envelope, { rootDir, publicKey, requireSignature = false } = {}) {
  exactObject(envelope, "DSSE envelope", ["payloadType", "payload", "payloadDigest", "signatures"], ["payloadType", "payload", "payloadDigest", "signatures"]);
  if (envelope.payloadType !== PAYLOAD_TYPE || typeof envelope.payload !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(envelope.payload) || !Array.isArray(envelope.signatures) || envelope.signatures.length > 16) throw new Error("Invalid DSSE envelope");
  if (!/^sha256:[0-9a-f]{64}$/.test(envelope.payloadDigest)) throw new Error("Invalid provenance payloadDigest");
  for (const [index, signature] of envelope.signatures.entries()) {
    exactObject(signature, `DSSE signature[${index}]`, ["keyid", "sig"], ["keyid", "sig"]);
    if (!/^sha256:[0-9a-f]{64}$/.test(signature.keyid) || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(signature.sig)) throw new Error("Invalid DSSE signature");
  }
  assertNoSecrets(envelope, "Provenance envelope");
  const payload = Buffer.from(envelope.payload, "base64");
  if (`sha256:${sha256(payload)}` !== envelope.payloadDigest) throw new Error("Provenance payload digest mismatch");
  let statement;
  try { statement = JSON.parse(payload.toString("utf8")); } catch { throw new Error("Provenance payload is not valid JSON"); }
  if (canonicalJson(statement) !== payload.toString("utf8")) throw new Error("Provenance payload is not canonical JSON");
  exactObject(statement, "in-toto statement", ["_type", "subject", "predicateType", "predicate"], ["_type", "subject", "predicateType", "predicate"]);
  if (statement._type !== "https://in-toto.io/Statement/v1" || statement.predicateType !== "https://slsa.dev/provenance/v1") throw new Error("Unsupported provenance statement type");
  if (!Array.isArray(statement.subject) || statement.subject.length < 1 || statement.subject.length > 256) throw new Error("Provenance subjects are invalid");
  const subjectNames = new Set();
  for (const [index, subject] of statement.subject.entries()) {
    exactObject(subject, `provenance subject[${index}]`, ["name", "digest"], ["name", "digest"]);
    portableRelativePath(subject.name, "Provenance subject name");
    if (subjectNames.has(subject.name)) throw new Error(`Duplicate provenance subject ${subject.name}`);
    subjectNames.add(subject.name);
    exactObject(subject.digest, `provenance subject digest[${index}]`, ["sha256"], ["sha256"]);
    if (!/^[0-9a-f]{64}$/.test(subject.digest.sha256)) throw new Error("Provenance subject digest is invalid");
  }
  if (requireSignature && envelope.signatures.length === 0) throw new Error("A provenance signature is required");
  let signatureVerified = false;
  if (publicKey) {
    const expectedKeyId = publicKeyId(publicKey);
    signatureVerified = envelope.signatures.some((item) => item.keyid === expectedKeyId && verify(null, pae(envelope.payloadType, payload), publicKey, Buffer.from(item.sig, "base64")));
    if (envelope.signatures.length && !signatureVerified) throw new Error("Provenance signature verification failed");
  } else if (requireSignature) {
    throw new Error("A public key is required to verify the signature");
  }
  const findings = [];
  if (envelope.signatures.length && !publicKey) findings.push({ code: "signature_unverified", reason: "A signature is present but no public key was supplied." });
  if (rootDir) {
    for (const expected of statement.subject ?? []) {
      try {
        const actual = describeFile(rootDir, expected.name);
        if (actual.digest.slice("sha256:".length) !== expected.digest?.sha256) findings.push({ code: "subject_changed", name: expected.name });
      } catch (error) { findings.push({ code: "subject_unavailable", name: expected.name, reason: error.message }); }
    }
  }
  return {
    schemaVersion: "tugboat.provenance-verification.v1",
    status: findings.some((item) => item.code.startsWith("subject_")) ? "blocked" : findings.length ? "insufficient_evidence" : "ready",
    signatureVerified,
    statement,
    findings,
    claimedSlsaLevel: null,
    digest: canonicalDigest({ payloadDigest: envelope.payloadDigest, signatureVerified, findings }),
  };
}
