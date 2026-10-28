import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createProofProvenance, verifyProofProvenance } from "./lib/provenance.mjs";

test("signed proof provenance uses in-toto/SLSA structure and verifies exact subjects", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-provenance-"));
  fs.writeFileSync(path.join(root, "artifact.txt"), "proof\n");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const envelope = createProofProvenance({
    rootDir: root,
    subjects: ["artifact.txt"],
    materials: [{ uri: "git+https://example.invalid/repo@abc", digest: { sha256: "a".repeat(64) } }],
    builderId: "https://tugboat.invalid/builder/v4",
    invocation: { capsuleDigest: `sha256:${"b".repeat(64)}` },
    privateKey,
  });
  const verified = verifyProofProvenance(envelope, { rootDir: root, publicKey, requireSignature: true });
  assert.equal(verified.status, "ready");
  assert.equal(verified.statement._type, "https://in-toto.io/Statement/v1");
  assert.equal(verified.statement.predicateType, "https://slsa.dev/provenance/v1");
  assert.equal(verified.claimedSlsaLevel, null);
});

test("provenance rejects wrong keys, payload tampering, missing required signatures, and changed subjects", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-provenance-"));
  fs.writeFileSync(path.join(root, "artifact.txt"), "proof\n");
  const keys = generateKeyPairSync("ed25519");
  const wrong = generateKeyPairSync("ed25519");
  const signed = createProofProvenance({ rootDir: root, subjects: ["artifact.txt"], materials: [], builderId: "builder", invocation: {}, privateKey: keys.privateKey });
  assert.equal(verifyProofProvenance(signed).status, "insufficient_evidence");
  assert.throws(() => verifyProofProvenance(signed, { publicKey: wrong.publicKey, requireSignature: true }), /signature/);
  const tampered = structuredClone(signed);
  tampered.payload = Buffer.from("{}", "utf8").toString("base64");
  assert.throws(() => verifyProofProvenance(tampered, { publicKey: keys.publicKey }), /digest mismatch/);
  const unsigned = createProofProvenance({ rootDir: root, subjects: ["artifact.txt"], materials: [], builderId: "builder", invocation: {} });
  assert.throws(() => verifyProofProvenance(unsigned, { requireSignature: true }), /signature is required/);
  const extra = { ...unsigned, trusted: true };
  assert.throws(() => verifyProofProvenance(extra), /Unknown DSSE envelope field/);
  fs.writeFileSync(path.join(root, "artifact.txt"), "changed\n");
  assert.equal(verifyProofProvenance(signed, { rootDir: root, publicKey: keys.publicKey }).status, "blocked");
});
