import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "./lib/canonical.mjs";
import { ProviderUnavailableError, verifyDeploymentEvidence } from "./lib/deployment.mjs";

const SHA = "a".repeat(40);
const git = { sha: SHA, clean: true, patchDigest: null, files: [] };

test("GitHub Actions deployment evidence uses the provider head SHA and conclusion", () => {
  const evidence = verifyDeploymentEvidence({
    id: "E-DEPLOY", provider: "github-actions", externalId: "123", repository: "example/tugboat",
    environment: "production", expectedSha: SHA, requirementIds: ["R1"], git,
  }, { run: () => JSON.stringify({ headSha: SHA, status: "completed", conclusion: "success", url: "https://example.test/run/123" }) });
  assert.equal(evidence.verification.status, "passed");
  assert.equal(evidence.deployment.deployedSha, SHA);
  assert.equal(evidence.deployment.source, "github-actions:123");
});

test("deployment verification rejects a successful run for a different SHA", () => {
  const evidence = verifyDeploymentEvidence({
    id: "E-MISMATCH", provider: "github-actions", externalId: "124", repository: "example/tugboat",
    environment: "production", expectedSha: SHA, requirementIds: ["R1"], git,
  }, { run: () => JSON.stringify({ headSha: "b".repeat(40), status: "completed", conclusion: "success", url: "https://example.test/run/124" }) });
  assert.equal(evidence.verification.status, "failed");
  assert.match(evidence.verification.reason, /does not match/i);
});

test("AWS CloudFormation deployment evidence reads the deployed SHA from stack outputs", () => {
  const evidence = verifyDeploymentEvidence({
    id: "E-AWS", provider: "aws-cloudformation", externalId: "example-runtime", region: "us-east-1",
    environment: "production", expectedSha: SHA, requirementIds: ["R1"], git,
  }, { run: () => JSON.stringify({ Stacks: [{ StackStatus: "UPDATE_COMPLETE", Outputs: [{ OutputKey: "DeployedSha", OutputValue: SHA }] }] }) });
  assert.equal(evidence.verification.status, "passed");
  assert.equal(evidence.deployment.deployedSha, SHA);
});

test("signed external deployment attestation is verified cryptographically", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const attestation = { deployedSha: SHA, environment: "production", status: "success", issuer: "release-controller", observedAt: new Date().toISOString() };
  const signature = sign(null, Buffer.from(canonicalJson(attestation)), privateKey).toString("base64");
  const evidence = verifyDeploymentEvidence({
    id: "E-SIGNED", provider: "signed-attestation", externalId: "release-1", environment: "production",
    expectedSha: SHA, requirementIds: ["R1"], git, attestation, signature,
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
  });
  assert.equal(evidence.verification.status, "passed");
});

test("provider unavailability is distinct from a failed deployment", () => {
  assert.throws(() => verifyDeploymentEvidence({
    id: "E-OFFLINE", provider: "github-actions", externalId: "125", repository: "example/tugboat",
    environment: "production", expectedSha: SHA, requirementIds: ["R1"], git,
  }, { run: () => { throw new Error("gh is not authenticated"); } }), (error) => error instanceof ProviderUnavailableError && error.exitCode === 6);
});
