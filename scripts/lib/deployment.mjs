import { execFileSync } from "node:child_process";
import { verify } from "node:crypto";

import { canonicalJson } from "./canonical.mjs";

export class ProviderUnavailableError extends Error {
  constructor(provider, cause) {
    super(`Deployment provider ${provider} is unavailable: ${cause.message}`);
    this.name = "ProviderUnavailableError";
    this.exitCode = 6;
    this.cause = cause;
  }
}

function defaultRun(command, args) {
  return execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function baseEvidence(input, { deployedSha, status, reason, verifier, url }) {
  return {
    schemaVersion: 1,
    id: input.id,
    kind: "deployment",
    requirementIds: input.requirementIds,
    capturedAt: input.capturedAt ?? new Date().toISOString(),
    origin: { actor: input.actor ?? { name: input.provider, kind: "provider" }, cwd: input.cwd ?? process.cwd() },
    git: input.git,
    verification: { status, verifier, reason, url },
    deployment: {
      provider: input.provider,
      environment: input.environment,
      deployedSha,
      expectedSha: input.expectedSha,
      source: `${input.provider}:${input.externalId}`,
    },
    artifacts: [],
  };
}

function verdict(input, deployedSha, providerSuccess, verifier, url, providerReason) {
  const matches = deployedSha === input.expectedSha;
  const passed = providerSuccess && matches;
  const reason = !providerSuccess
    ? providerReason
    : !matches
      ? `Provider deployed SHA ${deployedSha} does not match expected SHA ${input.expectedSha}`
      : "Provider independently confirmed the deployed SHA and successful release";
  return baseEvidence(input, { deployedSha, status: passed ? "passed" : "failed", reason, verifier, url });
}

export function verifyDeploymentEvidence(input, { run = defaultRun } = {}) {
  try {
    if (input.provider === "github-actions") {
      const data = JSON.parse(run("gh", ["run", "view", String(input.externalId), "--repo", input.repository, "--json", "headSha,status,conclusion,url"]));
      return verdict(input, data.headSha, data.status === "completed" && data.conclusion === "success", `github-actions:${input.externalId}`, data.url, `GitHub run concluded ${data.status}/${data.conclusion}`);
    }
    if (input.provider === "aws-cloudformation") {
      const data = JSON.parse(run("aws", ["cloudformation", "describe-stacks", "--stack-name", input.externalId, "--region", input.region ?? "us-east-1", "--output", "json"]));
      const stack = data.Stacks?.[0];
      const deployedSha = stack?.Outputs?.find((item) => item.OutputKey === "DeployedSha")?.OutputValue
        ?? stack?.Tags?.find((item) => item.Key === "TugboatDeployedSha")?.Value;
      const success = /_COMPLETE$/.test(stack?.StackStatus ?? "") && !/ROLLBACK/.test(stack?.StackStatus ?? "");
      return verdict(input, deployedSha, success, `aws-cloudformation:${input.externalId}`, undefined, `CloudFormation stack status ${stack?.StackStatus ?? "missing"}`);
    }
    if (input.provider === "signed-attestation") {
      const signatureValid = verify(null, Buffer.from(canonicalJson(input.attestation)), input.publicKey, Buffer.from(input.signature, "base64"));
      const success = signatureValid && input.attestation.status === "success" && input.attestation.environment === input.environment;
      return verdict(input, input.attestation.deployedSha, success, `signed-attestation:${input.attestation.issuer}`, undefined, signatureValid ? `Attestation status ${input.attestation.status}` : "Attestation signature is invalid");
    }
    throw new Error(`Unsupported provider ${input.provider}`);
  } catch (error) {
    if (error instanceof ProviderUnavailableError) throw error;
    if (error.message.startsWith("Unsupported provider")) throw error;
    throw new ProviderUnavailableError(input.provider, error);
  }
}
