import assert from "node:assert/strict";
import test from "node:test";

import { analyzeCertifiedChange, compareAnalyzerRuns, validateAnalyzerReport } from "./lib/analyzer-protocol.mjs";
import { canonicalDigest } from "./lib/proof-runtime.mjs";

function analyze(analyzerId, path, before, after) {
  return analyzeCertifiedChange({ analyzerId, before: { path, source: before }, after: { path, source: after } });
}

test("Terraform analyzer detects resource replacement and IAM/network expansion", () => {
  const base = `resource "aws_s3_bucket" "logs" { bucket = "logs" }\n`;
  const safe = `${base}resource "aws_s3_bucket" "archive" { bucket = "archive" }\n`;
  assert.equal(analyze("terraform", "infra/main.tf", base, safe).status, "ready");
  const replaced = `resource "aws_iam_role" "logs" { name = "logs" }\n`;
  const replacement = analyze("terraform", "infra/main.tf", base, replaced);
  assert.equal(replacement.status, "blocked");
  assert.ok(replacement.counterexamples.some((item) => item.subject.includes("logs")));
  const privateNetwork = `resource "aws_security_group" "web" { ingress { cidr_blocks = ["10.0.0.0/8"] } }\n`;
  const publicNetwork = `resource "aws_security_group" "web" { ingress { cidr_blocks = ["0.0.0.0/0"] } }\n`;
  const expansion = analyze("terraform", "infra/network.tf", privateNetwork, publicNetwork);
  assert.equal(expansion.status, "blocked");
  assert.ok(expansion.effects.some((effect) => effect.type === "terraform.network_resource"));
});

test("CloudFormation/CDK analyzer detects replacements, IAM expansion, and generated-template drift", () => {
  const digestA = `sha256:${"a".repeat(64)}`;
  const digestB = `sha256:${"b".repeat(64)}`;
  const template = (resources, sourceDigest = digestA) => JSON.stringify({ AWSTemplateFormatVersion: "2010-09-09", Metadata: { TugboatSourceDigest: sourceDigest }, Resources: resources });
  const base = template({ Logs: { Type: "AWS::S3::Bucket", Properties: {} } });
  const safe = template({ Logs: { Type: "AWS::S3::Bucket", Properties: {} }, Archive: { Type: "AWS::S3::Bucket", Properties: {} } });
  assert.equal(analyze("cloudformation-cdk", "cdk/template.json", base, safe).status, "ready");
  const iam = template({ Logs: { Type: "AWS::IAM::Role", Properties: { AssumeRolePolicyDocument: {} } } });
  assert.equal(analyze("cloudformation-cdk", "cdk/template.json", base, iam).status, "blocked");
  const drift = analyze("cloudformation-cdk", "cdk/template.json", base, template({ Logs: { Type: "AWS::S3::Bucket", Properties: {} } }, digestB));
  assert.equal(drift.status, "insufficient_evidence");
  assert.equal(drift.uncertainty[0].code, "generated_template_drift");
});

test("GitHub Actions analyzer detects trigger, permission, secret, and unpinned-action expansion", () => {
  const pinned = `owner/action@${"a".repeat(40)}`;
  const workflow = (overrides = {}) => JSON.stringify({
    name: "CI",
    on: { push: {} },
    permissions: { contents: "read" },
    jobs: { build: { runs_on: "ubuntu-latest", steps: [{ uses: pinned }] } },
    ...overrides,
  });
  const base = workflow();
  const safe = JSON.stringify({ name: "CI", on: { push: {} }, permissions: { contents: "read" }, jobs: { build: { runs_on: "ubuntu-latest", steps: [{ uses: pinned }, { uses: `owner/other@${"b".repeat(40)}` }] } } });
  assert.equal(analyze("github-actions", ".github/workflows/ci.json", base, safe).status, "ready");
  const dangerousTrigger = workflow({ on: { push: {}, pull_request_target: {} } });
  assert.equal(analyze("github-actions", ".github/workflows/ci.json", base, dangerousTrigger).status, "blocked");
  const writePermission = workflow({ permissions: { contents: "write" } });
  assert.equal(analyze("github-actions", ".github/workflows/ci.json", base, writePermission).status, "blocked");
  const unpinned = JSON.stringify({ name: "CI", on: { push: {} }, permissions: { contents: "read" }, jobs: { build: { steps: [{ uses: "owner/action@main" }] } } });
  assert.equal(analyze("github-actions", ".github/workflows/ci.json", base, unpinned).status, "blocked");
  const secret = JSON.stringify({ name: "CI", on: { push: {} }, permissions: { contents: "read" }, jobs: { build: { steps: [{ uses: pinned, env: { TOKEN: "${{ secrets.DEPLOY_TOKEN }}" } }] } } });
  assert.equal(analyze("github-actions", ".github/workflows/ci.json", base, secret).status, "blocked");
});

test("OCI analyzer detects root user, capability, entrypoint, and layer changes", () => {
  const image = (overrides = {}) => JSON.stringify({
    schemaVersion: 2,
    config: { digest: `sha256:${"a".repeat(64)}` },
    configData: { User: "65532:65532", Entrypoint: ["/app"], Cmd: [], CapAdd: [] },
    layers: [{ digest: `sha256:${"b".repeat(64)}` }],
    provenance: { subjectDigest: `sha256:${"c".repeat(64)}` },
    ...overrides,
  });
  const base = image();
  const safe = image({ layers: [{ digest: `sha256:${"b".repeat(64)}` }, { digest: `sha256:${"d".repeat(64)}` }] });
  assert.equal(analyze("oci", "image/inspection.json", base, safe).status, "ready");
  const root = image({ configData: { User: "0", Entrypoint: ["/app"], Cmd: [], CapAdd: [] } });
  assert.equal(analyze("oci", "image/inspection.json", base, root).status, "blocked");
  const capability = image({ configData: { User: "65532:65532", Entrypoint: ["/app"], Cmd: [], CapAdd: ["NET_ADMIN"] } });
  assert.equal(analyze("oci", "image/inspection.json", base, capability).status, "blocked");
  const entrypoint = image({ configData: { User: "65532:65532", Entrypoint: ["/bin/sh"], Cmd: [], CapAdd: [] } });
  assert.equal(analyze("oci", "image/inspection.json", base, entrypoint).status, "blocked");
  const layer = image({ layers: [{ digest: `sha256:${"e".repeat(64)}` }] });
  assert.equal(analyze("oci", "image/inspection.json", base, layer).status, "blocked");
});

test("platform analyzers fail closed on unsupported syntax and malformed documents", () => {
  const cases = [
    ["terraform", "infra/main.tf", "module \"dynamic\" { source = var.source }"],
    ["cloudformation-cdk", "cdk/template.json", "{not-json"],
    ["github-actions", ".github/workflows/ci.yml", "on: [push]\njobs: {}\n"],
    ["oci", "image/inspection.json", "{\"schemaVersion\":1}"],
  ];
  for (const [id, path, source] of cases) {
    const report = analyze(id, path, source, source);
    assert.equal(report.status, "insufficient_evidence", `${id} did not fail closed`);
    assert.ok(["parse_error", "unsupported_construct"].includes(report.uncertainty[0].code));
  }
});

test("platform analyzers reject secrets and bounds violations and prove deterministic reruns", () => {
  const pin = `owner/action@${"a".repeat(40)}`;
  const samples = [
    ["terraform", "infra/main.tf", `resource "aws_s3_bucket" "logs" { bucket = "logs" }`],
    ["cloudformation-cdk", "cdk/template.json", JSON.stringify({ Resources: { Logs: { Type: "AWS::S3::Bucket", Properties: {} } } })],
    ["github-actions", ".github/workflows/ci.json", JSON.stringify({ on: { push: {} }, jobs: { build: { steps: [{ uses: pin }] } } })],
    ["oci", "image/inspection.json", JSON.stringify({ schemaVersion: 2, configData: { User: "65532", Entrypoint: ["/app"], Cmd: [], CapAdd: [] }, layers: [], provenance: {} })],
  ];
  const fakeSecret = ["ghp", "abcdefghijklmnopqrstuvwxyz1234567890"].join("_");
  for (const [id, path, source] of samples) {
    const first = analyze(id, path, source, source);
    const second = analyze(id, path, source, source);
    assert.equal(compareAnalyzerRuns(first, second).status, "ready");
    const divergent = structuredClone(first);
    divergent.limitations = [...divergent.limitations, "synthetic divergence"];
    divergent.digest = canonicalDigest(Object.fromEntries(Object.entries(divergent).filter(([key]) => key !== "digest")));
    assert.deepEqual(validateAnalyzerReport(divergent), divergent);
    assert.equal(compareAnalyzerRuns(first, divergent).status, "blocked");
    assert.throws(() => analyzeCertifiedChange({ analyzerId: id, before: { path, source }, after: { path, source: `${source}\n${fakeSecret}` } }), /secret/i, `${id} accepted secret-bearing source`);
    assert.throws(() => analyzeCertifiedChange({ analyzerId: id, before: { path, source }, after: { path, source }, executionLimits: { timeoutMs: 1 } }), /timed out/, `${id} exceeded its timeout`);
    assert.throws(() => analyzeCertifiedChange({ analyzerId: id, before: { path, source }, after: { path, source }, executionLimits: { maxOutputBytes: 64 } }), /output exceeded/, `${id} exceeded its output bound`);
  }
});
