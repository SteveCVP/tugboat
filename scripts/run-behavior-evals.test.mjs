import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { systemBundle } from "./run-behavior-evals.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HARNESS = path.join(HERE, "run-behavior-evals.mjs");

test("help prints usage without creating output or calling Claude", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-eval-help-"));
  const stdout = execFileSync(process.execPath, [HARNESS, "--help", "--out", out], { encoding: "utf8" });
  assert.match(stdout, /Usage:/);
  assert.match(stdout, /--dry-run/);
  assert.equal(fs.existsSync(path.join(out, "report.json")), false);
});

test("dry-run plans every bounded baseline, treatment, and judge call", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-eval-dry-"));
  execFileSync(process.execPath, [HARNESS, "--dry-run", "--out", out, "--max-per-call-usd", "0.05", "--max-total-budget-usd", "3"], { encoding: "utf8" });
  const report = JSON.parse(fs.readFileSync(path.join(out, "report.json"), "utf8"));
  assert.equal(report.scenarioCount, 16);
  assert.equal(report.plannedCalls, 48);
  assert.equal(report.maximumBudgetUsd, 2.4);
  assert.equal(report.model, "provider-default");
  assert.equal(report.mode, "dry-run");
  assert.ok(fs.existsSync(path.join(out, "tugboat-system-prompt.md")));
});

test("shipped behavior suite pressure-tests every mission-intelligence boundary", () => {
  const evals = JSON.parse(fs.readFileSync(path.join(HERE, "..", "evals", "evals.json"), "utf8")).evals;
  const byId = new Map(evals.map((item) => [item.id, item]));
  for (const id of [
    "impact-before-proof-selection",
    "anti-slop-contract-rejection",
    "plans-are-not-proof",
    "unproved-capability-routing",
    "incomplete-federated-release",
    "gate-passes-because-test-is-weak",
    "evidence-copied-without-context",
    "adapter-sandbox-overclaim",
    "agent-consensus-is-not-proof",
  ]) assert.ok(byId.has(id), id);
  assert.match(systemBundle(), /intelligence impact/);
  assert.match(systemBundle(), /intelligence lint/);
  assert.match(systemBundle(), /intelligence portfolio/);
  assert.match(systemBundle(), /intelligence adversary/);
  assert.match(systemBundle(), /intelligence route/);
  assert.match(systemBundle(), /intelligence federation/);
  assert.match(systemBundle(), /proof mutate/);
  assert.match(systemBundle(), /consensus is not proof/i);
});

test("one fake paired run records assertion-level treatment improvement", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-eval-live-"));
  const evalPath = path.join(out, "evals.json");
  fs.writeFileSync(evalPath, JSON.stringify({ evals: [{ id: "ledger-test", prompt: "Plan the work.", assertions: ["ledger"] }] }));
  const fake = path.join(out, "fake-claude.mjs");
  fs.writeFileSync(fake, `#!/usr/bin/env node
const args=process.argv.slice(2); const prompt=args.at(-1) || "";
if (args.includes("--json-schema")) {
  console.log(JSON.stringify({result: JSON.stringify({assertions:[{text:"ledger",baseline:false,treatment:true,evidence:"treatment captured it"}],baseline_score:0,treatment_score:1,verdict:"treatment improved"})}));
} else {
  console.log(JSON.stringify({result: args.includes("--append-system-prompt-file") ? "treatment uses ledger" : "baseline plan"}));
}`);
  fs.chmodSync(fake, 0o755);
  execFileSync(process.execPath, [HARNESS, "--out", out, "--evals", evalPath, "--limit", "1", "--claude-bin", fake, "--max-per-call-usd", "0.01", "--max-total-budget-usd", "0.03"], { encoding: "utf8" });
  const report = JSON.parse(fs.readFileSync(path.join(out, "report.json"), "utf8"));
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].judge.treatment_score, 1);
  assert.equal(report.results[0].judge.baseline_score, 0);
  assert.equal(report.results[0].judge.assertions[0].treatment, true);
  assert.ok(fs.existsSync(path.join(out, "responses", `${report.results[0].id}.treatment.txt`)));
});

test("an incomplete or mathematically inconsistent judge response blocks the evaluation", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-eval-judge-"));
  const evalPath = path.join(out, "evals.json");
  fs.writeFileSync(evalPath, JSON.stringify({ evals: [{ id: "judge-test", prompt: "Plan the work.", assertions: ["ledger", "proof"] }] }));
  const fake = path.join(out, "incomplete-judge.mjs");
  fs.writeFileSync(fake, `#!/usr/bin/env node
const args=process.argv.slice(2);
if (args.includes("--json-schema")) {
  console.log(JSON.stringify({result: JSON.stringify({assertions:[{text:"ledger",baseline:false,treatment:true,evidence:"one assertion only"}],baseline_score:0,treatment_score:1,verdict:"incomplete"})}));
} else {
  console.log(JSON.stringify({result: args.includes("--append-system-prompt-file") ? "treatment" : "baseline"}));
}`);
  fs.chmodSync(fake, 0o755);
  assert.throws(() => execFileSync(process.execPath, [HARNESS, "--out", out, "--evals", evalPath, "--claude-bin", fake, "--max-per-call-usd", "0.01", "--max-total-budget-usd", "0.03"], { encoding: "utf8", stdio: "pipe" }), /Command failed/);
  const report = JSON.parse(fs.readFileSync(path.join(out, "report.json"), "utf8"));
  assert.equal(report.status, "BLOCKED");
  assert.equal(report.blocker.code, "CLAUDE_CALL_FAILED");
  assert.equal(report.results.length, 0);
});

test("refuses a run whose maximum possible spend exceeds the total budget", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-eval-budget-"));
  assert.throws(() => execFileSync(process.execPath, [HARNESS, "--dry-run", "--out", out, "--max-per-call-usd", "0.10", "--max-total-budget-usd", "1"], { encoding: "utf8", stdio: "pipe" }), /Command failed/);
  assert.ok(!fs.existsSync(path.join(out, "report.json")));
});

test("provider failure leaves a sanitized blocked report", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-eval-blocked-"));
  const fake = path.join(out, "logged-out-claude.mjs");
  fs.writeFileSync(fake, `#!/usr/bin/env node
console.error(JSON.stringify({result:"Not logged in · Please run /login",session_id:"do-not-store"}));
process.exit(1);
`);
  fs.chmodSync(fake, 0o755);
  assert.throws(() => execFileSync(process.execPath, [HARNESS, "--out", out, "--limit", "1", "--claude-bin", fake, "--max-per-call-usd", "0.01", "--max-total-budget-usd", "0.03"], { encoding: "utf8", stdio: "pipe" }), /Command failed/);
  const report = JSON.parse(fs.readFileSync(path.join(out, "report.json"), "utf8"));
  assert.equal(report.status, "BLOCKED");
  assert.equal(report.blocker.code, "CLAUDE_AUTH_REQUIRED");
  assert.doesNotMatch(JSON.stringify(report), /do-not-store|session_id/);
});
