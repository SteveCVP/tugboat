import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

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
  execFileSync(process.execPath, [HARNESS, "--dry-run", "--out", out, "--max-per-call-usd", "0.05", "--max-total-budget-usd", "2"], { encoding: "utf8" });
  const report = JSON.parse(fs.readFileSync(path.join(out, "report.json"), "utf8"));
  assert.equal(report.scenarioCount, 7);
  assert.equal(report.plannedCalls, 21);
  assert.equal(report.maximumBudgetUsd, 1.05);
  assert.equal(report.model, "provider-default");
  assert.equal(report.mode, "dry-run");
  assert.ok(fs.existsSync(path.join(out, "tugboat-system-prompt.md")));
});

test("one fake paired run records assertion-level treatment improvement", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-eval-live-"));
  const fake = path.join(out, "fake-claude.mjs");
  fs.writeFileSync(fake, `#!/usr/bin/env node
const args=process.argv.slice(2); const prompt=args.at(-1) || "";
if (args.includes("--json-schema")) {
  console.log(JSON.stringify({result: JSON.stringify({assertions:[{text:"ledger",baseline:false,treatment:true,evidence:"treatment captured it"}],baseline_score:0,treatment_score:1,verdict:"treatment improved"})}));
} else {
  console.log(JSON.stringify({result: args.includes("--append-system-prompt-file") ? "treatment uses ledger" : "baseline plan"}));
}`);
  fs.chmodSync(fake, 0o755);
  execFileSync(process.execPath, [HARNESS, "--out", out, "--limit", "1", "--claude-bin", fake, "--max-per-call-usd", "0.01", "--max-total-budget-usd", "0.03"], { encoding: "utf8" });
  const report = JSON.parse(fs.readFileSync(path.join(out, "report.json"), "utf8"));
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].judge.treatment_score, 1);
  assert.equal(report.results[0].judge.baseline_score, 0);
  assert.equal(report.results[0].judge.assertions[0].treatment, true);
  assert.ok(fs.existsSync(path.join(out, "responses", `${report.results[0].id}.treatment.txt`)));
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
