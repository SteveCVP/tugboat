#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { isMainModule } from "./lib/entrypoint.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SKILL = path.dirname(HERE);
const DEFAULT_EVALS = path.join(SKILL, "evals", "evals.json");

function usage() {
  return `Usage:
  run-behavior-evals.mjs --dry-run [--out DIR] [--limit N]
  run-behavior-evals.mjs [--out DIR] [--limit N] [--model MODEL]
    [--claude-bin PATH] [--timeout-ms N]
    [--max-per-call-usd N] [--max-total-budget-usd N]

Each scenario makes three bounded calls: baseline, Tugboat treatment, and judge.`;
}

function parseArgs(argv) {
  const values = new Map();
  const flags = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    if (index + 1 < argv.length && !argv[index + 1].startsWith("--")) {
      values.set(token.slice(2), argv[index + 1]);
      index += 1;
    } else flags.add(token.slice(2));
  }
  return { values, flags };
}

function numberArg(args, name, fallback) {
  const value = Number(args.values.get(name) ?? fallback);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`--${name} must be positive`);
  return value;
}

function systemBundle() {
  const files = [
    path.join(SKILL, "SKILL.md"),
    path.join(SKILL, "references", "operating-protocol.md"),
    path.join(SKILL, "references", "efficiency-and-context.md"),
  ];
  return files.map((file) => `\n# ${path.relative(SKILL, file)}\n\n${fs.readFileSync(file, "utf8")}`).join("\n");
}

function parseClaudeEnvelope(stdout) {
  const envelope = JSON.parse(stdout.trim());
  if (envelope.structured_output) return envelope.structured_output;
  if (typeof envelope.result === "string") return envelope.result;
  return envelope.result ?? envelope;
}

function classifyFailure(error) {
  const message = String(error?.message ?? error);
  if (/not logged in|\/login/i.test(message)) {
    return { code: "CLAUDE_AUTH_REQUIRED", message: "Claude CLI authentication is required before live behavior evaluation." };
  }
  if (/timed out/i.test(message)) {
    return { code: "CLAUDE_TIMEOUT", message: "A bounded Claude call timed out." };
  }
  return { code: "CLAUDE_CALL_FAILED", message: "A bounded Claude call failed; inspect the local terminal output without storing provider envelopes in the report." };
}

function callClaude({ binary, model, budget, timeoutMs, cwd, prompt, systemFile, schema }) {
  const args = [
    "--print", "--safe-mode", "--no-session-persistence", "--effort", "high",
    "--tools", "", "--max-budget-usd", String(budget),
    "--output-format", "json",
  ];
  if (model) args.push("--model", model);
  if (systemFile) args.push("--append-system-prompt-file", systemFile);
  if (schema) args.push("--json-schema", JSON.stringify(schema));
  args.push(prompt);
  const result = spawnSync(binary, args, { cwd, encoding: "utf8", timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 });
  if (result.error?.code === "ETIMEDOUT" || result.signal) throw new Error(`Claude call timed out after ${timeoutMs}ms`);
  if (result.status !== 0) throw new Error(`Claude call failed (${result.status}): ${(result.stderr || result.stdout).trim()}`);
  return parseClaudeEnvelope(result.stdout);
}

function judgeSchema(evaluation) {
  return {
    type: "object",
    additionalProperties: false,
    required: ["assertions", "baseline_score", "treatment_score", "verdict"],
    properties: {
      assertions: {
        type: "array",
        minItems: evaluation.assertions.length,
        maxItems: evaluation.assertions.length,
        items: {
          type: "object",
          additionalProperties: false,
          required: ["text", "baseline", "treatment", "evidence"],
          properties: {
            text: { type: "string" }, baseline: { type: "boolean" },
            treatment: { type: "boolean" }, evidence: { type: "string" },
          },
        },
      },
      baseline_score: { type: "number" },
      treatment_score: { type: "number" },
      verdict: { type: "string" },
    },
  };
}

function validateScore(value, label, expected) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${label} must be a finite number from 0 to 1`);
  }
  if (Math.abs(value - expected) > 1e-12) throw new Error(`${label} does not equal the assertion pass fraction`);
}

function validateJudge(evaluation, judge) {
  if (!judge || typeof judge !== "object" || Array.isArray(judge)) throw new Error("Judge response must be an object");
  if (!Array.isArray(judge.assertions) || judge.assertions.length !== evaluation.assertions.length) {
    throw new Error("Judge response must cover every assertion exactly once");
  }
  judge.assertions.forEach((assertion, index) => {
    if (!assertion || typeof assertion !== "object" || Array.isArray(assertion)) throw new Error(`Judge assertion ${index + 1} must be an object`);
    if (assertion.text !== evaluation.assertions[index]) throw new Error(`Judge assertion ${index + 1} does not match the supplied assertion`);
    if (typeof assertion.baseline !== "boolean" || typeof assertion.treatment !== "boolean") throw new Error(`Judge assertion ${index + 1} needs boolean scores`);
    if (typeof assertion.evidence !== "string" || assertion.evidence.trim().length === 0) throw new Error(`Judge assertion ${index + 1} needs evidence`);
  });
  const count = judge.assertions.length;
  const baseline = count ? judge.assertions.filter(({ baseline: passed }) => passed).length / count : 0;
  const treatment = count ? judge.assertions.filter(({ treatment: passed }) => passed).length / count : 0;
  validateScore(judge.baseline_score, "baseline_score", baseline);
  validateScore(judge.treatment_score, "treatment_score", treatment);
  if (typeof judge.verdict !== "string" || judge.verdict.trim().length === 0) throw new Error("Judge verdict must be a non-empty string");
  return judge;
}

function generationPrompt(evaluation) {
  return `You are planning a development mission. Do not run tools, edit files, ask the user questions, or claim work is complete. Respond with the exact operating approach you would take.\n\nREQUEST:\n${evaluation.prompt}`;
}

function judgePrompt(evaluation, baseline, treatment) {
  return `Act as a strict process evaluator. Score the two responses independently against every supplied assertion. Do not reward references to Tugboat by name; score only observable behavior in the response. Return one assertion object per supplied assertion, then scores from 0 to 1 equal to the fraction passed.\n\nSCENARIO:\n${evaluation.prompt}\n\nASSERTIONS:\n${evaluation.assertions.map((item, index) => `${index + 1}. ${item}`).join("\n")}\n\nBASELINE RESPONSE:\n${baseline}\n\nTREATMENT RESPONSE:\n${treatment}`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.flags.has("help")) {
    console.log(usage());
    return;
  }
  const out = path.resolve(args.values.get("out") ?? "tugboat-eval-output");
  const evalPath = path.resolve(args.values.get("evals") ?? DEFAULT_EVALS);
  const evals = JSON.parse(fs.readFileSync(evalPath, "utf8")).evals;
  const limit = Math.min(numberArg(args, "limit", evals.length), evals.length);
  const selected = evals.slice(0, limit);
  const perCall = numberArg(args, "max-per-call-usd", 0.05);
  const totalLimit = numberArg(args, "max-total-budget-usd", 2);
  const plannedCalls = selected.length * 3;
  const maximumBudgetUsd = Number((plannedCalls * perCall).toFixed(2));
  if (maximumBudgetUsd > totalLimit) {
    throw new Error(`Refusing evaluation: maximum ${maximumBudgetUsd.toFixed(2)} USD exceeds --max-total-budget-usd ${totalLimit.toFixed(2)}`);
  }
  fs.mkdirSync(out, { recursive: true });
  fs.mkdirSync(path.join(out, "responses"), { recursive: true });
  const systemFile = path.join(out, "tugboat-system-prompt.md");
  fs.writeFileSync(systemFile, systemBundle());
  const report = {
    generatedAt: new Date().toISOString(),
    mode: args.flags.has("dry-run") ? "dry-run" : "live",
    status: args.flags.has("dry-run") ? "PLANNED" : "RUNNING",
    scenarioCount: selected.length,
    plannedCalls,
    maximumBudgetUsd,
    model: args.values.get("model") ?? process.env.TUGBOAT_EVAL_MODEL ?? "provider-default",
    results: [],
  };
  if (args.flags.has("dry-run")) {
    report.scenarios = selected.map(({ id, assertions }) => ({ id, assertions: assertions.length }));
    fs.writeFileSync(path.join(out, "report.json"), JSON.stringify(report, null, 2));
    console.log(`Tugboat behavior evaluation planned: ${selected.length} scenarios, ${plannedCalls} bounded calls, max ${maximumBudgetUsd.toFixed(2)} USD`);
    return;
  }

  const binary = args.values.get("claude-bin") ?? "claude";
  const model = args.values.get("model") ?? process.env.TUGBOAT_EVAL_MODEL;
  const timeoutMs = numberArg(args, "timeout-ms", 120_000);
  for (const evaluation of selected) {
    try {
      const prompt = generationPrompt(evaluation);
      const baseline = callClaude({ binary, model, budget: perCall, timeoutMs, cwd: out, prompt });
      const treatment = callClaude({ binary, model, budget: perCall, timeoutMs, cwd: out, prompt, systemFile });
      fs.writeFileSync(path.join(out, "responses", `${evaluation.id}.baseline.txt`), `${baseline}\n`);
      fs.writeFileSync(path.join(out, "responses", `${evaluation.id}.treatment.txt`), `${treatment}\n`);
      const judged = callClaude({
        binary, model, budget: perCall, timeoutMs, cwd: out,
        prompt: judgePrompt(evaluation, baseline, treatment), schema: judgeSchema(evaluation),
      });
      const judge = validateJudge(evaluation, typeof judged === "string" ? JSON.parse(judged) : judged);
      report.results.push({ id: evaluation.id, judge });
      fs.writeFileSync(path.join(out, "report.json"), JSON.stringify(report, null, 2));
    } catch (error) {
      report.status = "BLOCKED";
      report.failedScenario = evaluation.id;
      report.blocker = classifyFailure(error);
      fs.writeFileSync(path.join(out, "report.json"), JSON.stringify(report, null, 2));
      throw new Error(report.blocker.message);
    }
  }
  const improved = report.results.filter((item) => item.judge.treatment_score > item.judge.baseline_score).length;
  report.summary = { improved, tied: report.results.length - improved };
  report.status = "COMPLETE";
  fs.writeFileSync(path.join(out, "report.json"), JSON.stringify(report, null, 2));
  console.log(`Tugboat behavior evaluation complete: ${improved}/${report.results.length} scenarios improved`);
}

if (isMainModule(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

export { callClaude, generationPrompt, judgePrompt, systemBundle, validateJudge };
