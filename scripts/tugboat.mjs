#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

import { sha256 } from "./lib/canonical.mjs";
import { conformAdapter, inspectAdapter, runAdapter } from "./lib/adapter-sdk.mjs";
import { loadBoundaryManifest, readBoundaryManifest } from "./lib/boundary-manifest.mjs";
import { compareBundles, createBundle, inspectBundle, readBundle } from "./lib/bundle.mjs";
import { compileBundleAlgebra } from "./lib/bundle-algebra.mjs";
import { composeBundles, planComposition, verifyCompositionCertificate, verifyMergeCertificate } from "./lib/composition.mjs";
import { CERTIFIED_CHANGESET_LIMITS } from "./lib/certified-changeset.mjs";
import { compileCausalGraph } from "./lib/causal-kernel.mjs";
import { compileImpactGraph, inspectTrackedChanges } from "./lib/causality-intelligence.mjs";
import { claimRequirements, compileExecutionPacket, releaseClaim } from "./lib/control-plane.mjs";
import { assertContinuity, inspectContinuity, reconcileMission } from "./lib/continuity.mjs";
import { compileDecisionMemory } from "./lib/decision-memory.mjs";
import { verifyDeploymentEvidence } from "./lib/deployment.mjs";
import { compileDifferentialReview } from "./lib/differential-review.mjs";
import { captureEvidenceCapsule, replayEvidenceCapsule, verifyEvidenceCapsule } from "./lib/evidence-capsule.mjs";
import { isMainModule } from "./lib/entrypoint.mjs";
import { captureCommandEvidence, captureObservationEvidence, checkpointMission, gitSnapshot, recordEvidence } from "./lib/evidence.mjs";
import { compileFederation } from "./lib/federation.mjs";
import { explainMissionHistory, explainRollbackHistory } from "./lib/history-debugger.mjs";
import { readMissionState } from "./lib/intelligence-core.mjs";
import { compileLanguageRecommendation, MAX_PROFILE_BYTES } from "./lib/language-optimizer.mjs";
import { closeMission, MissionValidationError, validateMission } from "./lib/mission-validator.mjs";
import { migrateLegacyMission } from "./lib/migrate.mjs";
import { certifyBundleNonInterference, readAndVerifyNonInterferenceWitness, verifyBundleNonInterference, writeNonInterferenceWitness } from "./lib/non-interference.mjs";
import { compileEvidenceFreshness, compileProofPortfolio, compileReleaseSimulation } from "./lib/proof-intelligence.mjs";
import { runProofMutations } from "./lib/proof-mutation.mjs";
import { promoteBundle } from "./lib/promotion.mjs";
import { createProofProvenance, verifyProofProvenance } from "./lib/provenance.mjs";
import { compileAdversarialAcceptance, compileAntiSlopReport } from "./lib/quality-intelligence.mjs";
import { backupMission, rebuildMission } from "./lib/recovery.mjs";
import { activeRequirementIds, createMission, missionReducer } from "./lib/reducer.mjs";
import { renderMission } from "./lib/render.mjs";
import { proveRollbackEquivalence, verifyRollbackCertificate } from "./lib/rollback-equivalence.mjs";
import { compileExecutionRouting } from "./lib/routing-intelligence.mjs";
import { resolveActor } from "./lib/security.mjs";
import { appendEvent, readState, replayEvents } from "./lib/store.mjs";
import { compileTrustGraph } from "./lib/trust-intelligence.mjs";
import { computeSourceDigest, validateLedger } from "./validate-ledger.mjs";

const REQUIREMENT_COLUMNS = [
  "ID", "Requirement", "Source", "Material", "Acceptance", "Proof target",
  "Implementation", "Tests", "Browser proof", "Production proof", "Status",
];
const PRESERVATION_COLUMNS = ["ID", "Preservation instruction", "Source", "Regression proof", "Status"];
const COMPLETION_COLUMNS = ["Requirement ID", "User-visible result", "Implementation", "Tests", "Browser evidence", "Deployed SHA", "Production result"];

function die(message) {
  const error = new Error(message);
  error.exitCode = 2;
  throw error;
}

function parseArgs(argv) {
  const [rawCommand, ...rest] = argv;
  const command = rawCommand === "--help" ? undefined : rawCommand;
  const subcommand = ["adapter", "boundary", "bundle", "capsule", "certificate", "history", "intelligence", "kernel", "language", "proof", "provenance", "review", "rollback"].includes(command) && rest[0] && !rest[0].startsWith("--") ? rest.shift() : undefined;
  const values = new Map();
  const flags = new Set(rawCommand === "--help" ? ["help"] : []);
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];
    if (token === "--") {
      values.set("_command", rest.slice(index + 1));
      break;
    }
    if (!token.startsWith("--")) die(`Unexpected argument: ${token}`);
    if (index + 1 < rest.length && !rest[index + 1].startsWith("--")) {
      values.set(token.slice(2), rest[index + 1]);
      index += 1;
    } else flags.add(token.slice(2));
  }
  return { command, subcommand, values, flags };
}

function required(args, name) {
  const value = args.values.get(name);
  if (!value) die(`Missing --${name}`);
  return value;
}

function git(cwd, args) {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

function esc(value) {
  return String(value ?? "").replaceAll("\\", "\\\\").replaceAll("|", "\\|").replaceAll("\n", " ").trim();
}

function parseRow(line) {
  const cells = [];
  let value = "";
  let escaped = false;
  for (const character of line.trim().slice(1, -1)) {
    if (escaped) {
      value += character;
      escaped = false;
    } else if (character === "\\") escaped = true;
    else if (character === "|") {
      cells.push(value.trim());
      value = "";
    } else value += character;
  }
  cells.push(value.trim());
  return cells;
}

function row(cells) {
  return `| ${cells.map(esc).join(" | ")} |`;
}

function sectionBounds(markdown, heading) {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim().toLowerCase() === `## ${heading}`.toLowerCase());
  if (start < 0) die(`Missing section: ${heading}`);
  const next = lines.slice(start + 1).findIndex((line) => line.startsWith("## "));
  return { lines, start, end: next < 0 ? lines.length : start + 1 + next };
}

function tableState(markdown, heading) {
  const bounds = sectionBounds(markdown, heading);
  const tableLines = [];
  for (let index = bounds.start + 1; index < bounds.end; index += 1) {
    if (bounds.lines[index].trim().startsWith("|")) tableLines.push(index);
  }
  if (tableLines.length < 2) die(`Malformed table: ${heading}`);
  const headers = parseRow(bounds.lines[tableLines[0]]);
  const rows = tableLines.slice(2).map((lineIndex) => ({ lineIndex, cells: parseRow(bounds.lines[lineIndex]) }));
  return { ...bounds, headers, rows, insertAt: tableLines.at(-1) + 1 };
}

function updateTableRow(markdown, heading, id, updates, { append = false, columns } = {}) {
  const state = tableState(markdown, heading);
  const headers = columns ?? state.headers;
  const found = state.rows.find((candidate) => candidate.cells[0] === id);
  if (!found && !append) die(`${heading} does not contain ${id}`);
  const cells = found ? [...found.cells] : headers.map(() => "");
  if (!found) cells[0] = id;
  for (const [key, value] of Object.entries(updates)) {
    const index = headers.indexOf(key);
    if (index < 0) die(`${heading} has no column ${key}`);
    cells[index] = value;
  }
  if (found) state.lines[found.lineIndex] = row(cells);
  else state.lines.splice(state.insertAt, 0, row(cells));
  return state.lines.join("\n");
}

function removeTableRow(markdown, heading, id) {
  const state = tableState(markdown, heading);
  const found = state.rows.find((candidate) => candidate.cells[0] === id);
  if (found) state.lines.splice(found.lineIndex, 1);
  return state.lines.join("\n");
}

function tableObjects(markdown, heading, columns) {
  const state = tableState(markdown, heading);
  return state.rows.map(({ cells }) => Object.fromEntries(columns.map((column, index) => [column, cells[index] ?? ""])));
}

function field(markdown, label) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return markdown.match(new RegExp(`^- ${escaped}:\\s*(.+)$`, "mi"))?.[1]?.trim().replace(/^`|`$/g, "") ?? "";
}

function replaceField(markdown, label, value) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`^- ${escaped}:\\s*.+$`, "mi");
  if (!pattern.test(markdown)) die(`Missing metadata field: ${label}`);
  return markdown.replace(pattern, `- ${label}: \`${value}\``);
}

function nowIso() {
  return new Date().toISOString();
}

function appendAudit(markdown, entry) {
  const line = row([
    entry.timestamp, entry.actor, entry.ids, entry.action, entry.reason, entry.evidence, entry.next,
  ]);
  const marker = "\n## Entry Rules";
  const index = markdown.indexOf(marker);
  if (index >= 0) return `${markdown.slice(0, index).trimEnd()}\n${line}\n${markdown.slice(index)}`;
  return `${markdown.trimEnd()}\n${line}\n`;
}

function missionPaths(ledgerPath) {
  const dir = path.dirname(ledgerPath);
  return {
    dir,
    ledger: ledgerPath,
    audit: path.join(dir, "audit-log.md"),
    handoff: path.join(dir, "context-handoff.md"),
    completion: path.join(dir, "completion-report.md"),
  };
}

function atomicMissionWrite(paths, contents, validationOptions = {}) {
  const stage = fs.mkdtempSync(path.join(path.dirname(paths.dir), ".tugboat-stage-"));
  try {
    fs.cpSync(paths.dir, stage, { recursive: true });
    for (const [key, contentsValue] of Object.entries(contents)) {
      fs.writeFileSync(path.join(stage, path.basename(paths[key])), contentsValue);
    }
    const stageLedger = path.join(stage, path.basename(paths.ledger));
    const errors = validateLedger(stageLedger, { strictSource: true, strictGit: true, ...validationOptions });
    if (errors.length) die(`Proposed mission update is invalid:\n- ${errors.join("\n- ")}`);
    const temporary = [];
    for (const [key, contentsValue] of Object.entries(contents)) {
      const target = paths[key];
      const temp = `${target}.tmp-${process.pid}`;
      fs.writeFileSync(temp, contentsValue);
      temporary.push({ temp, target, original: fs.readFileSync(target) });
    }
    const replaced = [];
    try {
      for (const item of temporary) {
        fs.renameSync(item.temp, item.target);
        replaced.push(item);
      }
    } catch (error) {
      for (const item of replaced) {
        const restore = `${item.target}.restore-${process.pid}`;
        fs.writeFileSync(restore, item.original);
        fs.renameSync(restore, item.target);
      }
      throw error;
    } finally {
      for (const item of temporary) fs.rmSync(item.temp, { force: true });
    }
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
}

function missionMarkdown({ mission, title, owner, root, branch, sha, source, digest, deployPath, criticalPath, requirements, preservation, target }) {
  const requirementRows = requirements.map((item) => row([
    item.id, item.requirement, item.source, item.material === false ? "no" : "yes", item.acceptance,
    item.proofTarget ?? target, "pending", "pending", "pending", "pending", "PENDING",
  ])).join("\n");
  const preservationRows = preservation.map((item) => row([
    item.id, item.instruction, item.source, "pending", "PENDING",
  ])).join("\n");
  return `# Tugboat Requirement Ledger

## Mission Metadata

- Mission ID: \`${mission}\`
- Mission title: \`${title}\`
- Owner: \`${owner}\`
- Repository: \`${root}\`
- Worktree: \`${root}\`
- Branch: \`${branch}\`
- Baseline SHA: \`${sha}\`
- Current SHA: \`${sha}\`
- Mission status: \`ACTIVE\`
- Protocol version: \`1.1\`
- Source specification(s): \`${source}\`
- Source specification digest: \`${digest}\`
- Audit log: \`./audit-log.md\`
- Context handoff: \`./context-handoff.md\`
- Canonical deploy path: \`${deployPath}\`
- Rollback anchor: \`${sha}\`
- Deadline / budget: \`not specified\`
- Critical path: \`${criticalPath}\`
- Gate cadence: \`slice=targeted; integration=affected; release=full\`
- Retry policy: \`two-strike: diagnose before a third identical rerun\`

## Baseline And Preservation Contract

| ${PRESERVATION_COLUMNS.join(" | ")} |
|---|---|---|---|---|
${preservationRows}

## Requirement-To-Proof Ledger

| ${REQUIREMENT_COLUMNS.join(" | ")} |
|---|---|---|---|---|---|---|---|---|---|---|
${requirementRows}

## Release Slices

| Slice | Requirement IDs | Operator journey | Dependencies | Target gate | Status |
|---|---|---|---|---|---|

## Scope Changes

| Timestamp | Author | Change | Requirement IDs | Reason | Approval evidence |
|---|---|---|---|---|---|

## Decisions And Assumptions

| Timestamp | Requirement IDs | Decision or bounded assumption | Evidence | Reversal condition |
|---|---|---|---|---|

## Review Findings And Dispositions

| Timestamp | Reviewer | Scope | Finding | Severity | Requirement IDs | Disposition | Proof |
|---|---|---|---|---|---|---|---|

## Deployment Record

| Timestamp | Environment | Deployed SHA | Migration/order notes | Rollback anchor | Result | Production evidence |
|---|---|---|---|---|---|---|

## Completion Map

| ${COMPLETION_COLUMNS.join(" | ")} |
|---|---|---|---|---|---|---|
`;
}

function handleInit(args) {
  const cwd = process.cwd();
  const root = git(cwd, ["rev-parse", "--show-toplevel"]);
  const branch = git(cwd, ["branch", "--show-current"]);
  const sha = git(cwd, ["rev-parse", "HEAD"]);
  if (!root || !branch || !sha) die("init must run inside a Git worktree with a commit and branch");
  const dir = path.resolve(cwd, required(args, "dir"));
  if (fs.existsSync(dir) && fs.readdirSync(dir).length) die(`Mission directory is not empty: ${dir}`);
  const sourceAbsolute = path.resolve(cwd, required(args, "source"));
  const requirementsFile = path.resolve(cwd, required(args, "requirements-file"));
  if (!fs.existsSync(sourceAbsolute) || !fs.statSync(sourceAbsolute).isFile()) die(`Source specification not found: ${sourceAbsolute}`);
  const input = JSON.parse(fs.readFileSync(requirementsFile, "utf8"));
  const contract = {
    requirements: input.requirements?.map((item) => ({
      ...item,
      proofTarget: item.proofTarget ?? item.proof_target,
    })),
    preservation: input.preservation ?? input.preservations,
  };
  if (!Array.isArray(contract.requirements) || !contract.requirements.length) die("requirements-file needs at least one requirement");
  if (!Array.isArray(contract.preservation) || !contract.preservation.length) die("requirements-file needs at least one preservation row");
  for (const item of contract.requirements) {
    if (!item.id || !item.requirement || !item.source || !item.acceptance || !item.proofTarget) die("each requirement needs id, requirement, source, acceptance, and proofTarget/proof_target");
  }
  for (const item of contract.preservation) {
    if (!item.id || !item.instruction || !item.source) die("each preservation needs id, instruction, and source");
  }

  fs.mkdirSync(path.dirname(dir), { recursive: true });
  const stage = fs.mkdtempSync(path.join(path.dirname(dir), ".tugboat-init-"));
  try {
    const sourceRelative = path.relative(stage, sourceAbsolute) || path.basename(sourceAbsolute);
    const ledgerPath = path.join(stage, "requirement-ledger.md");
    const placeholder = missionMarkdown({
      mission: required(args, "mission"), title: required(args, "title"), owner: required(args, "owner"),
      root, branch, sha, source: sourceRelative.startsWith(".") ? sourceRelative : `./${sourceRelative}`,
      digest: "sha256:" + "0".repeat(64), deployPath: required(args, "deploy-path"),
      criticalPath: required(args, "critical-path"), requirements: contract.requirements,
      preservation: contract.preservation, target: args.values.get("target") ?? "production",
    });
    fs.writeFileSync(ledgerPath, placeholder);
    const digest = computeSourceDigest(ledgerPath, field(placeholder, "Source specification(s)"));
    const ledger = replaceField(placeholder, "Source specification digest", digest);
    fs.writeFileSync(ledgerPath, ledger);
    const timestamp = nowIso();
    const audit = `# Tugboat Audit Log\n\n| Timestamp | Actor | Requirement IDs | Action | Decision / reason | Evidence | Next step |\n|---|---|---|---|---|---|---|\n${row([timestamp, "Tugboat CLI", contract.requirements.map((item) => item.id).join(","), "initialized mission", "captured approved source and Git baseline", sourceRelative, `start ${required(args, "critical-path")}`])}\n\n## Entry Rules\n\nAppend only; record measured evidence and never secrets.\n`;
    const handoff = `# Tugboat Context Handoff\n\n- Updated: \`${timestamp}\`\n- Mission: \`${required(args, "mission")}\`\n- Mission status: \`ACTIVE\`\n- Repo / worktree: \`${root}\`\n- Branch / current SHA: \`${branch} / ${sha}\`\n- Active requirement IDs: \`${contract.requirements.map((item) => item.id).join(",")}\`\n- Newly proven: \`none\`\n- Current blocker/decision: \`none\`\n- Latest commits: \`${sha}\`\n- Files in active working set: \`${dir}\`\n- Running sessions/processes: \`none\`\n- Ignore as stale: \`none\`\n- Critical path: \`${required(args, "critical-path")}\`\n- Gate cadence: \`slice=targeted; integration=affected; release=full\`\n- Exact next action: \`start ${required(args, "critical-path")}\`\n- Next acceptance check: \`targeted proof for ${required(args, "critical-path")}\`\n`;
    const completion = "# Tugboat Completion Report\n\nStatus: `ACTIVE`\n\nPopulate only after the completion gate passes.\n";
    fs.writeFileSync(path.join(stage, "audit-log.md"), audit);
    fs.writeFileSync(path.join(stage, "context-handoff.md"), handoff);
    fs.writeFileSync(path.join(stage, "completion-report.md"), completion);
    const errors = validateLedger(ledgerPath, { strictSource: true, strictGit: true });
    if (errors.length) die(`Initialized mission is invalid:\n- ${errors.join("\n- ")}`);
    if (fs.existsSync(dir)) fs.rmdirSync(dir);
    fs.renameSync(stage, dir);
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
  console.log(`Tugboat mission initialized: ${path.join(dir, "requirement-ledger.md")}`);
}

function contractFromInput(input) {
  const requirements = input.requirements?.map((item) => ({
    ...item,
    proofTarget: item.proofTarget ?? item.proof_target,
  }));
  const preservations = (input.preservation ?? input.preservations)?.map((item) => ({
    ...item,
    regressionProofTarget: item.regressionProofTarget ?? item.regression_proof ?? "regression evidence",
  }));
  if (!Array.isArray(requirements) || !requirements.length) die("requirements-file needs at least one requirement");
  if (!Array.isArray(preservations) || !preservations.length) die("requirements-file needs at least one preservation row");
  for (const item of requirements) {
    if (!item.id || !item.requirement || !item.source || !item.acceptance || !item.proofTarget) die("each requirement needs id, requirement, source, acceptance, and proofTarget/proof_target");
  }
  for (const item of preservations) {
    if (!item.id || !item.instruction || !item.source) die("each preservation needs id, instruction, and source");
  }
  return { requirements, preservations, slices: input.slices ?? [] };
}

function resolvedActor(args, cwd) {
  return resolveActor({
    explicit: args.values.get("actor"),
    gitName: git(cwd, ["config", "user.name"]) ?? "",
  });
}

function csv(value) {
  return [...new Set((value ?? "").split(",").map((item) => item.trim()).filter(Boolean))];
}

function jsonFile(args, name, fallback) {
  if (!args.values.has(name)) return fallback;
  const file = path.resolve(args.values.get(name));
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    die(`Cannot read --${name} ${file}: ${error.message}`);
  }
}

function boundedProfileFile(args) {
  if (!args.values.has("profile")) return {};
  const file = path.resolve(args.values.get("profile"));
  try {
    const size = fs.statSync(file).size;
    if (size > MAX_PROFILE_BYTES) die("Decision profile exceeds 64 KiB");
    const buffer = fs.readFileSync(file);
    if (buffer.length > MAX_PROFILE_BYTES) die("Decision profile exceeds 64 KiB");
    return JSON.parse(buffer.toString("utf8"));
  } catch (error) {
    if (error.exitCode) throw error;
    die(`Cannot read --profile ${file}: ${error.message}`);
  }
}

function keyFile(args, name) {
  if (!args.values.has(name)) return undefined;
  const file = path.resolve(args.values.get(name));
  try {
    return fs.readFileSync(file);
  } catch (error) {
    die(`Cannot read --${name} ${file}: ${error.message}`);
  }
}

function bundlePolicy(args) {
  return {
    publicKey: keyFile(args, "public-key"),
    requireSignature: args.flags.has("require-signature"),
  };
}

function requirementMappings(value) {
  const mappings = {};
  for (const item of csv(value)) {
    const separator = item.indexOf(":");
    if (separator < 1 || separator === item.length - 1) die(`Invalid requirement mapping ${item}; expected SOURCE:TARGET`);
    const source = item.slice(0, separator);
    const target = item.slice(separator + 1);
    if (mappings[source]) die(`Duplicate requirement mapping for ${source}`);
    mappings[source] = target;
  }
  return mappings;
}

function printResult(value, args, summary) {
  if (args.flags.has("json")) console.log(JSON.stringify(value, null, 2));
  else console.log(summary(value));
}

function handleBundleCreate(args) {
  const missionDir = path.resolve(required(args, "dir"));
  const state = readState(missionDir);
  if (!state?.metadata) die(`No Tugboat v2 mission in ${missionDir}`);
  const outputPath = path.resolve(required(args, "output"));
  createBundle({
    missionDir,
    id: required(args, "id"),
    outputPath,
    requirementIds: csv(required(args, "requirements")),
    commitShas: csv(args.values.get("commits")),
    components: jsonFile(args, "components-file", []),
    commitRequirements: jsonFile(args, "commit-requirements-file", undefined),
    dependsOn: csv(args.values.get("depends-on")),
    privateKey: keyFile(args, "private-key"),
    actor: resolvedActor(args, state.metadata.worktree),
    createdAt: args.values.get("created-at"),
  });
  const summary = inspectBundle(readBundle(outputPath));
  printResult(summary, args, (item) => `Bundle ${item.id} created: ${outputPath}\nDigest: ${item.digest}`);
}

function handleBundleInspect(args) {
  const summary = inspectBundle(readBundle(path.resolve(required(args, "file")), bundlePolicy(args)));
  printResult(summary, args, (item) => `Bundle ${item.id}: ${item.requirementIds.length} requirements, ${item.commits.length} commits, ${item.components.length} components\nSignature: ${item.signature.status}`);
}

function handleBundleCompare(args) {
  const files = csv(required(args, "bundles"));
  const policy = bundlePolicy(args);
  const comparison = compareBundles(files.map((file) => readBundle(path.resolve(file), policy)));
  printResult(comparison, args, (item) => `Compared ${item.candidateCount} bundles: ${item.candidates.map((candidate) => candidate.id).join(", ")}\nComponent conflicts: ${item.components.filter((component) => component.conflict).length}`);
}

function handleBundleAlgebra(args) {
  if (args.subcommand === "compose" && args.values.has("manifest")) {
    if (args.flags.has("apply") === args.flags.has("dry-run")) die("executable bundle compose requires exactly one of --dry-run or --apply");
    if (args.flags.has("apply") && (!args.values.has("composition-certificate") || !args.values.has("merge-certificate"))) {
      die("bundle compose --apply requires --composition-certificate and --merge-certificate so admission evidence is durably emitted");
    }
    const manifestFile = path.resolve(required(args, "manifest"));
    const input = boundedJsonPath(manifestFile, "bundle composition manifest");
    if (!input || typeof input !== "object" || Array.isArray(input) || !Array.isArray(input.candidates)) die("Bundle composition manifest must contain a candidates array");
    for (const field of Object.keys(input)) if (!["candidates", "gates", "generatedAt", "rollbackAdmission"].includes(field)) die(`Unknown bundle composition manifest field ${field}`);
    const manifestDir = path.dirname(manifestFile);
    let rollbackAdmission = { required: false };
    if (input.rollbackAdmission !== undefined) {
      const declaration = input.rollbackAdmission;
      if (!declaration || typeof declaration !== "object" || Array.isArray(declaration) || typeof declaration.required !== "boolean") die("rollbackAdmission needs a boolean required field");
      const allowed = declaration.required ? ["required", "boundaryManifest", "policy", "runtimeEffects"] : ["required"];
      for (const field of Object.keys(declaration)) if (!allowed.includes(field)) die(`Unknown rollbackAdmission field ${field}`);
      if (declaration.required) {
        if (typeof declaration.boundaryManifest !== "string" || !declaration.boundaryManifest || !declaration.policy || typeof declaration.policy !== "object" || Array.isArray(declaration.policy) || !Array.isArray(declaration.runtimeEffects)) die("Required rollback admission needs boundaryManifest, policy, and runtimeEffects");
        rollbackAdmission = {
          required: true,
          boundary: loadBoundaryManifest(path.resolve(manifestDir, declaration.boundaryManifest)).envelope,
          policy: declaration.policy,
          runtimeEffects: declaration.runtimeEffects,
        };
      }
    }
    const candidates = input.candidates.map((candidate) => {
      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) die("Bundle composition candidates must be objects");
      const allowed = ["bundlePath", "requirementIds", "mappings", "witnessFile", "boundaryManifest", "proofGraph", "root", "analyzerReports"];
      for (const field of Object.keys(candidate)) if (!allowed.includes(field)) die(`Unknown bundle composition candidate field ${field}`);
      for (const field of ["bundlePath", "witnessFile", "boundaryManifest", "proofGraph", "root"]) if (typeof candidate[field] !== "string" || !candidate[field]) die(`Bundle composition candidate is missing ${field}`);
      const bundlePath = path.resolve(manifestDir, candidate.bundlePath);
      const rootDir = path.resolve(manifestDir, candidate.root);
      const loadedBoundary = loadBoundaryManifest(path.resolve(manifestDir, candidate.boundaryManifest), { rootDir });
      const boundary = loadedBoundary.envelope;
      const bundle = readBundle(bundlePath, bundlePolicy(args));
      const witness = readAndVerifyNonInterferenceWitness(path.resolve(manifestDir, candidate.witnessFile), { bundle, boundary, rootDir });
      const affectedComponents = new Set([
        ...(witness.payload.body.directlyAffectedComponentIds ?? []),
        ...(witness.payload.body.transitivelyAffectedComponentIds ?? []),
      ]);
      const requiredInvalidatedGateIds = new Set(Object.values(loadedBoundary.verification.gates).filter((gate) => gate.mandatory).map((gate) => gate.id));
      const certifiedAnalyzerIds = new Set(["cloudformation-cdk", "github-actions", "go", "graphql", "oci", "openapi", "python", "sql", "terraform", "typescript"]);
      const affectedSubjects = new Set(affectedComponents);
      for (const component of loadedBoundary.verification.components) {
        if (!affectedComponents.has(component.id)) continue;
        for (const interfaceId of component.interfaceIds) affectedSubjects.add(interfaceId);
        for (const gateId of component.gateIds) requiredInvalidatedGateIds.add(gateId);
        for (const invariantId of component.invariantIds) {
          const invariant = loadedBoundary.verification.invariants[invariantId];
          for (const subjectId of invariant?.subjectIds ?? []) affectedSubjects.add(subjectId);
          for (const gateId of invariant?.gateIds ?? []) requiredInvalidatedGateIds.add(gateId);
        }
      }
      for (const invariant of Object.values(loadedBoundary.verification.invariants)) {
        if (invariant.subjectIds.some((subjectId) => affectedSubjects.has(subjectId))) for (const gateId of invariant.gateIds) requiredInvalidatedGateIds.add(gateId);
      }
      for (const gate of Object.values(loadedBoundary.verification.gates)) {
        if (gate.subjectIds.some((subjectId) => affectedSubjects.has(subjectId))) requiredInvalidatedGateIds.add(gate.id);
      }
      return {
        bundlePath,
        requirementIds: candidate.requirementIds,
        mappings: candidate.mappings,
        analyzerReports: candidate.analyzerReports,
        witness,
        proofGraph: boundedJsonPath(path.resolve(manifestDir, candidate.proofGraph), `proof invalidation graph for ${bundle.payload.id}`),
        policyGates: Object.values(loadedBoundary.verification.gates).map((gate) => ({ id: gate.id, kind: gate.kind, mandatory: gate.mandatory })).sort((left, right) => left.id.localeCompare(right.id)),
        policyRequiredInvalidatedGateIds: [...requiredInvalidatedGateIds].sort(),
        analyzerObligations: Object.values(loadedBoundary.verification.interfaces)
          .filter((descriptor) => certifiedAnalyzerIds.has(descriptor.kind))
          .map((descriptor) => ({ analyzerId: descriptor.kind, path: descriptor.path }))
          .sort((left, right) => `${left.analyzerId}:${left.path}`.localeCompare(`${right.analyzerId}:${right.path}`)),
      };
    });
    const missionDir = path.resolve(required(args, "dir"));
    const state = readState(missionDir);
    if (!state?.metadata) die(`No Tugboat v2 target mission in ${missionDir}`);
    const compositionOptions = {
      missionDir,
      candidates,
      gates: input.gates ?? [],
      actor: resolvedActor(args, state.metadata.worktree),
      generatedAt: input.generatedAt,
      rollbackAdmission,
      ...bundlePolicy(args),
      compositionCertificatePath: args.values.get("composition-certificate"),
      mergeCertificatePath: args.values.get("merge-certificate"),
    };
    const result = args.flags.has("apply") ? composeBundles(compositionOptions) : planComposition(compositionOptions);
    printResult(result, args, (item) => item.dryRun
      ? `Composition proof ready: ${item.certificate.payload.body.canonicalOrder.join(" -> ")}; ${item.certificate.payload.body.orders.length} dependency-valid orders; target unchanged`
      : item.status === "complete"
        ? `Composition merged at ${item.head}: ${item.canonicalOrder.join(" -> ")}; certificates published`
        : `RECOVERY REQUIRED after composition target movement at ${item.head}: ${item.evidenceEmission.reason ?? "one or more certificate artifacts remain staged"}`);
    if (!result.dryRun && result.status === "recovery_required") process.exitCode = 5;
    return;
  }
  const input = boundedJsonPath(required(args, "candidates"), "bundle algebra candidates");
  if (!input || typeof input !== "object" || Array.isArray(input) || !Array.isArray(input.candidates)) die("Bundle algebra candidates file must contain a candidates array");
  if (args.subcommand === "compose" && !args.flags.has("dry-run")) die("bundle compose is planning-only in this release; pass --dry-run");
  const report = compileBundleAlgebra({ candidates: input.candidates, proposedOrder: input.proposedOrder });
  printResult(report, args, (item) => `Bundle algebra: ${item.verdict}; order ${item.canonicalOrder.join(" -> ")}; hazards ${item.hazards.length}; execution authorized: no`);
}

function certifiedSummary(item) {
  return `Certified changeset ${item.bundleId}: ${item.verdict}; direct ${item.directlyAffectedComponentIds.length}; dependent ${item.transitivelyAffectedComponentIds.length}; unaffected ${item.provenUnaffectedComponentIds.length}`;
}

function handleBundleCertify(args) {
  const rootDir = path.resolve(args.values.get("root") ?? process.cwd());
  const bundle = readBundle(path.resolve(required(args, "bundle")), bundlePolicy(args));
  const boundary = loadBoundaryManifest(path.resolve(required(args, "boundary-manifest")), { rootDir }).envelope;
  const witness = certifyBundleNonInterference({
    bundle,
    boundary,
    rootDir,
    producer: resolvedActor(args, rootDir),
    generatedAt: args.values.get("generated-at") ?? new Date().toISOString(),
  });
  writeNonInterferenceWitness(path.resolve(required(args, "output")), witness);
  const result = verifyBundleNonInterference(witness, { bundle, boundary, rootDir });
  printResult(result, args, certifiedSummary);
}

function handleCertificate(args) {
  if (args.subcommand === "verify-rollback") {
    const certificate = boundedJsonPath(required(args, "file"), "rollback certificate", CERTIFIED_CHANGESET_LIMITS.maxEnvelopeBytes);
    const result = verifyRollbackCertificate(certificate, { repository: path.resolve(required(args, "repository")) });
    printResult(result, args, (item) => `Rollback certificate verified: ${item.status}; ${item.digest}`);
    return;
  }
  if (args.subcommand === "verify-composition") {
    const certificate = boundedJsonPath(required(args, "file"), "composition certificate", CERTIFIED_CHANGESET_LIMITS.maxEnvelopeBytes);
    const result = verifyCompositionCertificate(certificate, { repository: args.values.has("repository") ? path.resolve(args.values.get("repository")) : undefined });
    printResult(result, args, (item) => `Composition certificate verified: ${item.digest}`);
    return;
  }
  if (args.subcommand === "verify-merge") {
    const certificate = boundedJsonPath(required(args, "file"), "merge certificate", CERTIFIED_CHANGESET_LIMITS.maxEnvelopeBytes);
    const compositionCertificate = boundedJsonPath(required(args, "composition"), "composition certificate", CERTIFIED_CHANGESET_LIMITS.maxEnvelopeBytes);
    const result = verifyMergeCertificate(certificate, { compositionCertificate, repository: args.values.get("repository") });
    printResult(result, args, (item) => `Merge certificate verified: ${item.digest}`);
    return;
  }
  if (args.subcommand !== "verify") die(`Unknown certificate subcommand: ${args.subcommand ?? "none"}\n${usage()}`);
  const rootDir = path.resolve(args.values.get("root") ?? process.cwd());
  const bundle = readBundle(path.resolve(required(args, "bundle")), bundlePolicy(args));
  const boundary = loadBoundaryManifest(path.resolve(required(args, "boundary-manifest")), { rootDir }).envelope;
  const result = readAndVerifyNonInterferenceWitness(path.resolve(required(args, "file")), { bundle, boundary, rootDir });
  printResult(result, args, certifiedSummary);
}

function handleBoundary(args) {
  if (args.subcommand !== "verify") die(`Unknown boundary subcommand: ${args.subcommand ?? "none"}\n${usage()}`);
  const file = path.resolve(required(args, "file"));
  const rootDir = path.resolve(args.values.get("root") ?? process.cwd());
  const result = readBoundaryManifest(file, { rootDir });
  printResult(
    result,
    args,
    (item) => `Boundary manifest ${item.id}: ${item.status}; ${item.componentCount} components\nDigest: ${item.digest}`,
  );
}

function handleCherryPick(args) {
  const missionDir = path.resolve(required(args, "dir"));
  const state = readState(missionDir);
  if (!state?.metadata) die(`No Tugboat v2 target mission in ${missionDir}`);
  const result = promoteBundle({
    missionDir,
    bundlePath: path.resolve(required(args, "bundle")),
    requirementIds: csv(required(args, "requirements")),
    excludeIds: csv(args.values.get("exclude")),
    mappings: requirementMappings(args.values.get("map")),
    ...bundlePolicy(args),
    dryRun: args.flags.has("dry-run"),
    validationCommand: args.values.get("_command"),
    actor: resolvedActor(args, state.metadata.worktree),
  });
  printResult(result, args, (item) => item.dryRun
    ? `Promotion plan for ${item.plan.bundleId}: ${item.plan.valid ? "ready" : "blocked"}`
    : `Promoted ${item.bundleId} at ${item.head}`);
}

function handleInitV2(args) {
  const cwd = process.cwd();
  const root = git(cwd, ["rev-parse", "--show-toplevel"]);
  const branch = git(cwd, ["branch", "--show-current"]);
  const sha = git(cwd, ["rev-parse", "HEAD"]);
  if (!root || !branch || !sha) die("init must run inside a Git worktree with a commit and branch");
  const dir = path.resolve(cwd, required(args, "dir"));
  const sourceAbsolute = path.resolve(cwd, required(args, "source"));
  const requirementsFile = path.resolve(cwd, required(args, "requirements-file"));
  if (!fs.existsSync(sourceAbsolute) || !fs.statSync(sourceAbsolute).isFile()) die(`Source specification not found: ${sourceAbsolute}`);
  const contract = contractFromInput(JSON.parse(fs.readFileSync(requirementsFile, "utf8")));
  const criticalPath = required(args, "critical-path").split(",").filter(Boolean);
  const sourcePath = path.relative(root, sourceAbsolute) || path.basename(sourceAbsolute);
  const state = createMission({
    dir,
    actor: resolvedActor(args, cwd),
    metadata: {
      id: required(args, "mission"),
      title: required(args, "title"),
      owner: required(args, "owner"),
      target: args.values.get("target") ?? "production",
      repository: root,
      worktree: root,
      branch,
      baselineGitSha: sha,
      source: { path: sourcePath, digest: `sha256:${sha256(fs.readFileSync(sourceAbsolute))}` },
      criticalPath,
      deployPath: required(args, "deploy-path"),
    },
    requirements: contract.requirements,
    preservations: contract.preservations,
    slices: contract.slices,
  });
  console.log(`Tugboat v${state.protocolVersion} mission initialized: ${dir}`);
}

function v2MissionDir(args) {
  if (args.values.has("dir")) return path.resolve(args.values.get("dir"));
  if (args.values.has("ledger")) return path.dirname(path.resolve(args.values.get("ledger")));
  die("Missing --dir or --ledger");
}

function statusMissionDir(args) {
  const dir = v2MissionDir(args);
  const ledgerPath = path.join(dir, "requirement-ledger.md");
  if (!fs.existsSync(path.join(dir, "state.json")) && fs.existsSync(ledgerPath)) {
    const protocolVersion = field(fs.readFileSync(ledgerPath, "utf8"), "Protocol version");
    if (protocolVersion && protocolVersion !== "2.0") {
      die(`Legacy Tugboat ${protocolVersion} mission detected at ${dir}. Migration is required for status and next. Run: tugboat migrate --legacy-dir ${JSON.stringify(dir)} --dir <new-mission-dir>`);
    }
  }
  return dir;
}

function handleStatusV2(args) {
  const dir = statusMissionDir(args);
  const state = replayEvents(dir, { reducer: missionReducer }).state;
  const stored = readState(dir);
  if (!stored || stored.lastEventHash !== state.lastEventHash || stored.revision !== state.revision) die("state.json does not match event replay");
  const status = {
    mission: state.metadata.id,
    missionStatus: state.status,
    revision: state.revision,
    activeSlice: state.activeSliceId,
    activeRequirements: activeRequirementIds(state),
    conflicts: Object.values(state.amendments).filter((item) => !item.supersededBy && item.conflictsWith.length).map((item) => ({ amendment: item.id, conflictsWith: item.conflictsWith })),
    nextAction: state.handoff.nextAction,
  };
  if (args.flags.has("json")) console.log(JSON.stringify(status, null, 2));
  else {
    console.log(`${status.mission}: ${status.missionStatus} revision=${status.revision}`);
    console.log(`Active slice: ${status.activeSlice ?? "none"}`);
    console.log(`Active: ${status.activeRequirements.join(",") || "none"}`);
    console.log(`Conflicts: ${status.conflicts.length}`);
    console.log(`Next: ${status.nextAction}`);
  }
}

function handleNextV2(args) {
  const dir = statusMissionDir(args);
  const state = replayEvents(dir, { reducer: missionReducer }).state;
  const stored = readState(dir);
  if (!stored || stored.lastEventHash !== state.lastEventHash || stored.revision !== state.revision) die("state.json does not match event replay");
  const snapshot = gitSnapshot(state.metadata.worktree, { excludePaths: [dir] });
  const packet = compileExecutionPacket(state, {
    observedAt: args.values.get("observed-at") ?? new Date().toISOString(),
    git: {
      head: snapshot.sha,
      branch: git(state.metadata.worktree, ["branch", "--show-current"]),
      dirty: !snapshot.clean,
      patchDigest: snapshot.patchDigest,
    },
  });
  if (args.flags.has("json")) console.log(JSON.stringify(packet, null, 2));
  else {
    console.log(`${packet.mission.id}: ${packet.mission.status} revision=${packet.mission.revision}`);
    console.log(`Slice: ${packet.activeSlice?.id ?? "none"} · ${packet.activeSlice?.operatorJourney ?? "mission complete"}`);
    console.log(`Ready: ${packet.ready.map((item) => item.id).join(",") || "none"}`);
    console.log(`Claimed: ${packet.claimed.map((item) => `${item.id}@${item.claim.holder}`).join(",") || "none"}`);
    console.log(`Blocked: ${packet.blocked.map((item) => item.id).join(",") || "none"}`);
    console.log(`Next: ${packet.next.action ?? "none"}`);
    console.log(`Packet: ${packet.packetDigest}`);
  }
}

function handleLanguageRecommend(args) {
  const dir = v2MissionDir(args);
  const state = replayEvents(dir, { reducer: missionReducer }).state;
  const stored = readState(dir);
  if (!stored?.metadata || stored.lastEventHash !== state.lastEventHash || stored.revision !== state.revision) {
    die("state.json does not match event replay");
  }
  const repoDir = path.resolve(args.values.get("repo") ?? state.metadata.worktree);
  const report = compileLanguageRecommendation(state, {
    profile: boundedProfileFile(args),
    repoDir,
  });
  if (args.flags.has("json")) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  const primary = report.recommendation.primary;
  const topology = report.recommendation.topology;
  console.log(`Architecture: ${report.recommendation.status}`);
  console.log(`Primary: ${primary?.label ?? "no justified choice"}`);
  console.log(`Topology: ${topology.kind === "undecided" ? "undecided" : topology.kind === "polyglot" ? `${topology.primary} + ${topology.secondary}` : "single language"}`);
  console.log(`Why: ${report.recommendation.rationale[0]}`);
  console.log(`Evidence gaps: ${report.uncertainties.join(" ") || "none in the declared decision inputs"}`);
  console.log(`Decision: ${report.digest}`);
}

const MAX_INTELLIGENCE_INPUT_BYTES = 1024 * 1024;
const INTELLIGENCE_OPERATIONS = new Set([
  "adversary",
  "federation",
  "freshness",
  "impact",
  "lint",
  "memory",
  "portfolio",
  "route",
  "simulate",
  "trust",
]);

function intelligenceJsonFile(args, name, { optional = false, profile = false } = {}) {
  const input = args.values.get(name);
  if (!input) {
    if (optional) return undefined;
    die(`Missing --${name}`);
  }
  const file = path.resolve(input);
  let size;
  try {
    size = fs.statSync(file).size;
  } catch {
    die(`Cannot read --${name} JSON file`);
  }
  const limit = profile ? MAX_PROFILE_BYTES : MAX_INTELLIGENCE_INPUT_BYTES;
  if (size > limit) die(`${name} exceeds ${profile ? "64 KiB" : "1 MiB"}`);
  let source;
  try {
    source = fs.readFileSync(file, "utf8");
  } catch {
    die(`Cannot read --${name} JSON file`);
  }
  if (Buffer.byteLength(source) > limit) die(`${name} exceeds ${profile ? "64 KiB" : "1 MiB"}`);
  try {
    return JSON.parse(source);
  } catch {
    die(`Invalid JSON in --${name}`);
  }
}

function intelligenceState(args) {
  return readMissionState(v2MissionDir(args));
}

function compileIntelligence(args) {
  const operation = args.subcommand;
  if (!INTELLIGENCE_OPERATIONS.has(operation)) die(`Unknown intelligence operation: ${operation ?? "none"}`);
  if (operation === "impact") {
    const state = intelligenceState(args);
    const repo = path.resolve(args.values.get("repo") ?? state.metadata.worktree);
    const base = args.values.get("base") ?? state.metadata.baselineGitSha;
    const head = args.values.get("head") ?? "HEAD";
    const profile = intelligenceJsonFile(args, "profile", { profile: true });
    return compileImpactGraph(state, inspectTrackedChanges(repo, base, head).changes, profile);
  }
  if (operation === "lint") {
    return compileAntiSlopReport(intelligenceState(args), intelligenceJsonFile(args, "profile", { optional: true, profile: true }) ?? {});
  }
  if (operation === "simulate") {
    return compileReleaseSimulation(
      intelligenceState(args),
      intelligenceJsonFile(args, "profile", { optional: true, profile: true }) ?? {},
      intelligenceJsonFile(args, "impact", { optional: true }),
      intelligenceJsonFile(args, "adversarial", { optional: true }),
    );
  }
  if (operation === "route") {
    return compileExecutionRouting(
      intelligenceState(args),
      intelligenceJsonFile(args, "workers"),
      intelligenceJsonFile(args, "profile", { profile: true }),
      required(args, "observed-at"),
      intelligenceJsonFile(args, "trust", { optional: true }),
    );
  }
  if (operation === "memory") {
    return compileDecisionMemory(
      intelligenceJsonFile(args, "records"),
      intelligenceJsonFile(args, "context"),
      required(args, "observed-at"),
    );
  }
  if (operation === "portfolio") {
    return compileProofPortfolio(
      intelligenceState(args),
      intelligenceJsonFile(args, "impact"),
      intelligenceJsonFile(args, "catalog"),
    );
  }
  if (operation === "freshness") {
    return compileEvidenceFreshness(
      intelligenceState(args),
      intelligenceJsonFile(args, "policy"),
      required(args, "observed-at"),
      intelligenceJsonFile(args, "impact", { optional: true }),
    );
  }
  if (operation === "trust") {
    return compileTrustGraph(intelligenceJsonFile(args, "graph"), intelligenceJsonFile(args, "policy"));
  }
  if (operation === "adversary") {
    return compileAdversarialAcceptance(intelligenceState(args), intelligenceJsonFile(args, "profile", { optional: true, profile: true }) ?? {});
  }
  return compileFederation(intelligenceJsonFile(args, "manifest"));
}

function intelligenceGaps(report) {
  const candidates = [
    ...(report.gaps ?? []),
    ...(report.findings ?? []).filter(({ severity }) => severity === "error"),
    ...(report.unassigned ?? []),
    ...(report.violations ?? []),
    ...(report.uncoveredObligations ?? []),
    ...(report.oracleGaps ?? []),
    ...(report.journeys ?? []).filter(({ verdict }) => verdict === "blocked"),
  ];
  return candidates.slice(0, 3).map((item) => {
    if (typeof item === "string") return item;
    return item.message ?? item.code ?? item.ruleId ?? item.requirementId ?? item.id ?? JSON.stringify(item);
  });
}

function handleIntelligence(args) {
  const report = compileIntelligence(args);
  if (args.flags.has("json")) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`${args.subcommand}: ${report.status}`);
    for (const gap of intelligenceGaps(report)) console.log(`Gap: ${gap}`);
    console.log(`Digest: ${report.digest}`);
  }
  if (args.flags.has("gate") && report.status !== "ready") process.exitCode = 2;
}

function jsonFileArgument(args, name, { optional = false } = {}) {
  return intelligenceJsonFile(args, name, { optional });
}

function boundedTextFile(file, label, limit = MAX_INTELLIGENCE_INPUT_BYTES) {
  const resolved = path.resolve(file);
  let stat;
  try { stat = fs.statSync(resolved); } catch { die(`Cannot read ${label}`); }
  if (!stat.isFile() || stat.size > limit) die(`${label} exceeds ${limit} bytes or is not a file`);
  const value = fs.readFileSync(resolved, "utf8");
  if (Buffer.byteLength(value) > limit) die(`${label} exceeds ${limit} bytes`);
  return value;
}

function boundedJsonPath(file, label, limit = MAX_INTELLIGENCE_INPUT_BYTES) {
  try { return JSON.parse(boundedTextFile(file, label, limit)); } catch (error) {
    if (error.exitCode) throw error;
    die(`Invalid JSON in ${label}`);
  }
}

function csvArgument(args, name, { optional = false } = {}) {
  const value = args.values.get(name);
  if (!value) {
    if (optional) return [];
    die(`Missing --${name}`);
  }
  const values = value.split(",").map((item) => item.trim()).filter(Boolean);
  if (!values.length || values.length > 256 || new Set(values).size !== values.length) die(`--${name} must contain 1 to 256 unique comma-separated values`);
  return values;
}

function writeJsonArtifact(args, report) {
  const output = args.values.get("output");
  if (output) {
    const file = path.resolve(output);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const temporary = `${file}.tmp-${process.pid}`;
    fs.writeFileSync(temporary, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, file);
  }
  if (args.flags.has("json") || !output) console.log(JSON.stringify(report, null, 2));
  else console.log(`Wrote ${report.schemaVersion ?? "artifact"}: ${output}`);
}

function handleProof(args) {
  if (args.subcommand !== "mutate") die(`Unknown proof subcommand: ${args.subcommand ?? "none"}`);
  const command = args.values.get("_command");
  if (!Array.isArray(command) || !command.length) die("Proof mutation needs `-- <command> [args]`");
  const report = runProofMutations({ repoDir: path.resolve(required(args, "repo")), plan: jsonFileArgument(args, "plan"), command });
  writeJsonArtifact(args, report);
  if (args.flags.has("gate") && report.status !== "ready") process.exitCode = 2;
}

function handleCapsule(args) {
  if (args.subcommand === "capture") {
    const command = args.values.get("_command");
    if (!Array.isArray(command) || !command.length) die("Capsule capture needs `-- <command> [args]`");
    writeJsonArtifact(args, captureEvidenceCapsule({
      repoDir: path.resolve(required(args, "repo")),
      inputPaths: csvArgument(args, "inputs"),
      artifactPaths: csvArgument(args, "artifacts", { optional: true }),
      command,
      capturedAt: args.values.get("captured-at") ?? new Date().toISOString(),
    }));
    return;
  }
  const capsule = jsonFileArgument(args, "file");
  if (args.subcommand === "verify") {
    writeJsonArtifact(args, verifyEvidenceCapsule(capsule, { repoDir: args.values.has("repo") ? path.resolve(args.values.get("repo")) : undefined }));
    return;
  }
  if (args.subcommand === "replay") {
    const command = args.values.get("_command");
    if (!Array.isArray(command) || !command.length) die("Capsule replay needs `-- <command> [args]`");
    writeJsonArtifact(args, replayEvidenceCapsule(capsule, { repoDir: path.resolve(required(args, "repo")), command }));
    return;
  }
  die(`Unknown capsule subcommand: ${args.subcommand ?? "none"}`);
}

function handleProvenance(args) {
  if (args.subcommand === "create") {
    const rootDir = path.resolve(args.values.get("root") ?? process.cwd());
    const keyFile = args.values.get("private-key");
    writeJsonArtifact(args, createProofProvenance({
      rootDir,
      subjects: csvArgument(args, "subjects"),
      materials: jsonFileArgument(args, "materials", { optional: true }) ?? [],
      builderId: required(args, "builder"),
      invocation: jsonFileArgument(args, "invocation", { optional: true }) ?? {},
      privateKey: keyFile ? boundedTextFile(keyFile, "private key", 64 * 1024) : undefined,
    }));
    return;
  }
  if (args.subcommand === "verify") {
    const publicKeyFile = args.values.get("public-key");
    writeJsonArtifact(args, verifyProofProvenance(jsonFileArgument(args, "file"), {
      rootDir: args.values.has("root") ? path.resolve(args.values.get("root")) : undefined,
      publicKey: publicKeyFile ? boundedTextFile(publicKeyFile, "public key", 64 * 1024) : undefined,
      requireSignature: args.flags.has("require-signature"),
    }));
    return;
  }
  die(`Unknown provenance subcommand: ${args.subcommand ?? "none"}`);
}

function handleKernel(args) {
  if (args.subcommand !== "compile") die(`Unknown kernel subcommand: ${args.subcommand ?? "none"}`);
  writeJsonArtifact(args, compileCausalGraph(jsonFileArgument(args, "graph"), { cacheDir: path.resolve(required(args, "cache")) }));
}

function adapterOptions(args) {
  const manifestFile = path.resolve(required(args, "manifest"));
  return { manifest: jsonFileArgument(args, "manifest"), manifestDir: path.dirname(manifestFile) };
}

function handleAdapter(args) {
  const options = adapterOptions(args);
  if (args.subcommand === "inspect") {
    writeJsonArtifact(args, inspectAdapter(options.manifest, { manifestDir: options.manifestDir }));
    return;
  }
  const runOptions = {
    ...options,
    inputRoot: path.resolve(args.values.get("input-root") ?? options.manifestDir),
    inputPaths: csvArgument(args, "inputs", { optional: true }),
    environment: jsonFileArgument(args, "environment", { optional: true }) ?? {},
  };
  if (args.subcommand === "run") {
    writeJsonArtifact(args, runAdapter({ ...runOptions, input: jsonFileArgument(args, "input") }));
    return;
  }
  if (args.subcommand === "conform") {
    writeJsonArtifact(args, conformAdapter(runOptions, jsonFileArgument(args, "cases")));
    return;
  }
  die(`Unknown adapter subcommand: ${args.subcommand ?? "none"}`);
}

function handleHistory(args) {
  if (args.subcommand !== "explain") die(`Unknown history subcommand: ${args.subcommand ?? "none"}`);
  if (args.values.has("rollback-certificate")) {
    writeJsonArtifact(args, explainRollbackHistory(boundedJsonPath(args.values.get("rollback-certificate"), "rollback certificate", CERTIFIED_CHANGESET_LIMITS.maxEnvelopeBytes), { repository: path.resolve(required(args, "repository")) }));
    return;
  }
  writeJsonArtifact(args, explainMissionHistory(v2MissionDir(args), {
    revision: args.values.has("revision") ? Number(args.values.get("revision")) : undefined,
    requirementId: args.values.get("requirement"),
  }));
}

function handleRollback(args) {
  if (args.subcommand !== "prove") die(`Unknown rollback subcommand: ${args.subcommand ?? "none"}`);
  const manifestFile = path.resolve(required(args, "manifest"));
  const input = boundedJsonPath(manifestFile, "rollback manifest", CERTIFIED_CHANGESET_LIMITS.maxEnvelopeBytes);
  if (!input || typeof input !== "object" || Array.isArray(input) || typeof input.repository !== "string" || !input.repository) die("Rollback manifest needs a repository path");
  const repository = path.resolve(path.dirname(manifestFile), input.repository);
  const result = proveRollbackEquivalence({
    ...input,
    repository,
    producer: resolvedActor(args, repository),
    outputPath: path.resolve(required(args, "output")),
  });
  printResult(result, args, (item) => `Rollback proof: ${item.status}; ${item.certificate.digest}`);
  if (result.status !== "equivalent") process.exitCode = 4;
}

function handleReview(args) {
  if (args.subcommand !== "compare") die(`Unknown review subcommand: ${args.subcommand ?? "none"}`);
  const reviews = csvArgument(args, "reviews").map((file, index) => boundedJsonPath(file, `review[${index}]`));
  const report = compileDifferentialReview(reviews);
  writeJsonArtifact(args, report);
  if (args.flags.has("gate") && report.status !== "ready") process.exitCode = 2;
}

function publicClaim(claim) {
  return {
    id: claim.id,
    holder: claim.holder,
    requirementIds: claim.requirementIds,
    acquiredAt: claim.acquiredAt,
    expiresAt: claim.expiresAt,
    status: claim.status,
    ...(claim.releasedAt ? { releasedAt: claim.releasedAt } : {}),
  };
}

function handleClaimV2(args) {
  const dir = v2MissionDir(args);
  const state = readState(dir);
  if (!state) die(`No Tugboat v2 state in ${dir}`);
  if (args.values.has("now")) die("--now is not supported; lease time comes from the local system clock");
  const ttlSeconds = Number(args.values.get("ttl-seconds") ?? 900);
  const result = claimRequirements(dir, {
    id: required(args, "id"),
    holder: required(args, "holder"),
    requirementIds: required(args, "requirements").split(",").filter(Boolean),
    ttlSeconds,
    actor: resolvedActor(args, state.metadata.worktree),
    now: new Date().toISOString(),
    expectedRevision: args.values.has("expected-revision") ? Number(args.values.get("expected-revision")) : undefined,
    expectedHead: args.values.get("expected-head"),
  });
  const claim = publicClaim(result.claim);
  if (args.flags.has("json")) console.log(JSON.stringify(claim, null, 2));
  else console.log(`Claim ${claim.id}: ${claim.requirementIds.join(",")} held by ${claim.holder} until ${claim.expiresAt}`);
}

function handleReleaseV2(args) {
  const dir = v2MissionDir(args);
  const state = readState(dir);
  if (!state) die(`No Tugboat v2 state in ${dir}`);
  if (args.values.has("now")) die("--now is not supported; lease time comes from the local system clock");
  const result = releaseClaim(dir, {
    claimId: required(args, "claim"),
    holder: required(args, "holder"),
    actor: resolvedActor(args, state.metadata.worktree),
    now: new Date().toISOString(),
    expectedRevision: args.values.has("expected-revision") ? Number(args.values.get("expected-revision")) : undefined,
    expectedHead: args.values.get("expected-head"),
  });
  const claim = publicClaim(result.claim);
  if (args.flags.has("json")) console.log(JSON.stringify(claim, null, 2));
  else console.log(`Released claim ${claim.id} held by ${claim.holder}`);
}

function handleAmendV2(args) {
  const dir = v2MissionDir(args);
  const state = readState(dir);
  if (!state) die(`No Tugboat v2 state in ${dir}`);
  const affectedIds = required(args, "requirements").split(",").filter(Boolean);
  let replacements = {};
  if (args.values.has("replacement-file")) replacements = JSON.parse(fs.readFileSync(path.resolve(args.values.get("replacement-file")), "utf8"));
  if (args.values.has("requirement-text") || args.values.has("acceptance")) {
    if (affectedIds.length !== 1) die("--requirement-text/--acceptance requires exactly one affected requirement");
    replacements[affectedIds[0]] = {
      ...(replacements[affectedIds[0]] ?? {}),
      ...(args.values.has("requirement-text") ? { requirement: args.values.get("requirement-text") } : {}),
      ...(args.values.has("acceptance") ? { acceptance: args.values.get("acceptance") } : {}),
    };
  }
  const head = git(state.metadata.worktree, ["rev-parse", "HEAD"]);
  const result = appendEvent(dir, {
    type: "SCOPE_AMENDED",
    actor: resolvedActor(args, state.metadata.worktree),
    payload: {
      id: required(args, "id"),
      reason: required(args, "reason"),
      affectedIds,
      supersedes: (args.values.get("supersedes") ?? "").split(",").filter(Boolean),
      replacements,
      sliceProgressionVersion: 1,
    },
  }, { reducer: missionReducer, expectedRevision: state.revision, currentHead: head });
  renderMission(dir, result.state);
  console.log(`Scope amendment ${required(args, "id")} recorded; ${affectedIds.join(",")} requires fresh proof`);
}

function handleEvidenceV2(args) {
  const dir = v2MissionDir(args);
  const state = readState(dir);
  if (!state) die(`No Tugboat v2 state in ${dir}`);
  const kind = args.values.get("kind") ?? "command";
  const common = {
    id: required(args, "id"), requirementIds: required(args, "requirements").split(",").filter(Boolean),
    cwd: state.metadata.worktree, actor: resolvedActor(args, state.metadata.worktree), excludePaths: [dir],
  };
  let evidence;
  if (kind === "command") {
    const command = args.values.get("_command");
    if (!Array.isArray(command) || !command.length) die("Command evidence needs `-- <command> [args]`");
    evidence = captureCommandEvidence({ ...common, command });
  } else if (["operator", "browser"].includes(kind)) {
    evidence = captureObservationEvidence({ ...common, kind, url: required(args, "url"), result: required(args, "result"), viewport: args.values.get("viewport") });
  } else die(`Unsupported evidence kind ${kind}`);
  const updated = recordEvidence(dir, evidence);
  console.log(`Evidence ${evidence.id} recorded (${evidence.verification.status}); revision=${updated.revision}`);
}

function handleCheckpointV2(args) {
  const dir = v2MissionDir(args);
  if (args.values.has("evidence") && !args.values.has("evidence-ids")) die("Free-form --evidence is a note, not proof; use --evidence-ids with structured evidence");
  const requirementIds = (args.values.get("requirements") ?? "").split(",").filter(Boolean);
  const preservationIds = (args.values.get("preservations") ?? "").split(",").filter(Boolean);
  const state = checkpointMission(dir, {
    actor: resolvedActor(args, readState(dir)?.metadata.worktree ?? process.cwd()),
    requirementIds,
    preservationIds,
    status: required(args, "status"),
    evidenceRefs: required(args, "evidence-ids").split(",").filter(Boolean),
    result: args.values.get("result"),
    action: required(args, "action"),
    nextAction: required(args, "next"),
    nextCheck: args.values.get("next-check"),
    blocker: args.values.get("blocker"),
  });
  console.log(`Tugboat checkpoint recorded: ${[...requirementIds, ...preservationIds].join(",")} revision=${state.revision}`);
}

function v2ResumeState(dir, options = {}) {
  const report = assertContinuity(dir, options);
  const state = report.state;
  return {
    mission: state.metadata.id,
    status: state.status,
    revision: state.revision,
    branch: state.metadata.branch,
    actualSha: report.git.actualHead,
    activeSlice: state.activeSliceId,
    activeRequirements: activeRequirementIds(state),
    provenRequirements: Object.values(state.requirements).filter((item) => item.status.startsWith("PROVEN(")).map((item) => item.id),
    nextAction: state.handoff.nextAction,
    handoffUpdated: state.handoff.updatedAt,
  };
}

function handleResumeV2(args) {
  const state = v2ResumeState(v2MissionDir(args), {
    maxHandoffAgeHours: args.values.has("max-handoff-age-hours") ? Number(args.values.get("max-handoff-age-hours")) : 24,
  });
  if (args.flags.has("json")) console.log(JSON.stringify(state, null, 2));
  else {
    console.log(`${state.mission}: ${state.status} revision=${state.revision}`);
    console.log(`Git: ${state.branch} actual=${state.actualSha}`);
    console.log(`Active slice: ${state.activeSlice}`);
    console.log(`Active: ${state.activeRequirements.join(",") || "none"}`);
    console.log(`Next: ${state.nextAction}`);
  }
}

function handleReconcileV2(args) {
  const dir = v2MissionDir(args);
  const state = readState(dir);
  if (!state) die(`No Tugboat v2 state in ${dir}`);
  const updated = reconcileMission(dir, {
    actor: resolvedActor(args, state.metadata.worktree),
    reason: required(args, "reason"),
    issueCodes: required(args, "issues").split(",").filter(Boolean),
    allowCurrentPatch: args.flags.has("allow-current-patch"),
    acceptSourceDrift: args.flags.has("accept-source-drift"),
    nextAction: args.values.get("next"),
  });
  console.log(`Tugboat reconciliation recorded: revision=${updated.revision}`);
}

function handleDeploymentEvidenceV2(args) {
  const dir = v2MissionDir(args);
  const state = readState(dir);
  if (!state) die(`No Tugboat v2 state in ${dir}`);
  const snapshot = gitSnapshot(state.metadata.worktree, { excludePaths: [dir] });
  const provider = required(args, "provider");
  const evidence = verifyDeploymentEvidence({
    id: required(args, "id"),
    provider,
    externalId: required(args, "external-id"),
    repository: args.values.get("repository"),
    region: args.values.get("region"),
    environment: required(args, "environment"),
    expectedSha: args.values.get("expected-sha") ?? snapshot.sha,
    requirementIds: required(args, "requirements").split(",").filter(Boolean),
    git: snapshot,
    cwd: state.metadata.worktree,
    actor: resolvedActor(args, state.metadata.worktree),
  });
  if (evidence.verification.status !== "passed") {
    const error = new Error(evidence.verification.reason);
    error.exitCode = 3;
    throw error;
  }
  recordEvidence(dir, evidence);
  console.log(`Deployment evidence ${evidence.id} verified: ${evidence.deployment.deployedSha}`);
}

function handleValidateV2(args) {
  const report = validateMission(v2MissionDir(args), {
    baseRef: args.values.get("base"),
    maxHandoffAgeHours: args.values.has("max-handoff-age-hours") ? Number(args.values.get("max-handoff-age-hours")) : 24,
    requireCompletion: args.flags.has("release"),
  });
  if (args.flags.has("json")) console.log(JSON.stringify(publicValidationReport(report), null, 2));
  if (!report.valid) throw new MissionValidationError(report);
  if (!args.flags.has("json")) console.log(`Tugboat mission valid: revision=${report.state.revision}`);
}

function publicValidationReport(report) {
  return {
    valid: report.valid,
    errors: report.errors,
    mission: report.state?.metadata?.id ?? null,
    revision: report.state?.revision ?? null,
    status: report.state?.status ?? null,
    baselineRef: report.baselineRef ?? null,
  };
}

function handleCiV2(args) {
  const report = validateMission(v2MissionDir(args), { baseRef: args.values.get("base"), maxHandoffAgeHours: 24 });
  if (args.flags.has("json")) console.log(JSON.stringify(publicValidationReport(report), null, 2));
  else console.log(report.valid ? "Tugboat CI validation passed" : `Tugboat CI validation failed (${report.errors.length} errors)`);
  if (!report.valid) throw new MissionValidationError(report);
}

function handleCloseV2(args) {
  const dir = v2MissionDir(args);
  const state = readState(dir);
  if (!state) die(`No Tugboat v2 state in ${dir}`);
  const closed = closeMission(dir, { actor: resolvedActor(args, state.metadata.worktree), baseRef: args.values.get("base") });
  console.log(`Tugboat mission complete: ${closed.metadata.id} revision=${closed.revision}`);
}

function handleMigrate(args) {
  const legacyDir = path.resolve(required(args, "legacy-dir"));
  const destinationDir = path.resolve(required(args, "dir"));
  const state = migrateLegacyMission({ legacyDir, destinationDir, actor: resolvedActor(args, process.cwd()) });
  console.log(`Migrated Tugboat ${state.legacyImport.protocolVersion} mission to protocol ${state.protocolVersion}: ${destinationDir}`);
}

function handleBackup(args) {
  const destination = backupMission(v2MissionDir(args), { destinationRoot: args.values.has("destination") ? path.resolve(args.values.get("destination")) : undefined });
  console.log(`Tugboat backup created: ${destination}`);
}

function handleRebuild(args) {
  const state = rebuildMission(v2MissionDir(args));
  console.log(`Tugboat mission rebuilt from ${state.revision} events`);
}

function handleValidate(args) {
  const ledger = path.resolve(required(args, "ledger"));
  const errors = validateLedger(ledger, {
    strictSource: true,
    strictGit: true,
    baseRef: args.values.get("base"),
    maxHandoffAgeHours: args.values.get("max-handoff-age-hours") ? Number(args.values.get("max-handoff-age-hours")) : 24,
  });
  if (errors.length) die(`Tugboat validation failed:\n- ${errors.join("\n- ")}`);
  console.log(`Tugboat mission valid: ${ledger}`);
}

function refreshHandoff(handoff, ledger, { timestamp, newlyProven, next, nextCheck, latestCommit, blocker }) {
  const requirements = tableObjects(ledger, "Requirement-To-Proof Ledger", REQUIREMENT_COLUMNS);
  const active = requirements.filter((item) => ["PENDING", "IN_PROGRESS", "BLOCKED"].includes(item.Status)).map((item) => item.ID);
  const worktree = field(ledger, "Worktree");
  const branch = field(ledger, "Branch");
  const sha = field(ledger, "Current SHA");
  let updated = replaceField(handoff, "Updated", timestamp);
  updated = replaceField(updated, "Mission status", field(ledger, "Mission status"));
  updated = replaceField(updated, "Repo / worktree", worktree);
  updated = replaceField(updated, "Branch / current SHA", `${branch} / ${sha}`);
  updated = replaceField(updated, "Active requirement IDs", active.join(",") || "none");
  updated = replaceField(updated, "Newly proven", newlyProven || "none");
  updated = replaceField(updated, "Latest commits", `${latestCommit} checkpoint`);
  if (blocker) updated = replaceField(updated, "Current blocker/decision", blocker);
  updated = replaceField(updated, "Exact next action", next);
  updated = replaceField(updated, "Next acceptance check", nextCheck || next);
  return updated;
}

function handleCheckpoint(args) {
  const ledgerPath = path.resolve(required(args, "ledger"));
  const paths = missionPaths(ledgerPath);
  let ledger = fs.readFileSync(paths.ledger, "utf8");
  let audit = fs.readFileSync(paths.audit, "utf8");
  let handoff = fs.readFileSync(paths.handoff, "utf8");
  const status = required(args, "status");
  const requirementIds = (args.values.get("requirements") ?? "").split(",").filter(Boolean);
  const preservationIds = (args.values.get("preservations") ?? "").split(",").filter(Boolean);
  if (!requirementIds.length && !preservationIds.length) die("checkpoint needs --requirements or --preservations");
  const actualSha = git(field(ledger, "Worktree"), ["rev-parse", "HEAD"]);
  if (!actualSha) die("Cannot read Git HEAD for mission worktree");
  ledger = replaceField(ledger, "Current SHA", actualSha);
  const proven = [];
  for (const id of requirementIds) {
    const updates = { Status: status };
    for (const [flag, column] of [["implementation", "Implementation"], ["tests", "Tests"], ["browser", "Browser proof"], ["production", "Production proof"]]) {
      if (args.values.has(flag)) updates[column] = args.values.get(flag);
    }
    ledger = updateTableRow(ledger, "Requirement-To-Proof Ledger", id, updates);
    const requirement = tableObjects(ledger, "Requirement-To-Proof Ledger", REQUIREMENT_COLUMNS).find((item) => item.ID === id);
    if (status.startsWith("PROVEN(")) {
      proven.push(id);
      ledger = updateTableRow(ledger, "Completion Map", id, {
        "Requirement ID": id,
        "User-visible result": required(args, "result"),
        Implementation: requirement.Implementation,
        Tests: requirement.Tests,
        "Browser evidence": requirement["Browser proof"],
        "Deployed SHA": status === "PROVEN(production)" ? actualSha : `N/A: ${requirement["Proof target"]} proof target`,
        "Production result": requirement["Production proof"] === "pending" ? `N/A: ${requirement["Proof target"]} proof target` : requirement["Production proof"],
      }, { append: true, columns: COMPLETION_COLUMNS });
    } else ledger = removeTableRow(ledger, "Completion Map", id);
  }
  for (const id of preservationIds) {
    ledger = updateTableRow(ledger, "Baseline And Preservation Contract", id, {
      Status: status,
      "Regression proof": required(args, "preservation-proof"),
    });
    if (status.startsWith("PROVEN(")) proven.push(id);
  }
  const timestamp = nowIso();
  audit = appendAudit(audit, {
    timestamp, actor: args.values.get("actor") ?? "Tugboat CLI",
    ids: [...requirementIds, ...preservationIds].join(","), action: required(args, "action"),
    reason: args.values.get("reason") ?? "checkpointed measured work", evidence: required(args, "evidence"),
    next: required(args, "next"),
  });
  handoff = refreshHandoff(handoff, ledger, {
    timestamp,
    newlyProven: proven.join(","),
    next: required(args, "next"),
    nextCheck: args.values.get("next-check"),
    latestCommit: actualSha,
    blocker: args.values.get("blocker"),
  });
  atomicMissionWrite(paths, { ledger, audit, handoff });
  console.log(`Tugboat checkpoint recorded: ${[...requirementIds, ...preservationIds].join(",")}`);
}

function resumeState(ledgerPath) {
  const paths = missionPaths(ledgerPath);
  const ledger = fs.readFileSync(paths.ledger, "utf8");
  const handoff = fs.readFileSync(paths.handoff, "utf8");
  const requirements = tableObjects(ledger, "Requirement-To-Proof Ledger", REQUIREMENT_COLUMNS);
  const worktree = field(ledger, "Worktree");
  const recordedSha = field(ledger, "Current SHA");
  const actualSha = git(worktree, ["rev-parse", "HEAD"]);
  return {
    mission: field(ledger, "Mission ID"),
    status: field(ledger, "Mission status"),
    branch: field(ledger, "Branch"),
    recordedSha,
    actualSha,
    commitsAfterRecorded: actualSha && recordedSha ? Number(git(worktree, ["rev-list", "--count", `${recordedSha}..${actualSha}`]) ?? 0) : null,
    dirtyFiles: (git(worktree, ["status", "--porcelain"]) ?? "").split("\n").filter(Boolean),
    activeRequirements: requirements.filter((item) => ["PENDING", "IN_PROGRESS", "BLOCKED"].includes(item.Status)).map((item) => item.ID),
    provenRequirements: requirements.filter((item) => item.Status.startsWith("PROVEN(")).map((item) => item.ID),
    criticalPath: field(ledger, "Critical path"),
    nextAction: field(handoff, "Exact next action"),
    handoffUpdated: field(handoff, "Updated"),
  };
}

function handleResume(args) {
  const state = resumeState(path.resolve(required(args, "ledger")));
  if (args.flags.has("json")) console.log(JSON.stringify(state, null, 2));
  else {
    console.log(`${state.mission}: ${state.status}`);
    console.log(`Git: ${state.branch} recorded=${state.recordedSha} actual=${state.actualSha} commits-after=${state.commitsAfterRecorded}`);
    console.log(`Active: ${state.activeRequirements.join(",") || "none"}`);
    console.log(`Critical path: ${state.criticalPath}`);
    console.log(`Next: ${state.nextAction}`);
  }
}

function completionReport(ledger) {
  const requirements = tableObjects(ledger, "Completion Map", COMPLETION_COLUMNS);
  const preservation = tableObjects(ledger, "Baseline And Preservation Contract", PRESERVATION_COLUMNS);
  return `# Tugboat Completion Report\n\n## Release\n\n- Mission: \`${field(ledger, "Mission ID")}\`\n- Status: \`COMPLETE\`\n- Repository: \`${field(ledger, "Repository")}\`\n- Current SHA: \`${field(ledger, "Current SHA")}\`\n- Rollback anchor: \`${field(ledger, "Rollback anchor")}\`\n- Canonical pipeline: \`${field(ledger, "Canonical deploy path")}\`\n\n## Requirement Proof\n\n| ID | Result operators can use | Implementation | Deterministic tests | Browser/operator evidence | Production evidence |\n|---|---|---|---|---|---|\n${requirements.map((item) => row([item["Requirement ID"], item["User-visible result"], item.Implementation, item.Tests, item["Browser evidence"], item["Production result"]])).join("\n")}\n\n## Preservation Proof\n\n| ID | Preserved behavior/design | Regression evidence | Production result |\n|---|---|---|---|\n${preservation.map((item) => row([item.ID, item["Preservation instruction"], item["Regression proof"], item.Status])).join("\n")}\n\n## Honest Residual Risk\n\nNo material approved requirement may be moved here.\n`;
}

function handleClose(args) {
  const ledgerPath = path.resolve(required(args, "ledger"));
  const paths = missionPaths(ledgerPath);
  let ledger = fs.readFileSync(paths.ledger, "utf8");
  let audit = fs.readFileSync(paths.audit, "utf8");
  let handoff = fs.readFileSync(paths.handoff, "utf8");
  const actualSha = git(field(ledger, "Worktree"), ["rev-parse", "HEAD"]);
  if (!actualSha) die("Cannot read Git HEAD for mission worktree");
  ledger = replaceField(ledger, "Current SHA", actualSha);
  ledger = replaceField(ledger, "Mission status", "COMPLETE");
  const timestamp = nowIso();
  audit = appendAudit(audit, {
    timestamp, actor: args.values.get("actor") ?? "Tugboat CLI", ids: "all",
    action: "closed mission", reason: "completion contract passed", evidence: actualSha, next: "stop",
  });
  handoff = refreshHandoff(handoff, ledger, {
    timestamp,
    newlyProven: "none",
    next: "stop; mission complete",
    nextCheck: "none; completion contract passed",
    latestCommit: actualSha,
    blocker: "none",
  });
  const completion = completionReport(ledger);
  atomicMissionWrite(paths, { ledger, audit, handoff, completion });
  console.log(`Tugboat mission complete: ${field(ledger, "Mission ID")}`);
}

function usage() {
  return `Usage:\n  tugboat init --dir DIR --mission ID --title TITLE --owner NAME --source FILE --requirements-file FILE --target local|production --critical-path IDs --deploy-path PATH [--legacy]\n  tugboat status --dir DIR [--json]\n  tugboat next --dir DIR [--observed-at ISO] [--json]\n  tugboat claim --dir DIR --id ID --holder NAME --requirements IDs [--ttl-seconds 900] [--expected-revision N] [--expected-head SHA] [--json]\n  tugboat release --dir DIR --claim ID --holder NAME [--expected-revision N] [--expected-head SHA] [--json]\n  tugboat amend --dir DIR --id ID --requirements IDs --reason TEXT [--supersedes IDs] [--replacement-file FILE]\n  tugboat evidence --dir DIR --id ID --requirements IDs -- <command> [args]\n  tugboat evidence --dir DIR --kind operator|browser --id ID --requirements IDs --url URL --result TEXT [--viewport TEXT]\n  tugboat deployment --dir DIR --id ID --provider github-actions|aws-cloudformation --external-id ID --environment ENV --requirements IDs\n  tugboat checkpoint --dir DIR --requirements IDs --status STATUS --evidence-ids IDS --action TEXT --next TEXT\n  tugboat reconcile --dir DIR --issues CODES --reason TEXT [--allow-current-patch] [--accept-source-drift]\n  tugboat validate --dir DIR [--base REF] [--release] [--json]\n  tugboat ci --dir DIR [--base REF] [--json]\n  tugboat resume --dir DIR [--json]\n  tugboat close --dir DIR [--base REF]\n  tugboat boundary verify --file FILE [--root DIR] [--json]\n  tugboat language recommend --dir MISSION [--repo REPOSITORY] [--profile FILE] [--json]\n  tugboat bundle create --dir SOURCE_MISSION --id ID --output FILE --requirements IDS [--commits SHAS] [--components-file FILE] [--commit-requirements-file FILE] [--depends-on IDS] [--private-key FILE]\n  tugboat bundle inspect --file FILE [--public-key FILE] [--require-signature] [--json]\n  tugboat bundle compare --bundles FILES [--public-key FILE] [--require-signature] [--json]\n  tugboat bundle commute --candidates FILE [--json]\n  tugboat bundle compose --candidates FILE --dry-run [--json]\n  tugboat bundle certify --bundle FILE --boundary-manifest FILE --root DIR --output FILE [--generated-at ISO] [--public-key FILE] [--require-signature] [--json]\n  tugboat certificate verify --file FILE --bundle FILE --boundary-manifest FILE --root DIR [--public-key FILE] [--require-signature] [--json]\n  tugboat cherry-pick --dir TARGET_MISSION --bundle FILE --requirements IDS [--exclude IDS] [--map SOURCE:TARGET] [--public-key FILE] [--require-signature] [--dry-run] -- COMMAND [ARGS]\n  tugboat migrate --legacy-dir DIR --dir NEW_DIR\n  tugboat backup --dir DIR [--destination DIR]\n  tugboat rebuild --dir DIR\n  tugboat proof mutate --repo REPO --plan FILE [--output FILE] [--json] [--gate] -- COMMAND [ARGS]\n  tugboat capsule capture --repo REPO --inputs PATHS [--artifacts PATHS] [--captured-at ISO] [--output FILE] -- COMMAND [ARGS]\n  tugboat capsule verify --file FILE [--repo REPO] [--output FILE] [--json]\n  tugboat capsule replay --file FILE --repo REPO [--output FILE] -- COMMAND [ARGS]\n  tugboat provenance create --root DIR --subjects PATHS [--materials FILE] --builder ID [--invocation FILE] [--private-key FILE] [--output FILE]\n  tugboat provenance verify --file FILE [--root DIR] [--public-key FILE] [--require-signature] [--json]\n  tugboat kernel compile --graph FILE --cache DIR [--output FILE] [--json]\n  tugboat adapter inspect --manifest FILE [--json]\n  tugboat adapter run --manifest FILE --input FILE [--inputs PATHS] [--input-root DIR] [--environment FILE] [--output FILE]\n  tugboat adapter conform --manifest FILE --cases FILE [--inputs PATHS] [--input-root DIR] [--environment FILE] [--output FILE]\n  tugboat history explain --dir MISSION [--revision N] [--requirement ID] [--json]\n  tugboat review compare --reviews FILES [--json] [--gate]`;
}

function intelligenceUsage() {
  return `Intelligence:\n  tugboat intelligence impact --dir MISSION --profile FILE [--repo REPOSITORY] [--base REF] [--head REF] [--json] [--gate]\n  tugboat intelligence lint|simulate|adversary --dir MISSION [--profile FILE] [--json] [--gate]\n  tugboat intelligence route --dir MISSION --workers FILE --profile FILE --observed-at ISO [--trust FILE] [--json] [--gate]\n  tugboat intelligence memory --records FILE --context FILE --observed-at ISO [--json] [--gate]\n  tugboat intelligence portfolio --dir MISSION --impact FILE --catalog FILE [--json] [--gate]\n  tugboat intelligence freshness --dir MISSION --policy FILE --observed-at ISO [--impact FILE] [--json] [--gate]\n  tugboat intelligence trust --graph FILE --policy FILE [--json] [--gate]\n  tugboat intelligence federation --manifest FILE [--json] [--gate]`;
}

function compositionUsage() {
  return `Certified composition:\n  tugboat bundle compose --dir TARGET_MISSION --manifest FILE (--dry-run|--apply) [--public-key FILE] [--require-signature] [--composition-certificate FILE] [--merge-certificate FILE] [--json]\n  tugboat certificate verify-composition --file FILE [--repository REPOSITORY] [--json]\n  tugboat certificate verify-merge --file FILE --composition FILE [--repository REPOSITORY] [--json]\n  --repository is mandatory when the composition binds rollback admission evidence.`;
}

function rollbackUsage() {
  return `Certified rollback:\n  tugboat rollback prove --manifest FILE --output FILE [--actor NAME] [--json]\n  tugboat certificate verify-rollback --file FILE --repository DIR [--json]\n  tugboat history explain --rollback-certificate FILE --repository DIR [--output FILE] [--json]`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.command || args.flags.has("help")) {
    console.log(`${usage()}\n${intelligenceUsage()}\n${compositionUsage()}\n${rollbackUsage()}`);
    return;
  }
  if (args.command === "init" && (args.flags.has("legacy") || args.values.get("protocol") === "1.1")) handleInit(args);
  else if (args.command === "init") handleInitV2(args);
  else if (args.command === "status") handleStatusV2(args);
  else if (args.command === "next") handleNextV2(args);
  else if (args.command === "claim") handleClaimV2(args);
  else if (args.command === "release") handleReleaseV2(args);
  else if (args.command === "amend") handleAmendV2(args);
  else if (args.command === "evidence") handleEvidenceV2(args);
  else if (args.command === "deployment") handleDeploymentEvidenceV2(args);
  else if (args.command === "checkpoint" && fs.existsSync(path.join(v2MissionDir(args), "state.json"))) handleCheckpointV2(args);
  else if (args.command === "checkpoint") handleCheckpoint(args);
  else if (args.command === "reconcile") handleReconcileV2(args);
  else if (args.command === "validate" && fs.existsSync(path.join(v2MissionDir(args), "state.json"))) handleValidateV2(args);
  else if (args.command === "validate") handleValidate(args);
  else if (args.command === "ci") handleCiV2(args);
  else if (args.command === "resume" && fs.existsSync(path.join(v2MissionDir(args), "state.json"))) handleResumeV2(args);
  else if (args.command === "resume") handleResume(args);
  else if (args.command === "close" && fs.existsSync(path.join(v2MissionDir(args), "state.json"))) handleCloseV2(args);
  else if (args.command === "close") handleClose(args);
  else if (args.command === "migrate") handleMigrate(args);
  else if (args.command === "backup") handleBackup(args);
  else if (args.command === "rebuild") handleRebuild(args);
  else if (args.command === "boundary") handleBoundary(args);
  else if (args.command === "certificate") handleCertificate(args);
  else if (args.command === "language" && args.subcommand === "recommend") handleLanguageRecommend(args);
  else if (args.command === "language") die(`Unknown language subcommand: ${args.subcommand ?? "none"}\n${usage()}`);
  else if (args.command === "intelligence") handleIntelligence(args);
  else if (args.command === "proof") handleProof(args);
  else if (args.command === "capsule") handleCapsule(args);
  else if (args.command === "provenance") handleProvenance(args);
  else if (args.command === "kernel") handleKernel(args);
  else if (args.command === "adapter") handleAdapter(args);
  else if (args.command === "history") handleHistory(args);
  else if (args.command === "rollback") handleRollback(args);
  else if (args.command === "review") handleReview(args);
  else if (args.command === "bundle" && args.subcommand === "create") handleBundleCreate(args);
  else if (args.command === "bundle" && args.subcommand === "inspect") handleBundleInspect(args);
  else if (args.command === "bundle" && args.subcommand === "compare") handleBundleCompare(args);
  else if (args.command === "bundle" && ["commute", "compose"].includes(args.subcommand)) handleBundleAlgebra(args);
  else if (args.command === "bundle" && args.subcommand === "certify") handleBundleCertify(args);
  else if (args.command === "bundle") die(`Unknown bundle subcommand: ${args.subcommand ?? "none"}\n${usage()}`);
  else if (args.command === "cherry-pick") handleCherryPick(args);
  else die(`Unknown command: ${args.command}\n${usage()}`);
}

if (isMainModule(import.meta.url)) {
  try {
    main();
  } catch (error) {
    const exitCode = error.exitCode ?? 1;
    if (process.argv.slice(2).includes("--json")) {
      console.error(JSON.stringify({ error: error.name ?? "Error", message: error.message, exitCode, details: error.details ?? null }, null, 2));
    } else {
      console.error(error.message);
      if (error.details?.counterexample) console.error(`Counterexample: ${JSON.stringify(error.details.counterexample)}`);
      if (error.details?.cleanupFailures) console.error(`Cleanup recovery: ${error.details.cleanupFailures.join("; ")}`);
      if (error.details?.recoveryRequired) console.error("Status: recovery_required");
    }
    process.exit(exitCode);
  }
}

export { parseArgs, resumeState, v2ResumeState };
