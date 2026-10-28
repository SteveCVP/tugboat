#!/usr/bin/env node

import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ALLOWED_MISSION = new Set(["ACTIVE", "PARTIAL", "BLOCKED", "COMPLETE"]);
const ALLOWED_STATUS = new Set([
  "PENDING",
  "IN_PROGRESS",
  "BLOCKED",
  "PROVEN(local)",
  "PROVEN(production)",
  "WAIVED(user)",
]);
const ALLOWED_TARGET = new Set(["documentation", "local", "production"]);
const REQUIRED_COLUMNS = [
  "ID",
  "Requirement",
  "Source",
  "Material",
  "Acceptance",
  "Proof target",
  "Implementation",
  "Tests",
  "Browser proof",
  "Production proof",
  "Status",
];
const REQUIRED_METADATA = [
  "Mission ID",
  "Mission title",
  "Owner",
  "Repository",
  "Worktree",
  "Branch",
  "Baseline SHA",
  "Current SHA",
  "Source specification(s)",
  "Source specification digest",
  "Canonical deploy path",
  "Rollback anchor",
];

function clean(value = "") {
  return value.trim().replace(/^`|`$/g, "");
}

function parseMarkdownRow(line) {
  const cells = [];
  let current = "";
  let escaped = false;
  for (const character of line.trim().slice(1, -1)) {
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (character === "|") {
      cells.push(current.trim());
      current = "";
    } else {
      current += character;
    }
  }
  cells.push(current.trim());
  return cells;
}

function tableRows(markdown, heading) {
  const linesAll = markdown.split(/\r?\n/);
  const start = linesAll.findIndex((line) => line.trim().toLowerCase() === `## ${heading}`.toLowerCase());
  if (start < 0) return null;
  const endOffset = linesAll.slice(start + 1).findIndex((line) => line.startsWith("## "));
  const end = endOffset < 0 ? linesAll.length : start + 1 + endOffset;
  const lines = linesAll.slice(start + 1, end).filter((line) => line.trim().startsWith("|"));
  if (lines.length < 2) return { headers: [], rows: [] };
  const headers = parseMarkdownRow(lines[0]);
  const rows = lines.slice(2).map(parseMarkdownRow).filter((row) => row.some(Boolean));
  return { headers, rows };
}

function field(markdown, label) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return clean(markdown.match(new RegExp(`^- ${escaped}:\\s*(.+)$`, "mi"))?.[1] ?? "");
}

function unresolved(value) {
  const normalized = clean(value).toLowerCase();
  if (!normalized) return true;
  if (/^n\/a:\s*\S/.test(normalized)) return false;
  return (
    normalized.startsWith("[") ||
    /\b(pending|tbd|todo|later|follow-up|not configured|not yet|placeholder)\b/.test(normalized)
  );
}

function resolveCompanion(ledgerPath, value) {
  const stripped = clean(value);
  return path.isAbsolute(stripped) ? stripped : path.resolve(path.dirname(ledgerPath), stripped);
}

function runGit(cwd, args) {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

function samePath(left, right) {
  try {
    return fs.realpathSync(left) === fs.realpathSync(right);
  } catch {
    return path.resolve(left) === path.resolve(right);
  }
}

export function computeSourceDigest(ledgerPath, sourceValue) {
  const sources = clean(sourceValue).split(";").map((entry) => clean(entry)).filter(Boolean);
  if (!sources.length) throw new Error("no source specification path recorded");
  const hash = createHash("sha256");
  for (const [index, source] of sources.entries()) {
    const absolute = path.isAbsolute(source) ? source : path.resolve(path.dirname(ledgerPath), source);
    if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
      throw new Error(`source specification not found: ${absolute}`);
    }
    if (index) hash.update("\n---TUGBOAT-SOURCE---\n");
    hash.update(fs.readFileSync(absolute));
  }
  return `sha256:${hash.digest("hex")}`;
}

function immutableRows(markdown, heading, count) {
  const table = tableRows(markdown, heading);
  if (!table) return new Map();
  return new Map(table.rows.map((row) => [row[0], row.slice(0, count)]));
}

function markdownDataRows(markdown) {
  return markdown.split(/\r?\n/)
    .filter((line) => line.trim().startsWith("|"))
    .slice(2)
    .map((line) => line.trim());
}

function validateAppendOnly(errors, absolute, markdown, baseRef, gitCwd) {
  const root = runGit(gitCwd, ["rev-parse", "--show-toplevel"]);
  if (!root) {
    errors.push(`Cannot inspect append-only history: ${gitCwd} is not a Git worktree.`);
    return;
  }
  const rootPath = fs.realpathSync(root);
  const ledgerPath = fs.realpathSync(absolute);
  const relativeLedger = path.relative(rootPath, ledgerPath);
  if (relativeLedger.startsWith("..")) {
    errors.push("Ledger is outside the Git worktree used for --base validation.");
    return;
  }
  const baseline = runGit(gitCwd, ["show", `${baseRef}:${relativeLedger}`]);
  if (baseline === null) {
    errors.push(`Baseline ${baseRef} does not contain ${relativeLedger}.`);
    return;
  }

  for (const [heading, immutableCount, label] of [
    ["Requirement-To-Proof Ledger", 6, "Requirement"],
    ["Baseline And Preservation Contract", 3, "Preservation"],
  ]) {
    const before = immutableRows(baseline, heading, immutableCount);
    const after = immutableRows(markdown, heading, immutableCount);
    for (const [id, cells] of before) {
      if (!after.has(id)) errors.push(`${label} ${id} was deleted from the baseline.`);
      else if (JSON.stringify(after.get(id)) !== JSON.stringify(cells)) {
        errors.push(`${label} ${id} meaning changed; append a scope change instead of rewriting it.`);
      }
    }
  }

  const beforeScope = tableRows(baseline, "Scope Changes")?.rows ?? [];
  const afterScope = tableRows(markdown, "Scope Changes")?.rows ?? [];
  if (JSON.stringify(afterScope.slice(0, beforeScope.length)) !== JSON.stringify(beforeScope)) {
    errors.push("Scope-change history was rewritten; append a correction instead.");
  }

  const auditValue = field(markdown, "Audit log");
  const auditPath = resolveCompanion(absolute, auditValue);
  const relativeAudit = path.relative(rootPath, fs.realpathSync(auditPath));
  const baselineAudit = relativeAudit.startsWith("..") ? null : runGit(gitCwd, ["show", `${baseRef}:${relativeAudit}`]);
  if (baselineAudit === null) {
    errors.push(`Baseline ${baseRef} does not contain the audit log ${relativeAudit}.`);
  } else if (fs.existsSync(auditPath)) {
    const beforeRows = markdownDataRows(baselineAudit);
    const afterRows = markdownDataRows(fs.readFileSync(auditPath, "utf8"));
    if (JSON.stringify(afterRows.slice(0, beforeRows.length)) !== JSON.stringify(beforeRows)) {
      errors.push("Audit history was rewritten; append a correction instead.");
    }
  }
}

export function validateLedger(ledgerPath, options = {}) {
  const errors = [];
  const absolute = path.resolve(ledgerPath);
  if (!fs.existsSync(absolute)) return [`Ledger not found: ${absolute}`];

  const markdown = fs.readFileSync(absolute, "utf8");
  const missionStatus = field(markdown, "Mission status");
  if (!ALLOWED_MISSION.has(missionStatus)) {
    errors.push(`Mission status must be one of ${[...ALLOWED_MISSION].join(", ")}; got "${missionStatus || "missing"}".`);
  }

  for (const label of REQUIRED_METADATA) {
    const value = field(markdown, label);
    if (unresolved(value)) errors.push(`${label} is missing or unresolved.`);
  }
  if (field(markdown, "Protocol version") === "1.1") {
    for (const label of ["Deadline / budget", "Critical path", "Gate cadence", "Retry policy"]) {
      if (unresolved(field(markdown, label))) errors.push(`${label} is required by Tugboat protocol 1.1.`);
    }
  }
  if (!/^[0-9a-f]{7,40}$/i.test(field(markdown, "Baseline SHA"))) errors.push("Baseline SHA must be a valid git SHA.");
  if (!/^sha256:[0-9a-f]{64}$/.test(field(markdown, "Source specification digest"))) {
    errors.push("Source specification digest must be sha256 followed by 64 lowercase hex characters.");
  }
  if (options.strictSource) {
    try {
      const actual = computeSourceDigest(absolute, field(markdown, "Source specification(s)"));
      const recorded = field(markdown, "Source specification digest");
      if (recorded !== actual) errors.push(`Source specification digest does not match: recorded ${recorded}, actual ${actual}.`);
    } catch (error) {
      errors.push(`Cannot verify source specification digest: ${error.message}`);
    }
  }

  const companions = new Map();
  for (const companion of ["Audit log", "Context handoff"]) {
    const value = field(markdown, companion);
    if (!value) {
      errors.push(`${companion} path is missing.`);
      continue;
    }
    const companionPath = resolveCompanion(absolute, value);
    if (!fs.existsSync(companionPath)) errors.push(`${companion} not found: ${companionPath}`);
    else companions.set(companion, companionPath);
  }

  const table = tableRows(markdown, "Requirement-To-Proof Ledger");
  if (!table) return [...errors, "Missing ## Requirement-To-Proof Ledger section."];
  if (table.headers.join("|") !== REQUIRED_COLUMNS.join("|")) {
    errors.push(`Requirement ledger columns must be exactly: ${REQUIRED_COLUMNS.join(" | ")}`);
    return errors;
  }
  if (!table.rows.length) errors.push("Requirement ledger has no rows.");

  const seen = new Set();
  const rows = table.rows.map((cells, index) => Object.fromEntries(REQUIRED_COLUMNS.map((key, i) => [key, cells[i] ?? ""])));
  for (const [index, row] of rows.entries()) {
    const prefix = `Row ${index + 1}${row.ID ? ` (${row.ID})` : ""}`;
    if (table.rows[index].length !== REQUIRED_COLUMNS.length) errors.push(`${prefix}: expected ${REQUIRED_COLUMNS.length} cells; escape literal pipes as \\|.`);
    if (!/^R[0-9]+(?:\.[0-9]+)?$/.test(row.ID)) errors.push(`${prefix}: invalid requirement ID.`);
    if (seen.has(row.ID)) errors.push(`${prefix}: duplicate requirement ID.`);
    seen.add(row.ID);
    if (!row.Requirement || !row.Source || !row.Acceptance) errors.push(`${prefix}: requirement, source, and acceptance are required.`);
    if (!new Set(["yes", "no"]).has(row.Material.toLowerCase())) errors.push(`${prefix}: Material must be yes or no.`);
    if (!ALLOWED_TARGET.has(row["Proof target"])) errors.push(`${prefix}: invalid proof target "${row["Proof target"]}".`);
    if (!ALLOWED_STATUS.has(row.Status)) errors.push(`${prefix}: invalid status "${row.Status}".`);

    const provenLocal = row.Status === "PROVEN(local)" || row.Status === "PROVEN(production)";
    if (provenLocal) {
      for (const key of ["Implementation", "Tests", "Browser proof"]) {
        if (unresolved(row[key])) errors.push(`${prefix}: ${key} is not proof for ${row.Status}.`);
      }
    }
    if (row.Status === "PROVEN(production)" && unresolved(row["Production proof"])) {
      errors.push(`${prefix}: Production proof is required for PROVEN(production).`);
    }
    if (row.Status === "WAIVED(user)" && !/waived by .+\b20\d{2}-\d{2}-\d{2}\b/i.test(row["Production proof"])) {
      errors.push(`${prefix}: WAIVED(user) requires "Waived by [name] YYYY-MM-DD" in Production proof.`);
    }
  }

  const preservation = tableRows(markdown, "Baseline And Preservation Contract");
  if (!preservation?.rows.length) {
    errors.push("Baseline And Preservation Contract must contain at least one preservation row (use N/A only with a reason)." );
  } else {
    const expected = ["ID", "Preservation instruction", "Source", "Regression proof", "Status"];
    if (preservation.headers.join("|") !== expected.join("|")) {
      errors.push(`Preservation columns must be exactly: ${expected.join(" | ")}`);
    } else {
      const preservationIds = new Set();
      for (const [index, cells] of preservation.rows.entries()) {
        const [id, instruction, source, proof, status] = cells;
        const prefix = `Preservation row ${index + 1}${id ? ` (${id})` : ""}`;
        if (cells.length !== expected.length) errors.push(`${prefix}: expected ${expected.length} cells; escape literal pipes as \\|.`);
        if (!/^P[0-9]+(?:\.[0-9]+)?$/.test(id)) errors.push(`${prefix}: invalid preservation ID.`);
        if (preservationIds.has(id)) errors.push(`${prefix}: duplicate preservation ID.`);
        preservationIds.add(id);
        if (!instruction || !source) errors.push(`${prefix}: instruction and source are required.`);
        if (!ALLOWED_STATUS.has(status)) errors.push(`${prefix}: invalid status "${status}".`);
        if ((status === "PROVEN(local)" || status === "PROVEN(production)") && unresolved(proof)) {
          errors.push(`${prefix}: regression proof is required for ${status}.`);
        }
        if (status === "WAIVED(user)" && !/waived by .+\b20\d{2}-\d{2}-\d{2}\b/i.test(proof)) {
          errors.push(`${prefix}: WAIVED(user) requires "Waived by [name] YYYY-MM-DD" in Regression proof.`);
        }
      }
    }
  }

  const auditPath = companions.get("Audit log");
  if (auditPath) {
    const audit = fs.readFileSync(auditPath, "utf8");
    const dataRows = audit.split(/\r?\n/).filter((line) => line.trim().startsWith("|")).slice(2).map(parseMarkdownRow);
    if (!dataRows.some((cells) => cells.length >= 7 && cells.every((cell) => cell && !cell.startsWith("[")))) {
      errors.push("Audit log has no completed evidence entry.");
    }
  }

  const handoffPath = companions.get("Context handoff");
  if (handoffPath) {
    const handoff = fs.readFileSync(handoffPath, "utf8");
    for (const label of ["Updated", "Mission", "Mission status", "Branch / current SHA", "Exact next action"]) {
      if (unresolved(field(handoff, label))) errors.push(`Context handoff field ${label} is missing or unresolved.`);
    }
    const handoffStatus = field(handoff, "Mission status");
    if (handoffStatus && handoffStatus !== missionStatus) errors.push(`Context handoff status ${handoffStatus} does not match ledger status ${missionStatus}.`);
    if (options.maxHandoffAgeHours && missionStatus !== "COMPLETE") {
      const updated = new Date(field(handoff, "Updated"));
      const now = options.now instanceof Date ? options.now : new Date();
      const ageHours = (now.getTime() - updated.getTime()) / 3_600_000;
      if (!Number.isFinite(updated.getTime())) errors.push("Context handoff Updated is not a valid timestamp.");
      else if (ageHours > options.maxHandoffAgeHours) {
        errors.push(`Context handoff is stale (${ageHours.toFixed(1)}h; limit ${options.maxHandoffAgeHours}h).`);
      }
    }
  }

  if (options.strictGit) {
    const gitCwd = path.resolve(options.gitCwd || field(markdown, "Worktree"));
    const root = runGit(gitCwd, ["rev-parse", "--show-toplevel"]);
    if (!root) errors.push(`Recorded worktree is not a Git worktree: ${gitCwd}`);
    else {
      if (!samePath(root, gitCwd)) errors.push(`Recorded worktree ${gitCwd} does not match Git root ${root}.`);
      const actualBranch = runGit(gitCwd, ["branch", "--show-current"]);
      const recordedBranch = field(markdown, "Branch");
      if (actualBranch !== recordedBranch) errors.push(`Recorded branch ${recordedBranch} does not match Git branch ${actualBranch}.`);
      const baseline = field(markdown, "Baseline SHA");
      const current = field(markdown, "Current SHA");
      if (runGit(gitCwd, ["cat-file", "-e", `${baseline}^{commit}`]) === null) errors.push(`Baseline SHA ${baseline} is not a Git commit.`);
      if (runGit(gitCwd, ["cat-file", "-e", `${current}^{commit}`]) === null) errors.push(`Current SHA ${current} is not a Git commit.`);
      if (runGit(gitCwd, ["merge-base", "--is-ancestor", baseline, current]) === null) errors.push(`Baseline SHA ${baseline} is not an ancestor of current SHA ${current}.`);
      if (runGit(gitCwd, ["merge-base", "--is-ancestor", current, "HEAD"]) === null) errors.push(`Recorded current SHA ${current} is not an ancestor of HEAD.`);
    }
  }

  if (options.baseRef) validateAppendOnly(errors, absolute, markdown, options.baseRef, path.resolve(options.gitCwd || field(markdown, "Worktree")));

  if (missionStatus === "COMPLETE") {
    const currentSha = field(markdown, "Current SHA");
    if (!/^[0-9a-f]{7,40}$/i.test(currentSha)) errors.push("COMPLETE mission requires a valid Current SHA.");
    for (const row of rows.filter((candidate) => candidate.Material.toLowerCase() === "yes")) {
      const target = row["Proof target"];
      const closed = row.Status === "WAIVED(user)" || row.Status === "PROVEN(production)" ||
        (target !== "production" && row.Status === "PROVEN(local)");
      if (!closed) errors.push(`COMPLETE mission has unclosed material requirement ${row.ID} (${row.Status}, target ${target}).`);
    }

    const hasProductionTarget = rows.some((row) => row.Material.toLowerCase() === "yes" && row["Proof target"] === "production");
    for (const cells of preservation?.rows ?? []) {
      const [id, , , , status] = cells;
      const closed = status === "WAIVED(user)" || status === "PROVEN(production)" || (!hasProductionTarget && status === "PROVEN(local)");
      if (!closed) errors.push(`COMPLETE mission has unclosed preservation requirement ${id} (${status}).`);
    }

    const completion = tableRows(markdown, "Completion Map");
    const completionHeaders = ["Requirement ID", "User-visible result", "Implementation", "Tests", "Browser evidence", "Deployed SHA", "Production result"];
    if (!completion || completion.headers.join("|") !== completionHeaders.join("|")) {
      errors.push(`Completion Map columns must be exactly: ${completionHeaders.join(" | ")}`);
    }
    const completionIds = new Set(completion?.rows.map((row) => row[0]) ?? []);
    for (const row of rows) {
      if (!completionIds.has(row.ID)) errors.push(`Completion Map is missing ${row.ID}.`);
    }
    for (const cells of completion?.rows ?? []) {
      const [id, ...proofCells] = cells;
      if (cells.length !== completionHeaders.length) errors.push(`Completion Map row ${id} has ${cells.length} cells; expected ${completionHeaders.length}.`);
      if (proofCells.some(unresolved)) errors.push(`Completion Map row ${id} contains unresolved proof.`);
    }
    if (rows.some((row) => row.Material.toLowerCase() === "yes" && row["Proof target"] === "production")) {
      if (!/^[0-9a-f]{7,40}$/i.test(field(markdown, "Rollback anchor"))) errors.push("Production-complete mission requires a valid rollback anchor SHA.");
    }
  }

  return errors;
}

function main() {
  const args = process.argv.slice(2);
  const ledger = args.find((arg) => !arg.startsWith("--"));
  if (!ledger) {
    console.error("Usage: node validate-ledger.mjs <requirement-ledger.md>");
    process.exit(2);
  }
  const value = (name) => {
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : undefined;
  };
  const errors = validateLedger(ledger, {
    strictSource: args.includes("--strict-source"),
    strictGit: args.includes("--strict-git"),
    baseRef: value("--base"),
    gitCwd: value("--git-cwd"),
    maxHandoffAgeHours: value("--max-handoff-age-hours") ? Number(value("--max-handoff-age-hours")) : undefined,
  });
  if (errors.length) {
    console.error(`Tugboat ledger validation failed (${errors.length}):`);
    for (const error of errors) console.error(`- ${error}`);
    process.exit(1);
  }
  console.log(`Tugboat ledger valid: ${path.resolve(ledger)}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main();
