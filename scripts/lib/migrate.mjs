import fs from "node:fs";
import path from "node:path";

import { sha256 } from "./canonical.mjs";
import { createMission, missionReducer } from "./reducer.mjs";
import { renderMission } from "./render.mjs";
import { redactSecrets } from "./security.mjs";
import { appendEvent } from "./store.mjs";

function field(markdown, label) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return markdown.match(new RegExp(`^- ${escaped}:\\s*(.+)$`, "mi"))?.[1]?.trim().replace(/^`|`$/g, "") ?? "";
}

function parseRow(line) {
  const cells = [];
  let current = "";
  let escaped = false;
  for (const character of line.trim().slice(1, -1)) {
    if (escaped) { current += character; escaped = false; }
    else if (character === "\\") escaped = true;
    else if (character === "|") { cells.push(current.trim()); current = ""; }
    else current += character;
  }
  cells.push(current.trim());
  return cells;
}

function table(markdown, heading) {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim().toLowerCase() === `## ${heading}`.toLowerCase());
  if (start < 0) throw new Error(`Legacy ledger is missing ${heading}`);
  const rows = [];
  for (let index = start + 1; index < lines.length && !lines[index].startsWith("## "); index += 1) {
    if (lines[index].trim().startsWith("|")) rows.push(parseRow(lines[index]));
  }
  if (rows.length < 2) throw new Error(`Legacy table ${heading} is malformed`);
  const headers = rows[0];
  return rows.slice(2).map((cells) => Object.fromEntries(headers.map((header, index) => [header, cells[index] ?? ""])));
}

function auditRows(markdown) {
  const lines = markdown.split(/\r?\n/).filter((line) => line.trim().startsWith("|"));
  if (lines.length < 2) return [];
  const headers = parseRow(lines[0]);
  return lines.slice(2).map((line) => {
    const cells = parseRow(line);
    return Object.fromEntries(headers.map((header, index) => [header, redactSecrets(cells[index] ?? "")]));
  });
}

export function migrateLegacyMission({ legacyDir, destinationDir, actor }) {
  const ledgerPath = path.join(legacyDir, "requirement-ledger.md");
  const auditPath = path.join(legacyDir, "audit-log.md");
  const ledger = fs.readFileSync(ledgerPath, "utf8");
  const audit = fs.existsSync(auditPath) ? fs.readFileSync(auditPath, "utf8") : "";
  const repository = field(ledger, "Repository");
  const sourceReference = field(ledger, "Source specification(s)");
  const absoluteSource = path.resolve(legacyDir, sourceReference);
  const requirementRows = table(ledger, "Requirement-To-Proof Ledger");
  const preservationRows = table(ledger, "Baseline And Preservation Contract");
  const requirements = requirementRows.map((item) => ({
    id: item.ID,
    requirement: item.Requirement,
    source: item.Source,
    material: item.Material !== "no",
    acceptance: item.Acceptance,
    proofTarget: item["Proof target"],
  }));
  const preservations = preservationRows.map((item) => ({ id: item.ID, instruction: item["Preservation instruction"], source: item.Source, regressionProofTarget: item["Regression proof"] }));
  let state = createMission({
    dir: destinationDir,
    actor,
    metadata: {
      id: field(ledger, "Mission ID"), title: field(ledger, "Mission title"), owner: field(ledger, "Owner"),
      target: requirements.some((item) => item.proofTarget === "production") ? "production" : "local",
      repository, worktree: field(ledger, "Worktree"), branch: field(ledger, "Branch"), baselineGitSha: field(ledger, "Baseline SHA"),
      source: { path: path.relative(repository, absoluteSource), digest: field(ledger, "Source specification digest") },
      criticalPath: field(ledger, "Critical path").split(",").filter(Boolean), deployPath: field(ledger, "Canonical deploy path"),
    },
    requirements,
    preservations,
  });
  const legacyImport = {
    protocolVersion: field(ledger, "Protocol version") || "1.1",
    sourceDirectory: legacyDir,
    ledgerDigest: `sha256:${sha256(ledger)}`,
    auditDigest: `sha256:${sha256(audit)}`,
    requirementCount: requirements.length,
    preservationCount: preservations.length,
    legacyRequirementRows: requirementRows.map((item) => Object.fromEntries(Object.entries(item).map(([key, value]) => [key, redactSecrets(value)]))),
    legacyPreservationRows: preservationRows.map((item) => Object.fromEntries(Object.entries(item).map(([key, value]) => [key, redactSecrets(value)]))),
    auditRows: auditRows(audit),
  };
  state = appendEvent(destinationDir, { type: "LEGACY_MIGRATED", actor, payload: legacyImport }, { reducer: missionReducer, expectedRevision: state.revision, currentHead: field(ledger, "Current SHA") }).state;
  renderMission(destinationDir, state);
  return state;
}
