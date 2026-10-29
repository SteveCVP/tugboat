import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { payloadDigest } from "../install.mjs";
import { canonicalJson } from "./canonical.mjs";
import { missionReducer } from "./reducer.mjs";
import { readState, replayEvents } from "./store.mjs";

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

function check(id, status, summary, action = null) {
  return { id, status, summary, action };
}

function protocolFromLedger(missionDir) {
  const ledger = path.join(missionDir, "requirement-ledger.md");
  if (!fs.existsSync(ledger)) return null;
  const match = fs.readFileSync(ledger, "utf8").match(/^- Protocol version:\s*`([^`]+)`/m);
  return match?.[1] ?? null;
}

function installationChecks(rootDir, nodeVersion) {
  const checks = [];
  const major = Number(/^v?(\d+)/.exec(nodeVersion)?.[1]);
  checks.push(Number.isInteger(major) && major >= 20
    ? check("runtime.node", "pass", `Node ${nodeVersion} satisfies Tugboat's Node >=20 requirement.`)
    : check("runtime.node", "attention", `Node ${nodeVersion} does not satisfy Tugboat's Node >=20 requirement.`, "Install Node 20 or newer, then rerun tugboat doctor."));

  let packageJson;
  try {
    packageJson = JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf8"));
  } catch (error) {
    checks.push(check("install.package", "attention", `Package metadata cannot be read: ${error.message}`, "Reinstall Tugboat from a trusted source."));
    checks.push(check("install.payload", "attention", "Payload integrity cannot be checked without package metadata.", "Reinstall Tugboat from a trusted source."));
    return { checks, version: null };
  }

  const manifestFile = path.join(rootDir, ".tugboat-install.json");
  if (!fs.existsSync(manifestFile)) {
    checks.push(check("install.package", "pass", `Tugboat ${packageJson.version} is running from an unmanaged source checkout.`));
    checks.push(check("install.payload", "info", "No installation manifest is present, so payload integrity is not asserted.", "Use node scripts/install.mjs for a managed installation."));
    return { checks, version: packageJson.version };
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
  } catch (error) {
    checks.push(check("install.package", "attention", `Installation metadata is invalid: ${error.message}`, "Reinstall Tugboat from a trusted source."));
    checks.push(check("install.payload", "attention", "Installed payload integrity could not be verified.", "Reinstall Tugboat from a trusted source."));
    return { checks, version: packageJson.version };
  }
  if (manifest.version === packageJson.version) {
    checks.push(check("install.package", "pass", `Tugboat ${packageJson.version} installation metadata matches the package.`));
  } else {
    checks.push(check("install.package", "attention", `Installation metadata says ${manifest.version}, but the package says ${packageJson.version}.`, "Reinstall Tugboat so package and installation metadata agree."));
  }
  try {
    const actualDigest = payloadDigest(rootDir);
    checks.push(actualDigest === manifest.payloadDigest
      ? check("install.payload", "pass", `Installed payload matches ${manifest.payloadDigest}.`)
      : check("install.payload", "attention", "Installed payload differs from its recorded digest.", "Reinstall Tugboat from a trusted source."));
  } catch (error) {
    checks.push(check("install.payload", "attention", `Installed payload integrity could not be verified: ${error.message}`, "Reinstall Tugboat from a trusted source."));
  }
  return { checks, version: packageJson.version };
}

function missionChecks(missionDir) {
  const checks = [];
  if (!fs.existsSync(missionDir) || !fs.statSync(missionDir).isDirectory()) {
    return [
      check("mission.protocol", "attention", `Mission directory does not exist: ${missionDir}`, "Pass an existing mission directory with --dir."),
      check("mission.replay", "attention", "Mission replay cannot be checked.", "Correct the mission path, then rerun tugboat doctor."),
      check("mission.lock", "info", "Mission lock state is unavailable."),
    ];
  }

  const stored = (() => {
    try {
      return readState(missionDir);
    } catch {
      return null;
    }
  })();
  const declaredProtocol = stored?.protocolVersion ?? protocolFromLedger(missionDir);
  if (declaredProtocol && declaredProtocol !== "2.0") {
    checks.push(check(
      "mission.protocol",
      "attention",
      `Mission uses legacy Tugboat protocol ${declaredProtocol}.`,
      `Run: tugboat migrate --legacy-dir ${JSON.stringify(missionDir)} --dir <new-mission-dir>`,
    ));
    checks.push(check("mission.replay", "info", "Protocol 2 replay is not applicable until migration."));
  } else if (declaredProtocol === "2.0") {
    checks.push(check("mission.protocol", "pass", "Mission uses Tugboat protocol 2.0."));
    try {
      const replayed = replayEvents(missionDir, { reducer: missionReducer }).state;
      if (!stored || canonicalJson(stored) !== canonicalJson(replayed)) throw new Error("state.json does not match event replay");
      checks.push(check("mission.replay", "pass", `Event replay matches state revision ${replayed.revision}.`));
    } catch (error) {
      checks.push(check("mission.replay", "attention", `Mission replay failed: ${error.message}`, `Back up the mission, then run: tugboat rebuild --dir ${JSON.stringify(missionDir)}`));
    }
  } else {
    checks.push(check("mission.protocol", "attention", "Mission protocol cannot be identified.", "Verify requirement-ledger.md and state.json, or initialize a new mission."));
    checks.push(check("mission.replay", "attention", "Mission replay cannot be verified without a recognized protocol.", "Repair or migrate the mission before continuing."));
  }

  const lock = path.join(missionDir, ".tugboat-lock");
  checks.push(fs.existsSync(lock)
    ? check("mission.lock", "attention", "A mission write lock is present.", "Wait for the current owner to finish. If no writer is active, inspect the lock owner before recovery.")
    : check("mission.lock", "pass", "No mission write lock is present."));
  return checks;
}

export function compileDoctorReport({ rootDir = PACKAGE_ROOT, missionDir, nodeVersion = process.version } = {}) {
  const installation = installationChecks(path.resolve(rootDir), nodeVersion);
  const checks = [...installation.checks, ...(missionDir ? missionChecks(path.resolve(missionDir)) : [])];
  return {
    schemaVersion: "tugboat.doctor.v1",
    status: checks.some(({ status }) => status === "attention") ? "attention" : "healthy",
    version: installation.version,
    runtime: { node: nodeVersion, platform: process.platform, architecture: process.arch },
    checks,
  };
}

export function formatDoctorReport(report) {
  const lines = [`Tugboat doctor: ${report.status}`];
  for (const item of report.checks) {
    lines.push(`${item.status.toUpperCase()} ${item.id}: ${item.summary}`);
    if (item.action) lines.push(`  Action: ${item.action}`);
  }
  return lines.join("\n");
}
