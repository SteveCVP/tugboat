#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { sha256 } from "./lib/canonical.mjs";
import { isMainModule } from "./lib/entrypoint.mjs";

const TARGETS = {
  agents: [".agents", "skills", "tugboat"],
  claude: [".claude", "skills", "tugboat"],
  codex: [".codex", "skills", "tugboat"],
};
const ENTRIES = ["package.json", "SKILL.md", "README.md", "MANIFEST.md", "starter-prompts.md", "scripts", "references", "templates", "evals"];

function walk(root, current = root) {
  const files = [];
  for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) files.push(...walk(root, absolute));
    else files.push(path.relative(root, absolute));
  }
  return files;
}

function payloadDigest(stage) {
  const proof = walk(stage).filter((file) => file !== ".tugboat-install.json").map((file) => `${file}:${sha256(fs.readFileSync(path.join(stage, file)))}`).join("\n");
  return `sha256:${sha256(proof)}`;
}

export function installTugboat({ sourceDir, home = os.homedir(), repo, targets = ["agents", "claude", "codex"] }) {
  const packageJson = JSON.parse(fs.readFileSync(path.join(sourceDir, "package.json"), "utf8"));
  const installed = [];
  const backups = [];
  for (const target of targets) {
    if (!TARGETS[target] && target !== "repo") throw new Error(`Unknown install target ${target}`);
    if (target === "repo" && !repo) throw new Error("The repo install target requires --repo");
    const destination = target === "repo" ? path.join(path.resolve(repo), ".tugboat", "runtime") : path.join(home, ...TARGETS[target]);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    const stage = `${destination}.stage-${process.pid}-${randomUUID().slice(0, 8)}`;
    fs.mkdirSync(stage);
    try {
      for (const entry of ENTRIES) {
        const source = path.join(sourceDir, entry);
        if (fs.existsSync(source)) fs.cpSync(source, path.join(stage, entry), { recursive: true });
      }
      const digest = payloadDigest(stage);
      fs.writeFileSync(path.join(stage, ".tugboat-install.json"), `${JSON.stringify({ version: packageJson.version, payloadDigest: digest, installedAt: new Date().toISOString(), target }, null, 2)}\n`);
      let backup = null;
      if (fs.existsSync(destination)) {
        backup = `${destination}.backup-${new Date().toISOString().replaceAll(":", "-")}`;
        fs.renameSync(destination, backup);
        backups.push(backup);
      }
      try {
        fs.renameSync(stage, destination);
      } catch (error) {
        if (backup && !fs.existsSync(destination)) fs.renameSync(backup, destination);
        throw error;
      }
      installed.push(destination);
      if (target === "repo") {
        const workflowSource = path.join(sourceDir, "templates", "github", "tugboat-validate.yml");
        const workflowDestination = path.join(path.resolve(repo), ".github", "workflows", "tugboat-validate.yml");
        fs.mkdirSync(path.dirname(workflowDestination), { recursive: true });
        if (fs.existsSync(workflowDestination)) {
          const workflowBackup = `${workflowDestination}.backup-${new Date().toISOString().replaceAll(":", "-")}`;
          fs.renameSync(workflowDestination, workflowBackup);
          backups.push(workflowBackup);
        }
        fs.copyFileSync(workflowSource, workflowDestination);
      }
    } finally {
      fs.rmSync(stage, { recursive: true, force: true });
    }
  }
  return { version: packageJson.version, installed, backups };
}

function parse(argv) {
  const values = {};
  const flags = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) throw new Error(`Unexpected argument ${token}`);
    if (index + 1 < argv.length && !argv[index + 1].startsWith("--")) values[token.slice(2)] = argv[++index];
    else flags.add(token.slice(2));
  }
  return { values, flags };
}

function usage() {
  return "Usage: node scripts/install.mjs [--source DIR] [--home DIR] [--targets agents,claude,codex,repo] [--repo DIR] [--json]";
}

if (isMainModule(import.meta.url)) {
  try {
    const args = parse(process.argv.slice(2));
    if (args.flags.has("help")) {
      console.log(usage());
      process.exit(0);
    }
    const sourceDir = path.resolve(args.values.source ?? path.dirname(path.dirname(fileURLToPath(import.meta.url))));
    const result = installTugboat({ sourceDir, home: path.resolve(args.values.home ?? os.homedir()), repo: args.values.repo ? path.resolve(args.values.repo) : undefined, targets: (args.values.targets ?? "agents,claude,codex").split(",").filter(Boolean) });
    if (args.flags.has("json")) console.log(JSON.stringify(result, null, 2));
    else console.log(`Installed Tugboat ${result.version}:\n${result.installed.join("\n")}`);
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
}
