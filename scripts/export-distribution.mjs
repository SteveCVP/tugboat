#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { isMainModule } from "./lib/entrypoint.mjs";
import { isTextBuffer, scanSecrets } from "./lib/security.mjs";

const PUBLIC_ENTRIES = [
  "package.json",
  "SKILL.md",
  "README.md",
  "MANIFEST.md",
  "starter-prompts.md",
  "scripts",
  "references",
  "templates",
  "evals",
  "docs/release-audit-4.0.0.md",
];

const joined = (...parts) => parts.join("");
const wordPattern = (parts, flags = "gi") => new RegExp(`\\b${joined(...parts)}\\b`, flags);

const FORBIDDEN_PROVENANCE = [
  new RegExp(joined("@crys", "talvp"), "i"),
  wordPattern(["crys", "tal(?: venture partners)?"], "i"),
  wordPattern(["c", "vp"], "i"),
  wordPattern(["deal", "flow"], "i"),
  wordPattern(["ste", "ve(?:n|phen)?"], "i"),
  new RegExp(joined("/Us", "ers/")),
];

export function hasForbiddenProvenance(value) {
  return FORBIDDEN_PROVENANCE.some((pattern) => {
    pattern.lastIndex = 0;
    return pattern.test(String(value ?? ""));
  });
}

const LICENSE = `MIT License

Copyright (c) 2026 Tugboat contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

const CONTRIBUTING = `# Contributing

Use Node.js 20 or newer. Create a focused branch, add a failing behavioral test
before changing runtime behavior, and run these gates before opening a pull request:

\`\`\`bash
npm test
npm run test:behavior
npm pack --dry-run
\`\`\`

Do not commit credentials, private mission data, generated bundles, or local
worktree paths. Keep Tugboat dependency-free unless a dependency is necessary
and its security and portability cost is explicitly accepted.
`;

const SECURITY = `# Security Policy

Do not open public issues containing credentials, private mission data, bundle
bodies, or exploit details. Report vulnerabilities through the repository's
private vulnerability-reporting channel. If that channel is unavailable,
contact the repository maintainer privately before disclosure.

Include the affected version, a minimal reproduction, impact, and any known
mitigation. Never include live secrets; use redacted fixtures.
`;

const GITIGNORE = `node_modules/
coverage/
.worktrees/
.superpowers/
tugboat-eval-output/
*.tmp
*.tgz
.tugboat-lock/
`;

const CI_WORKFLOW = `name: CI

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: \${{ github.workflow }}-\${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: \${{ github.event.pull_request.head.sha || github.sha }}
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 20
      - run: npm install --ignore-scripts --package-lock=false
      - run: npm run verify:public
      - run: npm test
      - run: npm run test:behavior
      - run: npm pack --dry-run
`;

const CODEQL_WORKFLOW = `name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "17 6 * * 1"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: \${{ github.workflow }}-\${{ github.ref }}
  cancel-in-progress: true

jobs:
  analyze:
    name: Analyze JavaScript
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: github/codeql-action/init@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with:
          languages: javascript-typescript
      - uses: github/codeql-action/analyze@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
`;

const DEPENDABOT = `version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      github-actions:
        patterns:
          - "*"
    open-pull-requests-limit: 5
`;

function walk(root, current = root) {
  return fs.readdirSync(current, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name)).flatMap((entry) => {
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) return walk(root, absolute);
    return [path.relative(root, absolute)];
  });
}

function copyEntry(sourceRoot, stage, relative) {
  const source = path.join(sourceRoot, relative);
  if (!fs.existsSync(source)) throw new Error(`Public export entry is missing: ${relative}`);
  const stat = fs.lstatSync(source);
  if (stat.isSymbolicLink()) throw new Error(`Public export contains a symbolic link: ${relative}`);
  const destination = path.join(stage, relative);
  if (stat.isDirectory()) {
    fs.mkdirSync(destination, { recursive: true });
    for (const child of fs.readdirSync(source).sort()) copyEntry(sourceRoot, stage, path.join(relative, child));
    return;
  }
  if (!stat.isFile()) throw new Error(`Public export contains an unsupported entry: ${relative}`);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  fs.chmodSync(destination, stat.mode);
}

function writePublicMetadata(stage) {
  const packageFile = path.join(stage, "package.json");
  const packageJson = JSON.parse(fs.readFileSync(packageFile, "utf8"));
  if (packageJson.name !== "tugboat-mission-control" || packageJson.private !== false || packageJson.license !== "MIT") {
    throw new Error("Canonical package metadata is not public-distribution ready");
  }
  fs.writeFileSync(path.join(stage, "LICENSE"), LICENSE);
  fs.writeFileSync(path.join(stage, "CONTRIBUTING.md"), CONTRIBUTING);
  fs.writeFileSync(path.join(stage, "SECURITY.md"), SECURITY);
  fs.writeFileSync(path.join(stage, ".gitignore"), GITIGNORE);
  const workflow = path.join(stage, ".github", "workflows", "ci.yml");
  fs.mkdirSync(path.dirname(workflow), { recursive: true });
  fs.writeFileSync(workflow, CI_WORKFLOW);
  fs.writeFileSync(path.join(stage, ".github", "workflows", "codeql.yml"), CODEQL_WORKFLOW);
  fs.writeFileSync(path.join(stage, ".github", "dependabot.yml"), DEPENDABOT);
  return packageJson;
}

function validatePublicOutput(stage) {
  for (const relative of walk(stage)) {
    const absolute = path.join(stage, relative);
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) throw new Error(`Public export contains a symbolic link: ${relative}`);
    if (!stat.isFile()) continue;
    const content = fs.readFileSync(absolute);
    if (!isTextBuffer(content)) continue;
    const text = content.toString("utf8");
    if (scanSecrets(text).length) throw new Error(`Secret material detected in public export: ${relative}`);
    if (hasForbiddenProvenance(text)) throw new Error(`Forbidden provenance detected in public export: ${relative}`);
  }
}

export function exportDistribution({ sourceDir, destinationDir }) {
  const source = fs.realpathSync(path.resolve(sourceDir));
  const destination = path.resolve(destinationDir);
  const relativeDestination = path.relative(source, destination);
  if (!relativeDestination.startsWith("..") && !path.isAbsolute(relativeDestination)) {
    throw new Error("Distribution destination must be outside the source repository");
  }
  if (fs.existsSync(destination)) {
    if (!fs.statSync(destination).isDirectory() || fs.readdirSync(destination).length) {
      throw new Error("Distribution destination must be absent or empty");
    }
  }
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const stage = path.join(path.dirname(destination), `.${path.basename(destination)}.stage-${process.pid}-${randomUUID().slice(0, 8)}`);
  fs.mkdirSync(stage);
  try {
    for (const entry of PUBLIC_ENTRIES) copyEntry(source, stage, entry);
    const packageJson = writePublicMetadata(stage);
    validatePublicOutput(stage);
    const destinationWasEmpty = fs.existsSync(destination);
    if (destinationWasEmpty) fs.rmdirSync(destination);
    try {
      fs.renameSync(stage, destination);
    } catch (error) {
      if (destinationWasEmpty && !fs.existsSync(destination)) fs.mkdirSync(destination);
      throw error;
    }
    return {
      destinationDir: fs.realpathSync(destination),
      files: walk(destination),
      packageName: packageJson.name,
      version: packageJson.version,
    };
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
}

function parse(argv) {
  const values = new Map();
  const flags = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) throw new Error(`Unexpected argument ${token}`);
    if (index + 1 < argv.length && !argv[index + 1].startsWith("--")) values.set(token.slice(2), argv[++index]);
    else flags.add(token.slice(2));
  }
  return { values, flags };
}

function usage() {
  return "Usage: node scripts/export-distribution.mjs --destination DIR [--source DIR] [--json]";
}

if (isMainModule(import.meta.url)) {
  try {
    const args = parse(process.argv.slice(2));
    if (args.flags.has("help")) {
      console.log(usage());
      process.exit(0);
    }
    const destination = args.values.get("destination");
    if (!destination) throw new Error("--destination is required");
    const source = args.values.get("source") ?? path.dirname(path.dirname(fileURLToPath(import.meta.url)));
    const result = exportDistribution({ sourceDir: source, destinationDir: destination });
    if (args.flags.has("json")) console.log(JSON.stringify(result, null, 2));
    else console.log(`Exported ${result.packageName}@${result.version} to ${result.destinationDir}`);
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
}
