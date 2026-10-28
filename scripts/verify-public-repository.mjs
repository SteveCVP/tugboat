#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import { hasForbiddenProvenance } from "./export-distribution.mjs";
import { isMainModule } from "./lib/entrypoint.mjs";
import { isTextBuffer, scanSecrets } from "./lib/security.mjs";

function git(root, args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr.trim()}`);
  return result.stdout;
}

function gitBuffer(root, args) {
  const result = spawnSync("git", args, { cwd: root, encoding: null, maxBuffer: 128 * 1024 * 1024 });
  if (result.status !== 0) {
    const stderr = result.stderr?.toString("utf8").trim() || "unknown error";
    throw new Error(`git ${args.join(" ")} failed: ${stderr}`);
  }
  return result.stdout;
}

function trackedFiles(root) {
  return git(root, ["ls-files", "-z"]).split("\0").filter(Boolean);
}

function commitIds(root) {
  return git(root, ["rev-list", "--all"]).split("\n").filter(Boolean);
}

function verifyReferenceMetadata(root) {
  const references = git(root, ["for-each-ref", "--format=%(refname) %(objectname) %(objecttype)"]);
  if (scanSecrets(references).length) throw new Error("Secret material detected in reference metadata");
  if (hasForbiddenProvenance(references)) throw new Error("Forbidden provenance detected in reference metadata");
}

function historicalObjects(root) {
  const listing = git(root, ["rev-list", "--objects", "--all"]);
  if (scanSecrets(listing).length) throw new Error("Secret material detected in historical object path");
  if (hasForbiddenProvenance(listing)) throw new Error("Forbidden provenance detected in historical object path");
  return [...new Set(listing.split("\n").filter(Boolean).map((line) => line.split(" ", 1)[0]))];
}

function annotatedTagIds(root) {
  return git(root, ["for-each-ref", "--format=%(objecttype) %(objectname)", "refs/tags"])
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      const [type, object] = line.split(" ");
      return type === "tag" && object ? [object] : [];
    });
}

export function verifyPublicRepository(rootDir) {
  const root = fs.realpathSync(path.resolve(rootDir));
  const files = trackedFiles(root);
  if (!files.length) throw new Error("Public verification requires at least one tracked file");

  for (const relative of files) {
    const absolute = path.join(root, relative);
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) throw new Error(`Symbolic link detected in tracked file: ${relative}`);
    if (!stat.isFile()) continue;
    const content = fs.readFileSync(absolute);
    if (!isTextBuffer(content)) continue;
    const text = content.toString("utf8");
    if (scanSecrets(text).length) throw new Error(`Secret material detected in tracked file: ${relative}`);
    if (hasForbiddenProvenance(text)) throw new Error(`Forbidden provenance detected in tracked file: ${relative}`);
  }

  const commits = commitIds(root);
  if (!commits.length) throw new Error("Public verification requires at least one commit");
  verifyReferenceMetadata(root);
  for (const commit of commits) {
    const metadata = git(root, ["cat-file", "commit", commit]);
    if (scanSecrets(metadata).length) throw new Error(`Secret material detected in commit metadata: ${commit}`);
    if (hasForbiddenProvenance(metadata)) throw new Error(`Forbidden provenance detected in commit metadata: ${commit}`);
  }

  for (const object of historicalObjects(root)) {
    if (git(root, ["cat-file", "-t", object]).trim() !== "blob") continue;
    const content = gitBuffer(root, ["cat-file", "blob", object]);
    if (!isTextBuffer(content)) continue;
    const text = content.toString("utf8");
    if (scanSecrets(text).length) throw new Error(`Secret material detected in historical blob: ${object}`);
    if (hasForbiddenProvenance(text)) throw new Error(`Forbidden provenance detected in historical blob: ${object}`);
  }

  for (const tag of annotatedTagIds(root)) {
    const metadata = git(root, ["cat-file", "tag", tag]);
    if (scanSecrets(metadata).length) throw new Error(`Secret material detected in tag metadata: ${tag}`);
    if (hasForbiddenProvenance(metadata)) throw new Error(`Forbidden provenance detected in tag metadata: ${tag}`);
  }

  return { root, files: files.length, commits: commits.length };
}

if (isMainModule(import.meta.url)) {
  try {
    const json = process.argv.includes("--json");
    const result = verifyPublicRepository(process.cwd());
    if (json) console.log(JSON.stringify(result, null, 2));
    else console.log(`Public repository verified: ${result.commits} commit(s), ${result.files} tracked file(s)`);
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
}
