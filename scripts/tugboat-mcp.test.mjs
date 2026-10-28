import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createMission } from "./lib/reducer.mjs";
import { readState } from "./lib/store.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SERVER = path.join(ROOT, "scripts", "tugboat-mcp.mjs");
const CLI = path.join(ROOT, "scripts", "tugboat.mjs");
const NOW = "2026-10-28T20:00:00.000Z";

function createMcpMission() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-mcp-"));
  const missionDir = path.join(repo, "mission");
  spawnSync("git", ["init", "-b", "main"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["config", "user.name", "Tugboat Test"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["config", "user.email", "tugboat@example.invalid"], { cwd: repo, encoding: "utf8" });
  fs.writeFileSync(path.join(repo, "spec.md"), "# MCP spec\n");
  fs.writeFileSync(path.join(repo, "operator.ts"), "export const operator = true;\n");
  spawnSync("git", ["add", "spec.md", "operator.ts"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["commit", "-m", "baseline"], { cwd: repo, encoding: "utf8" });
  const baseline = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).stdout.trim();
  createMission({
    dir: missionDir,
    actor: { name: "Tugboat Test", kind: "human", runtime: "test" },
    metadata: { id: "mcp-mission", title: "MCP Mission", owner: "Test", target: "local", repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline, source: { path: "spec.md", digest: `sha256:${"c".repeat(64)}` }, criticalPath: ["R1"], deployPath: "none" },
    requirements: [{ id: "R1", requirement: "Expose MCP", source: "spec", material: true, acceptance: "Wire protocol works", proofTarget: "local" }],
    preservations: [{ id: "P1", instruction: "Preserve replay", source: "spec", regressionProofTarget: "state tests" }],
    slices: [{ id: "S1", name: "MCP", requirementIds: ["R1"], dependencies: [], status: "ACTIVE", operatorJourney: "Connect an agent host" }],
  });
  return { repo, missionDir, baseline };
}

function request(id, method, params = undefined) {
  return JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
}

function runServer(missionDir, lines, { allowWrites = false, repo } = {}) {
  const result = spawnSync(process.execPath, [SERVER, "--dir", missionDir, ...(repo ? ["--repo", repo] : []), ...(allowWrites ? ["--allow-writes"] : [])], {
    input: `${lines.join("\n")}\n`,
    encoding: "utf8",
    env: { ...process.env, TUGBOAT_ACTOR: "mcp-test", TUGBOAT_RUNTIME: "node-test" },
    maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const outputLines = result.stdout.trim().split("\n").filter(Boolean);
  const responses = outputLines.map((line) => JSON.parse(line));
  assert.equal(responses.length, outputLines.length, "stdout must contain JSON-RPC only");
  return responses;
}

test("read-only MCP supports legacy and stateless discovery, deterministic tools, resources, bounded errors, and continued operation", () => {
  const { missionDir } = createMcpMission();
  const before = fs.readFileSync(path.join(missionDir, "events.jsonl"));
  const responses = runServer(missionDir, [
    "{not-json",
    request(1, "initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "wire-test", version: "1" } }),
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    request(2, "server/discover"),
    request(3, "tools/list"),
    request(4, "tools/call", { name: "tugboat_status", arguments: {} }),
    request(5, "tools/call", { name: "tugboat_next", arguments: { observedAt: NOW } }),
    request(6, "resources/list"),
    request(7, "resources/read", { uri: "tugboat://mission/current" }),
    request(8, "tools/call", { name: "tugboat_claim", arguments: { id: "C1", holder: "intruder", requirementIds: ["R1"], ttlSeconds: 60 } }),
    request(9, "tools/call", { name: "tugboat_status", arguments: { dir: "/tmp/other-mission" } }),
    request(11, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "legacy-wire-test", version: "1" } }),
    request(10, "ping"),
  ]);

  assert.deepEqual(responses.map((item) => item.id), [null, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 10]);
  assert.equal(responses[0].error.code, -32700);
  assert.equal(responses[1].result.protocolVersion, "2025-11-25");
  assert.equal(responses[1].result.serverInfo.name, "tugboat");
  assert.equal(responses[2].result.protocolVersion, "2026-07-28");
  assert.deepEqual(responses[3].result.tools.map((tool) => tool.name), ["tugboat_language_recommend", "tugboat_next", "tugboat_status"]);
  assert.equal(responses[4].result.structuredContent.mission, "mcp-mission");
  assert.equal(responses[5].result.structuredContent.schemaVersion, "tugboat.execution-packet.v1");
  assert.equal(responses[5].result.content[0].type, "text");
  assert.deepEqual(responses[6].result.resources.map((resource) => resource.uri), ["tugboat://mission/current"]);
  const resourcePacket = JSON.parse(responses[7].result.contents[0].text);
  assert.equal(resourcePacket.schemaVersion, "tugboat.execution-packet.v1");
  assert.equal(resourcePacket.mission.id, "mcp-mission");
  assert.match(resourcePacket.packetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(responses[8].result.isError, true);
  assert.match(responses[8].result.content[0].text, /read-only/i);
  assert.equal(responses[9].result.isError, true);
  assert.match(responses[9].result.content[0].text, /unknown argument.*dir/i);
  assert.equal(responses[10].result.protocolVersion, "2024-11-05");
  assert.deepEqual(responses[11].result, {});
  assert.deepEqual(fs.readFileSync(path.join(missionDir, "events.jsonl")), before);
});

test("write-enabled MCP exposes only context-bound coordination mutations and returns structured claims", () => {
  const { missionDir, baseline } = createMcpMission();
  const responses = runServer(missionDir, [
    request(1, "tools/list"),
    request(2, "tools/call", { name: "tugboat_claim", arguments: { id: "C1", holder: "codex-a", requirementIds: ["R1"], ttlSeconds: 60, expectedRevision: 1, expectedHead: baseline } }),
    request(3, "tools/call", { name: "tugboat_next", arguments: {} }),
    request(4, "tools/call", { name: "tugboat_release", arguments: { claimId: "C1", holder: "codex-a", expectedRevision: 2, expectedHead: baseline } }),
    request(5, "tools/call", { name: "tugboat_claim", arguments: { id: "C2", holder: "codex-a", requirementIds: ["R1"], ttlSeconds: 60, now: NOW } }),
    request(6, "tools/call", { name: "tugboat_claim", arguments: { id: "C3", holder: "codex-a", requirementIds: ["R1"], ttlSeconds: 60, expectedRevision: 3, expectedHead: "f".repeat(40) } }),
    request(7, "tools/call", { name: "tugboat_claim", arguments: { id: "C4", holder: "codex-a", requirementIds: ["R1"], ttlSeconds: 60, expectedRevision: 3 } }),
  ], { allowWrites: true });

  assert.deepEqual(responses[0].result.tools.map((tool) => tool.name), ["tugboat_claim", "tugboat_language_recommend", "tugboat_next", "tugboat_release", "tugboat_status"]);
  const claim = responses[1].result.structuredContent;
  assert.deepEqual({ id: claim.id, holder: claim.holder, requirementIds: claim.requirementIds, status: claim.status }, { id: "C1", holder: "codex-a", requirementIds: ["R1"], status: "ACTIVE" });
  assert.equal(Date.parse(claim.expiresAt) - Date.parse(claim.acquiredAt), 60_000);
  assert.deepEqual(responses[2].result.structuredContent.claimed.map((item) => item.claim.id), ["C1"]);
  assert.equal(responses[3].result.structuredContent.status, "RELEASED");
  assert.equal(responses[4].result.isError, true);
  assert.match(responses[4].result.content[0].text, /unknown argument.*now/i);
  assert.equal(responses[5].result.isError, true);
  assert.match(responses[5].result.content[0].text, /expected git head f{40}, actual [0-9a-f]{40}/i);
  assert.equal(responses[6].result.isError, true);
  assert.match(responses[6].result.content[0].text, /missing argument.*expectedHead/i);
  assert.equal(readState(missionDir).claims.C1.status, "RELEASED");
});

test("MCP rejects a frame larger than 1 MiB and still serves the next valid request", () => {
  const { missionDir } = createMcpMission();
  const oversized = "x".repeat(1024 * 1024 + 1);
  const responses = runServer(missionDir, [oversized, request(1, "ping")]);
  assert.equal(responses.length, 2);
  assert.equal(responses[0].id, null);
  assert.equal(responses[0].error.code, -32001);
  assert.match(responses[0].error.message, /1 MiB/);
  assert.deepEqual(responses[1], { jsonrpc: "2.0", id: 1, result: {} });
});

test("MCP language recommendation matches CLI, fixes paths at startup, bounds profiles, and never mutates mission state", () => {
  const { repo, missionDir } = createMcpMission();
  const profile = {
    maxLanguages: 1,
    requirementSignals: { R1: ["browser_ui"] },
    teamLanguages: ["typescript"],
  };
  const profilePath = path.join(repo, "architecture-profile.json");
  fs.writeFileSync(profilePath, JSON.stringify(profile));
  const cli = spawnSync(process.execPath, [CLI, "language", "recommend", "--dir", missionDir, "--repo", repo, "--profile", profilePath, "--json"], { cwd: repo, encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  const cliReport = JSON.parse(cli.stdout);
  const before = fs.readFileSync(path.join(missionDir, "events.jsonl"));

  const responses = runServer(missionDir, [
    request(1, "tools/call", { name: "tugboat_language_recommend", arguments: { profile } }),
    request(2, "tools/call", { name: "tugboat_language_recommend", arguments: { profile, repo: "/tmp/attacker" } }),
    request(3, "tools/call", { name: "tugboat_language_recommend", arguments: { profile: { requirementSignals: { R9: ["browser_ui"] } } } }),
    request(4, "tools/call", { name: "tugboat_language_recommend", arguments: { profile: { padding: "x".repeat(70 * 1024) } } }),
  ]);

  const mcpReport = responses[0].result.structuredContent;
  assert.equal(mcpReport.digest, cliReport.digest);
  assert.equal(responses[0].result.content[0].type, "text");
  assert.match(responses[0].result.content[0].text, /Primary: TypeScript/);
  assert.equal(JSON.stringify(mcpReport).includes(repo), false);
  assert.equal(responses[1].result.isError, true);
  assert.match(responses[1].result.content[0].text, /unknown argument.*repo/i);
  assert.equal(responses[2].result.isError, true);
  assert.match(responses[2].result.content[0].text, /unknown requirement R9/i);
  assert.equal(responses[3].result.isError, true);
  assert.match(responses[3].result.content[0].text, /profile exceeds 64 KiB/i);
  assert.deepEqual(fs.readFileSync(path.join(missionDir, "events.jsonl")), before);
});
