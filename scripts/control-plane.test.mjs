import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { activeClaims, claimRequirements, compileExecutionPacket, releaseClaim } from "./lib/control-plane.mjs";
import { canonicalJson } from "./lib/canonical.mjs";
import { createMission, missionReducer } from "./lib/reducer.mjs";
import { appendEvent, readState } from "./lib/store.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const OBSERVED_AT = "2026-10-28T18:00:00.000Z";

function fixtureState() {
  return {
    schemaVersion: 2,
    protocolVersion: "2.0",
    status: "ACTIVE",
    revision: 7,
    metadata: { id: "control-plane", criticalPath: ["R1", "R2", "R3", "R4"] },
    activeSliceId: "S1",
    slices: {
      S1: { id: "S1", name: "Control plane", requirementIds: ["R1", "R2", "R3", "R4"], dependencies: [], status: "ACTIVE", operatorJourney: "Ship the control plane" },
    },
    requirements: {
      R1: { id: "R1", requirement: "Compile next work", acceptance: "Packet is complete", proofTarget: "local", status: "PENDING", evidenceRefs: [] },
      R2: { id: "R2", requirement: "Resolve blocker", acceptance: "Blocker is gone", proofTarget: "local", status: "BLOCKED", evidenceRefs: [] },
      R3: { id: "R3", requirement: "Preserve proof", acceptance: "Proof remains", proofTarget: "local", status: "PROVEN(local)", evidenceRefs: ["E-COMMAND", "E-OPERATOR"] },
      R4: { id: "R4", requirement: "Add MCP", acceptance: "MCP works", proofTarget: "production", status: "IN_PROGRESS", evidenceRefs: ["E-COMMAND"] },
    },
    preservations: {
      P1: { id: "P1", instruction: "Preserve replay", regressionProofTarget: "state suite", status: "PENDING", evidenceRefs: [] },
    },
    evidence: {
      "E-COMMAND": { id: "E-COMMAND", kind: "command", verification: { status: "passed" }, output: { stdout: "private-command-output" } },
      "E-OPERATOR": { id: "E-OPERATOR", kind: "operator", verification: { status: "passed" }, result: "private-operator-notes" },
    },
    claims: {
      C1: { id: "C1", holder: "claude-worker", requirementIds: ["R4"], acquiredAt: "2026-10-28T17:50:00.000Z", expiresAt: "2026-10-28T18:10:00.000Z", status: "ACTIVE" },
      C0: { id: "C0", holder: "old-worker", requirementIds: ["R1"], acquiredAt: "2026-10-28T17:00:00.000Z", expiresAt: OBSERVED_AT, status: "ACTIVE" },
      C9: { id: "C9", holder: "released-worker", requirementIds: ["R2"], acquiredAt: "2026-10-28T17:50:00.000Z", expiresAt: "2026-10-28T18:10:00.000Z", status: "RELEASED" },
    },
    amendments: {},
    handoff: { nextAction: "implement R1", nextCheck: "node --test scripts/control-plane.test.mjs", blocker: null },
  };
}

function createClaimMission() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-claim-"));
  const missionDir = path.join(repo, "mission");
  spawnSync("git", ["init", "-b", "main"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["config", "user.name", "Tugboat Test"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["config", "user.email", "tugboat@example.invalid"], { cwd: repo, encoding: "utf8" });
  fs.writeFileSync(path.join(repo, "spec.md"), "# Spec\n");
  spawnSync("git", ["add", "spec.md"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["commit", "-m", "baseline"], { cwd: repo, encoding: "utf8" });
  const baseline = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).stdout.trim();
  createMission({
    dir: missionDir,
    actor: { name: "Tugboat Test", kind: "human", runtime: "test" },
    metadata: { id: "claim-mission", title: "Claim Mission", owner: "Test", target: "local", repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline, source: { path: "spec.md", digest: `sha256:${"b".repeat(64)}` }, criticalPath: ["R1", "R2", "R3"], deployPath: "none" },
    requirements: [
      { id: "R1", requirement: "First work", source: "spec", material: true, acceptance: "First works", proofTarget: "local" },
      { id: "R2", requirement: "Second work", source: "spec", material: true, acceptance: "Second works", proofTarget: "local" },
      { id: "R3", requirement: "Later work", source: "spec", material: true, acceptance: "Later works", proofTarget: "local" },
    ],
    preservations: [],
    slices: [
      { id: "S1", name: "Current", requirementIds: ["R1", "R2"], dependencies: [], status: "ACTIVE", operatorJourney: "Current work" },
      { id: "S2", name: "Later", requirementIds: ["R3"], dependencies: ["S1"], status: "PENDING", operatorJourney: "Later work" },
    ],
  });
  return { repo, missionDir, baseline };
}

function missionBytes(dir) {
  return Object.fromEntries(fs.readdirSync(dir).sort().filter((name) => fs.statSync(path.join(dir, name)).isFile()).map((name) => [name, fs.readFileSync(path.join(dir, name))]));
}

function runCli(args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(ROOT, "scripts", "tugboat.mjs"), ...args], { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("execution packet separates ready, blocked, and claimed work with literal proof gaps", () => {
  const packet = compileExecutionPacket(fixtureState(), {
    observedAt: OBSERVED_AT,
    git: { head: "a".repeat(40), branch: "feat/control-plane", dirty: false },
  });

  assert.equal(packet.schemaVersion, "tugboat.execution-packet.v1");
  assert.deepEqual(packet.ready.map((item) => item.id), ["R1"]);
  assert.deepEqual(packet.blocked.map((item) => [item.id, item.reason]), [["R2", "requirement_status"]]);
  assert.deepEqual(packet.claimed.map((item) => [item.id, item.claim.id, item.claim.holder]), [["R4", "C1", "claude-worker"]]);
  assert.deepEqual(packet.ready[0].proofGaps, ["deterministic", "operator"]);
  assert.deepEqual(packet.claimed[0].proofGaps, ["operator", "deployment"]);
  assert.deepEqual(packet.preservations, [{ id: "P1", instruction: "Preserve replay", regressionProofTarget: "state suite", status: "PENDING" }]);
  assert.deepEqual(packet.next, { action: "implement R1", check: "node --test scripts/control-plane.test.mjs", blocker: null });
  assert.doesNotMatch(JSON.stringify(packet), /private-command-output|private-operator-notes/);
});

test("a claim expires at its exact boundary and no longer blocks readiness", () => {
  const state = fixtureState();
  assert.deepEqual(activeClaims(state, "2026-10-28T17:59:59.999Z").map((claim) => claim.id), ["C0", "C1"]);
  assert.deepEqual(activeClaims(state, OBSERVED_AT).map((claim) => claim.id), ["C1"]);
  assert.deepEqual(compileExecutionPacket(state, { observedAt: OBSERVED_AT, git: null }).ready.map((item) => item.id), ["R1"]);
});

test("a completed mission advertises no executable work and tells agents to stop", () => {
  const state = fixtureState();
  state.status = "COMPLETE";
  state.handoff = { nextAction: "stop; mission complete", nextCheck: "none", blocker: null };
  const packet = compileExecutionPacket(state, { observedAt: OBSERVED_AT, git: null });
  assert.deepEqual(packet.ready, []);
  assert.deepEqual(packet.blocked, []);
  assert.deepEqual(packet.claimed, []);
  assert.equal(packet.next.action, "stop; mission complete");
});

test("a dependency-blocked slice exposes only unmet prerequisite work and cannot claim downstream work", () => {
  const state = fixtureState();
  state.claims = {};
  state.requirements.R0 = { id: "R0", requirement: "Finish prerequisite", acceptance: "Prerequisite works", proofTarget: "local", status: "PENDING", evidenceRefs: [] };
  state.requirements.R2.status = "PROVEN(local)";
  state.requirements.R3.status = "PROVEN(local)";
  state.requirements.R4.status = "PROVEN(local)";
  state.slices.S0 = { id: "S0", name: "Foundation", requirementIds: ["R0"], dependencies: [], status: "PENDING", operatorJourney: "Finish the foundation" };
  state.slices.S1.dependencies = ["S0"];
  const packet = compileExecutionPacket(state, { observedAt: OBSERVED_AT, git: null });
  assert.deepEqual(packet.ready.map((item) => item.id), ["R0"]);
  assert.deepEqual(packet.blocked.map((item) => [item.id, item.reason, item.blockedBy]), [["R1", "slice_dependency", ["R0"]]]);

  const { missionDir } = createClaimMission();
  appendEvent(missionDir, { type: "SLICE_ACTIVATED", actor: { name: "Test", kind: "human" }, payload: { sliceId: "S2" } }, { reducer: missionReducer, expectedRevision: 1 });
  const before = missionBytes(missionDir);
  assert.throws(() => claimRequirements(missionDir, { id: "DOWNSTREAM", holder: "worker", requirementIds: ["R3"], ttlSeconds: 60, actor: { name: "Worker", kind: "agent" }, now: OBSERVED_AT }), /R3.*active slice.*depend/i);
  assert.deepEqual(missionBytes(missionDir), before);
});

test("packet digest is canonical, stable, and changes with execution state", () => {
  const first = compileExecutionPacket(fixtureState(), { observedAt: OBSERVED_AT, git: { head: "a".repeat(40), branch: "main", dirty: false } });
  const second = compileExecutionPacket(fixtureState(), { observedAt: OBSERVED_AT, git: { head: "a".repeat(40), branch: "main", dirty: false } });
  assert.deepEqual(first, second);
  const { packetDigest, ...body } = first;
  const expected = `sha256:${createHash("sha256").update(canonicalJson(body)).digest("hex")}`;
  assert.equal(packetDigest, expected);

  const changed = fixtureState();
  changed.handoff.nextAction = "different next action";
  assert.notEqual(compileExecutionPacket(changed, { observedAt: OBSERVED_AT, git: { head: "a".repeat(40), branch: "main", dirty: false } }).packetDigest, first.packetDigest);
});

test("next CLI returns the same structured execution contract from a real mission", () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-control-cli-"));
  const missionDir = path.join(repo, "mission");
  spawnSync("git", ["init", "-b", "main"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["config", "user.name", "Tugboat Test"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["config", "user.email", "tugboat@example.invalid"], { cwd: repo, encoding: "utf8" });
  fs.writeFileSync(path.join(repo, "spec.md"), "# Spec\n");
  spawnSync("git", ["add", "spec.md"], { cwd: repo, encoding: "utf8" });
  spawnSync("git", ["commit", "-m", "baseline"], { cwd: repo, encoding: "utf8" });
  const baseline = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).stdout.trim();
  createMission({
    dir: missionDir,
    actor: { name: "Tugboat Test", kind: "human", runtime: "test" },
    metadata: { id: "cli-mission", title: "CLI Mission", owner: "Test", target: "local", repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline, source: { path: "spec.md", digest: `sha256:${"b".repeat(64)}` }, criticalPath: ["R1"], deployPath: "none" },
    requirements: [{ id: "R1", requirement: "Compile packet", source: "spec", material: true, acceptance: "Packet compiles", proofTarget: "local" }],
    preservations: [],
    slices: [{ id: "S1", name: "Packet", requirementIds: ["R1"], dependencies: [], status: "ACTIVE", operatorJourney: "Compile packet" }],
  });

  const result = spawnSync(process.execPath, [path.join(ROOT, "scripts", "tugboat.mjs"), "next", "--dir", missionDir, "--observed-at", OBSERVED_AT, "--json"], { cwd: repo, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const packet = JSON.parse(result.stdout);
  assert.equal(packet.mission.id, "cli-mission");
  assert.deepEqual(packet.ready.map((item) => item.id), ["R1"]);
  assert.equal(packet.observation.git.head, baseline);
  assert.equal(packet.observation.git.dirty, false);
});

test("claim acquisition is replayable, rendered, and blocks overlapping work atomically", () => {
  const { missionDir } = createClaimMission();
  const acquired = claimRequirements(missionDir, {
    id: "C1", holder: "codex-a", requirementIds: ["R1"], ttlSeconds: 900,
    actor: { name: "Codex A", kind: "agent", runtime: "codex" }, now: OBSERVED_AT,
  });
  assert.equal(acquired.state.claims.C1.status, "ACTIVE");
  assert.equal(acquired.state.claims.C1.expiresAt, "2026-10-28T18:15:00.000Z");
  assert.match(fs.readFileSync(path.join(missionDir, "context-handoff.md"), "utf8"), /C1.*codex-a.*R1/);

  const before = missionBytes(missionDir);
  assert.throws(() => claimRequirements(missionDir, {
    id: "C2", holder: "claude-b", requirementIds: ["R1"], ttlSeconds: 900,
    actor: { name: "Claude B", kind: "agent", runtime: "claude" }, now: "2026-10-28T18:01:00.000Z",
  }), /R1.*claimed.*C1/i);
  assert.deepEqual(missionBytes(missionDir), before);
});

test("two real processes racing for one requirement produce exactly one durable winner", async () => {
  const { repo, missionDir } = createClaimMission();
  const common = ["--dir", missionDir, "--holder", "race-worker", "--requirements", "R1", "--ttl-seconds", "60", "--json"];
  const results = await Promise.all([
    runCli(["claim", "--id", "RACE-A", ...common], repo),
    runCli(["claim", "--id", "RACE-B", ...common], repo),
  ]);
  assert.equal(results.filter((item) => item.status === 0).length, 1, results.map((item) => item.stderr).join("\n"));
  assert.equal(results.filter((item) => item.status !== 0).length, 1, results.map((item) => item.stderr).join("\n"));
  assert.match(results.find((item) => item.status !== 0).stderr, /locked|claimed|expected revision/i);
  const state = readState(missionDir);
  assert.equal(state.revision, 2);
  assert.equal(Object.values(state.claims).filter((claim) => claim.status === "ACTIVE").length, 1);
  assert.equal(fs.readFileSync(path.join(missionDir, "events.jsonl"), "utf8").trim().split("\n").length, 2);
});

test("claim acquisition rejects invalid TTL, duplicates, closed work, out-of-slice work, and stale revisions without mutation", () => {
  const { missionDir } = createClaimMission();
  appendEvent(missionDir, {
    type: "REQUIREMENT_PROVEN", actor: { name: "Test", kind: "human" },
    payload: { requirementId: "R2", status: "PROVEN(local)", evidenceRefs: [], result: "done" },
  }, { reducer: missionReducer, expectedRevision: 1 });
  const cases = [
    [{ id: "SHORT", holder: "worker", requirementIds: ["R1"], ttlSeconds: 29, now: OBSERVED_AT }, /ttl.*30/i],
    [{ id: "LONG", holder: "worker", requirementIds: ["R1"], ttlSeconds: 14401, now: OBSERVED_AT }, /ttl.*14400/i],
    [{ id: "DUP", holder: "worker", requirementIds: ["R1", "R1"], ttlSeconds: 60, now: OBSERVED_AT }, /unique/i],
    [{ id: "CLOSED", holder: "worker", requirementIds: ["R2"], ttlSeconds: 60, now: OBSERVED_AT }, /R2.*open/i],
    [{ id: "LATER", holder: "worker", requirementIds: ["R3"], ttlSeconds: 60, now: OBSERVED_AT }, /R3.*active slice/i],
    [{ id: "STALE", holder: "worker", requirementIds: ["R1"], ttlSeconds: 60, now: OBSERVED_AT, expectedRevision: 1 }, /expected revision 1, actual 2/i],
    [{ id: "STALE-HEAD", holder: "worker", requirementIds: ["R1"], ttlSeconds: 60, now: OBSERVED_AT, expectedHead: "f".repeat(40) }, /expected git head f{40}, actual [0-9a-f]{40}/i],
  ];
  for (const [input, expected] of cases) {
    const before = missionBytes(missionDir);
    assert.throws(() => claimRequirements(missionDir, { ...input, actor: { name: "Worker", kind: "agent", runtime: "test" } }), expected);
    assert.deepEqual(missionBytes(missionDir), before);
  }
});

test("expired work can be reclaimed at the exact boundary while the prior lease stays auditable", () => {
  const { missionDir } = createClaimMission();
  claimRequirements(missionDir, { id: "C1", holder: "worker-a", requirementIds: ["R1"], ttlSeconds: 30, actor: { name: "A", kind: "agent" }, now: OBSERVED_AT });
  const reclaimed = claimRequirements(missionDir, { id: "C2", holder: "worker-b", requirementIds: ["R1"], ttlSeconds: 60, actor: { name: "B", kind: "agent" }, now: "2026-10-28T18:00:30.000Z" });
  assert.equal(reclaimed.state.claims.C1.status, "EXPIRED");
  assert.equal(reclaimed.state.claims.C2.status, "ACTIVE");
  assert.deepEqual(activeClaims(reclaimed.state, "2026-10-28T18:00:30.000Z").map((claim) => claim.id), ["C2"]);
});

test("only the active holder can release a claim and rejected release is byte-for-byte non-mutating", () => {
  const { missionDir } = createClaimMission();
  claimRequirements(missionDir, { id: "C1", holder: "worker-a", requirementIds: ["R1"], ttlSeconds: 60, actor: { name: "A", kind: "agent" }, now: OBSERVED_AT });
  const before = missionBytes(missionDir);
  assert.throws(() => releaseClaim(missionDir, { claimId: "C1", holder: "worker-b", actor: { name: "B", kind: "agent" }, now: "2026-10-28T18:00:10.000Z" }), /holder.*worker-a/i);
  assert.deepEqual(missionBytes(missionDir), before);

  const released = releaseClaim(missionDir, { claimId: "C1", holder: "worker-a", actor: { name: "A", kind: "agent" }, now: "2026-10-28T18:00:10.000Z" });
  assert.equal(released.state.claims.C1.status, "RELEASED");
  assert.equal(released.state.claims.C1.releasedAt, "2026-10-28T18:00:10.000Z");
});

test("claim and release CLI expose stable JSON and enforce holder ownership", () => {
  const { repo, missionDir } = createClaimMission();
  const before = missionBytes(missionDir);
  const forgedClock = spawnSync(process.execPath, [path.join(ROOT, "scripts", "tugboat.mjs"), "claim", "--dir", missionDir, "--id", "FORGED", "--holder", "codex-a", "--requirements", "R1", "--ttl-seconds", "60", "--now", OBSERVED_AT, "--json"], { cwd: repo, encoding: "utf8" });
  assert.equal(forgedClock.status, 2);
  assert.match(forgedClock.stderr, /--now.*not supported/i);
  assert.deepEqual(missionBytes(missionDir), before);

  const claim = spawnSync(process.execPath, [path.join(ROOT, "scripts", "tugboat.mjs"), "claim", "--dir", missionDir, "--id", "C1", "--holder", "codex-a", "--requirements", "R1", "--ttl-seconds", "60", "--json"], { cwd: repo, encoding: "utf8" });
  assert.equal(claim.status, 0, claim.stderr);
  const claimed = JSON.parse(claim.stdout);
  assert.deepEqual({ id: claimed.id, holder: claimed.holder, requirementIds: claimed.requirementIds, status: claimed.status }, { id: "C1", holder: "codex-a", requirementIds: ["R1"], status: "ACTIVE" });
  assert.equal(Date.parse(claimed.expiresAt) - Date.parse(claimed.acquiredAt), 60_000);

  const release = spawnSync(process.execPath, [path.join(ROOT, "scripts", "tugboat.mjs"), "release", "--dir", missionDir, "--claim", "C1", "--holder", "codex-a", "--json"], { cwd: repo, encoding: "utf8" });
  assert.equal(release.status, 0, release.stderr);
  assert.equal(JSON.parse(release.stdout).status, "RELEASED");
  assert.equal(readState(missionDir).claims.C1.status, "RELEASED");
});
