import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "./lib/canonical.mjs";
import { withMissionLock } from "./lib/lock.mjs";
import { assertNoSecrets, redactSecrets, resolveActor, scanSecrets } from "./lib/security.mjs";
import { appendEvent, readState, replayEvents } from "./lib/store.mjs";

function tempMission() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-v2-store-"));
}

test("canonical JSON is stable across object key order", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, x: 3 } }), canonicalJson({ a: { x: 3, y: 2 }, z: 1 }));
});

test("actor resolution is portable and follows explicit, env, CI, Git, OS precedence", () => {
  assert.equal(resolveActor({ explicit: "Alex", env: { TUGBOAT_ACTOR: "Codex" }, gitName: "Git User", userName: "os" }).name, "Alex");
  assert.equal(resolveActor({ env: { TUGBOAT_ACTOR: "Codex" }, gitName: "Git User", userName: "os" }).name, "Codex");
  assert.deepEqual(resolveActor({ env: { GITHUB_ACTOR: "release-bot", GITHUB_ACTIONS: "true" }, gitName: "Git User", userName: "os" }), { name: "release-bot", kind: "ci", runtime: "github-actions" });
  assert.equal(resolveActor({ env: {}, gitName: "Git User", userName: "os" }).name, "Git User");
  assert.equal(resolveActor({ env: {}, gitName: "", userName: "os" }).name, "os");
});

test("secret scanner detects and redacts common credentials without changing ordinary prose", () => {
  const secretText = [
    ["AWS_ACCESS_KEY_ID=AK", "IAIOSFODNN7EXAMPLE"].join(""),
    ["token=gh", "p_123456789012345678901234567890123456"].join(""),
    ["Authorization: Bear", "er eyJhbG", "ciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz0123456789"].join(""),
    ["-----BEGIN PRIV", "ATE KEY-----"].join(""),
  ].join("\n");
  const kinds = scanSecrets(secretText).map((finding) => finding.kind);
  for (const kind of ["aws-access-key", "github-token", "jwt", "private-key"]) assert.ok(kinds.includes(kind), kinds);
  const redacted = redactSecrets(secretText);
  for (const marker of ["[REDACTED AWS ACCESS KEY]", "[REDACTED GITHUB TOKEN]", "[REDACTED JWT]", "[REDACTED PRIVATE KEY]"]) assert.ok(redacted.includes(marker), marker);
  assert.equal(redactSecrets("Founder API strategy and key question are documented."), "Founder API strategy and key question are documented.");
});

test("object secret scanning cannot lose a credential at an escaped newline boundary", () => {
  const fakeSecret = ["ghp", "123456789012345678901234567890123456"].join("_");
  assert.throws(() => assertNoSecrets({ source: `ordinary line\n${fakeSecret}` }), /github-token/);
});

test("event store replays a hash chain and rejects tampering", () => {
  const dir = tempMission();
  const reduce = (state, event) => ({ ...state, total: (state.total ?? 0) + event.payload.amount });
  appendEvent(dir, { type: "ADDED", actor: { name: "Alex", kind: "human" }, payload: { amount: 2 } }, { reducer: reduce, initialState: { schemaVersion: 2, total: 0 } });
  appendEvent(dir, { type: "ADDED", actor: { name: "Codex", kind: "agent" }, payload: { amount: 3 } }, { reducer: reduce, initialState: { schemaVersion: 2, total: 0 }, expectedRevision: 1 });
  assert.equal(readState(dir).total, 5);
  assert.equal(readState(dir).revision, 2);
  assert.equal(replayEvents(dir, { reducer: reduce, initialState: { schemaVersion: 2, total: 0 } }).state.total, 5);

  const log = path.join(dir, "events.jsonl");
  fs.writeFileSync(log, fs.readFileSync(log, "utf8").replace('"amount":2', '"amount":9'));
  assert.throws(() => replayEvents(dir, { reducer: reduce, initialState: { schemaVersion: 2, total: 0 } }), /hash mismatch/i);
});

test("event store rejects stale revisions and stale Git heads", () => {
  const dir = tempMission();
  appendEvent(dir, { type: "GENESIS", actor: { name: "Alex", kind: "human" }, payload: {} }, { currentHead: "abc", expectedHead: "abc" });
  assert.throws(() => appendEvent(dir, { type: "CHANGE", actor: { name: "Alex", kind: "human" }, payload: {} }, { expectedRevision: 0 }), /expected revision 0.*actual 1/i);
  assert.throws(() => appendEvent(dir, { type: "CHANGE", actor: { name: "Alex", kind: "human" }, payload: {} }, { expectedHead: "abc", currentHead: "def" }), /expected Git HEAD abc.*actual def/i);
});

test("filesystem lock rejects a competing writer and releases after failure", () => {
  const dir = tempMission();
  withMissionLock(dir, () => {
    assert.throws(() => withMissionLock(dir, () => undefined), /locked/i);
  });
  assert.throws(() => withMissionLock(dir, () => { throw new Error("boom"); }), /boom/);
  assert.equal(withMissionLock(dir, () => "released"), "released");
});

test("filesystem lock retries when a competing writer releases before inspection", () => {
  const dir = tempMission();
  const lock = path.join(dir, ".tugboat-lock");
  fs.mkdirSync(lock);
  fs.writeFileSync(path.join(lock, "owner.json"), JSON.stringify({ pid: process.pid, hostname: os.hostname() }));

  let raced = false;
  const fileSystem = Object.create(fs);
  fileSystem.statSync = (target) => {
    if (!raced && target === lock) {
      raced = true;
      fs.rmSync(lock, { recursive: true, force: true });
      const error = new Error(`ENOENT: no such file or directory, stat '${lock}'`);
      error.code = "ENOENT";
      throw error;
    }
    return fs.statSync(target);
  };

  assert.equal(withMissionLock(dir, () => "acquired after release", { fileSystem }), "acquired after release");
  assert.equal(raced, true);
  assert.equal(fs.existsSync(lock), false);
});

test("a reducer failure cannot append an event or change the snapshot", () => {
  const dir = tempMission();
  appendEvent(dir, { type: "GENESIS", actor: { name: "Alex", kind: "human" }, payload: {} });
  const beforeLog = fs.readFileSync(path.join(dir, "events.jsonl"), "utf8");
  const beforeState = fs.readFileSync(path.join(dir, "state.json"), "utf8");
  assert.throws(() => appendEvent(dir, { type: "INVALID", actor: { name: "Alex", kind: "human" }, payload: {} }, {
    expectedRevision: 1,
    reducer: (state, event) => {
      if (event.type === "INVALID") throw new Error("invalid transition");
      return state;
    },
  }), /invalid transition/);
  assert.equal(fs.readFileSync(path.join(dir, "events.jsonl"), "utf8"), beforeLog);
  assert.equal(fs.readFileSync(path.join(dir, "state.json"), "utf8"), beforeState);
});

test("an old lock owned by a live process is not reclaimed", () => {
  const dir = tempMission();
  const lock = path.join(dir, ".tugboat-lock");
  fs.mkdirSync(lock);
  fs.writeFileSync(path.join(lock, "owner.json"), JSON.stringify({ pid: process.pid, acquiredAt: new Date(0).toISOString() }));
  fs.utimesSync(lock, new Date(0), new Date(0));
  assert.throws(() => withMissionLock(dir, () => "unsafe", { staleMs: 1, now: Date.now() }), /live process|locked/i);
});

test("an old lock from another host is never reclaimed automatically", () => {
  const dir = tempMission();
  const lock = path.join(dir, ".tugboat-lock");
  fs.mkdirSync(lock);
  fs.writeFileSync(path.join(lock, "owner.json"), JSON.stringify({ pid: 999999, hostname: "different-host", acquiredAt: new Date(0).toISOString() }));
  fs.utimesSync(lock, new Date(0), new Date(0));
  assert.throws(() => withMissionLock(dir, () => "unsafe", { staleMs: 1, now: Date.now() }), /locked/i);
});
