import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { withMissionLock } from "./lock.mjs";
import { assertNoSecrets } from "./security.mjs";

const ZERO_HASH = "0".repeat(64);

function statePath(dir) {
  return path.join(dir, "state.json");
}

function eventPath(dir) {
  return path.join(dir, "events.jsonl");
}

function writeAtomic(file, contents) {
  const temp = `${file}.tmp-${process.pid}-${randomUUID()}`;
  const descriptor = fs.openSync(temp, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, contents);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temp, file);
}

export function readState(dir) {
  const file = statePath(dir);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function writeStateSnapshot(dir, state) {
  fs.mkdirSync(dir, { recursive: true });
  writeAtomic(statePath(dir), `${JSON.stringify(state, null, 2)}\n`);
}

export function eventHash(event) {
  const { hash: _ignored, ...unsigned } = event;
  return sha256(canonicalJson(unsigned));
}

export function replayEvents(dir, { reducer = (state) => state, initialState = { schemaVersion: 2 } } = {}) {
  const file = eventPath(dir);
  if (!fs.existsSync(file)) return { events: [], state: { ...initialState, revision: 0, lastEventHash: ZERO_HASH } };
  const raw = fs.readFileSync(file, "utf8");
  const lines = raw === "" ? [] : raw.split("\n").filter((line) => line.length > 0);
  let previousHash = ZERO_HASH;
  let state = { ...initialState, revision: 0, lastEventHash: ZERO_HASH };
  const events = [];
  for (let index = 0; index < lines.length; index += 1) {
    let event;
    try {
      event = JSON.parse(lines[index]);
    } catch (error) {
      throw new Error(`Event ${index + 1} is not valid JSON: ${error.message}`);
    }
    const expectedSequence = index + 1;
    if (event.sequence !== expectedSequence) throw new Error(`Event sequence mismatch: expected ${expectedSequence}, received ${event.sequence}`);
    if (event.previousHash !== previousHash) throw new Error(`Event ${event.sequence} previous hash mismatch`);
    if (event.hash !== eventHash(event)) throw new Error(`Event ${event.sequence} hash mismatch`);
    state = reducer(state, event);
    state = { ...state, schemaVersion: state.schemaVersion ?? 2, revision: event.sequence, lastEventHash: event.hash, updatedAt: event.timestamp };
    if (event.gitHead !== undefined) state.currentHead = event.gitHead;
    previousHash = event.hash;
    events.push(event);
  }
  return { events, state };
}

export function appendEvent(dir, input, {
  reducer = (state) => state,
  initialState = { schemaVersion: 2 },
  expectedRevision,
  expectedHead,
  currentHead,
  allowSecrets = false,
} = {}) {
  return withMissionLock(dir, () => {
    const replayed = replayEvents(dir, { reducer, initialState });
    if (expectedRevision !== undefined && expectedRevision !== replayed.state.revision) {
      throw new Error(`Expected revision ${expectedRevision}, actual ${replayed.state.revision}`);
    }
    if (expectedHead !== undefined && currentHead !== expectedHead) {
      throw new Error(`Expected Git HEAD ${expectedHead}, actual ${currentHead ?? "unknown"}`);
    }
    if (!allowSecrets) assertNoSecrets(input, "event");
    const unsigned = {
      id: input.id ?? randomUUID(),
      sequence: replayed.state.revision + 1,
      timestamp: input.timestamp ?? new Date().toISOString(),
      actor: input.actor,
      type: input.type,
      payload: input.payload ?? {},
      gitHead: currentHead,
      previousHash: replayed.state.lastEventHash ?? ZERO_HASH,
    };
    const event = { ...unsigned, hash: sha256(canonicalJson(unsigned)) };
    const reduced = reducer(replayed.state, event);
    const state = {
      ...reduced,
      schemaVersion: reduced.schemaVersion ?? 2,
      revision: event.sequence,
      lastEventHash: event.hash,
      updatedAt: event.timestamp,
      ...(currentHead !== undefined ? { currentHead } : {}),
    };
    fs.mkdirSync(dir, { recursive: true });
    const descriptor = fs.openSync(eventPath(dir), "a", 0o600);
    try {
      fs.writeSync(descriptor, `${canonicalJson(event)}\n`);
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    writeAtomic(statePath(dir), `${JSON.stringify(state, null, 2)}\n`);
    return { event, state };
  });
}

export function verifySnapshot(dir, options = {}) {
  const stored = readState(dir);
  const replayed = replayEvents(dir, options).state;
  if (!stored) throw new Error("Missing state.json snapshot");
  if (canonicalJson(stored) !== canonicalJson(replayed)) throw new Error("state.json does not match event replay");
  return replayed;
}
