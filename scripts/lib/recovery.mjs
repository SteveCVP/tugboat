import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { sha256 } from "./canonical.mjs";
import { missionReducer } from "./reducer.mjs";
import { renderMission } from "./render.mjs";
import { replayEvents, writeStateSnapshot } from "./store.mjs";

function safeTimestamp() {
  return new Date().toISOString().replaceAll(":", "-");
}

export function backupMission(missionDir, { destinationRoot = path.join(path.dirname(missionDir), "tugboat-backups") } = {}) {
  fs.mkdirSync(destinationRoot, { recursive: true });
  const destination = path.join(destinationRoot, `${path.basename(missionDir)}-${safeTimestamp()}-${randomUUID().slice(0, 8)}`);
  fs.cpSync(missionDir, destination, { recursive: true, filter: (source) => path.basename(source) !== ".tugboat-lock" });
  const events = fs.readFileSync(path.join(destination, "events.jsonl"));
  const state = fs.existsSync(path.join(destination, "state.json")) ? fs.readFileSync(path.join(destination, "state.json")) : Buffer.from("");
  const manifest = { schemaVersion: 1, source: missionDir, createdAt: new Date().toISOString(), eventsDigest: `sha256:${sha256(events)}`, stateDigest: `sha256:${sha256(state)}` };
  fs.writeFileSync(path.join(destination, "backup-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  return destination;
}

export function rebuildMission(missionDir) {
  const state = replayEvents(missionDir, { reducer: missionReducer }).state;
  writeStateSnapshot(missionDir, state);
  const evidenceDir = path.join(missionDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true });
  for (const evidence of Object.values(state.evidence ?? {})) fs.writeFileSync(path.join(evidenceDir, `${evidence.id}.json`), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  renderMission(missionDir, state);
  return state;
}
