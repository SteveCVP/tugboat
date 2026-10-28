#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { activeClaims, claimRequirements, compileExecutionPacket, releaseClaim } from "./lib/control-plane.mjs";
import { gitSnapshot } from "./lib/evidence.mjs";
import { isMainModule } from "./lib/entrypoint.mjs";
import { compileLanguageRecommendation, MAX_PROFILE_BYTES } from "./lib/language-optimizer.mjs";
import { activeRequirementIds, missionReducer } from "./lib/reducer.mjs";
import { resolveActor } from "./lib/security.mjs";
import { readState, replayEvents } from "./lib/store.mjs";

const MAX_FRAME_BYTES = 1024 * 1024;
const RESOURCE_URI = "tugboat://mission/current";
const CURRENT_PROTOCOL = "2026-07-28";
const LEGACY_PROTOCOL = "2025-11-25";
const SUPPORTED_PROTOCOLS = new Set(["2024-11-05", "2025-03-26", "2025-06-18", LEGACY_PROTOCOL, CURRENT_PROTOCOL]);
const PACKAGE = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8"));

class RpcError extends Error {
  constructor(code, message, data) {
    super(message);
    this.code = code;
    this.data = data;
  }
}

function parseStartup(argv) {
  let dir = null;
  let repo = null;
  let allowWrites = false;
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--allow-writes") allowWrites = true;
    else if (token === "--dir" && argv[index + 1] && !argv[index + 1].startsWith("--")) dir = path.resolve(argv[++index]);
    else if (token === "--repo" && argv[index + 1] && !argv[index + 1].startsWith("--")) repo = path.resolve(argv[++index]);
    else throw new Error(`Unknown or incomplete startup argument: ${token}`);
  }
  if (!dir) throw new Error("Missing --dir");
  return { dir, repo, allowWrites };
}

function loadState(dir) {
  const replayed = replayEvents(dir, { reducer: missionReducer }).state;
  const stored = readState(dir);
  if (!stored?.metadata) throw new Error(`No Tugboat v2 state in ${dir}`);
  if (stored.revision !== replayed.revision || stored.lastEventHash !== replayed.lastEventHash) {
    throw new Error("state.json does not match event replay");
  }
  return replayed;
}

function assertObject(value, label) {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}

function exactArguments(value, allowed, required = []) {
  const args = assertObject(value, "Tool arguments");
  const unknown = Object.keys(args).filter((key) => !allowed.includes(key));
  if (unknown.length) throw new Error(`Unknown argument(s): ${unknown.join(", ")}`);
  const missing = required.filter((key) => args[key] === undefined || args[key] === null || args[key] === "");
  if (missing.length) throw new Error(`Missing argument(s): ${missing.join(", ")}`);
  return args;
}

function stringArg(args, key) {
  if (typeof args[key] !== "string" || !args[key].trim()) throw new Error(`${key} must be a non-empty string`);
  return args[key];
}

function integerArg(args, key, fallback) {
  const value = args[key] ?? fallback;
  if (!Number.isInteger(value)) throw new Error(`${key} must be an integer`);
  return value;
}

function revisionArg(args) {
  const value = integerArg(args, "expectedRevision");
  if (value < 1) throw new Error("expectedRevision must be a positive integer");
  return value;
}

function headArg(args) {
  const value = stringArg(args, "expectedHead");
  if (!/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(value)) throw new Error("expectedHead must be a 40- or 64-character lowercase Git object ID");
  return value;
}

function publicClaim(claim) {
  return {
    id: claim.id,
    holder: claim.holder,
    requirementIds: [...claim.requirementIds],
    acquiredAt: claim.acquiredAt,
    expiresAt: claim.expiresAt,
    status: claim.status,
    ...(claim.releasedAt ? { releasedAt: claim.releasedAt } : {}),
  };
}

function serverInfo() {
  return { name: "tugboat", version: PACKAGE.version };
}

function capabilities() {
  return {
    tools: { listChanged: false },
    resources: { subscribe: false, listChanged: false },
  };
}

const READ_TOOLS = [
  {
    name: "tugboat_language_recommend",
    title: "Recommend implementation languages",
    description: "Compile an evidence-grounded one- or two-language architecture from the fixed mission and repository.",
    inputSchema: {
      type: "object",
      properties: {
        profile: {
          type: "object",
          description: "Optional bounded decision profile with team, constraint, priority, and requirement-signal evidence.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "tugboat_next",
    title: "Compile next safe work",
    description: "Compile the content-addressed execution packet for the fixed Tugboat mission.",
    inputSchema: {
      type: "object",
      properties: { observedAt: { type: "string", format: "date-time" } },
      additionalProperties: false,
    },
  },
  {
    name: "tugboat_status",
    title: "Read mission status",
    description: "Read the fixed mission's replay-verified status without evidence bodies.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

const WRITE_TOOLS = [
  {
    name: "tugboat_claim",
    title: "Claim active requirements",
    description: "Atomically lease open requirements in the active release slice.",
    inputSchema: {
      type: "object",
      required: ["id", "holder", "requirementIds", "expectedRevision", "expectedHead"],
      properties: {
        id: { type: "string", minLength: 1 },
        holder: { type: "string", minLength: 1 },
        requirementIds: { type: "array", minItems: 1, uniqueItems: true, items: { type: "string", minLength: 1 } },
        ttlSeconds: { type: "integer", minimum: 30, maximum: 14400, default: 900 },
        expectedRevision: { type: "integer", minimum: 1 },
        expectedHead: { type: "string", pattern: "^[0-9a-f]{40}([0-9a-f]{24})?$" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "tugboat_release",
    title: "Release a claim",
    description: "Release an active requirement lease as its exact holder.",
    inputSchema: {
      type: "object",
      required: ["claimId", "holder", "expectedRevision", "expectedHead"],
      properties: {
        claimId: { type: "string", minLength: 1 },
        holder: { type: "string", minLength: 1 },
        expectedRevision: { type: "integer", minimum: 1 },
        expectedHead: { type: "string", pattern: "^[0-9a-f]{40}([0-9a-f]{24})?$" },
      },
      additionalProperties: false,
    },
  },
];

function tools(allowWrites) {
  return [...READ_TOOLS, ...(allowWrites ? WRITE_TOOLS : [])].sort((left, right) => left.name.localeCompare(right.name));
}

function resources() {
  return [{
    uri: RESOURCE_URI,
    name: "Current Tugboat execution packet",
    description: "Replay-verified, content-addressed next-work packet for the fixed mission.",
    mimeType: "application/json",
  }];
}

function packet(dir, observedAt = new Date().toISOString()) {
  const state = loadState(dir);
  const snapshot = gitSnapshot(state.metadata.worktree, { excludePaths: [dir] });
  return compileExecutionPacket(state, {
    observedAt,
    git: { head: snapshot.sha, branch: state.metadata.branch, dirty: !snapshot.clean, patchDigest: snapshot.patchDigest },
  });
}

function status(dir) {
  const state = loadState(dir);
  const observedAt = new Date().toISOString();
  return {
    mission: state.metadata.id,
    missionStatus: state.status,
    revision: state.revision,
    activeSlice: state.activeSliceId,
    activeRequirements: state.status === "COMPLETE" ? [] : activeRequirementIds(state),
    activeClaims: activeClaims(state, observedAt),
    conflicts: Object.values(state.amendments ?? {})
      .filter((item) => !item.supersededBy && item.conflictsWith.length)
      .map((item) => ({ amendment: item.id, conflictsWith: item.conflictsWith })),
    nextAction: state.handoff.nextAction,
    observedAt,
  };
}

function languageRecommendation(dir, repo, profile = {}) {
  if (Buffer.byteLength(JSON.stringify(profile)) > MAX_PROFILE_BYTES) throw new Error("decision profile exceeds 64 KiB");
  return compileLanguageRecommendation(loadState(dir), { profile, repoDir: repo });
}

function toolSuccess(text, structuredContent) {
  return { content: [{ type: "text", text }], structuredContent };
}

function toolFailure(error) {
  return { content: [{ type: "text", text: error.message }], isError: true };
}

function callTool({ dir, repo, allowWrites, actor }, params) {
  const call = assertObject(params, "tools/call params");
  if (typeof call.name !== "string") throw new RpcError(-32602, "tools/call requires a tool name");
  try {
    if (call.name === "tugboat_language_recommend") {
      const args = exactArguments(call.arguments, ["profile"]);
      const profile = assertObject(args.profile, "profile");
      const result = languageRecommendation(dir, repo, profile);
      const primary = result.recommendation.primary?.label ?? "no justified choice";
      const secondary = result.recommendation.topology.secondary ? `; Secondary: ${result.recommendation.topology.secondary}` : "";
      return toolSuccess(`Architecture: ${result.recommendation.status}; Primary: ${primary}${secondary}; Decision: ${result.digest}`, result);
    }
    if (call.name === "tugboat_status") {
      exactArguments(call.arguments, []);
      const result = status(dir);
      return toolSuccess(`${result.mission}: ${result.missionStatus} revision=${result.revision}; active=${result.activeRequirements.join(",") || "none"}`, result);
    }
    if (call.name === "tugboat_next") {
      const args = exactArguments(call.arguments, ["observedAt"]);
      if (args.observedAt !== undefined) stringArg(args, "observedAt");
      const result = packet(dir, args.observedAt ?? new Date().toISOString());
      const text = `Ready: ${result.ready.map((item) => item.id).join(",") || "none"}; claimed: ${result.claimed.map((item) => item.id).join(",") || "none"}; blocked: ${result.blocked.map((item) => item.id).join(",") || "none"}. Next: ${result.next.action ?? "none"}`;
      return toolSuccess(text, result);
    }
    if (call.name === "tugboat_claim") {
      if (!allowWrites) throw new Error("Tugboat MCP is read-only; restart with --allow-writes to use coordination mutations");
      const args = exactArguments(call.arguments, ["id", "holder", "requirementIds", "ttlSeconds", "expectedRevision", "expectedHead"], ["id", "holder", "requirementIds", "expectedRevision", "expectedHead"]);
      stringArg(args, "id");
      stringArg(args, "holder");
      if (!Array.isArray(args.requirementIds) || !args.requirementIds.length || args.requirementIds.some((id) => typeof id !== "string" || !id)) throw new Error("requirementIds must be a non-empty string array");
      const result = claimRequirements(dir, {
        id: args.id,
        holder: args.holder,
        requirementIds: args.requirementIds,
        ttlSeconds: integerArg(args, "ttlSeconds", 900),
        expectedRevision: revisionArg(args),
        expectedHead: headArg(args),
        now: new Date().toISOString(),
        actor,
      });
      const claim = publicClaim(result.claim);
      return toolSuccess(`Claimed ${claim.requirementIds.join(",")} as ${claim.id} for ${claim.holder} until ${claim.expiresAt}`, claim);
    }
    if (call.name === "tugboat_release") {
      if (!allowWrites) throw new Error("Tugboat MCP is read-only; restart with --allow-writes to use coordination mutations");
      const args = exactArguments(call.arguments, ["claimId", "holder", "expectedRevision", "expectedHead"], ["claimId", "holder", "expectedRevision", "expectedHead"]);
      stringArg(args, "claimId");
      stringArg(args, "holder");
      const result = releaseClaim(dir, {
        claimId: args.claimId,
        holder: args.holder,
        expectedRevision: revisionArg(args),
        expectedHead: headArg(args),
        now: new Date().toISOString(),
        actor,
      });
      const claim = publicClaim(result.claim);
      return toolSuccess(`Released ${claim.id} for ${claim.holder}`, claim);
    }
    throw new Error(`Unknown tool: ${call.name}`);
  } catch (error) {
    return toolFailure(error);
  }
}

function dispatch(context, request) {
  if (!request || typeof request !== "object" || Array.isArray(request) || request.jsonrpc !== "2.0" || typeof request.method !== "string") {
    throw new RpcError(-32600, "Invalid JSON-RPC request");
  }
  const params = request.params === undefined ? {} : assertObject(request.params, "params");
  if (request.method === "initialize") {
    const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : LEGACY_PROTOCOL;
    const protocolVersion = SUPPORTED_PROTOCOLS.has(requested) ? requested : LEGACY_PROTOCOL;
    return { protocolVersion, capabilities: capabilities(), serverInfo: serverInfo(), instructions: "Use tugboat_next before acting. Claims coordinate work but never prove it." };
  }
  if (request.method === "server/discover") {
    return { protocolVersion: CURRENT_PROTOCOL, capabilities: capabilities(), serverInfo: serverInfo(), tools: tools(context.allowWrites), resources: resources() };
  }
  if (request.method === "ping") return {};
  if (request.method === "tools/list") return { tools: tools(context.allowWrites) };
  if (request.method === "tools/call") return callTool(context, params);
  if (request.method === "resources/list") return { resources: resources() };
  if (request.method === "resources/read") {
    if (params.uri !== RESOURCE_URI) throw new RpcError(-32602, `Unknown resource URI: ${params.uri ?? "missing"}`);
    const current = packet(context.dir);
    return { contents: [{ uri: RESOURCE_URI, mimeType: "application/json", text: `${JSON.stringify(current, null, 2)}\n` }] };
  }
  if (request.method.startsWith("notifications/")) return undefined;
  throw new RpcError(-32601, `Method not found: ${request.method}`);
}

function response(id, result) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function errorResponse(id, error) {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code: error.code ?? -32603, message: error.message ?? "Internal error", ...(error.data === undefined ? {} : { data: error.data }) },
  };
}

function serve(context) {
  const write = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
  const handleLine = (raw) => {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (!line) return;
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      write(errorResponse(null, new RpcError(-32700, "Parse error")));
      return;
    }
    const isNotification = request && typeof request === "object" && !Array.isArray(request) && request.id === undefined;
    try {
      const result = dispatch(context, request);
      if (!isNotification && result !== undefined) write(response(request.id, result));
    } catch (error) {
      if (!isNotification) write(errorResponse(request?.id, error));
    }
  };

  let buffer = "";
  let discarding = false;
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf("\n", offset);
      if (discarding) {
        if (newline < 0) return;
        write(errorResponse(null, new RpcError(-32001, "Request frame exceeds 1 MiB")));
        discarding = false;
        offset = newline + 1;
        continue;
      }
      if (newline < 0) {
        const remainder = chunk.slice(offset);
        if (Buffer.byteLength(buffer) + Buffer.byteLength(remainder) > MAX_FRAME_BYTES) {
          buffer = "";
          discarding = true;
        } else buffer += remainder;
        return;
      }
      const segment = chunk.slice(offset, newline);
      if (Buffer.byteLength(buffer) + Buffer.byteLength(segment) > MAX_FRAME_BYTES) {
        buffer = "";
        write(errorResponse(null, new RpcError(-32001, "Request frame exceeds 1 MiB")));
      } else {
        const line = buffer + segment;
        buffer = "";
        handleLine(line);
      }
      offset = newline + 1;
    }
  });
  process.stdin.on("end", () => {
    if (discarding) write(errorResponse(null, new RpcError(-32001, "Request frame exceeds 1 MiB")));
    else if (buffer) handleLine(buffer);
  });
}

if (isMainModule(import.meta.url)) {
  try {
    const startup = parseStartup(process.argv.slice(2));
    const state = loadState(startup.dir);
    serve({ ...startup, repo: startup.repo ?? state.metadata.worktree, actor: resolveActor() });
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(2);
  }
}

export { MAX_FRAME_BYTES, dispatch, parseStartup, serve, tools };
