import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { compileEffectFootprint, extractBundleEffects } from "./lib/effect-footprint.mjs";
import { effectFixture, writeFixtureFile } from "./fixtures/certified-changesets/effect-fixture.mjs";
import { sha256 } from "./lib/canonical.mjs";

test("extracts canonical create, modify, delete, rename, and mode effects directly from verified patches", () => {
  const context = effectFixture();
  const result = extractBundleEffects(context.coreBundle);
  assert.deepEqual(result.uncertainty, []);
  assert.deepEqual(result.effects.map((item) => [item.operation, item.path, item.previousPath ?? null]), [
    ["create", "src/core/create.mjs", null],
    ["delete", "src/core/delete.mjs", null],
    ["mode_change", "src/core/mode.sh", null],
    ["modify", "src/core/modify.mjs", null],
    ["rename", "src/core/renamed.mjs", "src/core/old-name.mjs"],
  ]);
  for (const effect of result.effects) {
    assert.equal(effect.bundleId, "B-CORE");
    assert.deepEqual(effect.requirementIds, ["R1"]);
    assert.match(effect.id, /^effect:[0-9a-f]{64}$/);
    assert.match(effect.sourceDigest, /^sha256:[0-9a-f]{64}$/);
  }
});

test("maps effects to exact ownership and propagates declared read dependencies without widening unrelated components", () => {
  const context = effectFixture();
  const footprint = compileEffectFootprint({
    bundle: context.coreBundle,
    boundary: context.boundary,
    rootDir: context.repo,
    producer: { name: "Codex", kind: "agent", runtime: "codex" },
    generatedAt: "2026-10-29T17:00:00.000Z",
  });
  assert.equal(footprint.payload.verdict, "ready");
  assert.deepEqual([...new Set(footprint.payload.body.effects.map((item) => item.componentId))], ["component:core"]);
  assert.deepEqual(footprint.payload.body.directlyAffectedComponentIds, ["component:core"]);
  assert.deepEqual(footprint.payload.body.transitivelyAffectedComponentIds, ["component:api"]);
  assert.deepEqual(footprint.payload.body.provenUnaffectedComponentIds, ["component:docs"]);
  assert.deepEqual(footprint.payload.body.readWriteHazards, [{
    writerComponentId: "component:core",
    readerComponentId: "component:api",
    dependencyPath: ["component:api", "component:core"],
  }]);
});

test("fails closed with explicit uncertainty when a verified bundle contains an unsupported patch", () => {
  const context = effectFixture();
  const unsupported = {
    digest: `sha256:${"d".repeat(64)}`,
    payload: {
      id: "B-UNSUPPORTED",
      patches: [{ sourceSha: "a".repeat(40), requirementIds: ["R1"], digest: `sha256:${sha256("not a patch")}` }],
      components: [],
    },
    patches: [Buffer.from("not a patch")],
  };
  const footprint = compileEffectFootprint({
    bundle: unsupported,
    boundary: context.boundary,
    rootDir: context.repo,
    producer: { name: "Codex", kind: "agent", runtime: "codex" },
    generatedAt: "2026-10-29T17:00:00.000Z",
  });
  assert.equal(footprint.payload.verdict, "insufficient_evidence");
  assert.deepEqual(footprint.payload.body.uncertainty.map((item) => item.code), ["unsupported_patch"]);
});

test("effect footprint is deterministic and detects stale boundary source bytes", () => {
  const context = effectFixture();
  const input = {
    bundle: context.coreBundle, boundary: context.boundary, rootDir: context.repo,
    producer: { name: "Codex", kind: "agent", runtime: "codex" }, generatedAt: "2026-10-29T17:00:00.000Z",
  };
  assert.deepEqual(compileEffectFootprint(input), compileEffectFootprint(input));
  writeFixtureFile(context.repo, "docs/architecture.md", "# Architecture v2\n");
  assert.throws(() => compileEffectFootprint(input), /stale digest.*source:architecture/);
});
