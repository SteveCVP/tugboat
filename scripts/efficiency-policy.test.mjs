import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SKILL = path.dirname(HERE);
const efficiency = fs.readFileSync(path.join(SKILL, "references", "efficiency-and-context.md"), "utf8");
const runner = fs.readFileSync(path.join(SKILL, "scripts", "run-behavior-evals.mjs"), "utf8");

test("efficiency policy makes completion and proof the governing objective", () => {
  assert.match(efficiency, /approved outcome and required proof come first/i);
  assert.match(efficiency, /no explicit hard token/i);
  assert.match(efficiency, /do not invent/i);
  assert.match(efficiency, /reduce repetition/i);
  assert.match(efficiency, /do not\s+reduce approved scope/i);
  assert.match(efficiency, /Do not stop core/i);
  assert.match(efficiency, /consumes tokens/i);
});

test("model routing protects consequential work", () => {
  for (const term of ["Architecture", "difficult debugging", "security", "final review"]) {
    assert.match(efficiency, new RegExp(term, "i"));
  }
  assert.match(efficiency, /model quality.*adequate|adequate model quality/i);
  assert.doesNotMatch(runner, /\?\?\s*["']haiku["']/i);
  assert.doesNotMatch(runner, /["']--effort["'],\s*["']low["']/i);
});

test("cost alternatives preserve observable certainty", () => {
  assert.match(efficiency, /certainty-preserving/i);
  assert.match(efficiency, /same acceptance criteria/i);
  assert.match(efficiency, /deterministic\s+equivalence/i);
  assert.match(efficiency, /user approval/i);
  assert.match(efficiency, /cost.*time.*proof risk/i);
});
