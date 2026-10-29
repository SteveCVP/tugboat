import { analyzeRaw } from "./analyzer-runtime.mjs";

let encoded = "";
for await (const chunk of process.stdin) encoded += chunk;
const request = JSON.parse(encoded);
if (request.protocolVersion !== "tugboat.adapter.v1" || !request.input) throw new Error("Unsupported adapter request");
process.stdout.write(JSON.stringify(analyzeRaw(request.input)));
