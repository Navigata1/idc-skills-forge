#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn, spawnSync } from "node:child_process";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../../..");
const VERIFY = process.env.IDC_SEALED_VERIFY || join(REPO, "scripts/verify-sealed-artifacts.mjs");
const CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; connect-src 'none'; font-src 'none'; img-src data: blob:; media-src data: blob:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; worker-src 'none'";
const chromeCandidates = [
  process.env.IDC_CHROME_PATH,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
].filter(Boolean);
const chromePath = chromeCandidates.find((candidate) => existsSync(candidate));
if (!chromePath) {
  console.log("SKIP test-sealed-artifacts — no supported Chrome/Chromium executable");
  process.exit(0);
}

const root = mkdtempSync(join(tmpdir(), "idc-sealed-test-"));
const configPath = join(root, "config.json");
const outputPath = join(root, "evidence.json");
const state = { name: "mobile", width: 375, height: 812, media: "screen" };
const only = process.argv.find((argument) => argument.startsWith("--case="))?.slice(7);
const captureDir = process.argv.find((argument) => argument.startsWith("--capture-dir="))?.slice(14);
if (captureDir) mkdirSync(captureDir, { recursive: true });
let passed = 0;
let deliveries = 0;
const sink = createServer((_request, response) => { deliveries += 1; response.end("unexpected delivery"); });
await new Promise((accept) => sink.listen(0, "127.0.0.1", accept));
const sinkUrl = `http://127.0.0.1:${sink.address().port}/attempt`;

function html(body, title = "sealed-test") {
  return `<!doctype html><meta http-equiv="Content-Security-Policy" content="${CSP}"><title>${title}</title><body>${body}</body>`;
}

async function runArtifact(name, body) {
  const artifact = join(root, `${name}.html`);
  writeFileSync(artifact, html(body, name), "utf8");
  writeFileSync(configPath, `${JSON.stringify({
    schema: "idc-sealed-artifacts/v1",
    observationMs: 300,
    settleMs: 250,
    artifacts: [{ path: artifact, label: name, states: [state] }],
  })}\n`, "utf8");
  const child = spawn(
    process.execPath,
    [VERIFY, "--config", configPath, "--output", outputPath],
    { encoding: "utf8", env: { ...process.env, IDC_CHROME_PATH: chromePath } },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const status = await new Promise((accept, reject) => { child.once("error", reject); child.once("exit", accept); });
  const result = { status, stdout, stderr };
  const evidence = JSON.parse(readFileSync(outputPath, "utf8"));
  if (captureDir) writeFileSync(join(captureDir, `sealed-${name}.json`), JSON.stringify({
    command: [process.execPath, VERIFY, "--config", configPath, "--output", outputPath],
    verifierSHA256: createHash("sha256").update(readFileSync(VERIFY)).digest("hex"),
    fixture: readFileSync(artifact, "utf8"), config: JSON.parse(readFileSync(configPath, "utf8")),
    result, unexpectedExternalDeliveries: deliveries, evidence,
  }, null, 2) + "\n");
  assert.equal(deliveries, 0, "isolated loopback sink received an unexpected request");
  return { result, evidence, page: evidence.artifacts?.[0]?.states?.[0]?.page };
}

function ok(label) {
  passed += 1;
  console.log(`  ok    ${label}`);
}

try {
  writeFileSync(join(root, "unused.html"), html("<main>unused</main>", "unused"), "utf8");
  writeFileSync(configPath, `${JSON.stringify({
    schema: "idc-sealed-artifacts/v1",
    observationMs: 300,
    artifacts: [{ path: join(root, "unused.html"), label: "unused", states: [state] }],
  })}\n`, "utf8");
  if (!only || only === "preflight") {
    const preflight = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `delete globalThis.WebSocket; process.argv = [process.execPath, ${JSON.stringify(VERIFY)}, "--config", ${JSON.stringify(configPath)}, "--output", ${JSON.stringify(outputPath)}]; await import(${JSON.stringify(pathToFileURL(VERIFY).href)});`,
      ],
      { encoding: "utf8", env: { ...process.env, IDC_CHROME_PATH: chromePath } },
    );
    assert.equal(preflight.status, 1, preflight.stdout + preflight.stderr);
    assert.match(preflight.stderr, /WebSocket.*(?:Node 21|experimental-websocket)/i);
    ok("missing Node WebSocket fails in an actionable preflight");
  }

  if (!only || only === "clean") {
    const clean = await runArtifact("clean", "<main>sealed</main>");
    assert.equal(clean.result.status, 0, clean.result.stdout + clean.result.stderr);
    assert.equal(clean.page.rtcGuard.installed, true);
    assert.equal(clean.page.rtcGuard.attempts, 0);
    assert.equal(clean.evidence.enforced.webrtc.ipHandlingPolicy, "disable_non_proxied_udp");
    const bounded = clean.evidence.artifacts[0].states[0].observation;
    assert.equal(bounded.configuredObservationMs, 300);
    assert.equal(bounded.configuredSettleMs, 250);
    assert.ok(bounded.actualLoadLifetimeMs >= 550);
    assert.equal(bounded.targetTerminated, true);
    assert.equal(bounded.lifetimeContainmentProven, false);
    ok("clean page proves the RTC guard and launch policy are active");
  }

  if (!only || only === "rtc") {
    const rtc = await runArtifact(
      "rtc-attempt",
      `<main>rtc</main><script>try { const pc = new RTCPeerConnection({iceServers:[{urls:"stun:127.0.0.1:9"}]}); pc.createDataChannel("x"); } catch {}</script>`,
    );
    assert.equal(rtc.result.status, 1, rtc.result.stdout + rtc.result.stderr);
    assert.equal(rtc.page.rtcGuard.installed, true);
    assert.equal(rtc.page.rtcGuard.attempts, 1);
    assert.equal(rtc.evidence.artifacts[0].states[0].passed, false);
    ok("an RTCPeerConnection attempt is blocked and fails the state");
  }

  if (!only || only === "delayed") {
    const delayed = await runArtifact("delayed", `<main>delayed</main><script>
      setTimeout(() => { try { new RTCPeerConnection(); } catch {} fetch(${JSON.stringify(sinkUrl)}).catch(() => {}); }, 450);
    </script>`);
    assert.equal(delayed.result.status, 1, delayed.result.stdout + delayed.result.stderr);
    assert.ok(delayed.page.rtcGuard.attempts > 0);
    assert.equal(delayed.evidence.artifacts[0].states[0].initialPage.rtcGuard.attempts, 0);
    assert.ok(delayed.evidence.artifacts[0].states[0].rtcAttempts.length > 0);
    assert.equal(delayed.evidence.artifacts[0].states[0].observation.targetTerminated, true);
    ok("delayed attempt after initial observation fails during explicit settle interval");
  }

  if (!only || only === "subframe") {
    const subframe = await runArtifact("subframe", `<main>subframe</main><script>
      const child = document.createElement('iframe'); document.body.append(child);
      try { new child.contentWindow.RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.1:9'}]}); } catch {}
    </script>`);
    assert.equal(subframe.result.status, 1, subframe.result.stdout + subframe.result.stderr);
    assert.ok(subframe.evidence.artifacts[0].states[0].forbiddenFrames.length > 0);
    ok("about:blank child frame is rejected even when top-level RTC count is zero");
  }

  if (!only || only === "delayed-http") {
    const delayed = await runArtifact("delayed-http", `<main>delayed HTTP</main><script>
      setTimeout(() => { location.href = ${JSON.stringify(sinkUrl)}; }, 450);
    </script>`);
    assert.equal(delayed.result.status, 1, delayed.result.stdout + delayed.result.stderr);
    assert.ok(delayed.evidence.artifacts[0].states[0].attempts.some((attempt) => attempt.url === sinkUrl));
    ok("delayed HTTP navigation is intercepted and fails with zero loopback delivery");
  }

  if (!only || only === "overflow") {
    const overflow = await runArtifact(
      "overflow",
      `<style>html,body{overflow:hidden}.wide{width:5000px;height:1px}</style><main>overflow</main><div class="wide"></div>`,
    );
    assert.equal(overflow.result.status, 1, overflow.result.stdout + overflow.result.stderr);
    assert.ok(overflow.page.overflowingElements.length > 0);
    assert.equal(overflow.evidence.artifacts[0].states[0].passed, false);
    ok("overflowing elements fail even when root overflow is hidden");
  }

  console.log(`RESULT pass=${passed} fail=0 unexpectedExternalDeliveries=${deliveries} (loopback HTTP sink only; no ICE packet capture)`);
} finally {
  await new Promise((accept) => sink.close(accept));
  rmSync(root, { recursive: true, force: true });
}
