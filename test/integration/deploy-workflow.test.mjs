import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const workflow = readFileSync(new URL("../../.github/workflows/deploy.yml", import.meta.url), "utf8");

function parseSteps(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l === "    steps:");
  assert.ok(start >= 0, "deploy.yml has no steps");
  const chunks = [];
  for (const line of lines.slice(start + 1)) {
    if (line.startsWith("      - ")) chunks.push(["        " + line.slice(8)]);
    else if (chunks.length && (line.startsWith("        ") || line.trim() === "")) chunks.at(-1).push(line);
    else if (line.trim() !== "") break;
  }
  return chunks.map((chunk) => {
    const step = {};
    const body = chunk.map((l) => l.slice(8));
    for (let i = 0; i < body.length; i++) {
      const m = /^([\w-]+):\s*(.*)$/.exec(body[i]);
      if (!m) continue;
      const [, key, value] = m;
      if (value === "|") {
        const block = [];
        while (i + 1 < body.length && (body[i + 1].startsWith("  ") || body[i + 1].trim() === "")) block.push(body[++i].slice(2));
        step[key] = block.join("\n").trim() + "\n";
      } else if (value === "") {
        const map = {};
        while (i + 1 < body.length && body[i + 1].startsWith("  ")) {
          const kv = /^\s+([\w-]+):\s*(.*)$/.exec(body[++i]);
          map[kv[1]] = kv[2];
        }
        step[key] = map;
      } else {
        step[key] = value.replace(/^'(.*)'$/, "$1");
      }
    }
    return step;
  });
}

const steps = parseSteps(workflow);
let work;
let origin;
let author;
let bin;
let deployLog;
let runCount = 0;

function git(cwd, ...args) {
  return execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd, encoding: "utf8" }).trim();
}

function push(message, branch = "main") {
  git(author, "checkout", "-q", "-B", branch);
  git(author, "commit", "-q", "--allow-empty", "-m", message);
  git(author, "push", "-q", "-f", "origin", `HEAD:refs/heads/${branch}`);
  return git(author, "rev-parse", "HEAD");
}

function condition(expr, outputs) {
  if (expr === undefined) return true;
  const m = /^steps\.([\w-]+)\.outputs\.([\w-]+) == '(.*)'$/.exec(expr);
  assert.ok(m, `unsupported if: ${expr}`);
  return outputs[m[1]]?.[m[2]] === m[3];
}

function runWorkflow(sha) {
  const ws = join(work, `run-${++runCount}`);
  const outputs = {};
  for (const step of steps) {
    if (!condition(step.if, outputs)) continue;
    if (step.uses?.startsWith("actions/checkout@")) {
      git(work, "clone", "-q", origin, ws);
      const ref = step.with?.ref;
      git(ws, "checkout", "-q", "--detach", ref ? `origin/${ref}` : sha);
      continue;
    }
    if (!step.run) continue;
    const out = join(work, `out-${runCount}`);
    writeFileSync(out, "");
    execFileSync("bash", ["-euo", "pipefail", "-c", step.run], {
      cwd: ws,
      stdio: "pipe",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, GITHUB_SHA: sha, GITHUB_OUTPUT: out, DEPLOY_LOG: deployLog },
    });
    if (step.id) {
      outputs[step.id] = Object.fromEntries(
        readFileSync(out, "utf8").split("\n").filter(Boolean).map((l) => l.split(/=(.*)/s).slice(0, 2)),
      );
    }
  }
}

function deployed() {
  return existsSync(deployLog) ? readFileSync(deployLog, "utf8").split("\n").filter(Boolean) : [];
}

before(() => {
  work = mkdtempSync(join(tmpdir(), "mcpecrets-deploy-"));
  origin = join(work, "origin.git");
  author = join(work, "author");
  bin = join(work, "bin");
  deployLog = join(work, "deploys");
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", origin]);
  git(work, "clone", "-q", origin, author);
  mkdirSync(bin);
  writeFileSync(join(bin, "npm"), "#!/usr/bin/env bash\nexit 0\n");
  writeFileSync(
    join(bin, "npx"),
    '#!/usr/bin/env bash\nif [ "$1 $2" = "wrangler deploy" ]; then git rev-parse HEAD >> "$DEPLOY_LOG"; fi\n',
  );
  chmodSync(join(bin, "npm"), 0o755);
  chmodSync(join(bin, "npx"), 0o755);
  push("initial");
});

after(() => {
  if (work) rmSync(work, { recursive: true, force: true });
});

test("deploy runs are serialized without cancelling queued runs", () => {
  assert.match(workflow, /concurrency:\n\s+group: deploy-worker\n\s+cancel-in-progress: false/);
  assert.ok(steps.some((s) => s.run?.includes("npx wrangler deploy")));
});

test("a merge followed by a badge commit deploys the badge commit", () => {
  rmSync(deployLog, { force: true });
  const merge = push("Merge pull request");
  const badge = push("Update vibe-coded badge [skip vibe-badge]");
  runWorkflow(merge);
  assert.deepEqual(deployed(), [badge]);
});

test("a run that executes after a newer merge never deploys the older commit", () => {
  rmSync(deployLog, { force: true });
  const first = push("first merge");
  const second = push("second merge");
  runWorkflow(first);
  runWorkflow(second);
  const log = deployed();
  assert.ok(!log.includes(first));
  assert.equal(log.at(-1), second);
});

test("a workflow_dispatch from another branch deploys the tip of main", () => {
  rmSync(deployLog, { force: true });
  const tip = push("main tip");
  const feature = push("feature work", "feature");
  git(author, "checkout", "-q", "main");
  git(author, "reset", "-q", "--hard", tip);
  runWorkflow(feature);
  assert.deepEqual(deployed(), [tip]);
});
