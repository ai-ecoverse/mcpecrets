import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import nacl from "tweetnacl";
import { unstable_startWorker } from "wrangler";

const SECRET_VALUE = "s3cr3t-value";
const GITHUB_TOKEN = "gho_integration";
const REDIRECT_URI = "http://localhost:3333/cb";

const dispatches = [];
let worker;
let base;
let persist;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function githubMock(request) {
  const url = new URL(request.url);
  if (url.host === "github.com" && url.pathname === "/login/oauth/access_token") {
    return json({ access_token: GITHUB_TOKEN, token_type: "bearer" });
  }
  if (url.host === "api.github.com" && url.pathname === "/user") {
    return json({ id: 4242, login: "octo" });
  }
  if (
    url.host === "api.github.com" &&
    url.pathname === "/repos/octo/vault/actions/workflows/retrieve-secret.yml/dispatches"
  ) {
    const body = await request.json();
    dispatches.push({ auth: request.headers.get("authorization"), body });
    queueMicrotask(() => deliveries.push(deliverSecret(body.inputs)));
    return new Response(null, { status: 204 });
  }
  return new Response("unexpected outbound " + request.url, { status: 599 });
}

function sealForWorkflow(message, recipientPublicKey) {
  const eph = nacl.box.keyPair();
  const nonceInput = new Uint8Array(64);
  nonceInput.set(eph.publicKey);
  nonceInput.set(recipientPublicKey, 32);
  const nonce = nacl.hash(nonceInput).slice(0, nacl.box.nonceLength);
  const boxed = nacl.box(message, nonce, recipientPublicKey, eph.secretKey);
  const out = new Uint8Array(32 + boxed.length);
  out.set(eph.publicKey);
  out.set(boxed, 32);
  return Buffer.from(out).toString("base64");
}

async function deliverSecret(inputs) {
  const publicKey = new Uint8Array(Buffer.from(inputs.public_key, "base64"));
  const encrypted = sealForWorkflow(new TextEncoder().encode(SECRET_VALUE), publicKey);
  const res = await fetch(`${base}/api/callback/${inputs.callback_token}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ encrypted }),
  });
  return res.status;
}

const deliveries = [];

async function readRpc(res) {
  const type = res.headers.get("content-type") ?? "";
  const text = await res.text();
  if (type.includes("text/event-stream")) {
    const data = text
      .split("\n")
      .filter((line) => line.startsWith("data: "))
      .map((line) => JSON.parse(line.slice(6)));
    return data.find((m) => "result" in m || "error" in m);
  }
  return JSON.parse(text);
}

async function authorize() {
  const reg = await fetch(`${base}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      redirect_uris: [REDIRECT_URI],
      client_name: "integration",
      token_endpoint_auth_method: "none",
    }),
  });
  assert.equal(reg.status, 201);
  const { client_id } = await reg.json();

  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const authUrl = new URL(`${base}/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", client_id);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", "read write");
  authUrl.searchParams.set("state", "client-state");
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  const auth = await fetch(authUrl, { redirect: "manual" });
  assert.equal(auth.status, 302);
  const github = new URL(auth.headers.get("location"));
  assert.equal(github.origin + github.pathname, "https://github.com/login/oauth/authorize");

  const cb = await fetch(
    `${base}/callback?code=gh-code&state=${github.searchParams.get("state")}`,
    { redirect: "manual" },
  );
  assert.equal(cb.status, 302);
  const back = new URL(cb.headers.get("location"));
  assert.equal(back.origin + back.pathname, REDIRECT_URI);
  assert.equal(back.searchParams.get("state"), "client-state");

  const tok = await fetch(`${base}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: back.searchParams.get("code"),
      redirect_uri: REDIRECT_URI,
      client_id,
      code_verifier: verifier,
    }),
  });
  assert.equal(tok.status, 200);
  const { access_token } = await tok.json();
  assert.ok(access_token);
  return access_token;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

before(async () => {
  const port = await freePort();
  persist = mkdtempSync(join(tmpdir(), "mcpecrets-it-"));
  worker = await unstable_startWorker({
    config: "wrangler.jsonc",
    bindings: {
      GITHUB_CLIENT_ID: { type: "plain_text", value: "test-client" },
      GITHUB_CLIENT_SECRET: { type: "plain_text", value: "test-secret" },
      WORKER_URL: { type: "plain_text", value: `http://127.0.0.1:${port}` },
    },
    dev: {
      server: { hostname: "127.0.0.1", port },
      inspector: false,
      persist,
      outboundService: githubMock,
      logLevel: "none",
    },
  });
  base = (await worker.url).origin;
});

after(async () => {
  await worker?.dispose();
  if (persist) rmSync(persist, { recursive: true, force: true });
});

test("serves OAuth authorization server metadata", async () => {
  const res = await fetch(`${base}/.well-known/oauth-authorization-server`);
  assert.equal(res.status, 200);
  const meta = await res.json();
  assert.equal(meta.registration_endpoint, `${base}/register`);
  assert.equal(meta.token_endpoint, `${base}/token`);
  assert.deepEqual(meta.protected_resources, [`${base}/mcp`]);
  assert.deepEqual(meta.scopes_supported, ["read", "write"]);
});

test("serves protected resource metadata for the /mcp endpoint", async () => {
  const res = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
  assert.equal(res.status, 200);
  const meta = await res.json();
  assert.equal(meta.resource, `${base}/mcp`);
  assert.deepEqual(meta.authorization_servers, [base]);
  assert.deepEqual(meta.scopes_supported, ["read", "write"]);
  assert.deepEqual(meta.bearer_methods_supported, ["header"]);
  assert.equal(meta.resource_name, "mcpecrets");
});

test("rejects authorization requests from unknown clients without crashing", async () => {
  const url = new URL(`${base}/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", "unknown-client");
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  const res = await fetch(url, { redirect: "manual" });
  assert.equal(res.status, 400);
  assert.match(await res.text(), /^Invalid OAuth request: /);
});

test("rejects unauthenticated MCP requests", async () => {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  assert.equal(res.status, 401);
  const challenge = res.headers.get("www-authenticate") ?? "";
  assert.match(challenge, /^Bearer /);
  assert.match(challenge, new RegExp(`resource_metadata="${base}/\\.well-known/oauth-protected-resource/mcp"`));
  assert.match(challenge, /scope="read write"/);
});

test("authenticated MCP session lists tools and round-trips get_secret through the Durable Object", async () => {
  const token = await authorize();
  const headers = {
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };

  const init = await fetch(`${base}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "integration", version: "0.0.0" },
      },
    }),
  });
  assert.equal(init.status, 200);
  const session = init.headers.get("mcp-session-id");
  assert.ok(session);
  const initMsg = await readRpc(init);
  assert.equal(initMsg.result.serverInfo.name, "mcpecrets");

  const sessionHeaders = {
    ...headers,
    "mcp-session-id": session,
    "mcp-protocol-version": initMsg.result.protocolVersion,
  };
  const notified = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: sessionHeaders,
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
  assert.equal(notified.status, 202);
  await notified.body?.cancel();

  const list = await readRpc(
    await fetch(`${base}/mcp`, {
      method: "POST",
      headers: sessionHeaders,
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    }),
  );
  assert.deepEqual(
    list.result.tools.map((t) => t.name).sort(),
    ["delete_secret", "get_secret", "init_vault", "list_secrets", "set_secret"],
  );

  const call = await readRpc(
    await fetch(`${base}/mcp`, {
      method: "POST",
      headers: sessionHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "get_secret", arguments: { repo: "octo/vault", name: "API_KEY" } },
      }),
    }),
  );
  assert.equal(dispatches.length, 1);
  assert.equal(dispatches[0].auth, `token ${GITHUB_TOKEN}`);
  assert.equal(dispatches[0].body.inputs.secret_name, "API_KEY");
  assert.deepEqual(await Promise.all(deliveries), [200]);
  assert.deepEqual(call.result.content, [{ type: "text", text: SECRET_VALUE }]);
});

test("secret callback with an unknown token is rejected", async () => {
  const res = await fetch(`${base}/api/callback/unknown`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ encrypted: "x" }),
  });
  assert.equal(res.status, 404);
});
