/**
 * Callback endpoint for receiving encrypted secrets from GitHub Actions.
 *
 * Flow:
 *  1. `get_secret` tool generates a one-time token + ephemeral keypair,
 *     stores `{ privateKey, status: "pending" }` in KV at `callback:{token}` with 60s TTL,
 *     then triggers a GitHub Actions workflow.
 *  2. The workflow encrypts the secret and POSTs to `POST /api/callback/{token}`
 *     with body `{ encrypted: "<base64>" }`.
 *  3. This handler validates the token, stores the encrypted payload, and marks it ready.
 *  4. The `get_secret` tool polls KV for `status: "ready"`, then decrypts.
 */

interface CallbackKVEntry {
  privateKey: string;
  status: "pending" | "ready";
  encrypted?: string;
}

export async function handleSecretCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  // Only accept POST
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  // Extract token from URL: /api/callback/{token}
  const url = new URL(request.url);
  const parts = url.pathname.split("/");
  // Expected: ["", "api", "callback", "{token}"]
  const token = parts[3];

  if (!token) {
    return new Response("Missing token", { status: 400 });
  }

  // Look up the callback entry in KV
  const kvKey = `callback:${token}`;
  const stored = await env.OAUTH_KV.get(kvKey, "json") as CallbackKVEntry | null;

  if (!stored) {
    return new Response("Token not found or expired", { status: 404 });
  }

  // Prevent replay — if already consumed, reject
  if (stored.status === "ready") {
    return new Response("Token already consumed", { status: 409 });
  }

  // Parse the request body
  let body: { encrypted?: string };
  try {
    body = await request.json() as { encrypted?: string };
  } catch {
    return new Response("Invalid JSON body", { status: 400 });
  }

  if (!body.encrypted || typeof body.encrypted !== "string") {
    return new Response("Missing or invalid 'encrypted' field", { status: 400 });
  }

  // Update the KV entry: mark as ready and store the encrypted payload.
  // Keep the same TTL (60s from original creation) — use a fresh 60s TTL
  // since the get_secret tool is actively polling.
  const updated: CallbackKVEntry = {
    privateKey: stored.privateKey,
    status: "ready",
    encrypted: body.encrypted,
  };

  await env.OAUTH_KV.put(kvKey, JSON.stringify(updated), {
    expirationTtl: 60,
  });

  return new Response("OK", { status: 200 });
}
