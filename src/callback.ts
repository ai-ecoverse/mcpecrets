/**
 * Callback endpoint for receiving encrypted secrets from GitHub Actions.
 *
 * Flow:
 *  1. `get_secret` tool generates a one-time token + ephemeral keypair,
 *     stores `{ doId }` in KV at `callback:{token}` with 60s TTL,
 *     then triggers a GitHub Actions workflow.
 *  2. The workflow encrypts the secret and POSTs to `POST /api/callback/{token}`
 *     with body `{ encrypted: "<base64>" }`.
 *  3. This handler reads the DO ID from KV, gets the DO stub, and forwards the
 *     encrypted payload to the DO via an internal fetch.
 *  4. The DO resolves the in-memory Promise, and `get_secret` returns the decrypted value.
 */

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

  // Look up the DO ID from KV
  const kvKey = `callback:${token}`;
  const doIdStr = await env.OAUTH_KV.get(kvKey);

  if (!doIdStr) {
    return new Response("Token not found or expired", { status: 404 });
  }

  // Parse the request body
  let body: { encrypted?: string };
  try {
    body = (await request.json()) as { encrypted?: string };
  } catch {
    return new Response("Invalid JSON body", { status: 400 });
  }

  if (!body.encrypted || typeof body.encrypted !== "string") {
    return new Response("Missing or invalid 'encrypted' field", { status: 400 });
  }

  // Get the DO stub and forward the callback
  const doId = env.MCP_AGENT.idFromString(doIdStr);
  const stub = env.MCP_AGENT.get(doId);
  const doResponse = await stub.fetch(
    new Request(`https://internal/internal/callback/${token}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ encrypted: body.encrypted }),
    }),
  );

  // Clean up the routing key
  await env.OAUTH_KV.delete(kvKey);

  return doResponse;
}
