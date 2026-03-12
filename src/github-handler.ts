import { Octokit } from "@octokit/rest";
import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

// GitHub OAuth endpoints
const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";

// Scopes we request from GitHub
const GITHUB_SCOPES = "repo workflow";

/**
 * Handles the /authorize route:
 *  1. Parse the incoming MCP OAuth request (from the OAuthProvider)
 *  2. Store the MCP OAuth request info in KV (keyed by a random state param)
 *  3. Redirect the user to GitHub for authorization
 */
export async function handleAuthorize(
  request: Request,
  env: Env & { OAUTH_PROVIDER: OAuthHelpers },
): Promise<Response> {
  // Parse the MCP OAuth authorization request
  const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  if (!oauthReqInfo.clientId) {
    return new Response("Invalid OAuth request: missing client_id", { status: 400 });
  }

  // Generate a random state parameter to tie the GitHub callback back to this MCP request
  const state = crypto.randomUUID();

  // Store the MCP OAuth request info in KV so we can retrieve it on callback
  await env.OAUTH_KV.put(
    `github_oauth_state:${state}`,
    JSON.stringify(oauthReqInfo),
    { expirationTtl: 600 }, // 10 minutes
  );

  // Build the GitHub authorization URL
  const githubAuthUrl = new URL(GITHUB_AUTHORIZE_URL);
  githubAuthUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubAuthUrl.searchParams.set("redirect_uri", new URL("/callback", request.url).toString());
  githubAuthUrl.searchParams.set("scope", GITHUB_SCOPES);
  githubAuthUrl.searchParams.set("state", state);

  return Response.redirect(githubAuthUrl.toString(), 302);
}

/**
 * Handles the /callback route:
 *  1. Validate the state parameter against KV
 *  2. Exchange the GitHub authorization code for an access token
 *  3. Fetch the authenticated GitHub user info
 *  4. Complete the MCP OAuth authorization flow (issues MCP access token with GitHub token in props)
 */
export async function handleCallback(
  request: Request,
  env: Env & { OAUTH_PROVIDER: OAuthHelpers },
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  // Retrieve and validate the stored MCP OAuth request info
  const storedData = await env.OAUTH_KV.get(`github_oauth_state:${state}`);
  if (!storedData) {
    return new Response("Invalid or expired state parameter", { status: 400 });
  }

  // Delete the state from KV immediately to prevent replay
  await env.OAUTH_KV.delete(`github_oauth_state:${state}`);

  const oauthReqInfo = JSON.parse(storedData);

  // Exchange the GitHub code for an access token
  const tokenResponse = await fetch(GITHUB_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: new URL("/callback", request.url).toString(),
    }),
  });

  if (!tokenResponse.ok) {
    return new Response("Failed to exchange code for token", { status: 502 });
  }

  const tokenData = (await tokenResponse.json()) as {
    access_token?: string;
    error?: string;
    error_description?: string;
  };

  if (tokenData.error || !tokenData.access_token) {
    return new Response(
      `GitHub OAuth error: ${tokenData.error_description || tokenData.error || "unknown"}`,
      { status: 400 },
    );
  }

  const gitHubToken = tokenData.access_token;

  // Fetch the authenticated GitHub user info
  const octokit = new Octokit({ auth: gitHubToken });
  const { data: ghUser } = await octokit.users.getAuthenticated();

  // Complete the MCP OAuth authorization — this issues the MCP access token
  // with the GitHub credentials embedded in props
  const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReqInfo,
    userId: String(ghUser.id),
    metadata: {
      gitHubLogin: ghUser.login,
    },
    scope: oauthReqInfo.scope,
    props: {
      gitHubToken,
      gitHubLogin: ghUser.login,
      gitHubUserId: ghUser.id,
    },
  });

  return Response.redirect(redirectTo, 302);
}
