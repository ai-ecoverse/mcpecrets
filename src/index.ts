import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { handleAuthorize, handleCallback } from "./github-handler";
import { handleSecretCallback } from "./callback";
import { registerTools } from "./tools";

// Props stored in the OAuth token — available to the MCP agent on every request
export type OAuthProps = {
  gitHubToken: string;
  gitHubLogin: string;
  gitHubUserId: number;
};

// ---------------------------------------------------------------------------
// MCP Agent — Durable Object that handles MCP protocol sessions
// ---------------------------------------------------------------------------
export class McpAgentDO extends McpAgent<Env, OAuthProps> {
  server = new McpServer({
    name: "mcpecrets",
    version: "0.1.0",
  });

  // Map of callback token → { resolve, reject } for pending get_secret calls
  pendingCallbacks = new Map<
    string,
    { resolve: (encrypted: string) => void; reject: (err: Error) => void }
  >();

  async init() {
    const props = this.props as unknown as OAuthProps;
    registerTools({
      props: {
        gitHubToken: props.gitHubToken,
        gitHubLogin: props.gitHubLogin,
      },
      env: { OAUTH_KV: this.env.OAUTH_KV },
      server: this.server,
      workerUrl: this.env.WORKER_URL,
      pendingCallbacks: this.pendingCallbacks,
      doId: this.ctx.id.toString(),
    });
  }

  // Handle internal callback delivery from the defaultHandler
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (
      url.pathname.startsWith("/internal/callback/") &&
      request.method === "POST"
    ) {
      const token = url.pathname.split("/internal/callback/")[1];
      const body = (await request.json()) as { encrypted: string };
      const pending = this.pendingCallbacks.get(token);
      if (pending) {
        pending.resolve(body.encrypted);
        this.pendingCallbacks.delete(token);
        return new Response("OK", { status: 200 });
      }
      return new Response("No pending callback", { status: 404 });
    }
    // Let the parent McpAgent handle MCP protocol requests
    return super.fetch(request);
  }
}

// ---------------------------------------------------------------------------
// Default handler — serves the authorization UI and non-API routes
// ---------------------------------------------------------------------------
const defaultHandler = {
  async fetch(request: Request, env: Env & { OAUTH_PROVIDER: import("@cloudflare/workers-oauth-provider").OAuthHelpers }, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Secret callback from GitHub Actions — route through the Durable Object
    if (url.pathname.startsWith("/api/callback/")) {
      return handleSecretCallback(request, env);
    }

    // GitHub OAuth flow
    if (url.pathname === "/authorize") {
      return handleAuthorize(request, env);
    }
    if (url.pathname === "/callback") {
      return handleCallback(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

// ---------------------------------------------------------------------------
// Main export — OAuthProvider wraps everything
// ---------------------------------------------------------------------------
export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: McpAgentDO.serve("/mcp", { binding: "MCP_AGENT" }),

  defaultHandler: defaultHandler as ExportedHandler,

  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",

  scopesSupported: ["read", "write"],

  accessTokenTTL: 3600, // 1 hour
});
