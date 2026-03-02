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
    });
  }
}

// ---------------------------------------------------------------------------
// Default handler — serves the authorization UI and non-API routes
// ---------------------------------------------------------------------------
const defaultHandler = {
  async fetch(request: Request, env: Env & { OAUTH_PROVIDER: import("@cloudflare/workers-oauth-provider").OAuthHelpers }, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Secret callback from GitHub Actions
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
