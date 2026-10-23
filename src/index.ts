import { OAuthProvider, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { handleAuthorize, handleCallback } from "./github-handler";
import { handleSecretCallback } from "./callback";
import { registerTools } from "./tools";

export type OAuthProps = {
  gitHubToken: string;
  gitHubLogin: string;
  gitHubUserId: number;
};

export class McpAgentDO extends McpAgent<Env, unknown, OAuthProps> {
  server = new McpServer({
    name: "mcpecrets",
    version: "0.1.0",
  });

  pendingCallbacks = new Map<
    string,
    { resolve: (encrypted: string) => void; reject: (err: Error) => void }
  >();

  async init() {
    const props = this.props!;
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
    return super.fetch(request);
  }
}

const defaultHandler: ExportedHandler<Env> = {
  async fetch(request, workerEnv) {
    const env = workerEnv as Env & { OAUTH_PROVIDER: OAuthHelpers };
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/callback/")) {
      return handleSecretCallback(request, env);
    }

    if (url.pathname === "/authorize") {
      return handleAuthorize(request, env);
    }
    if (url.pathname === "/callback") {
      return handleCallback(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

const apiHandler = McpAgentDO.serve("/mcp", { binding: "MCP_AGENT" });

const SCOPES = ["read", "write"];

function createProvider(workerUrl: string): OAuthProvider<Env> {
  const origin = new URL(workerUrl).origin;
  return new OAuthProvider<Env>({
    apiRoute: "/mcp",
    apiHandler,
    defaultHandler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/token",
    clientRegistrationEndpoint: "/register",
    scopesSupported: SCOPES,
    requiredScopes: SCOPES,
    resourceMetadata: {
      resource: `${origin}/mcp`,
      authorization_servers: [origin],
      bearer_methods_supported: ["header"],
      resource_name: "mcpecrets",
    },
    accessTokenTTL: 3600,
  });
}

const providers = new Map<string, OAuthProvider<Env>>();

function providerFor(workerUrl: string): OAuthProvider<Env> {
  let provider = providers.get(workerUrl);
  if (!provider) {
    provider = createProvider(workerUrl);
    providers.set(workerUrl, provider);
  }
  return provider;
}

export default {
  fetch(request, env, ctx) {
    return providerFor(env.WORKER_URL).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
