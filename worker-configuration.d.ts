// Type definitions for Cloudflare Worker environment

declare namespace Cloudflare {
	interface Env {
		// KV namespace for OAuth state storage
		OAUTH_KV: KVNamespace;

		// GitHub OAuth credentials
		GITHUB_CLIENT_ID: string;
		GITHUB_CLIENT_SECRET: string;

		// Secret key for cookie encryption
		COOKIE_ENCRYPTION_KEY: string;

		// Durable Object binding for MCP state
		MCP_OBJECT: DurableObjectNamespace<import("./src/index").MCPSecrets>;
	}
}

interface Env extends Cloudflare.Env {}
