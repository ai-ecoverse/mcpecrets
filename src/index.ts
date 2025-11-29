import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { GitHubHandler } from "./github-handler";

// Context from the auth process, encrypted & stored in the auth token
// and provided to the DurableMCP as this.props
export type Props = {
	login: string;
	name: string;
	email: string;
	accessToken: string;
};

export class MCPSecrets extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "MCPSecrets",
		version: "1.0.0",
	});

	async init() {
		// Register the get-username tool
		this.server.tool(
			"get-username",
			"Get the authenticated GitHub username",
			{},
			async () => {
				if (!this.props?.login) {
					return {
						content: [
							{
								text: "Error: Not authenticated. Please authenticate with GitHub first.",
								type: "text",
							},
						],
						isError: true,
					};
				}

				return {
					content: [
						{
							text: this.props.login,
							type: "text",
						},
					],
				};
			}
		);
	}
}

export default new OAuthProvider({
	// MCP endpoints - supporting both SSE (legacy) and Streamable-HTTP (recommended)
	apiHandlers: {
		"/sse": MCPSecrets.serveSSE("/sse"), // Legacy SSE protocol
		"/mcp": MCPSecrets.serve("/mcp"), // Streamable-HTTP protocol (recommended)
	},
	// OAuth endpoints
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	tokenEndpoint: "/token",
	// Default handler for non-API requests (handles GitHub OAuth flow)
	defaultHandler: GitHubHandler as any,
});
