# MCPSecrets

A Cloudflare Worker implementing the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) with GitHub OAuth authentication and Dynamic Client Registration.

## Features

- **Remote MCP Server**: Implements the latest MCP specification with Streamable-HTTP transport
- **OAuth 2.1 with PKCE**: Full OAuth 2.1 support with dynamic client registration
- **GitHub Authentication**: Users authenticate with their GitHub account
- **Secure by Default**: CSRF protection, state validation, and secure cookie handling

## Available Tools

| Tool | Description |
|------|-------------|
| `get-username` | Returns the authenticated user's GitHub username |

## Setup

### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)
- A Cloudflare account
- A GitHub OAuth App

### 1. Create a GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the details:
   - **Application name**: MCPSecrets (or your preferred name)
   - **Homepage URL**: `https://mcpecrets.<your-subdomain>.workers.dev`
   - **Authorization callback URL**: `https://mcpecrets.<your-subdomain>.workers.dev/callback`
4. Save the Client ID and generate a Client Secret

### 2. Install Dependencies

```bash
npm install
```

### 3. Create KV Namespace

```bash
wrangler kv namespace create "OAUTH_KV"
```

Copy the ID from the output and update `wrangler.jsonc`:

```jsonc
"kv_namespaces": [
  {
    "binding": "OAUTH_KV",
    "id": "<your-kv-namespace-id>"
  }
]
```

### 4. Set Secrets

```bash
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET
wrangler secret put COOKIE_ENCRYPTION_KEY
```

Generate the cookie encryption key with:
```bash
openssl rand -hex 32
```

### 5. Deploy

```bash
npm run deploy
```

## Local Development

1. Copy `.dev.vars.example` to `.dev.vars` and fill in your GitHub OAuth credentials:

```bash
cp .dev.vars.example .dev.vars
```

2. For local development, update your GitHub OAuth App callback URL to:
   - `http://localhost:8788/callback`

3. Start the development server:

```bash
npm run dev
```

## Usage with MCP Clients

### Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "mcpecrets": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcpecrets.<your-subdomain>.workers.dev/mcp"
      ]
    }
  }
}
```

### Cursor

Use the MCP connection type with URL:
```
https://mcpecrets.<your-subdomain>.workers.dev/mcp
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/mcp` | Streamable-HTTP MCP endpoint |
| `/authorize` | OAuth authorization endpoint |
| `/token` | OAuth token endpoint |
| `/register` | OAuth dynamic client registration |
| `/callback` | GitHub OAuth callback |

## Architecture

This worker uses:
- [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider) - OAuth 2.1 provider implementation
- [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/sdk) - MCP SDK
- [`agents`](https://www.npmjs.com/package/agents) - Cloudflare Agents framework for durable MCP state
- [Hono](https://hono.dev/) - Lightweight web framework for routing

## License

Apache-2.0
