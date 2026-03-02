import { Octokit } from "@octokit/rest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import { blake2b } from "blakejs";
import { generateWorkflowYaml } from "./workflow-template";

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/**
 * Encrypt a value using the sealed box construction expected by the
 * GitHub Actions Secrets API (libsodium crypto_box_seal).
 *
 * Format: ephemeral_pk (32) || crypto_box(msg, nonce, recipient_pk, eph_sk)
 * Nonce is derived using BLAKE2b(eph_pk || recipient_pk, outputLength=24).
 */
function sealedBoxForGitHub(
  message: Uint8Array,
  recipientPublicKey: Uint8Array,
): Uint8Array {
  const ephemeralKeyPair = nacl.box.keyPair();

  const nonceInput = new Uint8Array(
    ephemeralKeyPair.publicKey.length + recipientPublicKey.length,
  );
  nonceInput.set(ephemeralKeyPair.publicKey);
  nonceInput.set(recipientPublicKey, ephemeralKeyPair.publicKey.length);
  const nonce = blake2b(nonceInput, undefined, nacl.box.nonceLength);

  const encrypted = nacl.box(
    message,
    nonce,
    recipientPublicKey,
    ephemeralKeyPair.secretKey,
  );

  const result = new Uint8Array(
    ephemeralKeyPair.publicKey.length + encrypted.length,
  );
  result.set(ephemeralKeyPair.publicKey);
  result.set(encrypted, ephemeralKeyPair.publicKey.length);
  return result;
}

/**
 * Decrypt a sealed box produced by the workflow template.
 *
 * The workflow template uses the same nonce-derivation scheme:
 *   nonce = first 24 bytes of SHA-512(eph_pk || recipient_pk)
 *   ciphertext format: eph_pk (32) || nacl.box output
 */
function sealedBoxOpen(
  ciphertext: Uint8Array,
  recipientPublicKey: Uint8Array,
  recipientSecretKey: Uint8Array,
): Uint8Array | null {
  if (ciphertext.length < nacl.box.publicKeyLength) return null;

  const ephemeralPublicKey = ciphertext.slice(0, nacl.box.publicKeyLength);
  const encrypted = ciphertext.slice(nacl.box.publicKeyLength);

  const nonceInput = new Uint8Array(
    ephemeralPublicKey.length + recipientPublicKey.length,
  );
  nonceInput.set(ephemeralPublicKey);
  nonceInput.set(recipientPublicKey, ephemeralPublicKey.length);
  const nonce = nacl.hash(nonceInput).slice(0, nacl.box.nonceLength);

  return nacl.box.open(
    encrypted,
    nonce,
    ephemeralPublicKey,
    recipientSecretKey,
  );
}

// ---------------------------------------------------------------------------
// GitHub helpers
// ---------------------------------------------------------------------------

/**
 * Commit/update the workflow file in the vault repo.
 */
async function commitWorkflow(
  octokit: Octokit,
  owner: string,
  repo: string,
  secretNames: string[],
): Promise<void> {
  const path = ".github/workflows/retrieve-secret.yml";
  const content = generateWorkflowYaml(secretNames);
  const contentBase64 = btoa(content);

  let sha: string | undefined;
  try {
    const { data } = await octokit.repos.getContent({ owner, repo, path });
    if ("sha" in data) {
      sha = data.sha;
    }
  } catch {
    // File doesn't exist yet
  }

  await octokit.repos.createOrUpdateFileContents({
    owner,
    repo,
    path,
    message: "chore: update retrieve-secret workflow (mcpecrets)",
    content: contentBase64,
    ...(sha ? { sha } : {}),
  });
}

/**
 * Get all secret names in a repo (paginated).
 */
async function getAllSecretNames(
  octokit: Octokit,
  owner: string,
  repo: string,
): Promise<string[]> {
  const names: string[] = [];
  let page = 1;
  for (;;) {
    const { data } = await octokit.actions.listRepoSecrets({
      owner,
      repo,
      per_page: 100,
      page,
    });
    for (const secret of data.secrets) {
      names.push(secret.name);
    }
    if (names.length >= data.total_count) break;
    page++;
  }
  return names;
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export type ToolContext = {
  props: {
    gitHubToken: string;
    gitHubLogin: string;
  };
  env: {
    OAUTH_KV: KVNamespace;
  };
  server: McpServer;
  workerUrl: string;
};

/**
 * Register all MCP tools on the given server. Called from McpAgentDO.init().
 */
export function registerTools(ctx: ToolContext) {
  const { server } = ctx;

  // -------------------------------------------------------------------------
  // init_vault
  // -------------------------------------------------------------------------
  server.registerTool(
    "init_vault",
    {
      description:
        "Create a new private GitHub repository to act as a secrets vault. " +
        "Commits an initial workflow file for secret retrieval.",
      inputSchema: {
        repo_name: z
          .string()
          .describe(
            "Name for the new vault repository (created under your GitHub account)",
          ),
      },
    },
    async ({ repo_name }) => {
      const octokit = new Octokit({ auth: ctx.props.gitHubToken });

      const { data: repo } =
        await octokit.repos.createForAuthenticatedUser({
          name: repo_name,
          private: true,
          auto_init: true,
          description: "Secret vault managed by mcpecrets",
          has_issues: false,
          has_projects: false,
          has_wiki: false,
        });

      await commitWorkflow(octokit, repo.owner.login, repo.name, []);

      return {
        content: [
          {
            type: "text" as const,
            text: `Vault created: ${repo.full_name}\nWorkflow file committed.`,
          },
        ],
      };
    },
  );

  // -------------------------------------------------------------------------
  // set_secret
  // -------------------------------------------------------------------------
  server.registerTool(
    "set_secret",
    {
      description:
        "Create or update a secret in a vault repository. " +
        "The value is encrypted with the repo's public key before storage.",
      inputSchema: {
        repo: z.string().describe("Repository in owner/repo format"),
        name: z
          .string()
          .describe("Secret name (uppercase, underscores allowed)"),
        value: z.string().describe("Secret value to store"),
      },
    },
    async ({ repo, name, value }) => {
      const [owner, repoName] = repo.split("/");
      const octokit = new Octokit({ auth: ctx.props.gitHubToken });

      const { data: publicKey } = await octokit.actions.getRepoPublicKey({
        owner,
        repo: repoName,
      });

      const keyBytes = naclUtil.decodeBase64(publicKey.key);
      const messageBytes = naclUtil.decodeUTF8(value);
      const encrypted = sealedBoxForGitHub(messageBytes, keyBytes);
      const encryptedBase64 = naclUtil.encodeBase64(encrypted);

      await octokit.actions.createOrUpdateRepoSecret({
        owner,
        repo: repoName,
        secret_name: name,
        encrypted_value: encryptedBase64,
        key_id: publicKey.key_id,
      });

      const allSecrets = await getAllSecretNames(octokit, owner, repoName);
      if (!allSecrets.includes(name)) {
        allSecrets.push(name);
      }
      await commitWorkflow(octokit, owner, repoName, allSecrets);

      return {
        content: [
          {
            type: "text" as const,
            text: `Secret "${name}" set in ${repo}. Workflow updated.`,
          },
        ],
      };
    },
  );

  // -------------------------------------------------------------------------
  // list_secrets
  // -------------------------------------------------------------------------
  server.registerTool(
    "list_secrets",
    {
      description:
        "List the names of all secrets in a vault repository. " +
        "Values are never exposed — only names are returned.",
      inputSchema: {
        repo: z.string().describe("Repository in owner/repo format"),
      },
    },
    async ({ repo }) => {
      const [owner, repoName] = repo.split("/");
      const octokit = new Octokit({ auth: ctx.props.gitHubToken });

      const names = await getAllSecretNames(octokit, owner, repoName);

      return {
        content: [
          {
            type: "text" as const,
            text:
              names.length > 0
                ? `Secrets in ${repo}:\n${names.map((n) => `  - ${n}`).join("\n")}`
                : `No secrets found in ${repo}.`,
          },
        ],
      };
    },
  );

  // -------------------------------------------------------------------------
  // get_secret
  // -------------------------------------------------------------------------
  server.registerTool(
    "get_secret",
    {
      description:
        "Retrieve a secret value from a vault repository. " +
        "Triggers a GitHub Actions workflow that encrypts and returns the value via callback.",
      inputSchema: {
        repo: z.string().describe("Repository in owner/repo format"),
        name: z.string().describe("Secret name to retrieve"),
      },
    },
    async ({ repo, name }) => {
      const [owner, repoName] = repo.split("/");
      const octokit = new Octokit({ auth: ctx.props.gitHubToken });

      // Generate ephemeral X25519 keypair
      const ephemeralKeyPair = nacl.box.keyPair();
      const publicKeyB64 = naclUtil.encodeBase64(ephemeralKeyPair.publicKey);

      // Generate a one-time callback token
      const callbackToken = crypto.randomUUID();

      // Store the private key in KV with 60s TTL.
      // The callback endpoint (src/callback.ts) validates the token and
      // updates status to "ready" with the encrypted payload.
      const kvKey = `callback:${callbackToken}`;
      await ctx.env.OAUTH_KV.put(
        kvKey,
        JSON.stringify({
          privateKey: naclUtil.encodeBase64(ephemeralKeyPair.secretKey),
          publicKey: publicKeyB64,
          status: "pending",
        }),
        { expirationTtl: 60 },
      );

      // Callback URL matches the route in src/callback.ts: /api/callback/{token}
      const callbackUrl = `${ctx.workerUrl}/api/callback/${callbackToken}`;

      // Trigger the workflow
      await octokit.actions.createWorkflowDispatch({
        owner,
        repo: repoName,
        workflow_id: "retrieve-secret.yml",
        ref: "main",
        inputs: {
          secret_name: name,
          callback_url: callbackUrl,
          callback_token: callbackToken,
          public_key: publicKeyB64,
        },
      });

      // Poll KV for the encrypted response (max 45 seconds)
      let encryptedValue: string | null = null;
      for (let i = 0; i < 45; i++) {
        await new Promise((resolve) => setTimeout(resolve, 1000));

        const stored = await ctx.env.OAUTH_KV.get(kvKey);
        if (!stored) break; // expired

        const data = JSON.parse(stored) as {
          status: string;
          encrypted?: string;
        };
        if (data.status === "ready" && data.encrypted) {
          encryptedValue = data.encrypted;
          break;
        }
      }

      // Clean up
      await ctx.env.OAUTH_KV.delete(kvKey);

      if (!encryptedValue) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Timed out waiting for secret "${name}" from ${repo}. The workflow may still be running — try again.`,
            },
          ],
        };
      }

      // Decrypt with the ephemeral private key
      const ciphertext = naclUtil.decodeBase64(encryptedValue);
      const plaintext = sealedBoxOpen(
        ciphertext,
        ephemeralKeyPair.publicKey,
        ephemeralKeyPair.secretKey,
      );

      if (!plaintext) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Failed to decrypt secret "${name}". The encryption may be corrupted.`,
            },
          ],
        };
      }

      return {
        content: [
          {
            type: "text" as const,
            text: naclUtil.encodeUTF8(plaintext),
          },
        ],
      };
    },
  );

  // -------------------------------------------------------------------------
  // delete_secret
  // -------------------------------------------------------------------------
  server.registerTool(
    "delete_secret",
    {
      description: "Delete a secret from a vault repository.",
      inputSchema: {
        repo: z.string().describe("Repository in owner/repo format"),
        name: z.string().describe("Secret name to delete"),
      },
    },
    async ({ repo, name }) => {
      const [owner, repoName] = repo.split("/");
      const octokit = new Octokit({ auth: ctx.props.gitHubToken });

      await octokit.actions.deleteRepoSecret({
        owner,
        repo: repoName,
        secret_name: name,
      });

      const allSecrets = await getAllSecretNames(octokit, owner, repoName);
      await commitWorkflow(octokit, owner, repoName, allSecrets);

      return {
        content: [
          {
            type: "text" as const,
            text: `Secret "${name}" deleted from ${repo}. Workflow updated.`,
          },
        ],
      };
    },
  );
}
