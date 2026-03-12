/**
 * Generates a GitHub Actions workflow YAML that retrieves a secret,
 * encrypts it with an ephemeral X25519 public key (sealed box),
 * and POSTs the ciphertext to a callback URL on the Worker.
 *
 * The workflow must be regenerated whenever secrets are added/removed,
 * because GitHub Actions cannot dynamically reference secrets by name.
 */
export function generateWorkflowYaml(secretNames: string[]): string {
  // Build the env mapping: SECRET_<NAME>: ${{ secrets.<NAME> }}
  const envLines = secretNames
    .map((name) => `          SECRET_${name}: \${{ secrets.${name} }}`)
    .join("\n");

  return `name: Retrieve Secret
on:
  workflow_dispatch:
    inputs:
      secret_name:
        description: "Name of the secret to retrieve"
        required: true
        type: string
      callback_url:
        description: "Worker callback URL to POST the encrypted value to"
        required: true
        type: string
      callback_token:
        description: "One-time auth token for the callback"
        required: true
        type: string
      public_key:
        description: "Base64-encoded X25519 public key for encryption"
        required: true
        type: string

jobs:
  retrieve:
    runs-on: ubuntu-latest
    steps:
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Install dependencies
        run: npm install tweetnacl tweetnacl-util

      - name: Encrypt and send secret
        env:
${envLines}
        run: |
          node << 'SCRIPT'
          const nacl = require("tweetnacl");
          const { decodeBase64, encodeBase64 } = require("tweetnacl-util");

          const secretName = "\${{ inputs.secret_name }}";
          const callbackUrl = "\${{ inputs.callback_url }}";
          const callbackToken = "\${{ inputs.callback_token }}";
          const publicKeyB64 = "\${{ inputs.public_key }}";

          // Read the secret value from the env mapping
          const envKey = "SECRET_" + secretName;
          const secretValue = process.env[envKey];

          if (!secretValue) {
            console.error("Secret not found: " + secretName);
            console.error("Available secret mappings: " + Object.keys(process.env).filter(k => k.startsWith("SECRET_")).join(", "));
            process.exit(1);
          }

          // Encrypt using NaCl sealed box
          const publicKey = decodeBase64(publicKeyB64);
          const messageBytes = new TextEncoder().encode(secretValue);

          // sealed box = ephemeral X25519 keypair + crypto_box
          const ephemeral = nacl.box.keyPair();
          // Derive nonce = first 24 bytes of SHA-512(eph_pk || recipient_pk)
          const nonceInput = new Uint8Array(ephemeral.publicKey.length + publicKey.length);
          nonceInput.set(ephemeral.publicKey);
          nonceInput.set(publicKey, ephemeral.publicKey.length);
          const nonce = nacl.hash(nonceInput).slice(0, nacl.box.nonceLength);
          const encrypted = nacl.box(messageBytes, nonce, publicKey, ephemeral.secretKey);

          // Sealed box format: ephemeral public key (32) + ciphertext (nonce is derivable)
          const sealed = new Uint8Array(ephemeral.publicKey.length + encrypted.length);
          sealed.set(ephemeral.publicKey, 0);
          sealed.set(encrypted, ephemeral.publicKey.length);

          const payload = encodeBase64(sealed);

          // POST to the Worker callback
          fetch(callbackUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": "Bearer " + callbackToken,
            },
            body: JSON.stringify({ encrypted: payload }),
          })
            .then((res) => {
              if (!res.ok) {
                console.error("Callback failed with status: " + res.status);
                process.exit(1);
              }
              console.log("Secret delivered successfully");
            })
            .catch((err) => {
              console.error("Callback request failed: " + err.message);
              process.exit(1);
            });
          SCRIPT
`;
}
