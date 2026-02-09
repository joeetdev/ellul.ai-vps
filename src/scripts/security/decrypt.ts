/**
 * Decrypt script - decrypts secrets using the server's private key.
 * Used for zero-knowledge secrets management.
 *
 * Hybrid encryption: RSA-OAEP (SHA-256) wraps AES-256-GCM key.
 * Browser appends GCM auth tag (16 bytes) to ciphertext.
 * openssl enc doesn't support GCM auth tags, so we use Node.js crypto.
 */
export function getDecryptScript(): string {
  return `#!/bin/bash
set -e
ENCRYPTED_KEY_B64="$1"
IV_B64="$2"
ENCRYPTED_DATA_B64="$3"
PRIVATE_KEY="/etc/ellulai/node.key"

if [ ! -f "$PRIVATE_KEY" ]; then
  echo "Error: Private key not found" >&2
  exit 1
fi

# Step 1: RSA-OAEP decrypt the AES key using openssl
AES_KEY=$(echo "$ENCRYPTED_KEY_B64" | base64 -d | \\
  openssl pkeyutl -decrypt -inkey "$PRIVATE_KEY" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 2>/dev/null | base64)

if [ -z "$AES_KEY" ]; then
  echo "Error: Failed to decrypt AES key" >&2
  exit 1
fi

# Step 2: AES-256-GCM decrypt using Node.js (handles auth tag correctly)
node -e "
const crypto = require('crypto');
const key = Buffer.from(process.argv[1], 'base64');
const iv = Buffer.from(process.argv[2], 'base64');
const data = Buffer.from(process.argv[3], 'base64');
// Browser appends 16-byte auth tag to ciphertext
const authTag = data.slice(-16);
const ciphertext = data.slice(0, -16);
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(authTag);
const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
process.stdout.write(decrypted.toString('utf8'));
" "$AES_KEY" "$IV_B64" "$ENCRYPTED_DATA_B64"`;
}
