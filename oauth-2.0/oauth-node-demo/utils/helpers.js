import { randomBytes, createHash } from "crypto";

// Base64 URL encode
function base64URL(input) {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// SHA256 + base64URL encode
export function sha256Base64Url(str) {
  const hash = createHash("sha256").update(str, "ascii").digest();
  return base64URL(hash);
}

// PKCE helpers
export function generateCodeVerifier() {
  return base64URL(randomBytes(32));
}

// Generate code challenge from code verifier
export function generateCodeChallengeS256(codeVerifier) {
  return sha256Base64Url(codeVerifier);
}

// OAuth state generator
export function generateState() {
  return base64URL(randomBytes(16));
}
