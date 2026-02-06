import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import { SignJWT, exportJWK, importPKCS8, importSPKI } from "jose";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { generateCodeVerifier, sha256Base64Url } from "../utils/helpers.js";

export async function createApp() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: false }));
  // app.use(bodyParser.json());
  app.use(cookieParser());

  const clients = new Map();
  const authorizationCodes = new Map();
  const refreshTokens = new Map();

  // Demo client registration
  clients.set("demo-client", {
    client_id: "demo-client",
    redirectUris: ["http://localhost:4000/callback"],
  });

  // __dirname setup
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);

  // Load RSA keys
  const PRIVATE_KEY_PEM = fs.readFileSync(
    path.join(__dirname, "private.pem"),
    "utf8"
  );

  const PUBLIC_KEY_PEM = fs.readFileSync(
    path.join(__dirname, "public.pem"),
    "utf8"
  );

  // Issuer and key ID
  const ISSUER = "http://localhost:3000";
  const KEY_ID = "demo-key-1";

  // Key variables
  let PRIVATE_KEY, PUBLIC_KEY;

  // Initialize keys
  async function initKeys() {
    PRIVATE_KEY = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
    PUBLIC_KEY = await importSPKI(PUBLIC_KEY_PEM, "RS256");
  }

  // Demo user
  function getDemoUser() {
    return {
      sub: "alice",
      name: "Alice Example",
      email: "alice@example.com",
    };
  }
  // Authorization endpoint
  app.get("/authorize", (req, res) => {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
    } = req.query;

    // Validate client_id and redirect_uri
    const client = clients.get(client_id);
    if (!client) {
      return res.status(400).send("Invalid client_id");
    }
    if (!client.redirectUris.includes(redirect_uri)) {
      return res.status(400).send("Invalid redirect_uri");
    }
    if (response_type !== "code") {
      return res.status(400).send("Unsupported response_type");
    }
    if (!code_challenge || code_challenge_method !== "S256") {
      return res.status(400).send("PKCE code challenge required");
    }

    // Simulate user authentication (in real scenarios, show a login page)
    const user = getDemoUser();

    // Generate authorization code
    const code = generateCodeVerifier();
    // Store the authorization code with associated data
    authorizationCodes.set(code, {
      client_id: client_id,
      redirect_uri: redirect_uri,
      code_challenge: code_challenge,
      scope,
      user: user,
      expires_at: Date.now() + 5 * 60 * 1000, // 5 minutes
    });

    // Redirect back to client with authorization code
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.append("code", code);
    if (state) {
      redirectUrl.searchParams.append("state", state);
    }
    res.redirect(redirectUrl.toString());
  });

  // Token endpoint
  app.post("/token", async (req, res) => {
    const { grant_type } = req.body;

    // Handle authorization code grant
    if (grant_type === "authorization_code") {
      // Extract parameters
      const { code, redirect_uri, client_id, code_verifier } = req.body;

      // Validate authorization code
      const record = authorizationCodes.get(code);
      // Remove the code to prevent reuse
      authorizationCodes.delete(code);

      // Check if code exists and is valid
      if (!record) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Authorization code not found",
        });
      }
      if (record.expires_at < Date.now()) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Authorization code expired",
        });
      }
      if (
        record.client_id !== client_id ||
        record.redirect_uri !== redirect_uri
      ) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid client_id or redirect_uri",
        });
      }

      // Verify PKCE code challenge
      const expectedChallenge = sha256Base64Url(code_verifier);
      if (expectedChallenge !== record.code_challenge) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid PKCE code verifier",
        });
      }

      // Create access token
      const accessToken = await new SignJWT({
        scope: record.scope,
        name: record.user.name,
        email: record.user.email,
      })
        .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
        .setIssuer(ISSUER)
        .setAudience(client_id)
        .setSubject(record.user.sub)
        .setExpirationTime("15m")
        .setIssuedAt()
        .sign(PRIVATE_KEY);

      // Create refresh token
      const refreshToken = generateCodeVerifier();
      refreshTokens.set(refreshToken, {
        client_id: client_id,
        sub: record.user.sub,
        scope: record.scope,
        expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000, // 30 days
      });

      // Return tokens
      return res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 900,
        refresh_token: refreshToken,
        scope: record.scope,
      });
    }

    // Handle refresh token grant
    if (grant_type === "refresh_token") {
      // Extract parameters
      const { refresh_token, client_id } = req.body;

      // Validate refresh token
      const record = refreshTokens.get(refresh_token);

      // Remove old refresh token to prevent reuse
      refreshTokens.delete(refresh_token);
      // Issue a new refresh token
      const newRefreshToken = generateCodeVerifier();
      refreshTokens.set(newRefreshToken, {
        client_id: client_id,
        sub: record.sub,
        scope: record.scope,
        expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000, // 30 days
      });

      // Check if refresh token exists and is valid
      if (!record || record.client_id !== client_id) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid refresh token",
        });
      }

      const user = getDemoUser();
      // Create access token
      const accessToken = await new SignJWT({
        scope: record.scope,
        sub: record.sub,
        name: user.name,
        email: user.email,
      })
        .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
        .setIssuer(ISSUER)
        .setAudience(client_id)
        .setSubject(record.sub)
        .setExpirationTime("15m")
        .setIssuedAt()
        .sign(PRIVATE_KEY);

      // Return new access token
      return res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 900,
      });
    }

    // Unsupported grant type
    res.status(400).json({
      error: "unsupported_grant_type",
      error_description: "Unsupported grant_type",
    });
  });

  // JWKS endpoint
  // Serve the public keys in JWKS format
  app.get("/.well-known/jwks.json", async (req, res) => {
    // Export the public key as JWK
    const jwk = await exportJWK(PUBLIC_KEY);
    jwk.use = "sig";
    jwk.alg = "RS256";
    jwk.kid = KEY_ID;
    // Return the JWKS
    res.json({ keys: [jwk] });
  });

  // Initialize keys before returning the app
  await initKeys();
  return app;
}
