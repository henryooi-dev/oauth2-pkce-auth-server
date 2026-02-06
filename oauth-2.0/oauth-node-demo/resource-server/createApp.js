import express from "express";
import { jwtVerify, createRemoteJWKSet } from "jose";

export function createApp() {
  // Create Express app
  const app = express();
  app.use(express.json());

  const ISSUER = "http://localhost:3000";
  const AUDIENCE = "demo-client";
  const JWKS_URL = new URL("http://localhost:3000/.well-known/jwks.json");

  const JWKS = createRemoteJWKSet(JWKS_URL);

  // Protected resource endpoint
  async function requireAuth(req, res, next) {
    // Extract Bearer token from Authorization header
    const auth = req.headers.authorization;
    // Check if the Authorization header is present and properly formatted
    if (!auth || !auth.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ error: "Missing or invalid Authorization header" });
    }

    // Extract the token from the header
    const token = auth.slice("Bearer ".length);

    // Verify the JWT
    try {
      // Verify the token using the JWKS, issuer, and audience
      const { payload } = await jwtVerify(token, JWKS, {
        issuer: ISSUER,
        audience: AUDIENCE,
      });
      // Attach the payload to the request object for downstream use
      req.user = payload;
      // Proceed to the next middleware or route handler
      next();
    } catch (err) {
      // If verification fails, respond with 401 Unauthorized
      return res
        .status(401)
        .json({ error: "Invalid token", message: err.message });
    }
  }

  // Middleware to require specific scope
  function requireScope(scope) {
    return (req, res, next) => {
      // Get scopes from the token payload
      const scopes = String(req.user?.scope || "")
        .split(" ")
        .filter(Boolean);

      // Check if the required scope is present
      if (!scopes.includes(scope)) {
        // If not, respond with 403 Forbidden
        return res
          .status(403)
          .json({ error: "Insufficient scope", required: scope });
      }
      // If the scope is present, proceed to the next middleware or route handler
      next();
    };
  }

  // Protected profile endpoint
  app.get("/profile", requireAuth, requireScope("api.read"), (req, res) => {
    // Respond with protected profile data
    res.json({
      message: "Protected profile data",
      user: {
        sub: req.user.sub,
        name: req.user.name,
        email: req.user.email,
        scope: req.user.scope,
      },
    });
  });

  return app;
}
