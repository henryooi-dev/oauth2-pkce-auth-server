import express from "express";
import cookieParser from "cookie-parser";
import {
  generateCodeVerifier,
  generateCodeChallengeS256,
  generateState,
} from "../utils/helpers.js";
import axios from "axios";

export async function createApp() {
  // Initialize Express app
  const app = express();
  app.use(cookieParser());

  // Configuration
  const AUTH_SERVER = "http://localhost:3000";
  const RESOURCE_SERVER = "http://localhost:5000";

  const CLIENT_ID = "demo-client";
  const REDIRECT_URI = "http://localhost:4000/callback";

  // Home route
  app.get("/", (req, res) => {
    res.send(`
    <h1>OAuth 2.0 PKCE Demo Client</h1>
    <p>Click the link below to log in via the Authorization Server.</p>
    <a href="/login">Log in with Authorization Server</a>
  `);
  });

  // Login route - initiates the OAuth 2.0 Authorization Code Flow with PKCE
  app.get("/login", (req, res) => {
    // Generate code verifier, code challenge, and state
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallengeS256(codeVerifier);

    const state = generateState();

    // Clear any existing cookies
    res.clearCookie("oauth_state");
    res.clearCookie("code_verifier");

    // Store code verifier and state in HTTP-only cookies
    res.cookie("code_verifier", codeVerifier, { httpOnly: true });
    res.cookie("oauth_state", state, { httpOnly: true });

    // Construct the authorization URL
    const authURL = new URL(`${AUTH_SERVER}/authorize`);
    authURL.searchParams.append("response_type", "code");
    authURL.searchParams.append("client_id", CLIENT_ID);
    authURL.searchParams.append("redirect_uri", REDIRECT_URI);
    authURL.searchParams.append("code_challenge_method", "S256");
    authURL.searchParams.append("code_challenge", codeChallenge);
    authURL.searchParams.append("scope", "api.read openid profile email");
    authURL.searchParams.append("state", state);

    res.redirect(authURL.toString());
  });

  // Callback route - handles the redirect from the Authorization Server
  app.get("/callback", async (req, res) => {
    // Extract authorization code and state from query parameters
    const { code, state } = req.query;
    const storedState = req.cookies["oauth_state"];
    const codeVerifier = req.cookies["code_verifier"];

    // Validate state parameter
    if (!code) return res.status(400).send("Authorization code not found.");
    if (!state || state !== storedState)
      return res.status(400).send("Invalid state parameter.");

    try {
      // Exchange authorization code for tokens
      const tokenRes = await axios.post(
        `${AUTH_SERVER}/token`,
        new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          code_verifier: codeVerifier,
        }).toString(),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );

      // Extract tokens from response
      const { access_token, refresh_token, expires_in } = tokenRes.data;

      // Store tokens in HTTP-only cookies
      res.cookie("access_token", access_token, { httpOnly: true });
      res.cookie("refresh_token", refresh_token, { httpOnly: true });

      res.clearCookie("oauth_state");
      res.clearCookie("code_verifier");

      //   res.redirect("/profile");
      // Display success message with tokens
      res.send(`
      <h1>Authorization Successful</h1>
      <p>Access Token: ${access_token}</p>
      <p>Refresh Token: ${refresh_token}</p>
      <p>Expires In: ${expires_in} seconds</p>
      <a href="/profile">View Profile Information</a>
      <br/>
      <a href="/refresh">Refresh Access Token</a>
    `);
    } catch (error) {
      console.error(error.response?.status);
      console.error(error.response?.data);
    }
  });

  // Profile route - fetches user profile information from the Resource Server
  app.get("/profile", async (req, res) => {
    // Extract access token from cookies
    const accessToken = req.cookies.access_token;
    // Check if access token is present
    if (!accessToken)
      return res.status(401).send("Access token not found. Please log in.");

    // Fetch profile information from Resource Server
    try {
      // Make API request to Resource Server
      const apiRes = await axios.get(`${RESOURCE_SERVER}/profile`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      // Display profile information
      res.send(`
            <h1>User Profile</h1>
            <pre>${JSON.stringify(apiRes.data, null, 2)}</pre>
            <a href="/">Home</a>
        `);
    } catch (error) {
      // Handle errors (e.g., invalid or expired token)
      res.status(500).send("Failed to fetch profile information.");
    }
  });

  // Refresh route - uses the refresh token to obtain a new access token
  app.get("/refresh", async (req, res) => {
    // Extract refresh token from cookies
    const refreshToken = req.cookies.refresh_token;
    // Check if refresh token is present
    if (!refreshToken) {
      // If not present, redirect to home
      return res.redirect("/");
    }

    // Request a new access token using the refresh token
    const tokenRes = await axios.post(
      `${AUTH_SERVER}/token`,
      new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    // Store the new access token in an HTTP-only cookie
    res.cookie("access_token", tokenRes.data.access_token, { httpOnly: true });

    // Display success message with new access token
    res.send(`
        <h1>Access Token Refreshed</h1>
        <p>New Access Token: ${tokenRes.data.access_token}</p>
        <a href="/profile">View Profile Information again</a>
    `);
  });

  return app;
}
