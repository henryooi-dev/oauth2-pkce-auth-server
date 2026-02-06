import request from "supertest";
import { createApp as createAuthApp } from "../auth-server/createApp.js";
import { createApp as createResourceApp } from "../resource-server/createApp.js";
import {
  generateCodeVerifier,
  generateCodeChallengeS256,
} from "../utils/helpers.js";

let authApp, resourceApp, authServer;

beforeAll(async () => {
  authApp = await createAuthApp();
  resourceApp = createResourceApp();
  authServer = authApp.listen(3000);
});

afterAll(async () => {
  authServer.close();
});

describe("Authorize Flow", () => {
  test("Valid request", async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallengeS256(codeVerifier);

    const authRes = await request(authApp).get("/authorize").query({
      response_type: "code",
      client_id: "demo-client",
      redirect_uri: "http://localhost:4000/callback",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    expect(authRes.status).toBe(302);
    expect(authRes.headers.location).toBeDefined();
  });
});

describe("Token Flow", () => {
  test("Exchange code for token", async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallengeS256(codeVerifier);

    const authRes = await request(authApp).get("/authorize").query({
      response_type: "code",
      client_id: "demo-client",
      redirect_uri: "http://localhost:4000/callback",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });

    expect(authRes.status).toBe(302);
    expect(authRes.headers.location).toBeDefined();

    const code = new URL(authRes.headers.location).searchParams.get("code");

    const tokenRes = await request(authApp).post("/token").type("form").send({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://localhost:4000/callback",
      client_id: "demo-client",
      code_verifier: codeVerifier,
    });

    expect(tokenRes.status).toBe(200);
    expect(tokenRes.body.access_token).toBeDefined();
  });
});

describe("Error Scenarios", () => {
  test("Invalid client", async () => {
    const res = await request(authApp).get("/authorize").query({
      response_type: "code",
      client_id: "bad-client",
      redirect_uri: "http://localhost:4000/callback",
      code_challenge: "abc",
      code_challenge_method: "S256",
    });

    expect(res.status).toBe(400);
  });

  test("Invalid redirect_uri", async () => {
    const res = await request(authApp).get("/authorize").query({
      response_type: "code",
      client_id: "demo-client",
      redirect_uri: "http://malicious.com/callback",
      code_challenge: "abc",
      code_challenge_method: "S256",
    });
    expect(res.status).toBe(400);
  });

  test("Missing parameters", async () => {
    const res = await request(authApp).get("/authorize").query({
      response_type: "code",
      client_id: "demo-client",
      // Missing redirect_uri and code_challenge
    });
    expect(res.status).toBe(400);
  });

  test("Profile requires auth", async () => {
    const res = await request(resourceApp).get("/profile");
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Missing or invalid Authorization header");
  });
});

describe("OAuth PKCE Flow", () => {
  test("Full OAuth flow works", async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallengeS256(codeVerifier);

    const authRes = await request(authApp).get("/authorize").query({
      response_type: "code",
      client_id: "demo-client",
      redirect_uri: "http://localhost:4000/callback",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      scope: "api.read",
    });

    expect(authRes.status).toBe(302);
    expect(authRes.headers.location).toBeDefined();

    const code = new URL(authRes.headers.location).searchParams.get("code");

    const tokenRes = await request(authApp).post("/token").type("form").send({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://localhost:4000/callback",
      client_id: "demo-client",
      code_verifier: codeVerifier,
    });

    expect(tokenRes.status).toBe(200);
    expect(tokenRes.body.access_token).toBeDefined();

    const token = tokenRes.body.access_token;

    const profileRes = await request(resourceApp)
      .get("/profile")
      .set("Authorization", `Bearer ${token}`);

    expect(profileRes.status).toBe(200);
  });
});
