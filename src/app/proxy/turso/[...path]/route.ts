// Server-side proxy for the built-in "mf-db" Turso connection.
//
// The browser talks to /proxy/turso/v3/pipeline with a placeholder token; this route checks the
// caller's Cloudflare Access login, then forwards the request to Turso with the real token, which
// only exists as a Worker secret. Configuration (Worker env):
//   TURSO_DATABASE_URL     libsql://… or https://… of the database          (wrangler.jsonc vars)
//   TURSO_AUTH_TOKEN       Turso database token                             (Worker secret)
//   CF_ACCESS_TEAM_DOMAIN  e.g. twilight-band-a89f.cloudflareaccess.com     (wrangler.jsonc vars)
//   CF_ACCESS_AUD          Access application audience tag                  (wrangler.jsonc vars)
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { NextRequest, NextResponse } from "next/server";

// Only the libSQL HTTP query endpoints are forwarded, so this cannot be used as a general relay.
const ALLOWED_PATHS = new Set(["v3/pipeline", "v2/pipeline"]);

type ProxyEnv = {
  TURSO_DATABASE_URL?: string;
  TURSO_AUTH_TOKEN?: string;
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
};

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let jwksDomain = "";

function readEnv(): ProxyEnv {
  const fromContext = getCloudflareContext().env as unknown as ProxyEnv;
  return {
    TURSO_DATABASE_URL: fromContext.TURSO_DATABASE_URL ?? process.env.TURSO_DATABASE_URL,
    TURSO_AUTH_TOKEN: fromContext.TURSO_AUTH_TOKEN ?? process.env.TURSO_AUTH_TOKEN,
    CF_ACCESS_TEAM_DOMAIN: fromContext.CF_ACCESS_TEAM_DOMAIN ?? process.env.CF_ACCESS_TEAM_DOMAIN,
    CF_ACCESS_AUD: fromContext.CF_ACCESS_AUD ?? process.env.CF_ACCESS_AUD,
  };
}

/** Returns the signed-in email, or null if the request did not come through Cloudflare Access. */
async function verifyAccess(req: NextRequest, env: ProxyEnv): Promise<string | null> {
  const token = req.headers.get("cf-access-jwt-assertion");
  if (!token || !env.CF_ACCESS_TEAM_DOMAIN || !env.CF_ACCESS_AUD) return null;
  const issuer = `https://${env.CF_ACCESS_TEAM_DOMAIN}`;
  if (!jwks || jwksDomain !== issuer) {
    jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
    jwksDomain = issuer;
  }
  try {
    const { payload } = await jwtVerify(token, jwks, { issuer, audience: env.CF_ACCESS_AUD });
    return typeof payload.email === "string" ? payload.email : "(service token)";
  } catch {
    return null;
  }
}

export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const subpath = (path ?? []).join("/");
  if (!ALLOWED_PATHS.has(subpath)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const env = readEnv();
  const email = await verifyAccess(req, env);
  if (!email) {
    return NextResponse.json({ error: "Cloudflare Access login required" }, { status: 401 });
  }
  if (!env.TURSO_DATABASE_URL || !env.TURSO_AUTH_TOKEN) {
    return NextResponse.json(
      { error: "Turso is not configured on the server (TURSO_DATABASE_URL / TURSO_AUTH_TOKEN)" },
      { status: 500 }
    );
  }

  const base = env.TURSO_DATABASE_URL.replace(/^libsql:\/\//, "https://").replace(/\/+$/, "");
  const upstream = await fetch(`${base}/${subpath}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.TURSO_AUTH_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: await req.text(),
  });

  // Audit trail in Workers Logs: who ran a request, and Turso's answer. No SQL or data is logged.
  console.log(JSON.stringify({ event: "turso_proxy", email, path: subpath, status: upstream.status }));

  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: {
      "Content-Type": upstream.headers.get("content-type") ?? "application/json",
      "Cache-Control": "no-store",
    },
  });
}

// The libSQL client probes GET /v2 or /v3 to check the protocol version before querying.
const VERSION_PATHS = new Set(["v3", "v2"]);

export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const subpath = (path ?? []).join("/");
  if (!VERSION_PATHS.has(subpath)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const env = readEnv();
  if (!(await verifyAccess(req, env))) {
    return NextResponse.json({ error: "Cloudflare Access login required" }, { status: 401 });
  }
  if (!env.TURSO_DATABASE_URL || !env.TURSO_AUTH_TOKEN) {
    return NextResponse.json({ error: "Turso is not configured on the server" }, { status: 500 });
  }

  const base = env.TURSO_DATABASE_URL.replace(/^libsql:\/\//, "https://").replace(/\/+$/, "");
  const upstream = await fetch(`${base}/${subpath}`, {
    headers: { Authorization: `Bearer ${env.TURSO_AUTH_TOKEN}` },
  });
  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: { "Content-Type": upstream.headers.get("content-type") ?? "text/plain", "Cache-Control": "no-store" },
  });
}
