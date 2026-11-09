import { createRemoteJWKSet, jwtVerify } from "jose";
import { RtcRole, RtcTokenBuilder } from "agora-token";

interface Env {
  AGORA_APP_ID: string;
  AGORA_APP_CERTIFICATE: string;
  FIREBASE_PROJECT_ID: string;
}

const FIREBASE_KEYS = createRemoteJWKSet(
  new URL(
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
  )
);

const PROJECT_ID = "khahish-final";
const ISSUER = `https://securetoken.google.com/${PROJECT_ID}`;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function validChannelName(value: unknown): value is string {
  if (typeof value !== "string") return false;

  const bytes = new TextEncoder().encode(value);

  return (
    bytes.length > 0 &&
    bytes.length < 64 &&
    /^[a-zA-Z0-9!#$%&()+\-:;,.=?@[\]^_{|}~]+$/.test(value)
  );
}

async function uidFromFirebaseUid(firebaseUid: string): Promise<number> {
  const data = new TextEncoder().encode(firebaseUid);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const view = new DataView(hash);

  const uid = view.getUint32(0, false);

  return uid === 0 ? 1 : uid;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ status: "ok", service: "khahish-agora-token" });
    }

    if (request.method !== "POST" || url.pathname !== "/rtc/token") {
      return json({ error: "Not found" }, 404);
    }

    try {
      if (
        !env.AGORA_APP_ID ||
        !env.AGORA_APP_CERTIFICATE ||
        env.FIREBASE_PROJECT_ID !== PROJECT_ID
      ) {
        return json({ error: "Server configuration error" }, 500);
      }

      const authorization = request.headers.get("Authorization") || "";
      const match = authorization.match(/^Bearer\s+(.+)$/i);

      if (!match) {
        return json({ error: "Authentication required" }, 401);
      }

      const { payload } = await jwtVerify(match[1], FIREBASE_KEYS, {
        algorithms: ["RS256"],
        issuer: ISSUER,
        audience: PROJECT_ID
      });

      const now = Math.floor(Date.now() / 1000);
      const uid = payload.sub;
      const issuedAt = payload.iat;
      const authTime = payload.auth_time;

      if (
        typeof uid !== "string" ||
        uid.length === 0 ||
        typeof issuedAt !== "number" ||
        typeof authTime !== "number" ||
        issuedAt > now + 60 ||
        authTime > now + 60 ||
        authTime > issuedAt + 60
      ) {
        return json({ error: "Invalid authentication" }, 401);
      }

      let body: { channelName?: unknown };

      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid request body" }, 400);
      }

      if (!validChannelName(body.channelName)) {
        return json({ error: "Invalid channel name" }, 400);
      }

      const agoraUid = await uidFromFirebaseUid(uid);
      const expiresIn = 3600;

      const token = RtcTokenBuilder.buildTokenWithUid(
        env.AGORA_APP_ID,
        env.AGORA_APP_CERTIFICATE,
        body.channelName,
        agoraUid,
        RtcRole.PUBLISHER,
        expiresIn,
        expiresIn
      );

      return json({
        token,
        appId: env.AGORA_APP_ID,
        channelName: body.channelName,
        uid: agoraUid,
        expiresIn
      });
    } catch (error) {
      console.error("Token request failed:", error);
      return json({ error: "Authentication or token request failed" }, 401);
    }
  }
};
