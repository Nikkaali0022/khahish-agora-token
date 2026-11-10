
import {
  createRemoteJWKSet,
  importPKCS8,
  jwtVerify,
  SignJWT
} from "jose";
import { RtcRole, RtcTokenBuilder } from "agora-token";

interface Env {
  AGORA_APP_ID: string;
  AGORA_APP_CERTIFICATE: string;
  FIREBASE_PROJECT_ID: string;
  FIREBASE_SERVICE_ACCOUNT_JSON?: string;
}

interface FirestoreDocument {
  name?: string;
  fields?: Record<string, any>;
}

interface ServiceAccount {
  project_id: string;
  client_email: string;
  private_key: string;
  token_uri?: string;
}

const FIREBASE_KEYS = createRemoteJWKSet(
  new URL(
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
  )
);

const PROJECT_ID = "khahish-final";
const ISSUER = "https://securetoken.google.com/" + PROJECT_ID;
const FIRESTORE_ROOT =
  "https://firestore.googleapis.com/v1/projects/" +
  PROJECT_ID +
  "/databases/(default)/documents";

let cachedGoogleToken = "";
let cachedGoogleTokenExpiresAt = 0;

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
    /^[a-zA-Z0-9!#$%&()+\-:;,.=?@[\\]^_{|}~]+$/.test(value)
  );
}

async function uidFromFirebaseUid(firebaseUid: string): Promise<number> {
  const data = new TextEncoder().encode(firebaseUid);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const view = new DataView(hash);
  const uid = view.getUint32(0, false) & 0x7fffffff;
  return uid === 0 ? 1 : uid;
}

async function verifyFirebaseUser(request: Request): Promise<string | null> {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;

  const verified = await jwtVerify(match[1], FIREBASE_KEYS, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: PROJECT_ID
  });

  const payload = verified.payload;
  const now = Math.floor(Date.now() / 1000);
  const uid = payload.sub;
  const issuedAt = payload.iat;
  const authTime = payload.auth_time;
  const expiresAt = payload.exp;

  if (
    typeof uid !== "string" ||
    uid.length === 0 ||
    typeof issuedAt !== "number" ||
    typeof authTime !== "number" ||
    typeof expiresAt !== "number" ||
    expiresAt <= now ||
    issuedAt > now + 60 ||
    authTime > now + 60 ||
    authTime > issuedAt + 60
  ) {
    return null;
  }

  return uid;
}

async function getGoogleAccessToken(env: Env): Promise<string> {
  if (cachedGoogleToken && cachedGoogleTokenExpiresAt > Date.now() + 60_000) {
    return cachedGoogleToken;
  }

  if (!env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    throw new Error("Push sender is not configured.");
  }

  const serviceAccount = JSON.parse(
    env.FIREBASE_SERVICE_ACCOUNT_JSON
  ) as ServiceAccount;

  if (
    serviceAccount.project_id !== PROJECT_ID ||
    !serviceAccount.client_email ||
    !serviceAccount.private_key
  ) {
    throw new Error("Firebase service account configuration is invalid.");
  }

  const tokenUri =
    serviceAccount.token_uri || "https://oauth2.googleapis.com/token";
  const privateKey = await importPKCS8(
    serviceAccount.private_key,
    "RS256"
  );

  const assertion = await new SignJWT({
    scope: "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/firebase.messaging"
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuer(serviceAccount.client_email)
    .setSubject(serviceAccount.client_email)
    .setAudience(tokenUri)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);

  const response = await fetch(tokenUri, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });

  const tokenData = (await response.json()) as {
    access_token?: string;
    expires_in?: number;
    error?: string;
  };

  if (!response.ok || !tokenData.access_token) {
    throw new Error("Google service authentication failed.");
  }

  cachedGoogleToken = tokenData.access_token;
  cachedGoogleTokenExpiresAt =
    Date.now() + Math.max(60, tokenData.expires_in || 3600) * 1000;

  return cachedGoogleToken;
}

async function firestoreRequest(
  accessToken: string,
  relativePath: string,
  init: RequestInit = {}
): Promise<Response> {
  return fetch(FIRESTORE_ROOT + "/" + relativePath, {
    ...init,
    headers: {
      Authorization: "Bearer " + accessToken,
      "Content-Type": "application/json",
      ...(init.headers || {})
    }
  });
}

async function getFirestoreDocument(
  accessToken: string,
  relativePath: string
): Promise<FirestoreDocument | null> {
  const response = await firestoreRequest(accessToken, relativePath);
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error("Could not read the required Khahish record.");
  }
  return (await response.json()) as FirestoreDocument;
}

function stringField(
  document: FirestoreDocument | null,
  field: string
): string {
  return document?.fields?.[field]?.stringValue || "";
}

function stringArrayField(
  document: FirestoreDocument | null,
  field: string
): string[] {
  const values = document?.fields?.[field]?.arrayValue?.values || [];
  return values
    .map((value: any) => value?.stringValue)
    .filter((value: unknown): value is string => typeof value === "string");
}

async function listUserTokens(
  accessToken: string,
  uid: string
): Promise<Array<{ token: string; documentPath: string }>> {
  const response = await firestoreRequest(
    accessToken,
    "users/" + encodeURIComponent(uid) + "/fcmTokens?pageSize=100"
  );

  if (!response.ok) {
    throw new Error("Could not read notification devices.");
  }

  const data = (await response.json()) as {
    documents?: FirestoreDocument[];
  };

  return (data.documents || [])
    .map((document) => ({
      token: stringField(document, "token"),
      documentPath: (document.name || "").split("/documents/")[1] || ""
    }))
    .filter((item) => item.token.length > 0 && item.documentPath.length > 0);
}

async function sendFcm(
  accessToken: string,
  token: string,
  data: Record<string, string>
): Promise<void> {
  const response = await fetch(
    "https://fcm.googleapis.com/v1/projects/" +
      PROJECT_ID +
      "/messages:send",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer " + accessToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: {
          token,
          data,
          android: {
            priority: "HIGH",
            ttl: "60s"
          }
        }
      })
    }
  );

  if (!response.ok) {
    throw new Error("Firebase Cloud Messaging rejected a device notification.");
  }
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function claimDispatch(
  accessToken: string,
  dispatchKey: string
): Promise<{ claimed: boolean; path: string }> {
  const path = "pushDispatches/" + dispatchKey;
  const response = await firestoreRequest(
    accessToken,
    "pushDispatches?documentId=" + encodeURIComponent(dispatchKey),
    {
      method: "POST",
      body: JSON.stringify({
        fields: {
          status: { stringValue: "processing" },
          createdAt: { integerValue: String(Date.now()) }
        }
      })
    }
  );

  if (response.status === 409) {
    return { claimed: false, path };
  }
  if (!response.ok) {
    throw new Error("Could not register notification dispatch.");
  }
  return { claimed: true, path };
}

async function updateDispatch(
  accessToken: string,
  path: string,
  status: string,
  sentCount: number
): Promise<void> {
  await firestoreRequest(accessToken, path, {
    method: "PATCH",
    body: JSON.stringify({
      fields: {
        status: { stringValue: status },
        sentCount: { integerValue: String(sentCount) },
        updatedAt: { integerValue: String(Date.now()) }
      }
    })
  });
}

async function releaseDispatch(
  accessToken: string,
  path: string
): Promise<void> {
  await firestoreRequest(accessToken, path, { method: "DELETE" });
}

async function sendToRecipients(
  accessToken: string,
  senderUid: string,
  recipientUids: string[],
  payload: Record<string, string>
): Promise<{ attempted: number; sent: number }> {
  let attempted = 0;
  let sent = 0;

  for (const recipientUid of [...new Set(recipientUids)]) {
    if (!recipientUid || recipientUid === senderUid) continue;

    // Fail closed: do not send a notification if the recipient's block
    // record cannot be checked successfully.
    const blocked = await getFirestoreDocument(
      accessToken,
      "users/" +
        encodeURIComponent(recipientUid) +
        "/blocked/" +
        encodeURIComponent(senderUid)
    );
    if (blocked) continue;

    const tokens = await listUserTokens(accessToken, recipientUid);
    attempted += tokens.length;

    const results = await Promise.allSettled(
      tokens.map((item) => sendFcm(accessToken, item.token, payload))
    );
    sent += results.filter((result) => result.status === "fulfilled").length;
  }

  if (attempted > 0 && sent === 0) {
    throw new Error("No device notification could be delivered.");
  }

  return { attempted, sent };
}

async function handleMessagePush(
  request: Request,
  env: Env,
  senderUid: string
): Promise<Response> {
  let body: { chatId?: unknown; messageId?: unknown };
  try {
    body = (await request.json()) as { chatId?: unknown; messageId?: unknown };
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }

  if (
    typeof body.chatId !== "string" ||
    typeof body.messageId !== "string" ||
    !body.chatId ||
    !body.messageId ||
    body.chatId.length > 200 ||
    body.messageId.length > 200
  ) {
    return json({ error: "Invalid chat or message ID." }, 400);
  }

  const accessToken = await getGoogleAccessToken(env);
  const chat = await getFirestoreDocument(
    accessToken,
    "chats/" + encodeURIComponent(body.chatId)
  );
  const message = await getFirestoreDocument(
    accessToken,
    "chats/" +
      encodeURIComponent(body.chatId) +
      "/messages/" +
      encodeURIComponent(body.messageId)
  );

  if (!chat || !message) return json({ error: "Message not found." }, 404);
  if (stringField(message, "senderId") !== senderUid) {
    return json({ error: "Message sender does not match the signed-in user." }, 403);
  }

  const members = stringArrayField(chat, "members");
  if (!members.includes(senderUid)) {
    return json({ error: "You are not a member of this chat." }, 403);
  }

  const dispatchKey =
    "message_" + (await sha256Hex(body.chatId + ":" + body.messageId));
  const dispatch = await claimDispatch(accessToken, dispatchKey);
  if (!dispatch.claimed) return json({ ok: true, duplicate: true });

  try {
    const profile = await getFirestoreDocument(
      accessToken,
      "users/" + encodeURIComponent(senderUid)
    );
    const senderName =
      stringField(profile, "name") ||
      stringField(profile, "displayName") ||
      "Khahish user";

    const result = await sendToRecipients(
      accessToken,
      senderUid,
      members,
      {
        title: senderName,
        body: "You have a new message.",
        type: "message",
        chatId: body.chatId,
        notificationId: body.messageId
      }
    );

    await updateDispatch(
      accessToken,
      dispatch.path,
      "sent",
      result.sent
    );
    return json({ ok: true, attempted: result.attempted, sent: result.sent });
  } catch (error) {
    await releaseDispatch(accessToken, dispatch.path);
    throw error;
  }
}

async function handleCallPush(
  request: Request,
  env: Env,
  callerUid: string
): Promise<Response> {
  let body: { callId?: unknown };
  try {
    body = (await request.json()) as { callId?: unknown };
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }

  if (
    typeof body.callId !== "string" ||
    !body.callId ||
    body.callId.length > 200
  ) {
    return json({ error: "Invalid call ID." }, 400);
  }

  const accessToken = await getGoogleAccessToken(env);
  const call = await getFirestoreDocument(
    accessToken,
    "calls/" + encodeURIComponent(body.callId)
  );

  if (!call) return json({ error: "Call not found." }, 404);
  if (
    stringField(call, "callerUid") !== callerUid ||
    stringField(call, "status") !== "ringing"
  ) {
    return json({ error: "Call is not eligible for notification." }, 403);
  }

  const calleeUid = stringField(call, "calleeUid");
  if (!calleeUid) return json({ error: "Invalid call recipient." }, 400);

  const dispatchKey = "call_" + (await sha256Hex(body.callId));
  const dispatch = await claimDispatch(accessToken, dispatchKey);
  if (!dispatch.claimed) return json({ ok: true, duplicate: true });

  try {
    const blocked = await getFirestoreDocument(
      accessToken,
      "users/" +
        encodeURIComponent(calleeUid) +
        "/blocked/" +
        encodeURIComponent(callerUid)
    );

    let result = { attempted: 0, sent: 0 };
    if (!blocked) {
      const callerName =
        stringField(call, "callerName") || "Khahish user";
      const isVideo = stringField(call, "callType") === "video";
      result = await sendToRecipients(
        accessToken,
        callerUid,
        [calleeUid],
        {
          title: callerName,
          body: isVideo ? "Incoming video call" : "Incoming voice call",
          type: "call",
          callId: body.callId,
          notificationId: body.callId
        }
      );
    }

    await updateDispatch(
      accessToken,
      dispatch.path,
      "sent",
      result.sent
    );
    return json({ ok: true, attempted: result.attempted, sent: result.sent });
  } catch (error) {
    await releaseDispatch(accessToken, dispatch.path);
    throw error;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ status: "ok", service: "khahish-agora-token" });
    }

    if (request.method === "POST" && url.pathname === "/rtc/token") {
      try {
        if (
          !env.AGORA_APP_ID ||
          !env.AGORA_APP_CERTIFICATE ||
          env.FIREBASE_PROJECT_ID !== PROJECT_ID
        ) {
          return json({ error: "Server configuration error" }, 500);
        }

        const uid = await verifyFirebaseUser(request);
        if (!uid) return json({ error: "Authentication required" }, 401);

        let body: { channelName?: unknown };
        try {
          body = (await request.json()) as { channelName?: unknown };
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
        console.error("Agora token request failed:", error);
        return json({ error: "Authentication or token request failed" }, 401);
      }
    }

    if (
      request.method === "POST" &&
      (url.pathname === "/push/message" || url.pathname === "/push/call")
    ) {
      if (env.FIREBASE_PROJECT_ID !== PROJECT_ID) {
        return json({ error: "Server configuration error." }, 500);
      }

      try {
        const uid = await verifyFirebaseUser(request);
        if (!uid) return json({ error: "Authentication required." }, 401);

        const result =
          url.pathname === "/push/message"
            ? await handleMessagePush(request, env, uid)
            : await handleCallPush(request, env, uid);

        return result;
      } catch (error) {
        console.error("Push dispatch failed:", error);
        return json({ error: "Push notification dispatch failed." }, 500);
      }
    }

    return json({ error: "Not found" }, 404);
  }
};
