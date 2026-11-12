
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

  // Khahish generates channel names as "khahish_" + a UUID without hyphens.
  // Keep validation deliberately simple and aligned with that format.
  return (
    bytes.length > 0 &&
    bytes.length < 64 &&
    /^[A-Za-z0-9_-]+$/.test(value)
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

  let verified;
  try {
    verified = await jwtVerify(match[1], FIREBASE_KEYS, {
      algorithms: ["RS256"],
      issuer: ISSUER,
      audience: PROJECT_ID
    });
  } catch {
    // Invalid, expired, or incorrectly signed Firebase tokens are
    // authentication failures, not internal server errors.
    return null;
  }

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

async function getFirestoreDocumentAsUser(
  request: Request,
  relativePath: string
): Promise<FirestoreDocument | null> {
  const authorization = request.headers.get("Authorization") || "";
  const response = await fetch(FIRESTORE_ROOT + "/" + relativePath, {
    headers: {
      Authorization: authorization,
      Accept: "application/json"
    }
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error("Could not verify the active call record.");
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

async function syncSecretLockedChatList(
  accessToken: string,
  uid: string,
  lockedContactUids: string[]
): Promise<void> {
  const queryResponse = await firestoreRequest(accessToken, ":runQuery", {
    method: "POST",
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: "chats" }],
        where: {
          fieldFilter: {
            field: { fieldPath: "members" },
            op: "ARRAY_CONTAINS",
            value: { stringValue: uid }
          }
        }
      }
    })
  });
  if (!queryResponse.ok) {
    throw new Error("Could not read chats to synchronize Secret Locked Chats.");
  }

  const rows = (await queryResponse.json()) as Array<{ document?: FirestoreDocument }>;
  const lockedContacts = new Set(lockedContactUids);
  const writes = rows.flatMap((row) => {
    const document = row.document;
    const name = document?.name;
    if (!document || !name) return [];
    const members = stringArrayField(document, "members");
    const isGroup = document.fields?.isGroup?.booleanValue === true;
    const peerUid = members.find((memberUid) => memberUid !== uid);
    const shouldHide = !isGroup && members.length === 2 && !!peerUid && lockedContacts.has(peerUid);
    const current = stringArrayField(document, "secretLockedForUids");
    const next = new Set(current);
    if (shouldHide) next.add(uid);
    else next.delete(uid);
    const nextValues = [...next];
    if (current.length === nextValues.length && current.every((value) => next.has(value))) return [];
    return [{
      update: {
        name,
        fields: {
          secretLockedForUids: {
            arrayValue: { values: nextValues.map((value) => ({ stringValue: value })) }
          }
        }
      },
      updateMask: { fieldPaths: ["secretLockedForUids"] }
    }];
  });

  for (let offset = 0; offset < writes.length; offset += 450) {
    const batchResponse = await firestoreRequest(accessToken, ":batchWrite", {
      method: "POST",
      body: JSON.stringify({ writes: writes.slice(offset, offset + 450) })
    });
    if (!batchResponse.ok) {
      throw new Error("Could not update chat visibility for Secret Locked Chats.");
    }
    const result = (await batchResponse.json()) as { status?: Array<{ code?: number }> };
    if (result.status?.some((status) => typeof status.code === "number" && status.code !== 0)) {
      throw new Error("Some chat visibility records could not be updated.");
    }
  }
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

    let recipientPayload = payload;
    if (payload.type === "message") {
      const lockConfig = await getFirestoreDocument(
        accessToken,
        secretLockPath(recipientUid)
      );
      if (stringArrayField(lockConfig, "lockedContactUids").includes(senderUid)) {
        recipientPayload = {
          ...payload,
          title: "Khahish • Locked Chat",
          body: "New message in a locked chat. Unlock Khahish to view it."
        };
      }
    }

    const results = await Promise.allSettled(
      tokens.map((item) => sendFcm(accessToken, item.token, recipientPayload))
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


const SECRET_LOCK_ITERATIONS = 160_000;
const SECRET_LOCK_SESSION_MINUTES = 20;

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64Decode(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function deriveSecretPasswordHash(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const saltBuffer = new ArrayBuffer(salt.length);
  new Uint8Array(saltBuffer).set(salt);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBuffer, iterations, hash: "SHA-256" },
    key,
    256
  );
  return new Uint8Array(bits);
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

function integerField(document: FirestoreDocument | null, field: string): number {
  const raw = document?.fields?.[field]?.integerValue;
  const value = typeof raw === "string" ? Number(raw) : Number(raw || 0);
  return Number.isFinite(value) ? value : 0;
}

function secretLockPath(uid: string): string {
  return "users/" + encodeURIComponent(uid) + "/secretChatLock/config";
}

function secretLockSessionPath(uid: string): string {
  return "users/" + encodeURIComponent(uid) + "/secretChatLock/sessions/current";
}

async function writeFirestoreDocument(
  accessToken: string,
  relativePath: string,
  fields: Record<string, unknown>
): Promise<void> {
  const response = await firestoreRequest(accessToken, relativePath, {
    method: "PATCH",
    body: JSON.stringify({ fields })
  });
  if (!response.ok) {
    throw new Error("Could not save the Secret Locked Chats security record.");
  }
}

async function verifyStoredSecretPassword(
  config: FirestoreDocument,
  password: string
): Promise<boolean> {
  const saltText = stringField(config, "passwordSalt");
  const hashText = stringField(config, "passwordHash");
  const iterations = integerField(config, "iterations");
  if (!saltText || !hashText || iterations < 100_000 || iterations > 500_000) {
    return false;
  }
  try {
    const actual = await deriveSecretPasswordHash(
      password,
      base64Decode(saltText),
      iterations
    );
    return constantTimeEqual(actual, base64Decode(hashText));
  } catch {
    return false;
  }
}

async function makeSecretPasswordFields(
  password: string,
  lockedContactUids: string[]
): Promise<Record<string, unknown>> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await deriveSecretPasswordHash(
    password,
    salt,
    SECRET_LOCK_ITERATIONS
  );
  return {
    passwordSalt: { stringValue: base64Encode(salt) },
    passwordHash: { stringValue: base64Encode(hash) },
    iterations: { integerValue: String(SECRET_LOCK_ITERATIONS) },
    lockedContactUids: {
      arrayValue: {
        values: lockedContactUids.map((uid) => ({ stringValue: uid }))
      }
    },
    updatedAt: { integerValue: String(Date.now()) }
  };
}

async function allowPasswordAttempt(
  accessToken: string,
  uid: string
): Promise<boolean> {
  const path = "users/" + encodeURIComponent(uid) + "/secretChatLock/attempts";
  const record = await getFirestoreDocument(accessToken, path);
  const count = integerField(record, "count");
  const start = record?.fields?.windowStartedAt?.timestampValue;
  const activeWindow = typeof start === "string" &&
    Date.now() - Date.parse(start) < 15 * 60_000;
  if (activeWindow && count >= 5) return false;

  const nextCount = activeWindow ? count + 1 : 1;
  const windowStartedAt = activeWindow ? start : new Date().toISOString();
  await writeFirestoreDocument(accessToken, path, {
    count: { integerValue: String(nextCount) },
    windowStartedAt: { timestampValue: windowStartedAt }
  });
  return true;
}

async function clearPasswordAttempts(
  accessToken: string,
  uid: string
): Promise<void> {
  await firestoreRequest(
    accessToken,
    "users/" + encodeURIComponent(uid) + "/secretChatLock/attempts",
    { method: "DELETE" }
  );
}

async function requireSecretLockSession(
  accessToken: string,
  uid: string
): Promise<boolean> {
  const session = await getFirestoreDocument(
    accessToken,
    secretLockSessionPath(uid)
  );
  const expiry = session?.fields?.expiresAt?.timestampValue;
  return typeof expiry === "string" && Date.parse(expiry) > Date.now();
}

async function handleSecretChatConfig(
  env: Env,
  uid: string
): Promise<Response> {
  const accessToken = await getGoogleAccessToken(env);
  const config = await getFirestoreDocument(accessToken, secretLockPath(uid));
  const lockedContactUids = stringArrayField(config, "lockedContactUids");
  await syncSecretLockedChatList(accessToken, uid, lockedContactUids);
  return json({
    hasPassword: Boolean(stringField(config, "passwordHash")),
    lockedContactUids
  });
}

async function handleSecretChatPassword(
  request: Request,
  env: Env,
  uid: string
): Promise<Response> {
  let body: {
    action?: unknown;
    password?: unknown;
    currentPassword?: unknown;
    newPassword?: unknown;
  };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }

  const action = body.action;
  const password = body.password;
  const currentPassword = body.currentPassword;
  const newPassword = body.newPassword;
  if (
    (action !== "create" && action !== "change") ||
    (action === "create" &&
      (typeof password !== "string" || password.length < 8 || password.length > 128)) ||
    (action === "change" &&
      (typeof currentPassword !== "string" ||
        typeof newPassword !== "string" ||
        newPassword.length < 8 ||
        newPassword.length > 128))
  ) {
    return json({ error: "Password must contain 8 to 128 characters." }, 400);
  }

  const accessToken = await getGoogleAccessToken(env);
  const path = secretLockPath(uid);
  const existing = await getFirestoreDocument(accessToken, path);
  const lockedContactUids = stringArrayField(existing, "lockedContactUids");

  if (action === "create") {
    if (stringField(existing, "passwordHash")) {
      return json({ error: "A Secret Locked Chats password already exists." }, 409);
    }
    const fields = await makeSecretPasswordFields(password as string, lockedContactUids);
    await writeFirestoreDocument(accessToken, path, fields);
    const expiresAt = new Date(Date.now() + SECRET_LOCK_SESSION_MINUTES * 60_000).toISOString();
    await writeFirestoreDocument(accessToken, secretLockSessionPath(uid), {
      expiresAt: { timestampValue: expiresAt },
      createdAt: { integerValue: String(Date.now()) }
    });
    return json({ ok: true, expiresAt, sessionMinutes: SECRET_LOCK_SESSION_MINUTES });
  } else {
    if (!(await allowPasswordAttempt(accessToken, uid))) {
      return json({ error: "Too many password attempts. Try again in 15 minutes." }, 429);
    }
    if (!existing || !(await verifyStoredSecretPassword(existing, currentPassword as string))) {
      return json({ error: "Current password is incorrect." }, 403);
    }
    await clearPasswordAttempts(accessToken, uid);
    const fields = await makeSecretPasswordFields(newPassword as string, lockedContactUids);
    await writeFirestoreDocument(accessToken, path, fields);
  }

  return json({ ok: true });
}

async function handleSecretChatUnlock(
  request: Request,
  env: Env,
  uid: string
): Promise<Response> {
  let body: { password?: unknown };
  try {
    body = (await request.json()) as { password?: unknown };
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }
  if (typeof body.password !== "string" || body.password.length < 1 || body.password.length > 128) {
    return json({ error: "Enter your Secret Locked Chats password." }, 400);
  }

  const accessToken = await getGoogleAccessToken(env);
  if (!(await allowPasswordAttempt(accessToken, uid))) {
    return json({ error: "Too many password attempts. Try again in 15 minutes." }, 429);
  }
  const config = await getFirestoreDocument(accessToken, secretLockPath(uid));
  if (!config || !(await verifyStoredSecretPassword(config, body.password))) {
    return json({ error: "Incorrect password." }, 403);
  }
  await clearPasswordAttempts(accessToken, uid);

  const expiresAt = new Date(Date.now() + SECRET_LOCK_SESSION_MINUTES * 60_000).toISOString();
  await writeFirestoreDocument(accessToken, secretLockSessionPath(uid), {
    expiresAt: { timestampValue: expiresAt },
    createdAt: { integerValue: String(Date.now()) }
  });
  return json({
    ok: true,
    expiresAt,
    sessionMinutes: SECRET_LOCK_SESSION_MINUTES
  });
}

async function handleSecretChatContacts(
  request: Request,
  env: Env,
  uid: string
): Promise<Response> {
  let body: { action?: unknown; contactUid?: unknown };
  try {
    body = (await request.json()) as { action?: unknown; contactUid?: unknown };
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }
  if (
    (body.action !== "add" && body.action !== "remove") ||
    typeof body.contactUid !== "string" ||
    !body.contactUid ||
    body.contactUid === uid ||
    body.contactUid.length > 128
  ) {
    return json({ error: "Invalid locked contact." }, 400);
  }

  const accessToken = await getGoogleAccessToken(env);
  if (!(await requireSecretLockSession(accessToken, uid))) {
    return json({ error: "Unlock Locked Chats again before changing contacts." }, 403);
  }

  const target = await getFirestoreDocument(
    accessToken,
    "publicProfiles/" + encodeURIComponent(body.contactUid)
  );
  if (!target) return json({ error: "Contact profile not found." }, 404);

  const path = secretLockPath(uid);
  const config = await getFirestoreDocument(accessToken, path);
  if (!config || !stringField(config, "passwordHash")) {
    return json({ error: "Create your Secret Locked Chats password first." }, 409);
  }

  const contacts = new Set(stringArrayField(config, "lockedContactUids"));
  if (body.action === "add") contacts.add(body.contactUid);
  else contacts.delete(body.contactUid);

  // Update the per-chat visibility index before committing the lock config.
  // If this fails, keep the old config so the normal chat list cannot leak previews.
  await syncSecretLockedChatList(accessToken, uid, [...contacts]);

  const updateResponse = await firestoreRequest(
    accessToken,
    path + "?updateMask.fieldPaths=lockedContactUids&updateMask.fieldPaths=updatedAt",
    {
      method: "PATCH",
      body: JSON.stringify({
        fields: {
          lockedContactUids: {
            arrayValue: {
              values: [...contacts].map((contactUid) => ({ stringValue: contactUid }))
            }
          },
          updatedAt: { integerValue: String(Date.now()) }
        }
      })
    }
  );
  if (!updateResponse.ok) {
    console.error("Secret Locked Chats contact update failed:", updateResponse.status);
    return json({ error: "Could not update your locked contacts. Please try again." }, 500);
  }

  return json({ ok: true, lockedContactUids: [...contacts] });
}

async function handleSecretChatLock(
  env: Env,
  uid: string
): Promise<Response> {
  const accessToken = await getGoogleAccessToken(env);
  const response = await firestoreRequest(
    accessToken,
    secretLockSessionPath(uid),
    { method: "DELETE" }
  );
  if (!response.ok && response.status !== 404) {
    return json({ error: "Could not lock Secret Chats right now." }, 500);
  }
  return json({ ok: true });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ status: "ok", service: "khahish-agora-token" });
    }

    if (url.pathname.startsWith("/secret-chats/")) {
      try {
        if (env.FIREBASE_PROJECT_ID !== PROJECT_ID) {
          return json({ error: "Server configuration error." }, 500);
        }
        const uid = await verifyFirebaseUser(request);
        if (!uid) return json({ error: "Authentication required." }, 401);

        if (request.method === "GET" && url.pathname === "/secret-chats/config") {
          return await handleSecretChatConfig(env, uid);
        }
        if (request.method === "POST" && url.pathname === "/secret-chats/password") {
          return await handleSecretChatPassword(request, env, uid);
        }
        if (request.method === "POST" && url.pathname === "/secret-chats/unlock") {
          return await handleSecretChatUnlock(request, env, uid);
        }
        if (request.method === "POST" && url.pathname === "/secret-chats/contacts") {
          return await handleSecretChatContacts(request, env, uid);
        }
        if (request.method === "POST" && url.pathname === "/secret-chats/lock") {
          return await handleSecretChatLock(env, uid);
        }
        return json({ error: "Not found." }, 404);
      } catch (error) {
        console.error("Secret Locked Chats request failed:", error);
        return json({ error: "Secret Locked Chats service unavailable." }, 500);
      }
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

        let body: { callId?: unknown; channelName?: unknown };
        try {
          body = (await request.json()) as {
            callId?: unknown;
            channelName?: unknown;
          };
        } catch {
          return json({ error: "Invalid request body" }, 400);
        }

        if (
          typeof body.callId !== "string" ||
          !body.callId.trim() ||
          body.callId.length > 200 ||
          !validChannelName(body.channelName)
        ) {
          return json({ error: "Invalid call or channel." }, 400);
        }

        // A Firebase login alone is not enough to mint a room token.
        // Confirm this account is one of the two participants in this
        // exact active call and that the client-supplied channel matches
        // the server-stored channel name.
        // Read with the caller's Firebase ID token so Firestore Security
        // Rules enforce caller/callee membership for this exact call record.
        const call = await getFirestoreDocumentAsUser(
          request,
          "calls/" + encodeURIComponent(body.callId)
        );

        if (!call) return json({ error: "Call not found." }, 404);

        const callerUid = stringField(call, "callerUid");
        const calleeUid = stringField(call, "calleeUid");
        const callStatus = stringField(call, "status");
        const storedChannel = stringField(call, "channelName");

        if (uid !== callerUid && uid !== calleeUid) {
          return json({ error: "You are not a participant in this call." }, 403);
        }
        if (callStatus !== "ringing" && callStatus !== "accepted") {
          return json({ error: "This call is no longer active." }, 409);
        }
        if (!storedChannel || storedChannel !== body.channelName) {
          return json({ error: "Call channel does not match." }, 403);
        }

        const agoraUid = await uidFromFirebaseUid(uid);
        const expiresIn = 3600;
        const token = RtcTokenBuilder.buildTokenWithUid(
          env.AGORA_APP_ID,
          env.AGORA_APP_CERTIFICATE,
          storedChannel,
          agoraUid,
          RtcRole.PUBLISHER,
          expiresIn,
          expiresIn
        );

        return json({
          token,
          appId: env.AGORA_APP_ID,
          callId: body.callId,
          channelName: storedChannel,
          uid: agoraUid,
          expiresIn
        });
      } catch (error) {
        console.error("Agora token request failed:", error);
        return json({ error: "Call authorization or token service unavailable." }, 500);
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
