# Khahish Calling and Push Notification Worker

Cloudflare Worker for issuing Agora RTC tokens and sending authenticated Firebase Cloud Messaging (FCM) alerts for Khahish.

## Firebase project

- Project ID: \`khahish-final\`
- Android package: \`com.khahish.app\`

## Cloudflare variables and secrets

Regular variables:

- \`AGORA_APP_ID\`
- \`FIREBASE_PROJECT_ID=khahish-final\`

Encrypted secrets:

- \`AGORA_APP_CERTIFICATE\`
- \`FIREBASE_SERVICE_ACCOUNT_JSON\` — the complete Firebase service-account JSON file contents

Never commit either secret to GitHub or put it in the Android APK.

### Configure the FCM service account

1. In Google Cloud Console, select project \`khahish-final\`.
2. Enable the Firebase Cloud Messaging API (HTTP v1).
3. Create or select a dedicated service account for this Worker.
4. Grant only the required roles: **Cloud Datastore User** (to read chat/call/token records and write dispatch de-duplication records) and **Firebase Cloud Messaging API Admin** (to send FCM messages).
5. Create a JSON key for that service account and copy the complete JSON contents.
6. In Cloudflare, open the \`khahish-agora-token\` Worker → Settings → Variables and Secrets. Add \`FIREBASE_SERVICE_ACCOUNT_JSON\` as an encrypted secret. Do not paste the key into this repository, a chat, or the Android project.
7. Keep \`FIREBASE_PROJECT_ID\` set to \`khahish-final\`.

The `FIREBASE_SERVICE_ACCOUNT_JSON` secret is required for both RTC call authorization and FCM delivery. For RTC token requests, the Worker reads the call document with this service account before issuing any Agora token. The Worker verifies every Firebase ID token against the Khahish Firebase project. It checks that the authenticated sender owns the message or outgoing call, verifies chat membership, checks recipient block records, and uses a server-side dispatch record to avoid repeat sends. Message notifications contain a generic preview rather than the private message text.

## API

### Health check

\`GET /health\`

### Agora RTC token

\`POST /rtc/token\`

Headers:

- \`Authorization: Bearer FIREBASE_ID_TOKEN\`
- \`Content-Type: application/json\`

Body:

\`\`\`json
{ "callId": "firestore-call-document-id", "channelName": "your-call-channel" }
\`\`\`

The Firebase ID token must belong to \`khahish-final\`. Agora credentials are short-lived; the App Certificate remains server-side.

The Worker reads the call document with its server-side Firebase service account and issues a token only when the authenticated Firebase UID is the caller or callee, the call is still ringing or accepted, and the supplied channel exactly matches the stored call channel.

### New message push

\`POST /push/message\`

Headers:

- \`Authorization: Bearer FIREBASE_ID_TOKEN\`
- \`Content-Type: application/json\`

Body:

\`\`\`json
{ "chatId": "firestore-chat-document-id", "messageId": "firestore-message-document-id" }
\`\`\`

The Worker reads the chat and message from Firestore, confirms the caller is the message sender and a chat member, then sends data-only high-priority FCM messages to other chat members who have registered device tokens and have not blocked the sender.

### Incoming call push

\`POST /push/call\`

Body:

\`\`\`json
{ "callId": "firestore-call-document-id" }
\`\`\`

The Worker confirms the authenticated user is the caller and the call is still ringing before notifying the callee.

## Deployment

Cloudflare Workers Git integration deploys from the \`main\` branch. This feature branch is intentionally not deployed until it has been reviewed and merged.

## Type checking

\`npm run typecheck\`
