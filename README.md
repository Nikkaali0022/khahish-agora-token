# Khahish Agora Token Service

Secure Cloudflare Worker for issuing Agora RTC tokens to authenticated Khahish users.

## Firebase Project

- Project ID: khahish-final
- Android package: com.khahish.app

## Required Cloudflare Variables

Regular variables:

- AGORA_APP_ID
- FIREBASE_PROJECT_ID

Encrypted secret:

- AGORA_APP_CERTIFICATE

Never commit the Agora App Certificate to GitHub.

## API

### Health check

GET /health

### Generate RTC token

POST /rtc/token

Headers:

Authorization: Bearer FIREBASE_ID_TOKEN
Content-Type: application/json

Body:

{
  "channelName": "your-call-channel"
}

The Firebase ID token must belong to the configured Firebase project.

## Token

- Publisher role
- Token lifetime: 1 hour
- Firebase UID mapped to numeric Agora UID

## Deployment

Cloudflare Workers Git integration deploys this project from the main branch.

Run type checking with:

npm run typecheck
