# Airgap Authenticator

**An offline authenticator that runs entirely in your browser.**

Install this PWA on your phone, create a vault, and authenticate websites or verify other people — all without a network connection. Credentials are encrypted in IndexedDB and protected by a WebAuthn passkey (PRF) or a demo passphrase.

## What you can do here

- **Website authentication** — Pair with any site running the [Airgap Auth](https://github.com/idltd/airgap-auth) server, then sign in by scanning QR codes while your phone stays offline.
- **Phone-to-phone verification** — Pair two phones in person, then later verify each other's identity through a signed QR exchange. No server needed at any stage.

## Install

Open this site on your phone in a Chromium browser (Brave, Chrome, Edge). Create your vault, then install the app using the browser's install/add-to-home-screen option. Wait for **Offline ready** before going offline.

## Website login

This authenticator is one half of the login flow. The other half is a website running the Airgap Auth server. Without a server there is nothing to log into — but you can still explore the vault, install the PWA, and try phone-to-phone verification between two devices.

To try the full login flow, run the server locally:

```sh
git clone https://github.com/idltd/airgap-auth.git
cd airgap-auth
export SERVER_MASTER_KEY_B64=$(openssl rand -base64 32)
export RP_ORIGINS=http://localhost:3000
export ALLOW_LOCAL_HTTP=true
go run ./cmd/airgap-auth
```

## Security

Credentials are encrypted independently with AES-256-GCM. Phone-to-phone verification uses ECDSA P-256 signed transcripts with fresh nonces. This is a demonstrator — see the [threat model](https://github.com/idltd/airgap-auth/blob/main/docs/threat-model.md) for known limitations.

## Licence

Copyright ID Ltd. All rights reserved.
