# Airgap Authenticator

### Your phone is the second factor. No network required.

A PWA authenticator that works entirely offline. Install it on your phone, create an encrypted vault, and authenticate by scanning QR codes. Your phone never connects to the server — not during pairing, not during login, not ever.

---

**Works offline from day one.** After installation the app runs from its service worker cache. Disable Wi-Fi, turn off mobile data, enable airplane mode — authentication still works. The camera is the only channel.

**Two modes of operation:**

- **Website login** — Pair with any site running [Airgap Auth](https://github.com/idltd/airgap-auth). Scan a challenge QR, approve on the phone, exchange two codes. The server never sees your private key.

- **Phone-to-phone verification** — Two people pair their phones face-to-face, then verify each other any time later. No server involved at any stage. Each phone proves it still holds the key established during pairing.

**Encrypted by default.** Every credential is independently encrypted with AES-256-GCM. The vault key is derived from a WebAuthn passkey using PRF, or from a passphrase via PBKDF2 (600,000 iterations) in demo mode. Nothing leaves the device unencrypted.

**Zero dependencies.** Plain HTML, CSS and JavaScript. No framework, no bundler, no npm. The QR libraries are vendored locally — no CDN requests, no external fonts, no telemetry.

---

## Install

Open this page on your phone in Chrome, Brave or Edge. Create your vault, then use your browser's *Install* or *Add to home screen* option. Wait for **Offline ready** before going offline.

## Try the full login flow

The authenticator is one half — the other half is a website running the [Airgap Auth](https://github.com/idltd/airgap-auth) server. To try it locally:

```sh
git clone https://github.com/idltd/airgap-auth.git && cd airgap-auth
export SERVER_MASTER_KEY_B64=$(openssl rand -base64 32)
export RP_ORIGINS=http://localhost:3000 ALLOW_LOCAL_HTTP=true
go run ./cmd/airgap-auth
```

## Security

See the [threat model](https://github.com/idltd/airgap-auth/blob/main/docs/threat-model.md). This is a working demonstrator of the protocol, not a certified product.

## Licence

Copyright ID Ltd. All rights reserved.
