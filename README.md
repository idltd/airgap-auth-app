# Airgap Auth App

**Your phone is your offline authenticator.**

Scan a QR code, approve on your phone, and check who you're connecting to. Once the app is installed and ready, authentication works without Wi-Fi, mobile data or Bluetooth.

**[Open the app](https://idltd.github.io/airgap-auth-app/)**

## Get started

1. Open the app on your Android phone in Chrome, Brave or Edge.
2. Create your vault. A passkey uses your phone's fingerprint, face or screen lock to protect saved keys.
3. Use your browser's **Install app** or **Add to home screen** option.
4. Wait for **Offline ready** before going offline.

It's a progressive web app (PWA), so you don't need an APK or an app-store download.

## Two things you can do

**Sign in to a website.** Open Websites, scan its QR code, approve and exchange the short codes. The website needs the companion [Airgap Auth Server](https://github.com/idltd/airgap-auth-server), which is a private repository.

**Pair with another person.** Open People and start pairing, or scan their phone. Follow each step and compare the full check code on both screens before saving. Later, select the saved contact and choose **Verify contact**. Either phone can start.

The People flow groups each step onto a compact phone screen. While scanning, the camera takes over that screen. QR text is available when you need an alternative to the camera.

## A few things to know

- Pair people in person and compare both check codes carefully. Verification checks the keys you paired; it doesn't independently establish someone's identity.
- Clearing browser data or losing your phone loses its saved keys. There is currently no backup or export.
- The demo passphrase option has lower assurance than a passkey vault.
- Open **Info** in the app for security, storage and update details.

## For developers

Plain HTML, CSS and JavaScript. No framework, bundler or npm install. Camera decoding and QR generation are bundled locally; the app makes no CDN requests.

Serve this directory over HTTPS (or localhost for development). GitHub Pages publishes it through [.github/workflows/pages.yml](.github/workflows/pages.yml). Keep the phone app and authentication server on separate origins.

When changing cached files, update the version in both `config.js` and `sw.js`. Existing installations offer **Update and reload** after checking online.

Copyright ID Ltd. All rights reserved.
