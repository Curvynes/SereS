# 💬 SereS

[![Beta Status](https://img.shields.io/badge/Status-Web%20Beta-orange.svg)](https://status.seres-chat.com)
[![Discord](https://img.shields.io/badge/Discord-Join%20Community-5865F2?logo=discord&logoColor=white)](https://discord.gg/vx3vKcp2Kq)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**SereS** is a next-generation web messaging platform designed to bridge the gap between WhatsApp and Discord—faster, cleaner, and built for the modern web.

---

## 🌐 Beta is Live now!

The **SereS Beta** is currently live and directly accessible on our official website. Try out the platform, test the new features, and experience the future of chat right in your browser!

👉 **[Access the SereS Web Beta](https://seres-chat.com)**

---

## ✨ Features

- **Modern & Sleek UI:** A clean, fast, and clutter-free interface designed for the modern web.
- **Best of Both Worlds:** Combines the simple direct messaging of WhatsApp with the rich community structure of Discord.
- **Real-time Engine:** Ultra-fast messaging, rich media sharing, and instant updates.
- **Dynamic Spaces:** Effortlessly jump between private 1-on-1 chats and group chats.
- **Rich Messaging:** Replies, emoji reactions, encrypted photos, files and voice messages, Discord-style formatting, @mentions, pinned messages, search and disappearing messages.
- **End-to-End Encrypted:** Every message is encrypted in your browser. The server only ever sees ciphertext.

---

## 👥 Join the Community

Help us refine SereS during the Beta phase! Share your feedback, report bugs, or chat with the team on our official Discord server.

👉 **[Join the SereS Discord Server](https://discord.gg/vx3vKcp2Kq)**

---

## 🚀 Local Development

Install the stable Rust toolchain, then start the backend from the repository root:

```bash
cargo run --manifest-path src/backend-rs/Cargo.toml
```

On Windows, run it in WSL; the WebAuthn dependency needs OpenSSL development packages to compile.
On Debian or Ubuntu, install them with `sudo apt install build-essential pkg-config libssl-dev`.
The backend serves `src/public/` and stores its SQLite database and uploaded binary data in
`src/backend/` by default. Set `SERES_DATA_DIR` or
`SERES_PUBLIC_DIR` to use other paths. If you have a `src/backend/.env`, run from that directory
so the Rust process loads the existing SMTP and passkey settings:

```bash
cd src/backend
cargo run --manifest-path ../backend-rs/Cargo.toml
```

The frontend is written in TypeScript (`src/frontend/`). It is compiled to
`src/public/` and the compiled `.js` files are committed;
after changing a `.ts` file run `tsc -p .` in the repository root.

Format and compile the backend with `cargo fmt --manifest-path src/backend-rs/Cargo.toml` and
`cargo check --manifest-path src/backend-rs/Cargo.toml`.

Optional environment variables: `PORT`, `HOST`, `SERES_DATA_DIR` (where `users.db` is stored),
`SERES_PUBLIC_DIR`, `SERES_ALLOWED_HOSTS`
(extra hostnames allowed as request `Origin`, comma separated), `URL` (uptime heartbeat).

---

## 🖥️ Install on a server (Ubuntu / Debian)

One script installs Rust, Node.js + npm, pm2, and the TURN server for calls, downloads SereS,
builds the Rust backend, and keeps it running with pm2, including after a reboot:

```bash
curl -fsSLO https://raw.githubusercontent.com/SereSChat/SereS/main/deploy/install.sh
bash install.sh --public-url https://beta.seres-chat.com --rp-id seres-chat.com
```

Run it as the user SereS should run as (it asks for `sudo`). SereS then listens on
`http://localhost:2222`; point your Cloudflare tunnel or reverse proxy there. To update
later, run `~/SereS/deploy/install.sh` again: it pulls the newest version, installs what is
new and restarts SereS. All options and the ports for calls: [deploy/README.md](deploy/README.md).

---

## 📞 Voice calls (browser)

- The 📞 button in a chat calls everyone in it; the others get a ringing card with *Answer* and
  *Decline*. In the call: mute, hang up and **add people**. Adding people creates a new group with
  everyone in the call and the added friends; the call moves there and you call everyone.
- The audio goes directly between the browsers (WebRTC, always encrypted). In a group everyone is
  connected with everyone, which works well for small groups. The connection offers are signed
  with the account keys, so the server can't listen in. When a direct connection isn't possible,
  the TURN server relays the encrypted audio (`TURN_URLS` / `TURN_SECRET`, set up by `install.sh`).
- Calls need `https://` (or `localhost`) because browsers only allow the microphone there. Calls
  only ring while SereS is open in a browser tab.

## 🔒 How the end-to-end encryption works

- **Your password never reaches the server in usable form.** The browser derives a master key with
  PBKDF2-SHA256 (600,000 iterations, random salt) and splits it with HKDF into an *auth hash*
  (sent to the server, stored with Argon2id) and a *key-wrapping key* (never leaves the device).
- **Identity keys:** on registration the browser creates a P-256 ECDH key pair (encryption) and a
  P-256 ECDSA key pair (signatures). The private keys are uploaded only after being encrypted with
  the key-wrapping key (AES-256-GCM). After login they are unlocked and stored in IndexedDB as
  *non-extractable* WebCrypto keys.
- **Messages:** every message gets a fresh AES-256-GCM key. That key is wrapped for each chat
  member with a pairwise key derived from ECDH + HKDF, and the whole envelope (chat, message id,
  sender, ciphertext, wrapped keys) is signed with the sender's ECDSA key. The server checks that
  a message is encrypted for exactly the current members, but can neither read nor forge it.
- **Groups:** new members only receive keys for messages sent after they joined.
- **Attachments:** every file is encrypted in the browser with its own AES-256-GCM key. The
  server only stores the ciphertext; the key travels inside the encrypted, signed message.
  Reactions, replies and forwarded messages are encrypted the same way.
- **Verification:** each chat shows a 60-digit security code (like WhatsApp/Signal). Compare it
  with your contact; contacts' key fingerprints are pinned on first use and you get a warning
  (and sending is blocked) if the server ever hands out a different key.
- **Limits:** this is not the Signal protocol – there is no forward secrecy (a stolen password +
  server database exposes old messages), and metadata (who chats with whom, when) is visible to
  the server (also that a message is a reaction, which messages are pinned and the
  disappearing-messages timer). Messages from before v1.1 stay readable and are marked *not encrypted*.

## 🔑 Forgot password: backup codes and e-mail reset

- **Backup codes (keep everything):** after registering – and later in the settings – you get
  10 codes like `K7QF-2M9X-HP4C-ZT8B`, shown **only once** (download them as `.txt` or copy
  them). Each code works once. The browser encrypts the private keys separately with a key
  derived from each code (PBKDF2 + HKDF, 80-bit codes); the server only stores the encrypted
  keys and an Argon2 hash per code. With a code, "Forgot password?" unlocks the keys in the
  browser, encrypts them again with the new password and **all chats stay readable**.
  Generating new codes makes all old ones invalid.
- **E-mail reset (fallback):** a link valid for 60 minutes. Without the password or a code the
  old keys can't be unlocked, so new keys are created: friends, groups and chats stay, but the
  user can't read their **own copy** of old messages anymore (they are hidden for them). The
  other members keep the full history; the old public keys are kept so they can still verify
  old messages. Contacts see a "security key changed" warning, like in WhatsApp.
- **Getting old messages back after an e-mail reset:** the other members see a notice in the
  chat and can press **"Share older messages"** (after accepting the new security key). Their
  browser unwraps the key of every old message it can read and wraps it again for the new keys;
  the server only stores these wrapped keys, the messages stay end-to-end encrypted and keep
  their original signature. This also works for resets from before this feature.

## 🛡️ Two-factor authentication (optional)

In the settings everyone can turn on a second factor for the login:

- **Passkeys** (WebAuthn): a phone, a security key, Windows Hello, Touch ID … On a computer the
  browser offers "use a phone or tablet" and shows a QR code, so the phone works as passkey.
- **Authenticator apps** (TOTP, 6-digit codes): Google/Microsoft Authenticator, Aegis, 1Password …
- **Backup codes** also work as second factor if the device is lost.

With 2FA on, the server only starts a session – and only hands out the encrypted keys – after
the second factor. Adding or removing a factor needs the current password. The e-mail reset is
not possible while 2FA is on (the mailbox alone must not be enough); use a backup code instead.

Passkeys need HTTPS (or `localhost`) and are bound to the domain. Set `PUBLIC_URL` (or
`WEBAUTHN_RP_ID`) in `.env` when SereS runs behind a reverse proxy.

## ✉️ E-mail setup (for password reset links)

SereS sends mails through any SMTP server, configured in `src/backend/.env`:

```bash
SMTP_HOST=localhost          # unset = e-mail reset disabled
SMTP_PORT=25                 # 587 for STARTTLS, 465 for SSL
SMTP_SECURITY=none           # starttls (default), ssl or none
SMTP_USER=                   # optional
SMTP_PASSWORD=               # optional
MAIL_FROM="SereS <no-reply@example.com>"
PUBLIC_URL=https://chat.example.com   # used for the links in the mails
# MAIL_DEBUG=1               # development: print mails to the console instead
```

To run your own send-only mail server on Ubuntu (Postfix + DKIM, no open ports):

```bash
sudo ./deploy/setup-mailserver.sh --domain example.com \
     --public-url https://chat.example.com \
     --seres-env /path/to/SereS/src/backend/.env \
     --test-to you@example.org
```

It prints the DNS records (SPF, DKIM, DMARC) and the reverse DNS (PTR) entry you have to set.
Many hosters block outgoing port 25 until you ask them to unblock it. Instead of your own
server you can also use any SMTP provider (Mailjet, Brevo, Postmark, your mail host, ...).
