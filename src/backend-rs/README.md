# Rust backend

The Axum service is the production backend. It serves the committed frontend from `src/public/`
and keeps the existing `/api/*` routes and response shapes. SQLite remains the relational store;
avatars and encrypted attachment bytes live in SQLite BLOB tables. No new upload writes files to
the data directory.

## Run locally

Install the stable Rust toolchain and run from `src/backend/` so `dotenvy` can read the existing
`.env` file:

```sh
cargo run --manifest-path ../backend-rs/Cargo.toml
```

The service listens on `127.0.0.1:2222` by default. Set `HOST` and `PORT` to change the listener.
`SERES_DATA_DIR` selects the directory containing `users.db` (default `src/backend`), and
`SERES_PUBLIC_DIR` selects the static frontend (default `src/public`).

## Existing installations

The service opens the existing `users.db` in place and applies additive schema migrations. At
first startup it imports pre-database friends, requests, and direct-message histories from
`user_data/` and `chats/`, then copies existing avatars and attachment bytes into SQLite. It leaves
the source files in place as a backup. New and updated records use the database.

Unreadable or corrupt legacy data stops startup and rolls back that import, so it can be retried
after repairing the source. Completed binary imports are recorded in SQLite, so deleting a group
picture does not restore the old backup on the next restart. Email uniqueness is enforced for new
writes, including concurrent registrations; any duplicate addresses in older databases are retained.

Existing WebAuthn records are also supported: the old Flask service stored a base64url COSE public
key, while the Rust service stores a serialized WebAuthn credential. Rust accepts both formats and
rewrites a legacy record into the new format after successful authentication.

## Build and format

```sh
cd src/backend-rs
cargo fmt
cargo check --locked
cargo build --release --locked
```

Password-reset email uses the same `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USER`,
`SMTP_PASSWORD`, `MAIL_FROM`, `MAIL_DEBUG`, and `PUBLIC_URL` settings as the previous service.
Passkeys use `WEBAUTHN_RP_ID` and `PUBLIC_URL` when the service is behind a reverse proxy.
