# Matrix tab

The Matrix tab is a browser client built on `matrix-js-sdk` 44.0.0. It is bundled separately from SereS's existing frontend because the Matrix SDK and its Rust/WASM crypto runtime are much larger than the rest of the app.

## Build

From this directory, run:

```sh
npm ci
npm run typecheck
npm test
npm run build
```

The build writes `src/public/matrix.js`, copies the Rust crypto runtime to `src/public/pkg/`, and copies the Apache 2.0 license texts to `src/public/licenses/`. Commit those generated public assets with frontend changes so a deployed SereS instance does not need to install Matrix dependencies at runtime.

## Login and encryption

Matrix uses a separate account and homeserver from SereS. Enter the homeserver URL, check discovery, then sign in with password or a homeserver-advertised legacy SSO flow. OAuth-only sign-in is not implemented yet. The Matrix access and refresh tokens are held in `sessionStorage` for the browser tab; the homeserver, user ID, and device ID are kept in `localStorage` so the account can be identified again after a reload. Sign-in is required again after the tab's session storage is cleared.

End-to-end encryption uses the SDK's Rust crypto implementation and its browser IndexedDB store, isolated by homeserver, user, and device. SereS limits the crypto store to one open Matrix tab per device with the Web Locks API. Matrix rooms created from SereS are private and encrypted by default. File attachments up to 20 MB are encrypted separately before upload, including attachments sent in threads. Spaces are created as Matrix `m.space` rooms, and rooms added under a selected Space receive both parent and child state events. Device verification and key backup management are not included yet; use another trusted Matrix client for those recovery steps.

## Calls

The room toolbar offers legacy Matrix 1:1 voice and video calls through the SDK. These use normal browser WebRTC permissions and depend on the homeserver's call signaling and TURN setup.

MatrixRTC opens the hosted Element Call app in a new tab. It requires a homeserver with MatrixRTC and a configured LiveKit transport; Element Call signs into Matrix separately because SereS does not pass its access token to another origin. A Jitsi widget can also be added to a room, but Jitsi is a separate service and its media is not Matrix end-to-end encrypted.

## Third-party licenses

`matrix-js-sdk` and `@matrix-org/matrix-sdk-crypto-wasm` are Apache 2.0 licensed. Their license texts ship under `src/public/licenses/` when the Matrix bundle is built.

The regression suite uses a simulated browser DOM for room switching, draft safety, account isolation, notifications and calls. It also tests attachment encryption and tamper detection with the actual Rust/WASM runtime. Live federation and calls still require testing against a configured homeserver.
