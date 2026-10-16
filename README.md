# Bond

**Version:** 0.1.0 · **Phase 1 — Secure 1-to-1 text messenger** · **Status: working end to end; hardening remains**

An invite-only, cross-platform, end-to-end encrypted 1-to-1 messenger. Cryptographic
identity belongs to each *device installation*, not to the account. The backend is an
encrypted store-and-forward relay that never requires plaintext message content.

---

## What this is, precisely

This project uses **three different things** that are often conflated:

| | Protects | Server can read content? |
|---|---|---|
| **Transport encryption** (TLS) | Bytes on the wire | Yes |
| **Application-level encryption** (server-side at rest) | Stolen disks | Yes — it holds the key |
| **End-to-end encryption** (used here) | Content between two devices | **No** |

TLS and E2EE are both used, and neither substitutes for the other. Neither protects a
device that is already compromised.

**Honest limits, up front:** message *content* is protected from the server; *metadata* is
not. The server learns who talks to whom, when, how often, message sizes and IP addresses.
This system is not anonymous, is not metadata-private, and has not been audited — only the
upstream crypto library has. See [docs/security-model.md](docs/security-model.md) for the
full inventory of what the server can and cannot see.

---

## Architecture

```
Flutter client (Android, iOS, Windows, Linux, macOS)
   plaintext + private keys live here, and nowhere else
        |  E2EE envelope over TLS 1.3 / WSS
        v
Caddy -> Node.js + TypeScript + Fastify  (REST + WebSocket)
        |
   PostgreSQL (metadata, public keys, ciphertext, delivery state)
   Redis (presence, connections, rate limits)
```

- **Protocol:** Signal Protocol (X3DH + Double Ratchet) via pub `libsignal` `7.3.1`,
  an FFI binding over Signal's Rust implementation. No custom cryptography anywhere.
- **Identity:** each installation is a distinct cryptographic device with its own identity
  key. Account authentication and device cryptographic identity are deliberately separate.
- **Verification:** safety numbers compared out of band. The server distributes public
  keys but is never an authority on whose they are.

---

## Design

Branding comes from [brand/](brand/) — the mark is the **O of BOND**, cut open with one dot
resting in the opening: the one person let in.

**Flare `#FF4D2E` is the colour of that dot and of nothing else.** Destructive states use
Apple's system red instead, which is close enough to be mistaken for it at a glance — which
is exactly why they are separate tokens in [client/lib/core/theme.dart](client/lib/core/theme.dart).
Spend the red on buttons and the logo's dot becomes just another red thing on the screen.

So the interface is monochrome: ink on paper in light, white on near-black in dark, with
emphasis carried by contrast and spacing rather than hue. The surface language is Apple's
(hairline separators, large radii, Cupertino transitions, no ink ripple) and the chat layout
is the familiar one, because the conversation is the last place to make someone learn a new
idiom.

The launch animation is **Orbit**, ported from `Demo-testing/brand/splash-lab.html` with its
original durations and curves: the dot travels the full circle while the ring appears behind
it as a trail, then settles into the gap it left. See
[client/lib/features/shell/splash.dart](client/lib/features/shell/splash.dart).

---

## Documentation

Read in this order:

| Document | Contents |
|---|---|
| [docs/crypto-design.md](docs/crypto-design.md) | Protocol selection, alternatives rejected and why, key lifecycle, known limitations |
| [docs/threat-model.md](docs/threat-model.md) | Assets, attackers, threats, mitigations, residual risks, the 20 design questions |
| [docs/architecture.md](docs/architecture.md) | System and client/server structure, all flows |
| [docs/security-model.md](docs/security-model.md) | Exactly what the server sees, retention, logging policy |
| [docs/decisions.md](docs/decisions.md) | Decision log and open questions |
| [docs/api.md](docs/api.md) | API reference — written alongside implementation |
| [docs/database.md](docs/database.md) | Schema reference — written alongside implementation |
| [docs/deployment.md](docs/deployment.md) | Deployment — written alongside infrastructure |

---

## Current state

- [x] 1. Repository structure
- [x] 2. Architecture documentation
- [x] 3. Threat model
- [x] 4. Crypto library selected **and validated** — adversarial tests pass on Windows
      x64, including ratchet survival across a real process restart. One item remains
      open (a mobile build); see [docs/crypto-design.md](docs/crypto-design.md)
- [x] 5. Backend authentication — register (invite-controlled, env-gated bootstrap),
      login, refresh rotation with reuse detection, logout
- [x] 6-13. **Backend complete** — devices, invitations, prekey distribution, contacts,
      encrypted envelopes, message API, WebSocket delivery, offline queue
- [x] 14-16. **Flutter client complete** — crypto service, DPAPI secure storage,
      encrypted local database, REST + WebSocket clients with reconnect, the full UI,
      and client-side device revocation
- [x] **MVP vertical slice passing** — two independent installations complete
      register → invite → accept → verify → encrypted send → decrypt → receipts →
      offline delivery across a restart → revocation, against a live server with
      nothing stubbed
- [ ] 17-20. Security suite (4 categories still missing), threat-model review,
      dependency audit

**103 tests green:** 48 client, 55 server. Typecheck clean on both.

See [docs/roadmap.md](docs/roadmap.md) for the full checklist.

### Watch it work

```bash
docker compose --env-file infra/.env -f infra/docker-compose.yml up -d
cd server && ./node_modules/.bin/tsx --env-file=.env src/database/migrate.ts
cd server && ./node_modules/.bin/tsx --env-file=.env scripts/demo-journey.ts
```

The demo drives a real server over real HTTP and a real WebSocket through the whole
journey — register, invite, accept, device provisioning, prekey exchange, verification,
encrypted send, real-time notification, receipts, offline delivery across a reconnect,
authorisation refusals and device revocation — and prints what the server database holds
while a message is in flight. It truncates the database it points at, so development only.

### Install it

```powershell
.\scripts\install-desktop.ps1 -Build
```

Builds the release, copies it to `%LOCALAPPDATA%\Bond`, and puts a shortcut on the Desktop
and in the Start menu using the brand icon. No elevation, no registry, and **not** added to
Windows startup unless you pass `-AddToStartup`.

It installs a copy rather than shortcutting `build/` on purpose: `flutter clean` deletes
that directory and every rebuild replaces the exe while it may be running, so a shortcut
into it breaks the first time the project is cleaned. Re-run the script after a rebuild to
update the installed copy.

A second, independent installation gets its own icon:

```powershell
.\scripts\install-desktop.ps1 -Profile two
```

### Run it from source

> **Windows Developer Mode must be on.** Flutter needs symlink support to build with
> plugins, and refuses without it. Run `start ms-settings:developers` from an elevated
> prompt and switch Developer Mode on. The test suites do **not** need it.

Two installations can run side by side on one machine — each profile gets its own
encrypted database and its own DPAPI-protected key:

```powershell
cd client
flutter run -d windows --dart-define=BOND_PROFILE=alice
flutter run -d windows --dart-define=BOND_PROFILE=bob
```

Point them elsewhere with `--dart-define=BOND_SERVER=https://host`; the default is
`http://127.0.0.1:3000`.

To create the first account, the server needs the bootstrap path enabled — registration
is invite-only, so nobody can invite user #1:

```bash
cd server && ALLOW_BOOTSTRAP_ACCOUNT=true ./node_modules/.bin/tsx --env-file=.env src/server.ts
```

Register Alice with the invitation field left empty, then invite Bob from her client.
Turn bootstrap back off afterwards.

### Tests

```bash
cd server && ./node_modules/.bin/vitest run        # 55 integration tests (needs the compose stack)
cd server && ./node_modules/.bin/tsc -p tsconfig.json --noEmit
cd client && flutter test                          # 48 tests
cd client && flutter analyze
```

The client suite includes `test/vertical_slice_test.dart`, which runs the whole journey
against a live server. It **skips** when no server is reachable, so it is safe to run
offline. To include it:

```bash
docker compose --env-file infra/.env -f infra/docker-compose.yml up -d
cd server && ./node_modules/.bin/tsx --env-file=.env src/database/migrate.ts
cd server && ./node_modules/.bin/tsx --env-file=.env scripts/reset-dev.ts
cd server && ALLOW_BOOTSTRAP_ACCOUNT=true ./node_modules/.bin/tsx --env-file=.env src/server.ts
cd client && flutter test test/vertical_slice_test.dart
```

The reset is required rather than tidy: the bootstrap path refuses once any user exists.

### Toolchain

Node 24.14 · npm 11.15 · Docker 29.3 · PostgreSQL 18.3 (local, port 5432) · git 2.53 ·
**Flutter 3.47.5 / Dart 3.13.4** at `C:\dev\flutter` · Visual Studio Build Tools 2026 with
the C++ x64 toolchain (sufficient for Windows desktop; no full Visual Studio needed).

Android tooling is deliberately **not** installed — the MVP targets Windows desktop first.

### Local development

```bash
# Postgres + Redis (Postgres on host port 5433 to avoid a local 5432 install)
docker compose --env-file infra/.env -f infra/docker-compose.yml up -d

# Apply migrations
cd server && ./node_modules/.bin/tsx --env-file=.env src/database/migrate.ts
```

---

## Non-negotiable rules

These are load-bearing. Breaking one breaks the security model, not just the style guide.

1. Never invent cryptography. Every primitive comes from the selected library.
2. Private keys never leave the device, and never enter PostgreSQL, logs, or crash reports.
3. No `plaintext_message` column, no `message_search_text` column, no plaintext-derived index.
4. No application-wide or shared master key for message content.
5. Never log plaintext, private keys, passwords, tokens, or invitation tokens.
6. Authorisation is decided server-side from the authenticated subject, never from
   client-supplied IDs.
7. Fail closed on security-sensitive operations. Never silently downgrade encryption or
   accept a changed identity key.
8. No secrets in source or in git. Environment only.
9. Cryptographic calls never appear in Flutter widgets — only via `services/crypto`.
10. Do not call this system secure because it has encryption. Say what is protected, from
    whom, and what is not.

## Out of scope for Phase 1

Group chats, voice/video, attachments, images, stories, channels, reactions, GIFs, message
editing, forwarding, disappearing messages, federation, anonymous accounts, web client,
public user discovery, social features, multi-device sync, key backup, push notifications,
sealed sender.
