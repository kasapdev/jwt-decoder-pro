# JWT Decoder Pro

[![CI](https://github.com/kasapdev/jwt-decoder-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/kasapdev/jwt-decoder-pro/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) ![Vanilla JS](https://img.shields.io/badge/Vanilla-JS-F7DF1E?logo=javascript&logoColor=black)

Decode and inspect JWT headers, claims, and expiry with live countdowns — fast, private, and fully offline.

> A zero-dependency JWT inspector. Paste a token, get instantly decoded header and payload JSON with syntax highlighting, a plain-English claims summary with live expiry countdowns, and clear warnings for risky tokens (`alg: none`, missing signatures) — all in your browser, with nothing ever leaving your machine. **It never verifies the signature and never asks for a secret or key.**

## Overview

JWT Decoder Pro is part of the **Web Utility Suite**. It runs entirely in the browser with no build step, no frameworks, and no network calls — open `index.html` from disk and it works. Paste any JWT and the header and payload segments are base64url-decoded, parsed as JSON, and rendered with the same token-aware syntax highlighting used across the suite. A dedicated claims panel surfaces `alg`, `typ`, `exp`, `iat`, `nbf`, `sub`, `iss`, and `aud` in human-readable form, with live "expires in / expired X ago" countdowns.

## Features

- **Instant decode** — paste a JWT and the header + payload are base64url-decoded (UTF-8 safe) and JSON-parsed live, debounced as you type.
- **Syntax-highlighted JSON** — tokenized keys, strings, numbers, booleans, null, braces and punctuation for both header and payload, all HTML-escaped before rendering.
- **Claims summary** — `alg` and `typ` shown as badges; `exp`, `iat`, `nbf` converted to human-readable local date/time; `sub`, `iss`, `aud` shown directly.
- **Live countdowns** — a ticking "Expires in Xh Ym Zs" / "Expired X ago" next to `exp`, and a matching "Not valid for another…" / "Valid since…" next to `nbf`, updating every second.
- **Security warnings** — a clear, unmissable warning badge when `alg` is `none` or the signature segment is empty/missing.
- **Decode-only, always** — a persistent notice makes clear this tool never verifies signatures and never asks for or accepts a secret/public key. Nothing is sent over the network.
- **Malformed-token handling** — wrong segment count, invalid base64, or invalid JSON all surface a clear error panel instead of a silent failure.
- **Copy** the raw header or payload JSON independently.
- **Load sample** — a realistic sample token to explore the tool.
- **Auto-persist** — your last pasted token is saved to `localStorage` and restored on return (stays entirely local to your browser).
- **Dark & light themes**, fully responsive down to 360px, accessible, and keyboard-driven.

## Installation

No dependencies, no build step.

```bash
git clone https://github.com/kasapdev/jwt-decoder-pro.git
cd jwt-decoder-pro
```

Then simply open `index.html` in any modern browser (double-click it, or `file://` it). That's it.

## Usage

1. Paste a JWT into the input — or click **Sample** to load an example.
2. Read the decoded **Header** and **Payload** panes, syntax-highlighted for readability.
3. Check the **Claims summary** for `alg`/`typ` badges and human-readable `exp`/`iat`/`nbf` with live countdowns.
4. Watch for the red warning badges if the token uses `alg: none` or is missing its signature — both are serious red flags if you encounter them in the wild.
5. **Copy** the header or payload JSON independently, or **Clear** to start over.

## Keyboard Shortcuts

| Action               | Shortcut          |
| -------------------- | ------------------ |
| Decode now             | <kbd>Ctrl/⌘</kbd> + <kbd>Enter</kbd> |
| Clear token           | <kbd>Ctrl/⌘</kbd> + <kbd>K</kbd> |
| Show shortcuts help   | <kbd>?</kbd>        |
| Close dialog          | <kbd>Esc</kbd>      |

## Screenshots

> _Screenshots coming soon._

![screenshot](docs/screenshot-1.png)
![screenshot](docs/screenshot-2.png)

## Roadmap

- [ ] Optional client-side signature verification for HMAC algorithms when a user explicitly pastes their own known secret (opt-in only, clearly separated from the decode view)
- [ ] JWK/JWKS-based verification for RS/ES algorithms
- [ ] Highlight non-standard/custom claims distinctly from registered claims
- [ ] Token history (recent tokens decoded this session, local-only)
- [ ] Encode mode — build a JWT from header/payload JSON for testing

## License

MIT Licensed. Part of the [Web Utility Suite](https://github.com/kasapdev/web-utility-suite).
