# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.1] - 2026-09-06

### Fixed

- Decoding a JWT whose header or payload segment picked up stray whitespace during copy/paste (e.g. a line wrap from a terminal, email, or code block) no longer fails with a spurious "Invalid base64url segment length" error. The segment length used to compute base64url padding was measured before removing whitespace, so a single embedded newline or space — which doesn't change the underlying base64 data at all — could push the length to the wrong value mod 4 and reject an otherwise perfectly valid token. Whitespace is now stripped from each segment before the padding/length check.
