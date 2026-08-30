# spki_pinning (monorepo)

True **SPKI (public-key) TLS pinning** for Dart & Flutter — survives
certificate renewal, integrates with any HTTP client, fail-closed, with
backup pins. Pure Dart: no platform channels, works on Android, iOS,
desktop, and server-side Dart.

| Package | What it is |
|---|---|
| [`packages/spki_pinning`](packages/spki_pinning) | Core: pin verification inside the TLS handshake, pinned `HttpClient` factory, pin tooling |
| [`packages/spki_pinning_dio`](packages/spki_pinning_dio) | Dio binding: routing `HttpClientAdapter` |
| [`packages/spki_pinning_http`](packages/spki_pinning_http) | package:http binding: routing `Client` |

Start with the [core package README](packages/spki_pinning/README.md) —
it carries the full pitch, quickstarts, rotation playbook, and security
model.

## Development

```bash
./tool/generate_fixtures.sh          # regenerate TLS test fixtures
cd packages/<pkg> && dart test       # per-package tests
```

No git commits are made by automation in this repo; commits are always
explicit and owner-driven.
