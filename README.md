# ssl_public_key_pinning (monorepo)

True **SPKI (public-key) TLS certificate pinning** for Dart & Flutter,
often called SSL pinning. Survives certificate renewal, integrates with any
HTTP client, fail-closed, with backup pins. Pure Dart: no platform channels,
works on Android, iOS, desktop, and server-side Dart.

| Package | What it is |
|---|---|
| [`packages/ssl_public_key_pinning`](packages/ssl_public_key_pinning) | Core: pin verification inside the TLS handshake, pinned `HttpClient` factory, pin tooling |
| [`packages/ssl_public_key_pinning_dio`](packages/ssl_public_key_pinning_dio) | Dio binding: routing `HttpClientAdapter` |
| [`packages/ssl_public_key_pinning_http`](packages/ssl_public_key_pinning_http) | package:http binding: routing `Client` |

Start with the [core package README](packages/ssl_public_key_pinning/README.md) -
it carries the full pitch, quickstarts, rotation playbook, and security
model.

## Development

```bash
./tool/generate_fixtures.sh          # regenerate TLS test fixtures
cd packages/<pkg> && dart test       # per-package tests
```
