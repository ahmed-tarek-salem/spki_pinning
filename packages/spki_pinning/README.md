# spki_pinning

True **SPKI (public-key) TLS pinning** for Dart & Flutter — survives
certificate renewal, integrates with any HTTP client, fail-closed, with
backup-pin support. Pure Dart: no platform channels, no native code, works
on Android, iOS, desktop, and server-side Dart.

## Why this package

Existing pinning packages force a trade-off this package removes:

| | SPKI (key) pinning | Works with your HTTP client |
|---|---|---|
| `http_certificate_pinning` | ✗ certificate fingerprint — breaks on every cert renewal | ✓ Dio & http |
| `smart_dev_pinning_plugin` | ✓ | ✗ owns the request natively |
| `public_key_pinning` | ✗ certificate-level despite the name (unmaintained) | — |
| **`spki_pinning`** | ✓ | ✓ Dio, http, or raw `HttpClient` |

**SPKI pinning** hashes the server's *public key* (`SubjectPublicKeyInfo`),
not the certificate. When the certificate is renewed with the same key —
which is what Let's Encrypt and most managed TLS setups do every 60–90
days — the pin keeps working. The pin only changes when the *key* changes,
which you control and plan for with a backup pin.

Pins use the standard `sha256/<base64>` format, interchangeable with
OkHttp's `CertificatePinner` and TrustKit configurations.

## Quickstart

### With Dio — [`spki_pinning_dio`](https://pub.dev/packages/spki_pinning_dio)

```dart
final dio = Dio()
  ..httpClientAdapter = SpkiPinningAdapter(SpkiPinning(pins: {
    'api.example.com': [
      'sha256/AAAA...=', // current key
      'sha256/BBBB...=', // backup key (see Rotation below)
    ],
  }));
```

### With package:http — [`spki_pinning_http`](https://pub.dev/packages/spki_pinning_http)

```dart
final client = SpkiPinningClient(SpkiPinning(pins: {
  'api.example.com': ['sha256/AAAA...=', 'sha256/BBBB...='],
}));
```

### With raw dart:io (this package alone)

```dart
final pinning = SpkiPinning(pins: {
  'api.example.com': ['sha256/AAAA...=', 'sha256/BBBB...='],
});
final client = pinning.createPinnedHttpClient(); // pinned hosts ONLY
```

The bindings route per host: pinned hosts go through the pin check,
every other host goes through normal CA validation. The raw pinned
`HttpClient` serves pinned hosts only and rejects everything else
(fail-closed).

## Getting your pins

```bash
dart run spki_pinning:pin api.example.com
```

or with openssl:

```bash
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

**Verify pins out-of-band** — from the server configuration you control,
not just from the network, which could itself be under attack while you
measure.

**Pin every key the server can present.** Many servers (GitHub, most CDNs)
hold multiple certificates (RSA + ECDSA is common) and choose per
connection based on the client's TLS parameters — a pin measured through
openssl can differ from the one your app is actually shown. The bundled
`dart run spki_pinning:pin` tool measures through the same TLS stack Dart
apps use, which is why it is the recommended way to read pins; still, ask
your server operator for the full set of live public keys and pin them
all.

## Rotation playbook

1. Always ship **at least two pins** per host: the current key and a
   backup key generated ahead of time and stored offline.
2. To rotate: activate the backup key on the server. Existing app versions
   keep working (the backup pin matches).
3. Ship the next app release with a new backup pin. Repeat.

A pin matches if **any** pin in the host's list matches — that is what
makes rotation possible without a forced update.

## Observability

```dart
SpkiPinning(
  pins: {...},
  observer: (event) => log.info('$event'),
)
```

Events: `accepted`, `pinMismatch` (includes the observed pin — handy
during setup), `unpinnedHost`, `parseFailure`. The library never logs by
itself, and observer exceptions can never affect the handshake decision.

## Security model

**Defends against:** man-in-the-middle attackers presenting fraudulent
*CA-valid* certificates for your pinned hosts — a compromised or coerced
CA, or a rogue root installed on the device (corporate TLS interception).
The check runs during the TLS handshake: on mismatch, **zero request
bytes** (headers, tokens, body) ever leave the app.

**Does not defend against:** an attacker with code execution or
instrumentation on the device itself (Frida-class tooling defeats *any*
in-process pinning, including native implementations), or a compromised
server private key.

**Known limitations, by design:**

- **The pin replaces CA validation for pinned hosts.** The pin *is* the
  trust anchor: a pinned host is accepted purely by key match (an attacker
  would need the server's private key to complete the handshake). This
  also means client-side expiry checks do not apply to pinned hosts.
- **Leaf pinning only.** Dart exposes only the leaf certificate, so
  pinning an intermediate CA's key (OkHttp-style) is not possible. Backup
  pins cover the rotation scenarios intermediate pinning is used for.
- **Per-host exact matching** (case-insensitive, port-agnostic). Wildcard
  patterns are on the roadmap.
- Unpinned hosts are only CA-validated when reached through the routing
  bindings (`spki_pinning_dio` / `spki_pinning_http`); the raw pinned
  client rejects them instead.

**Redirect safety:** the bindings follow redirects themselves and re-route
every hop, so a redirect can never carry a request across the pin boundary
unchecked; the `Authorization` header is dropped when a redirect changes
host.

## Errors

A failed pin check surfaces as:

- Dio: `DioException` with type `badCertificate` and
  `error is SpkiPinningException`.
- http: `SpkiPinningException`.
- Raw `HttpClient`: `HandshakeException` (the `dart:io` callback API only
  carries a boolean); details arrive via the observer.

Malformed pins throw `ArgumentError` at `SpkiPinning` construction — bad
configuration fails at startup, not at first request.
