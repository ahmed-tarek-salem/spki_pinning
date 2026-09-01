# ssl_public_key_pinning_dio

Dio binding for [`ssl_public_key_pinning`](https://pub.dev/packages/ssl_public_key_pinning):
true **SPKI (public-key) TLS pinning** that survives certificate renewal,
fail-closed, with backup pins - as a drop-in `HttpClientAdapter`.

```dart
import 'package:dio/dio.dart';
import 'package:ssl_public_key_pinning_dio/ssl_public_key_pinning_dio.dart';

final dio = Dio()
  ..httpClientAdapter = PublicKeyPinningAdapter(PublicKeyPinning(pins: {
    'api.example.com': [
      'sha256/AAAA...=', // current key
      'sha256/BBBB...=', // backup key
    ],
  }));
```

- Requests to pinned hosts are verified against the SPKI pin **during the
  TLS handshake** - on mismatch nothing is ever sent, and you get a
  `DioException` of type `badCertificate` wrapping a `PublicKeyPinningException`.
- Requests to every other host go through a normal CA-validated adapter
  (injectable via `innerAdapter`).
- Redirects are followed hop-by-hop with re-routing, so a redirect can
  never cross the pin boundary unchecked.

Generate pins with `dart run ssl_public_key_pinning:pin <host>`. For the full story
(rotation, security model, limitations), see the
[`ssl_public_key_pinning` README](https://pub.dev/packages/ssl_public_key_pinning).
