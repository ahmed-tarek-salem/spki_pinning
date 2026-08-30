# spki_pinning_dio

Dio binding for [`spki_pinning`](https://pub.dev/packages/spki_pinning):
true **SPKI (public-key) TLS pinning** that survives certificate renewal,
fail-closed, with backup pins — as a drop-in `HttpClientAdapter`.

```dart
import 'package:dio/dio.dart';
import 'package:spki_pinning_dio/spki_pinning_dio.dart';

final dio = Dio()
  ..httpClientAdapter = SpkiPinningAdapter(SpkiPinning(pins: {
    'api.example.com': [
      'sha256/AAAA...=', // current key
      'sha256/BBBB...=', // backup key
    ],
  }));
```

- Requests to pinned hosts are verified against the SPKI pin **during the
  TLS handshake** — on mismatch nothing is ever sent, and you get a
  `DioException` of type `badCertificate` wrapping a `SpkiPinningException`.
- Requests to every other host go through a normal CA-validated adapter
  (injectable via `innerAdapter`).
- Redirects are followed hop-by-hop with re-routing, so a redirect can
  never cross the pin boundary unchecked.

Generate pins with `dart run spki_pinning:pin <host>`. For the full story
(rotation, security model, limitations), see the
[`spki_pinning` README](https://pub.dev/packages/spki_pinning).
