// Self-demonstrating example: probes the live SPKI pin of a host, performs
// a pinned request with it (accepted), then corrupts the pin and shows the
// fail-closed rejection.
//
// NOTE: probing the pin over the network is fine for a demo, but in
// production you must obtain pins out-of-band (from the server
// configuration you control) and ship them statically, with a backup pin
// for your next key.
import 'dart:convert';
import 'dart:io';

import 'package:spki_pinning/spki_pinning.dart';

Future<void> main() async {
  const host = 'api.github.com';

  // 1. Probe the current pin (demo only — verify out-of-band in production).
  final pin = await fetchPinOf(host, 443);
  print('observed pin for $host: $pin');

  // 2. Pinned request with the correct pin.
  final pinning = SpkiPinning(
    pins: {
      host: [pin],
    },
    observer: (event) => print('  [observer] $event'),
  );
  final client = pinning.createPinnedHttpClient();
  final req = await client.getUrl(Uri.https(host, '/zen'));
  final res = await req.close();
  print(
      'pinned request: HTTP ${res.statusCode} — ${await utf8.decodeStream(res)}');
  client.close();

  // 3. Same request with a corrupted pin: rejected during the handshake,
  //    before a single request byte leaves the machine.
  final corrupted = pin.replaceRange(10, 11, pin[10] == 'A' ? 'B' : 'A');
  final badPinning = SpkiPinning(
    pins: {
      host: [corrupted],
    },
    observer: (event) => print('  [observer] $event'),
  );
  final badClient = badPinning.createPinnedHttpClient();
  try {
    await badClient.getUrl(Uri.https(host, '/zen'));
    print('UNEXPECTED: corrupted pin was accepted');
  } on HandshakeException {
    print('corrupted pin: rejected fail-closed, as designed');
  } finally {
    badClient.close(force: true);
  }
}
