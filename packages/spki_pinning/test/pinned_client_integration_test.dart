import 'dart:convert';
import 'dart:io';

import 'package:spki_pinning/spki_pinning.dart';
import 'package:test/test.dart';

import 'support/tls_harness.dart';

void main() {
  late TlsTestServer server;
  late String correctPin;
  const wrongPin = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  setUpAll(() async {
    server = await TlsTestServer.start(
        certPemPath: 'test/fixtures/localhost_rsa2048.crt.pem',
        keyPemPath: 'test/fixtures/localhost_rsa2048.key.pem');
    final pins =
        json.decode(File('test/fixtures/expected_pins.json').readAsStringSync())
            as Map<String, dynamic>;
    correctPin = pins['localhost_rsa2048'] as String;
  });

  tearDownAll(() => server.close());

  Future<String> get(HttpClient client, Uri url) async {
    final req = await client.getUrl(url);
    final res = await req.close();
    return utf8.decodeStream(res);
  }

  test('correct pin accepted — even self-signed (pin IS the trust anchor)',
      () async {
    final p = SpkiPinning(pins: {
      'localhost': [correctPin],
    });
    final client = p.createPinnedHttpClient();
    expect(await get(client, server.uri('localhost', '/ok')), 'ok');
    client.close();
  });

  test('backup pin accepted', () async {
    final p = SpkiPinning(pins: {
      'localhost': [wrongPin, correctPin],
    });
    final client = p.createPinnedHttpClient();
    expect(await get(client, server.uri('localhost', '/ok')), 'ok');
    client.close();
  });

  test('wrong pin rejected BEFORE any request byte reaches the server',
      () async {
    final before = server.requestCount;
    final events = <PinningEvent>[];
    final p = SpkiPinning(pins: {
      'localhost': [wrongPin],
    }, observer: events.add);
    final client = p.createPinnedHttpClient();
    await expectLater(get(client, server.uri('localhost', '/ok')),
        throwsA(isA<HandshakeException>()));
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(server.requestCount, before, reason: 'no request may be sent');
    expect(events.any((e) => e.type == PinningEventType.pinMismatch), isTrue);
    expect(p.lastRejectionFor('localhost')!.observedPin, correctPin);
    client.close(force: true);
  });

  test('unpinned host rejected on the pinned channel', () async {
    final p = SpkiPinning(pins: {
      'other.example': [correctPin],
    });
    final client = p.createPinnedHttpClient();
    await expectLater(get(client, server.uri('localhost', '/ok')),
        throwsA(isA<HandshakeException>()));
    client.close(force: true);
  });
}
