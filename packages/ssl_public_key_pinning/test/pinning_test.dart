import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ssl_public_key_pinning/ssl_public_key_pinning.dart';
import 'package:test/test.dart';

void main() {
  final der = Uint8List.fromList(
      File('test/fixtures/localhost_rsa2048.crt.der').readAsBytesSync());
  final pins =
      json.decode(File('test/fixtures/expected_pins.json').readAsStringSync())
          as Map<String, dynamic>;
  final correctPin = pins['localhost_rsa2048'] as String;
  const wrongPin = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  test('constructor rejects malformed pin at startup', () {
    expect(
        () => PublicKeyPinning(pins: {
              'a.com': ['garbage!'],
            }),
        throwsArgumentError);
  });

  test('constructor rejects empty pin list', () {
    expect(() => PublicKeyPinning(pins: {'a.com': []}), throwsArgumentError);
  });

  test('accepts matching pin, emits accepted event', () {
    final events = <PinningEvent>[];
    final p = PublicKeyPinning(pins: {
      'API.Example.com': [correctPin],
    }, observer: events.add);
    expect(p.checkDer(der, 'api.example.com', 443), isTrue);
    expect(events.single.type, PinningEventType.accepted);
  });

  test('backup pin semantics: any match accepts', () {
    final p = PublicKeyPinning(pins: {
      'a.com': [wrongPin, correctPin],
    });
    expect(p.checkDer(der, 'a.com', 443), isTrue);
  });

  test('mismatch rejects, event carries observed pin', () {
    final events = <PinningEvent>[];
    final p = PublicKeyPinning(pins: {
      'a.com': [wrongPin],
    }, observer: events.add);
    expect(p.checkDer(der, 'a.com', 443), isFalse);
    expect(events.single.type, PinningEventType.pinMismatch);
    expect(events.single.observedPin, correctPin);
    expect(p.lastRejectionFor('a.com')!.type, PinningEventType.pinMismatch);
  });

  test('unpinned host rejects fail-closed', () {
    final events = <PinningEvent>[];
    final p = PublicKeyPinning(pins: {
      'a.com': [correctPin],
    }, observer: events.add);
    expect(p.checkDer(der, 'other.com', 443), isFalse);
    expect(events.single.type, PinningEventType.unpinnedHost);
  });

  test('garbage DER rejects with parseFailure', () {
    final events = <PinningEvent>[];
    final p = PublicKeyPinning(pins: {
      'a.com': [correctPin],
    }, observer: events.add);
    expect(p.checkDer(Uint8List.fromList([1, 2, 3]), 'a.com', 443), isFalse);
    expect(events.single.type, PinningEventType.parseFailure);
  });

  test('observer exceptions are swallowed', () {
    final p = PublicKeyPinning(pins: {
      'a.com': [correctPin],
    }, observer: (_) => throw StateError('boom'));
    expect(p.checkDer(der, 'a.com', 443), isTrue);
  });

  test('isPinned is case-insensitive', () {
    final p = PublicKeyPinning(pins: {
      'A.com': [correctPin],
    });
    expect(p.isPinned('a.COM'), isTrue);
    expect(p.isPinned('b.com'), isFalse);
  });

  test('successful check clears lastRejectionFor', () {
    final p = PublicKeyPinning(pins: {
      'a.com': [correctPin],
    });
    expect(p.checkDer(Uint8List.fromList([1, 2, 3]), 'a.com', 443), isFalse);
    expect(p.lastRejectionFor('a.com'), isNotNull);
    expect(p.checkDer(der, 'a.com', 443), isTrue);
    expect(p.lastRejectionFor('a.com'), isNull);
  });

  test('createPinnedHttpClient returns configured client', () {
    final p = PublicKeyPinning(pins: {
      'a.com': [correctPin],
    });
    final c = p.createPinnedHttpClient();
    expect(c, isA<HttpClient>());
    c.close();
  });
}
