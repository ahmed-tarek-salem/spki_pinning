import 'package:ssl_public_key_pinning/ssl_public_key_pinning.dart';
import 'package:test/test.dart';

void main() {
  const b64 = 'brZgUhOMhcYUa3zPUX0X8Nt3H7VC0D3oBBk/PZpGDIc=';

  test('parses sha256/ prefixed pin', () {
    final pin = PublicKeyPin('sha256/$b64');
    expect(pin.formatted, 'sha256/$b64');
    expect(pin.digest.length, 32);
  });

  test('accepts bare base64 and normalizes', () {
    expect(PublicKeyPin(b64).formatted, 'sha256/$b64');
  });

  test('rejects invalid base64', () {
    expect(() => PublicKeyPin('sha256/not-base64!!'), throwsArgumentError);
  });

  test('rejects wrong digest length', () {
    expect(() => PublicKeyPin('sha256/AAAA'), throwsArgumentError);
  });

  test('equality by digest', () {
    expect(PublicKeyPin(b64), equals(PublicKeyPin('sha256/$b64')));
    expect({PublicKeyPin(b64), PublicKeyPin('sha256/$b64')}.length, 1);
  });

  test('matchesDigest', () {
    final pin = PublicKeyPin('sha256/$b64');
    expect(pin.matchesDigest(pin.digest), isTrue);
    final wrong = List<int>.from(pin.digest)..[0] ^= 0xff;
    expect(pin.matchesDigest(wrong), isFalse);
  });
}
