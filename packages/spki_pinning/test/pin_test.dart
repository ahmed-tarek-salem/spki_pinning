import 'package:spki_pinning/spki_pinning.dart';
import 'package:test/test.dart';

void main() {
  const b64 = 'brZgUhOMhcYUa3zPUX0X8Nt3H7VC0D3oBBk/PZpGDIc=';

  test('parses sha256/ prefixed pin', () {
    final pin = SpkiPin('sha256/$b64');
    expect(pin.formatted, 'sha256/$b64');
    expect(pin.digest.length, 32);
  });

  test('accepts bare base64 and normalizes', () {
    expect(SpkiPin(b64).formatted, 'sha256/$b64');
  });

  test('rejects invalid base64', () {
    expect(() => SpkiPin('sha256/not-base64!!'), throwsArgumentError);
  });

  test('rejects wrong digest length', () {
    expect(() => SpkiPin('sha256/AAAA'), throwsArgumentError);
  });

  test('equality by digest', () {
    expect(SpkiPin(b64), equals(SpkiPin('sha256/$b64')));
    expect({SpkiPin(b64), SpkiPin('sha256/$b64')}.length, 1);
  });

  test('matchesDigest', () {
    final pin = SpkiPin('sha256/$b64');
    expect(pin.matchesDigest(pin.digest), isTrue);
    final wrong = List<int>.from(pin.digest)..[0] ^= 0xff;
    expect(pin.matchesDigest(wrong), isFalse);
  });
}
