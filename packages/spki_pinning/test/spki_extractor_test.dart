import 'dart:typed_data';

import 'package:spki_pinning/spki_pinning.dart';
import 'package:test/test.dart';

Uint8List tlv(int tag, List<int> content) {
  final len = content.length;
  final header = <int>[tag];
  if (len < 0x80) {
    header.add(len);
  } else if (len <= 0xff) {
    header.addAll([0x81, len]);
  } else {
    header.addAll([0x82, len >> 8, len & 0xff]);
  }
  return Uint8List.fromList([...header, ...content]);
}

/// Builds a fake certificate: SEQ( SEQ( [version] serial sig issuer validity
/// subject SPKI ) sigAlg sigValue ).
Uint8List fakeCert({
  bool withVersion = true,
  List<int>? spkiContent,
  int issuerPadding = 0,
}) {
  final spki = tlv(0x30, spkiContent ?? [0x02, 0x01, 0x2a]);
  final tbsChildren = <int>[
    if (withVersion) ...tlv(0xa0, tlv(0x02, [0x02]).toList()),
    ...tlv(0x02, [0x01]), // serialNumber
    ...tlv(0x30, [0x02, 0x01, 0x00]), // signature AlgorithmIdentifier
    ...tlv(0x30, List.filled(issuerPadding, 0x00)), // issuer
    ...tlv(0x30, [0x02, 0x01, 0x00]), // validity
    ...tlv(0x30, []), // subject (empty SEQUENCE)
    ...spki,
  ];
  final tbs = tlv(0x30, tbsChildren);
  return tlv(0x30, [
    ...tbs,
    ...tlv(0x30, []),
    ...tlv(0x03, [0x00])
  ]);
}

/// Offset just past the SPKI inside [cert] (SPKI is the last TBS child in
/// [fakeCert]), found by locating the extracted bytes inside the cert.
int spkiEndOf(Uint8List cert) {
  final spki = extractSpkiDer(cert);
  for (var i = 0; i + spki.length <= cert.length; i++) {
    var match = true;
    for (var j = 0; j < spki.length; j++) {
      if (cert[i + j] != spki[j]) {
        match = false;
        break;
      }
    }
    if (match) return i + spki.length;
  }
  throw StateError('SPKI bytes not found in cert');
}

void main() {
  test('extracts SPKI TLV bytes exactly (v3-style, with [0] version)', () {
    final spki = tlv(0x30, [0x02, 0x01, 0x2a]);
    expect(extractSpkiDer(fakeCert()), equals(spki));
  });

  test('extracts SPKI from v1 certificate (no [0] version tag)', () {
    final spki = tlv(0x30, [0x02, 0x01, 0x2a]);
    expect(extractSpkiDer(fakeCert(withVersion: false)), equals(spki));
  });

  test('handles long-form lengths (issuer > 127 bytes)', () {
    final spki = tlv(0x30, [0x02, 0x01, 0x2a]);
    expect(extractSpkiDer(fakeCert(issuerPadding: 300)), equals(spki));
  });

  test('rejects non-SEQUENCE outer tag', () {
    final cert = fakeCert();
    cert[0] = 0x31;
    expect(() => extractSpkiDer(cert), throwsA(isA<SpkiParseException>()));
  });

  test('rejects wrong serial tag', () {
    final spki = tlv(0x30, [0x02, 0x01, 0x2a]);
    final tbs = tlv(0x30, [
      ...tlv(0x0c, [0x01]),
      ...tlv(0x30, [0x02, 0x01, 0x00]),
      ...tlv(0x30, []),
      ...tlv(0x30, [0x02, 0x01, 0x00]),
      ...tlv(0x30, []),
      ...spki,
    ]);
    final cert = tlv(0x30, [
      ...tbs,
      ...tlv(0x30, []),
      ...tlv(0x03, [0x00])
    ]);
    expect(() => extractSpkiDer(cert), throwsA(isA<SpkiParseException>()));
  });

  test('rejects indefinite length', () {
    final cert = fakeCert();
    cert[1] = 0x80;
    expect(() => extractSpkiDer(cert), throwsA(isA<SpkiParseException>()));
  });

  test('rejects empty input', () {
    expect(
        () => extractSpkiDer(Uint8List(0)), throwsA(isA<SpkiParseException>()));
  });

  test('rejects truncation at every offset up to the SPKI end', () {
    final cert = fakeCert(issuerPadding: 10);
    final spkiEnd = spkiEndOf(cert);
    for (var cut = 0; cut < spkiEnd; cut++) {
      final truncated = Uint8List.fromList(cert.sublist(0, cut));
      expect(
        () => extractSpkiDer(truncated),
        throwsA(isA<SpkiParseException>()),
        reason: 'cut at $cut must throw',
      );
    }
  });

  test('spkiPinOf formats sha256/<b64>', () {
    final pin = spkiPinOf(fakeCert());
    expect(pin, startsWith('sha256/'));
    expect(pin.length, 'sha256/'.length + 44);
  });
}
