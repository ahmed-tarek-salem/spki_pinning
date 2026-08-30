import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:spki_pinning/spki_pinning.dart';
import 'package:test/test.dart';

void main() {
  final expected =
      json.decode(File('test/fixtures/expected_pins.json').readAsStringSync())
          as Map<String, dynamic>;

  for (final entry in expected.entries) {
    test('golden: ${entry.key} matches openssl-computed pin', () {
      final der = Uint8List.fromList(
          File('test/fixtures/${entry.key}.crt.der').readAsBytesSync());
      expect(spkiPinOf(der), equals(entry.value));
    });
  }

  test('fixture coverage sanity', () {
    expect(
        expected.keys,
        containsAll(<String>[
          'localhost_rsa2048',
          'rsa4096',
          'ec_p256',
          'ec_p384',
          'ed25519',
          'v1_rsa2048',
          'unpinned_ip',
          'ca',
        ]));
  });
}
