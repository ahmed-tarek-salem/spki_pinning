import 'dart:convert';
import 'dart:io';

import 'package:spki_pinning/spki_pinning.dart';
import 'package:test/test.dart';

import 'support/tls_harness.dart';

void main() {
  test('fetchPinOf returns the golden pin of a live server', () async {
    final server = await TlsTestServer.start(
        certPemPath: 'test/fixtures/localhost_rsa2048.crt.pem',
        keyPemPath: 'test/fixtures/localhost_rsa2048.key.pem');
    final pins =
        json.decode(File('test/fixtures/expected_pins.json').readAsStringSync())
            as Map<String, dynamic>;
    expect(
        await fetchPinOf('localhost', server.port), pins['localhost_rsa2048']);
    await server.close();
  });

  test('fetchPinOf fails on closed port', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = server.port;
    await server.close();
    await expectLater(
        fetchPinOf('127.0.0.1', port, timeout: const Duration(seconds: 2)),
        throwsA(isA<Exception>()));
  });
}
