import 'dart:async';
import 'dart:io';

import 'spki_extractor.dart';

/// Connects to [host]:[port], reads the leaf certificate presented during
/// the handshake, and returns its `sha256/<b64>` SPKI pin. The handshake is
/// deliberately aborted after the certificate is read - this is a
/// measurement, not a trust decision, and no request is ever sent.
///
/// The probe uses the same TLS channel the pinned `HttpClient` uses, which
/// matters: servers holding multiple certificates (RSA + ECDSA is common)
/// choose per connection based on the client's TLS parameters, so a pin
/// measured through a different stack (e.g. openssl) can differ from the
/// one a Dart app will actually be shown.
///
/// Verify the result out-of-band (from the server configuration you
/// control): the network you measure from could itself be under attack.
Future<String> fetchPinOf(String host, int port,
    {Duration timeout = const Duration(seconds: 10)}) async {
  String? observed;
  final client = HttpClient(context: SecurityContext(withTrustedRoots: false))
    ..connectionTimeout = timeout
    ..badCertificateCallback = (cert, h, p) {
      observed = spkiPinOf(cert.der);
      return false; // measurement only - never complete the connection
    };
  try {
    final request = await client
        .getUrl(Uri(scheme: 'https', host: host, port: port, path: '/'))
        .timeout(timeout);
    await request.close();
  } on HandshakeException {
    // Expected: the callback aborts the handshake after reading the cert.
  } on TimeoutException {
    // Fall through to the null check below.
  } finally {
    client.close(force: true);
  }
  final pin = observed;
  if (pin == null) {
    throw const HandshakeException('could not read a certificate');
  }
  return pin;
}
