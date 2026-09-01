import 'dart:io';

/// Generates a fresh test CA and a CA-signed leaf for `127.0.0.1` at test
/// time (via the system `openssl`). Freshly generated because platform
/// verifiers (macOS SecTrust in particular) require server certs to have
/// short validity (≤398 days) and a `serverAuth` EKU - committing such a
/// fixture would create an expiry time-bomb in the repo.
class TestCa {
  TestCa._(this.dir);

  final Directory dir;

  String get caCertPath => '${dir.path}/ca.crt.pem';
  String get leafCertPath => '${dir.path}/leaf.crt.pem';
  String get leafKeyPath => '${dir.path}/leaf.key.pem';

  static Future<TestCa> generate() async {
    final dir = await Directory.systemTemp.createTemp('spki_test_ca');
    final d = dir.path;

    Future<void> ssl(List<String> args) async {
      final r = await Process.run('openssl', args);
      if (r.exitCode != 0) {
        throw StateError('openssl ${args.first} failed: ${r.stderr}');
      }
    }

    await ssl([
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-keyout',
      '$d/ca.key.pem',
      '-out',
      '$d/ca.crt.pem',
      '-days',
      '397',
      '-nodes',
      '-subj',
      '/CN=ssl_public_key_pinning Test CA',
    ]);
    await ssl([
      'req',
      '-new',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      '$d/leaf.key.pem',
      '-out',
      '$d/leaf.csr',
      '-subj',
      '/CN=127.0.0.1',
    ]);
    await File('$d/leaf.ext').writeAsString('subjectAltName=IP:127.0.0.1\n'
        'extendedKeyUsage=serverAuth\n'
        'basicConstraints=CA:FALSE\n');
    await ssl([
      'x509',
      '-req',
      '-in',
      '$d/leaf.csr',
      '-CA',
      '$d/ca.crt.pem',
      '-CAkey',
      '$d/ca.key.pem',
      '-CAcreateserial',
      '-days',
      '397',
      '-out',
      '$d/leaf.crt.pem',
      '-extfile',
      '$d/leaf.ext',
    ]);
    return TestCa._(dir);
  }

  Future<void> cleanup() => dir.delete(recursive: true);
}
