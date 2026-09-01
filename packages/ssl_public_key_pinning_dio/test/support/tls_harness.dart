import 'dart:io';

/// A local HTTPS server for integration tests. Routes:
/// `/ok` → 200 `ok`; `/redirect?code=<n>&to=<url>` → redirect;
/// `/echo-auth` → the `authorization` header or `none`;
/// `/echo-method` → the request method.
class TlsTestServer {
  TlsTestServer._(this._server);

  final HttpServer _server;
  int requestCount = 0;

  static Future<TlsTestServer> start({
    required String certPemPath,
    required String keyPemPath,
  }) async {
    final ctx = SecurityContext()
      ..useCertificateChain(certPemPath)
      ..usePrivateKey(keyPemPath);
    final server =
        await HttpServer.bindSecure(InternetAddress.loopbackIPv4, 0, ctx);
    final harness = TlsTestServer._(server);
    server.listen(harness._handle);
    return harness;
  }

  int get port => _server.port;

  Uri uri(String host, String path, [Map<String, String>? query]) => Uri(
      scheme: 'https',
      host: host,
      port: port,
      path: path,
      queryParameters: query);

  void _handle(HttpRequest req) {
    requestCount++;
    final res = req.response;
    switch (req.uri.path) {
      case '/ok':
        res.write('ok');
      case '/echo-auth':
        res.write(req.headers.value('authorization') ?? 'none');
      case '/echo-cookie':
        res.write(req.headers.value('cookie') ?? 'none');
      case '/echo-method':
        res.write(req.method);
      case '/redirect':
        final code = int.parse(req.uri.queryParameters['code'] ?? '302');
        res
          ..statusCode = code
          ..headers.set('location', req.uri.queryParameters['to']!);
      default:
        res.statusCode = 404;
    }
    res.close();
  }

  Future<void> close() => _server.close(force: true);
}
