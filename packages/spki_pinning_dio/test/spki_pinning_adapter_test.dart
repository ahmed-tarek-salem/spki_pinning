import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:spki_pinning_dio/spki_pinning_dio.dart';
import 'package:test/test.dart';

import 'support/test_ca.dart';
import 'support/tls_harness.dart';

void main() {
  late TlsTestServer pinnedServer; // cert: localhost_rsa2048, host: localhost
  late TlsTestServer plainServer; // cert: fresh CA-signed, host: 127.0.0.1
  late TestCa testCa;
  late String correctPin;
  const wrongPin = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  HttpClientAdapter trustingAdapter() =>
      IOHttpClientAdapter(createHttpClient: () {
        final ctx = SecurityContext()
          ..setTrustedCertificatesBytes(
              File(testCa.caCertPath).readAsBytesSync());
        return HttpClient(context: ctx);
      });

  Dio dioWith(List<String> localhostPins, {HttpClientAdapter? inner}) => Dio()
    ..httpClientAdapter = SpkiPinningAdapter(
        SpkiPinning(pins: {'localhost': localhostPins}),
        innerAdapter: inner ?? trustingAdapter());

  setUpAll(() async {
    pinnedServer = await TlsTestServer.start(
        certPemPath: 'test/fixtures/localhost_rsa2048.crt.pem',
        keyPemPath: 'test/fixtures/localhost_rsa2048.key.pem');
    testCa = await TestCa.generate();
    plainServer = await TlsTestServer.start(
        certPemPath: testCa.leafCertPath, keyPemPath: testCa.leafKeyPath);
    final pins =
        json.decode(File('test/fixtures/expected_pins.json').readAsStringSync())
            as Map<String, dynamic>;
    correctPin = pins['localhost_rsa2048'] as String;
  });

  tearDownAll(() async {
    await pinnedServer.close();
    await plainServer.close();
    await testCa.cleanup();
  });

  test('1. routes pinned host through pin check', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(pinnedServer.uri('localhost', '/ok'));
    expect(res.data, 'ok');
    dio.close();
  });

  test(
      '2. wrong pin: DioException.badCertificate wrapping '
      'SpkiPinningException, zero requests reach server', () async {
    final before = pinnedServer.requestCount;
    final dio = dioWith([wrongPin]);
    await expectLater(
        dio.getUri<String>(pinnedServer.uri('localhost', '/ok')),
        throwsA(isA<DioException>()
            .having((e) => e.type, 'type', DioExceptionType.badCertificate)
            .having((e) => e.error, 'error', isA<SpkiPinningException>())));
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(pinnedServer.requestCount, before);
    dio.close();
  });

  test('3. unpinned host goes through inner adapter with CA validation',
      () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(plainServer.uri('127.0.0.1', '/ok'));
    expect(res.data, 'ok');
    dio.close();
  });

  test(
      '4. unpinned host with default inner fails CA validation '
      '(not a pinning error)', () async {
    final dio = dioWith([correctPin], inner: IOHttpClientAdapter());
    await expectLater(
        dio.getUri<String>(plainServer.uri('127.0.0.1', '/ok')),
        throwsA(isA<DioException>().having(
            (e) => e.error, 'error', isNot(isA<SpkiPinningException>()))));
    dio.close();
  });

  test('5. redirect pinned→pinned stays checked', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(pinnedServer
        .uri('localhost', '/redirect', {'code': '302', 'to': '/ok'}));
    expect(res.data, 'ok');
    dio.close();
  });

  test('6. redirect unpinned→pinned re-applies the pin (bypass closed)',
      () async {
    final target = pinnedServer.uri('localhost', '/ok').toString();

    final bad = dioWith([wrongPin]);
    await expectLater(
        bad.getUri<String>(plainServer
            .uri('127.0.0.1', '/redirect', {'code': '302', 'to': target})),
        throwsA(isA<DioException>()
            .having((e) => e.error, 'error', isA<SpkiPinningException>())));
    bad.close();

    final good = dioWith([correctPin]);
    final res = await good.getUri<String>(plainServer
        .uri('127.0.0.1', '/redirect', {'code': '302', 'to': target}));
    expect(res.data, 'ok');
    good.close();
  });

  test('7. redirect pinned→unpinned goes through CA channel', () async {
    final target = plainServer.uri('127.0.0.1', '/ok').toString();
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(pinnedServer
        .uri('localhost', '/redirect', {'code': '302', 'to': target}));
    expect(res.data, 'ok');
    dio.close();
  });

  test('8. 303 converts POST to GET and drops body', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.postUri<String>(
        pinnedServer.uri(
            'localhost', '/redirect', {'code': '303', 'to': '/echo-method'}),
        data: 'payload');
    expect(res.data, 'GET');
    dio.close();
  });

  test('9. 307 preserves method and body', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.postUri<String>(
        pinnedServer.uri(
            'localhost', '/redirect', {'code': '307', 'to': '/echo-method'}),
        data: 'payload');
    expect(res.data, 'POST');
    dio.close();
  });

  test('10. Authorization dropped on cross-host redirect', () async {
    final target = plainServer.uri('127.0.0.1', '/echo-auth').toString();
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        options: Options(headers: {'authorization': 'Bearer x'}));
    expect(res.data, 'none');
    dio.close();
  });

  test('11. Authorization kept on same-host redirect', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': '/echo-auth'}),
        options: Options(headers: {'authorization': 'Bearer x'}));
    expect(res.data, 'Bearer x');
    dio.close();
  });

  test('12. maxRedirects respected', () async {
    final dio = dioWith([correctPin]);
    final loop = pinnedServer.uri('localhost', '/redirect',
        {'code': '302', 'to': '/redirect?code=302&to=%2Fok'});
    await expectLater(
        dio.getUri<String>(loop, options: Options(maxRedirects: 1)),
        throwsA(isA<DioException>()
            .having((e) => e.type, 'type', DioExceptionType.badResponse)));
    dio.close();
  });

  test('13. followRedirects=false returns the 3xx as-is', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': '/ok'}),
        options: Options(followRedirects: false, validateStatus: (_) => true));
    expect(res.statusCode, 302);
    dio.close();
  });

  test('16. Cookie dropped on cross-host redirect', () async {
    final target = plainServer.uri('127.0.0.1', '/echo-cookie').toString();
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        options: Options(headers: {'cookie': 'session=abc'}));
    expect(res.data, 'none');
    dio.close();
  });

  test('17. Authorization dropped on https to http downgrade, same host',
      () async {
    final plain = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    plain.listen((req) {
      req.response
        ..write(req.headers.value('authorization') ?? 'none')
        ..close();
    });
    final target = 'http://localhost:${plain.port}/echo-auth';
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        options: Options(headers: {'authorization': 'Bearer x'}));
    expect(res.data, 'none');
    dio.close();
    await plain.close(force: true);
  });

  test('14. http:// URL passes through inner untouched', () async {
    final plain = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    plain.listen((req) {
      req.response
        ..write('plain')
        ..close();
    });
    final dio = dioWith([correctPin]);
    final res = await dio
        .getUri<String>(Uri.parse('http://127.0.0.1:${plain.port}/anything'));
    expect(res.data, 'plain');
    dio.close();
    await plain.close(force: true);
  });

  test('15. realUri reflects the final hop after redirects', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(pinnedServer
        .uri('localhost', '/redirect', {'code': '302', 'to': '/ok'}));
    expect(res.realUri.path, '/ok');
    dio.close();
  });
}
