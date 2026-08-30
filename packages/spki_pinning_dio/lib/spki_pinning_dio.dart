/// Dio binding for spki_pinning: a routing [SpkiPinningAdapter].
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:spki_pinning/spki_pinning.dart';

export 'package:spki_pinning/spki_pinning.dart';

const _redirectCodes = {301, 302, 303, 307, 308};

/// A routing [HttpClientAdapter]: requests to pinned hosts go through a
/// pin-enforcing channel (checked during the TLS handshake, fail-closed),
/// everything else through [innerAdapter] with normal CA validation.
///
/// Redirects are resolved inside this adapter so every hop is re-routed —
/// a redirect can never move a request across the pin boundary unchecked.
/// Request bodies are buffered so 307/308 hops can retransmit them.
class SpkiPinningAdapter implements HttpClientAdapter {
  factory SpkiPinningAdapter(
    SpkiPinning pinning, {
    HttpClientAdapter? innerAdapter,
    void Function(HttpClient)? configurePinnedClient,
  }) {
    final pinned = IOHttpClientAdapter(createHttpClient: () {
      final client = pinning.createPinnedHttpClient();
      configurePinnedClient?.call(client);
      return client;
    });
    return SpkiPinningAdapter._(
        pinning, innerAdapter ?? IOHttpClientAdapter(), pinned);
  }

  SpkiPinningAdapter._(this._pinning, this._inner, this._pinned);

  final SpkiPinning _pinning;
  final HttpClientAdapter _inner;
  final IOHttpClientAdapter _pinned;

  bool _usesPinnedChannel(Uri url) =>
      url.scheme == 'https' && _pinning.isPinned(url.host);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    // Buffer the body once so 307/308 hops can retransmit it.
    Uint8List? body;
    if (requestStream != null) {
      final builder = BytesBuilder(copy: false);
      await for (final chunk in requestStream) {
        builder.add(chunk);
      }
      body = builder.takeBytes();
    }

    var url = options.uri;
    var method = options.method;
    var headers = Map<String, dynamic>.of(options.headers);
    var dropContentHeaders = false;
    final followRedirects = options.followRedirects;
    final maxRedirects = followRedirects ? options.maxRedirects : 0;
    final redirects = <RedirectRecord>[];
    var hops = 0;

    while (true) {
      final hopOptions = options.copyWith(
        method: method,
        baseUrl: '',
        path: url.toString(),
        queryParameters: const {},
        headers: headers,
        followRedirects: false,
      );
      if (dropContentHeaders) {
        // copyWith re-applies the original contentType when the headers map
        // has none — undo that for hops converted to GET.
        hopOptions.headers.removeWhere((k, _) {
          final key = k.toLowerCase();
          return key == 'content-length' || key == 'content-type';
        });
      }

      final pinnedHop = _usesPinnedChannel(url);
      ResponseBody response;
      try {
        response = await (pinnedHop ? _pinned : _inner).fetch(
          hopOptions,
          body == null ? null : Stream.value(body),
          cancelFuture,
        );
      } on HandshakeException {
        if (!pinnedHop) rethrow; // a real CA failure, not a pinning one
        throw DioException(
          requestOptions: options,
          type: DioExceptionType.badCertificate,
          error: SpkiPinningException(url.host,
              reason: _pinning.lastRejectionFor(url.host)?.toString()),
        );
      }

      final location = response.headers['location']?.first;
      if (!_redirectCodes.contains(response.statusCode) ||
          location == null ||
          !followRedirects) {
        if (redirects.isNotEmpty) response.redirects = redirects;
        return response;
      }
      if (hops >= maxRedirects) {
        await response.stream.drain<void>();
        throw DioException(
          requestOptions: options,
          type: DioExceptionType.badResponse,
          error: RedirectException('Redirect limit exceeded', const []),
        );
      }
      hops++;
      await response.stream.drain<void>();

      final next = url.resolveUri(Uri.parse(location));
      redirects.add(RedirectRecord(response.statusCode, method, next));
      if ({301, 302, 303}.contains(response.statusCode) &&
          method != 'GET' &&
          method != 'HEAD') {
        method = 'GET';
        body = null;
        dropContentHeaders = true;
        headers = Map.of(headers)
          ..removeWhere((k, _) {
            final key = k.toLowerCase();
            return key == 'content-length' || key == 'content-type';
          });
      }
      if (next.host.toLowerCase() != url.host.toLowerCase()) {
        headers = Map.of(headers)
          ..removeWhere((k, _) => k.toLowerCase() == 'authorization');
      }
      url = next;
    }
  }

  @override
  void close({bool force = false}) {
    _pinned.close(force: force);
    _inner.close(force: force);
  }
}
