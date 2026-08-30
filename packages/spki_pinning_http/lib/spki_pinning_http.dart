/// package:http binding for spki_pinning: a routing [SpkiPinningClient].
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:spki_pinning/spki_pinning.dart';

export 'package:spki_pinning/spki_pinning.dart';

const _redirectCodes = {301, 302, 303, 307, 308};

/// A routing [http.Client]: requests to pinned hosts go through a
/// pin-enforcing channel (checked during the TLS handshake, fail-closed);
/// all other requests go through [inner] with normal CA validation.
///
/// Redirects are followed manually so every hop is re-routed — a redirect
/// can never move a request across the pin boundary unchecked. Request
/// bodies are buffered so 307/308 hops can retransmit them (streaming
/// bodies are buffered too — the same trade-off OkHttp makes for
/// retriable bodies).
class SpkiPinningClient extends http.BaseClient {
  SpkiPinningClient(
    this._pinning, {
    http.Client? inner,
    void Function(HttpClient)? configurePinnedClient,
  }) : _inner = inner ?? http.Client() {
    final pinnedIo = _pinning.createPinnedHttpClient();
    configurePinnedClient?.call(pinnedIo);
    _pinned = IOClient(pinnedIo);
  }

  final SpkiPinning _pinning;
  final http.Client _inner;
  late final IOClient _pinned;

  bool _usesPinnedChannel(Uri url) =>
      url.scheme == 'https' && _pinning.isPinned(url.host);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    var body = await request.finalize().toBytes();
    var method = request.method;
    var url = request.url;
    final headers = Map<String, String>.of(request.headers);
    final maxRedirects = request.followRedirects ? request.maxRedirects : 0;
    var hops = 0;

    while (true) {
      final hop = http.Request(method, url)
        ..headers.addAll(headers)
        ..bodyBytes = body
        ..followRedirects = false
        ..persistentConnection = request.persistentConnection;

      final pinnedHop = _usesPinnedChannel(url);
      http.StreamedResponse response;
      try {
        response = await (pinnedHop ? _pinned : _inner).send(hop);
      } on HandshakeException {
        if (!pinnedHop) rethrow; // a real CA failure, not a pinning one
        throw SpkiPinningException(url.host,
            reason: _pinning.lastRejectionFor(url.host)?.toString());
      }

      final location = response.headers['location'];
      if (!_redirectCodes.contains(response.statusCode) ||
          location == null ||
          !request.followRedirects) {
        return response;
      }
      if (hops >= maxRedirects) {
        await response.stream.drain<void>();
        throw http.ClientException('Redirect limit exceeded', url);
      }
      hops++;
      await response.stream.drain<void>();

      final next = url.resolveUri(Uri.parse(location));
      if ({301, 302, 303}.contains(response.statusCode) &&
          method != 'GET' &&
          method != 'HEAD') {
        method = 'GET';
        body = Uint8List(0);
        headers.removeWhere((k, _) {
          final key = k.toLowerCase();
          return key == 'content-length' || key == 'content-type';
        });
      }
      if (next.host.toLowerCase() != url.host.toLowerCase()) {
        headers.removeWhere((k, _) => k.toLowerCase() == 'authorization');
      }
      url = next;
    }
  }

  @override
  void close() {
    _pinned.close();
    _inner.close();
  }
}
