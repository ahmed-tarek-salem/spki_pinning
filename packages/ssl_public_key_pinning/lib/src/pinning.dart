import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'exceptions.dart';
import 'observer.dart';
import 'pin.dart';
import 'spki_extractor.dart';

/// The pinning policy: which hosts are pinned to which SPKI pins, and the
/// fail-closed decision procedure applied during TLS handshakes.
///
/// Host matching is exact and case-insensitive, and ignores the port (the
/// same pins apply to 443 and 8443 - OkHttp semantics). A host with no
/// pins is *rejected* by the pinned channel; routing bindings send such
/// hosts through a normal CA-validated client instead.
class PublicKeyPinning {
  PublicKeyPinning({
    required Map<String, List<String>> pins,
    PinningObserver? observer,
  })  : _observer = observer,
        _pinsByHost = {
          for (final entry in pins.entries)
            entry.key.toLowerCase(): _parsePins(entry.key, entry.value),
        };

  static List<PublicKeyPin> _parsePins(String host, List<String> raw) {
    if (raw.isEmpty) {
      throw ArgumentError.value(raw, 'pins', 'empty pin list for "$host"');
    }
    return List.unmodifiable(raw.map(PublicKeyPin.new));
  }

  final Map<String, List<PublicKeyPin>> _pinsByHost;
  final PinningObserver? _observer;

  /// Most recent rejection per pinned host - bindings use this to enrich
  /// the generic [HandshakeException] into a [PublicKeyPinningException].
  final Map<String, PinningEvent> _lastRejection = {};

  /// Whether [host] has pins configured.
  bool isPinned(String host) => _pinsByHost.containsKey(host.toLowerCase());

  /// The most recent rejection event for [host], if any.
  PinningEvent? lastRejectionFor(String host) =>
      _lastRejection[host.toLowerCase()];

  /// Sync pin check on raw certificate DER. Fail-closed on every error path.
  bool checkDer(Uint8List der, String host, int port) {
    final key = host.toLowerCase();
    final pins = _pinsByHost[key];
    if (pins == null) {
      // Only pinned hosts are tracked in _lastRejection, so it stays
      // bounded; an unpinned-host rejection has a deterministic reason.
      _emit(PinningEvent(
        type: PinningEventType.unpinnedHost,
        host: host,
        port: port,
        message: 'no pins configured for this host; the pinned client '
            'refuses unpinned hosts - use a routing binding or add pins',
      ));
      return false;
    }
    Uint8List spki;
    try {
      spki = extractSpkiDer(der);
    } on SpkiParseException catch (e) {
      _reject(
          key,
          PinningEvent(
            type: PinningEventType.parseFailure,
            host: host,
            port: port,
            message: e.message,
          ));
      return false;
    }
    final digest = sha256.convert(spki).bytes;
    for (final pin in pins) {
      if (pin.matchesDigest(digest)) {
        _lastRejection.remove(key);
        _emit(PinningEvent(
            type: PinningEventType.accepted, host: host, port: port));
        return true;
      }
    }
    _reject(
        key,
        PinningEvent(
          type: PinningEventType.pinMismatch,
          host: host,
          port: port,
          observedPin: 'sha256/${base64.encode(digest)}',
        ));
    return false;
  }

  /// Adapter for `badCertificateCallback`.
  bool checkCertificate(X509Certificate cert, String host, int port) =>
      checkDer(Uint8List.fromList(cert.der), host, port);

  /// An [HttpClient] that trusts nothing but the pins: every handshake runs
  /// [checkCertificate] before any request byte is sent. Serves pinned
  /// hosts ONLY; every other host fails closed.
  HttpClient createPinnedHttpClient() =>
      HttpClient(context: SecurityContext(withTrustedRoots: false))
        ..badCertificateCallback = checkCertificate;

  void _reject(String key, PinningEvent event) {
    _lastRejection[key] = event;
    _emit(event);
  }

  void _emit(PinningEvent event) {
    try {
      _observer?.call(event);
    } catch (_) {
      // Observers must never break the handshake decision path.
    }
  }
}
