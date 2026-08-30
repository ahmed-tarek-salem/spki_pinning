import 'dart:convert';
import 'dart:typed_data';

/// A single SPKI pin: the SHA-256 digest of a `SubjectPublicKeyInfo`.
///
/// Accepts the standard `sha256/<base64>` form (HPKP / OkHttp / TrustKit
/// compatible) or bare base64. Malformed input throws [ArgumentError] at
/// construction, so bad pins fail at startup, not at first request.
class SpkiPin {
  factory SpkiPin(String pin) {
    final b64 =
        pin.startsWith('sha256/') ? pin.substring('sha256/'.length) : pin;
    Uint8List digest;
    try {
      digest = base64.decode(b64);
    } on FormatException {
      throw ArgumentError.value(pin, 'pin', 'not valid base64');
    }
    if (digest.length != 32) {
      throw ArgumentError.value(
          pin, 'pin', 'SHA-256 digest must be 32 bytes, got ${digest.length}');
    }
    return SpkiPin._(digest);
  }

  SpkiPin._(this.digest);

  /// 32-byte SHA-256 digest of the pinned SPKI.
  final Uint8List digest;

  /// Canonical `sha256/<base64>` form.
  String get formatted => 'sha256/${base64.encode(digest)}';

  /// Whether [digestBytes] equals this pin's digest.
  bool matchesDigest(List<int> digestBytes) {
    if (digestBytes.length != digest.length) return false;
    var diff = 0;
    for (var i = 0; i < digest.length; i++) {
      diff |= digest[i] ^ digestBytes[i];
    }
    return diff == 0;
  }

  @override
  bool operator ==(Object other) =>
      other is SpkiPin && matchesDigest(other.digest);

  @override
  int get hashCode => Object.hashAll(digest);

  @override
  String toString() => formatted;
}
