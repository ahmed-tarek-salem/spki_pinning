/// Thrown when certificate DER bytes cannot be walked to a
/// SubjectPublicKeyInfo. Always results in connection rejection.
class SpkiParseException implements Exception {
  SpkiParseException(this.message);

  final String message;

  @override
  String toString() => 'SpkiParseException: $message';
}

/// Thrown by the client bindings when a request to a pinned host fails its
/// TLS handshake. [reason] is best-effort detail from the most recent
/// observer event for the host.
class PublicKeyPinningException implements Exception {
  PublicKeyPinningException(this.host, {this.reason});

  final String host;
  final String? reason;

  @override
  String toString() =>
      'PublicKeyPinningException: pin verification failed for "$host"'
      '${reason == null ? '' : ' ($reason)'}';
}
