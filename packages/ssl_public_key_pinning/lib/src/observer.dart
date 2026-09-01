/// The outcome kinds a pin check can produce.
enum PinningEventType { accepted, pinMismatch, unpinnedHost, parseFailure }

/// A pin-check outcome, delivered to the optional [PinningObserver] for
/// logging/telemetry. The library itself never logs.
class PinningEvent {
  PinningEvent({
    required this.type,
    required this.host,
    required this.port,
    this.observedPin,
    this.message,
  });

  final PinningEventType type;
  final String host;
  final int port;

  /// The `sha256/<b64>` pin of the certificate actually presented, when it
  /// could be extracted. Useful during setup - but verify a pin out-of-band
  /// before trusting one observed over the network.
  final String? observedPin;

  final String? message;

  @override
  String toString() => 'PinningEvent(${type.name}, $host:$port'
      '${observedPin == null ? '' : ', observed: $observedPin'}'
      '${message == null ? '' : ', $message'})';
}

/// Callback receiving every pin-check outcome. Must not throw; exceptions
/// are swallowed so observers can never affect the handshake decision.
typedef PinningObserver = void Function(PinningEvent event);
