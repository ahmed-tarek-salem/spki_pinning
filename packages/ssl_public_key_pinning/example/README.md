# ssl_public_key_pinning example

A runnable Flutter app demonstrating the ssl_public_key_pinning family:

- probe a host's live SPKI pin (`fetchPinOf`)
- a pinned request that succeeds (correct pin, checked during the handshake)
- a pinned request that fails closed (wrong pin, nothing is ever sent)
- multi-host routing (unpinned hosts pass through normal CA validation)

Run it with `flutter run` from this directory.
