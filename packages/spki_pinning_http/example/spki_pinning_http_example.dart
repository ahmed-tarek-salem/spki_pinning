// Pinned + routed requests through package:http.
import 'package:spki_pinning_http/spki_pinning_http.dart';

Future<void> main() async {
  const host = 'api.github.com';
  // Demo only: in production obtain pins out-of-band and ship them
  // statically, always with a backup pin for your next key.
  final pin = await fetchPinOf(host, 443);

  final client = SpkiPinningClient(SpkiPinning(
    pins: {
      host: [
        pin,
        // 'sha256/<your backup pin>',
      ],
    },
  ));

  // Pinned host: verified against the SPKI pin during the handshake.
  final pinned = await client.get(Uri.https(host, '/zen'));
  print('pinned $host -> HTTP ${pinned.statusCode}: ${pinned.body}');

  // Unpinned host: routed through a normal CA-validated client.
  final unpinned = await client.get(Uri.https('example.com', '/'));
  print('unpinned example.com -> HTTP ${unpinned.statusCode}');

  client.close();
}
