// Pinned + routed requests through Dio.
import 'package:dio/dio.dart';
import 'package:spki_pinning_dio/spki_pinning_dio.dart';

Future<void> main() async {
  const host = 'api.github.com';
  // Demo only: in production obtain pins out-of-band and ship them
  // statically, always with a backup pin for your next key.
  final pin = await fetchPinOf(host, 443);

  final dio = Dio()
    ..httpClientAdapter = SpkiPinningAdapter(SpkiPinning(
      pins: {
        host: [
          pin,
          // 'sha256/<your backup pin>',
        ],
      },
    ));

  // Pinned host: verified against the SPKI pin during the handshake.
  final pinned = await dio.get<String>('https://$host/zen');
  print('pinned $host -> HTTP ${pinned.statusCode}: ${pinned.data}');

  // Unpinned host: routed through a normal CA-validated adapter.
  final unpinned = await dio.get<String>('https://example.com/');
  print('unpinned example.com -> HTTP ${unpinned.statusCode}');

  dio.close();
}
