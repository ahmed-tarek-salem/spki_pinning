import 'dart:io';

import 'package:spki_pinning/spki_pinning.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty || args.length > 2) {
    stderr.writeln('Usage: dart run spki_pinning:pin <host> [port]');
    exitCode = 64;
    return;
  }
  final host = args[0];
  final port = args.length == 2 ? int.tryParse(args[1]) : 443;
  if (port == null) {
    stderr.writeln('Invalid port: ${args[1]}');
    exitCode = 64;
    return;
  }
  try {
    final pin = await fetchPinOf(host, port);
    stdout.writeln(pin);
    stderr.writeln('WARNING: verify this key out-of-band (from the server '
        'configuration you control). The network you measured from could '
        'itself be under attack.');
  } on Exception catch (e) {
    stderr.writeln('Failed to read certificate from $host:$port: $e');
    exitCode = 1;
  }
}
