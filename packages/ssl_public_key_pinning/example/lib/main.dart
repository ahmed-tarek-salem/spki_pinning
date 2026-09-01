import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:ssl_public_key_pinning_dio/ssl_public_key_pinning_dio.dart';

void main() => runApp(const DemoApp());

class DemoApp extends StatelessWidget {
  const DemoApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'ssl_public_key_pinning demo',
        theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
        home: const DemoPage(),
      );
}

class DemoPage extends StatefulWidget {
  const DemoPage({super.key});

  @override
  State<DemoPage> createState() => _DemoPageState();
}

class _DemoPageState extends State<DemoPage> {
  final _hostController = TextEditingController(text: 'api.github.com');
  final _log = <_LogLine>[];
  bool _busy = false;

  static const _wrongPin =
      'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  String get _host => _hostController.text.trim();

  void _append(String text, {bool error = false, bool dim = false}) {
    setState(() => _log.add(_LogLine(text, error: error, dim: dim)));
  }

  Dio _dioWithPin(String pin) => Dio()
    ..httpClientAdapter = PublicKeyPinningAdapter(PublicKeyPinning(
      pins: {
        _host: [pin],
      },
      observer: (event) => _append('observer: $event', dim: true),
    ));

  Future<void> _run(String label, Future<void> Function() action) async {
    if (_busy) return;
    setState(() => _busy = true);
    _append('--- $label');
    try {
      await action();
    } catch (e) {
      _append('$e', error: true);
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _probe() => _run('Probe live pin of $_host', () async {
        // Demo only: in production obtain pins out-of-band, from the
        // server configuration you control, and ship them statically.
        final pin = await fetchPinOf(_host, 443);
        _append('observed pin: $pin');
      });

  Future<void> _correctPin() =>
      _run('GET https://$_host/ with the CORRECT pin', () async {
        final pin = await fetchPinOf(_host, 443);
        final res = await _dioWithPin(pin).get<dynamic>('https://$_host/');
        _append('HTTP ${res.statusCode}: pinned request succeeded');
      });

  Future<void> _wrongPinRequest() =>
      _run('GET https://$_host/ with a WRONG pin', () async {
        try {
          await _dioWithPin(_wrongPin).get<dynamic>('https://$_host/');
          _append('UNEXPECTED: wrong pin was accepted', error: true);
        } on DioException catch (e) {
          if (e.type == DioExceptionType.badCertificate) {
            _append('rejected fail-closed before any byte was sent:');
            _append('${e.error}', error: true);
          } else {
            rethrow;
          }
        }
      });

  Future<void> _unpinnedHost() =>
      _run('GET https://example.com/ (unpinned host)', () async {
        // Same Dio instance style, pins only cover _host. example.com is
        // routed to the inner CA-validated adapter automatically.
        final res =
            await _dioWithPin(_wrongPin).get<dynamic>('https://example.com/');
        _append('HTTP ${res.statusCode}: passed through normal '
            'CA validation (no pin applied)');
      });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('ssl_public_key_pinning demo')),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: TextField(
              controller: _hostController,
              decoration: const InputDecoration(
                labelText: 'Pinned host',
                border: OutlineInputBorder(),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton(
                  onPressed: _busy ? null : _probe,
                  child: const Text('Probe pin'),
                ),
                FilledButton(
                  onPressed: _busy ? null : _correctPin,
                  child: const Text('Correct pin'),
                ),
                FilledButton.tonal(
                  onPressed: _busy ? null : _wrongPinRequest,
                  child: const Text('Wrong pin'),
                ),
                OutlinedButton(
                  onPressed: _busy ? null : _unpinnedHost,
                  child: const Text('Unpinned host'),
                ),
              ],
            ),
          ),
          const SizedBox(height: 8),
          const Divider(height: 1),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(12),
              itemCount: _log.length,
              itemBuilder: (context, i) {
                final line = _log[i];
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2),
                  child: Text(
                    line.text,
                    style: TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12.5,
                      color: line.error
                          ? Theme.of(context).colorScheme.error
                          : line.dim
                              ? Theme.of(context).colorScheme.outline
                              : null,
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
      floatingActionButton: _log.isEmpty
          ? null
          : FloatingActionButton.small(
              onPressed: () => setState(_log.clear),
              tooltip: 'Clear log',
              child: const Icon(Icons.clear_all),
            ),
    );
  }
}

class _LogLine {
  _LogLine(this.text, {this.error = false, this.dim = false});

  final String text;
  final bool error;
  final bool dim;
}
