import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api/models.dart';
import '../core/session.dart';
import '../core/ui.dart';
import 'qr.dart';
import 'result.dart';

enum CheckKind { link, message, email }

/// Looks like a single link rather than a message.
bool looksLikeLink(String text) {
  final t = text.trim();
  if (t.contains(RegExp(r'\s'))) return false;
  return RegExp(
    r'^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?$',
    caseSensitive: false,
  ).hasMatch(t);
}

/// The home tab: paste a link, message or email and check it.
class CheckScreen extends StatefulWidget {
  const CheckScreen({super.key, required this.session});

  final Session session;

  @override
  State<CheckScreen> createState() => CheckScreenState();
}

class CheckScreenState extends State<CheckScreen> {
  final _text = TextEditingController();
  final _sender = TextEditingController();
  CheckKind _kind = CheckKind.link;
  bool _external = true;
  bool _busy = false;
  String? _error;
  Quota? _quota;
  List<Warning> _warnings = const [];

  @override
  void initState() {
    super.initState();
    _loadSide();
  }

  @override
  void dispose() {
    _text.dispose();
    _sender.dispose();
    super.dispose();
  }

  Future<void> _loadSide() async {
    final api = widget.session.api;
    try {
      final q = await api.get('/scans/quota') as Json;
      final w = await api.get('/public/warnings', org: false) as List;
      if (!mounted) return;
      setState(() {
        _quota = Quota(q);
        _warnings = w.cast<Json>().map(Warning.new).toList();
      });
    } catch (_) {
      // Nice to have; the checker works without it.
    }
  }

  /// Text shared from another app, or pasted.
  void prefill(String text) {
    setState(() {
      _text.text = text.trim();
      _kind = looksLikeLink(text) ? CheckKind.link : CheckKind.message;
      _error = null;
    });
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text;
    if (text == null || text.trim().isEmpty) {
      if (mounted) showMessage(context, 'Nothing to paste. Copy the link or message first.');
      return;
    }
    prefill(text);
  }

  Future<void> _submit() async {
    final text = _text.text.trim();
    if (text.isEmpty) {
      setState(() => _error = 'Paste something to check.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    final privacy = {'allow_external_intelligence_lookup': _external};
    try {
      final (path, body) = switch (_kind) {
        CheckKind.link => ('/scans/url', {'url': text, 'privacy': privacy}),
        CheckKind.message => (
          '/scans/message',
          {
            'text': text,
            'sender': _sender.text.trim().isEmpty ? null : _sender.text.trim(),
            'channel': 'sms',
            'privacy': privacy,
          },
        ),
        CheckKind.email => ('/scans/email', {'raw': text, 'privacy': privacy}),
      };
      final r = await widget.session.api.post(path, body: body) as Json;
      if (!mounted) return;
      _text.clear();
      _sender.clear();
      await Navigator.of(context).push(
        MaterialPageRoute(
          builder: (_) => ScanResultScreen(session: widget.session, scanId: r['id'] as String),
        ),
      );
      _loadSide();
    } catch (e) {
      setState(() => _error = errorText(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _scanQr() async {
    final payload = await Navigator.of(context)
        .push<String>(MaterialPageRoute(builder: (_) => const QrScannerScreen()));
    if (payload == null || !mounted) return;
    setState(() => _busy = true);
    try {
      final r = await widget.session.api.post('/scans/qr', body: {'payload': payload}) as Json;
      if (!mounted) return;
      await Navigator.of(context).push(
        MaterialPageRoute(
          builder: (_) => ScanResultScreen(session: widget.session, scanId: r['id'] as String),
        ),
      );
    } catch (e) {
      if (mounted) showMessage(context, errorText(e), error: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final session = widget.session;
    final name = session.me?.firstName ?? '';
    final scope = session.membership?.organisationName;
    final hint = switch (_kind) {
      CheckKind.link => 'Paste a link, e.g. mtn-momo-refund.xyz/claim',
      CheckKind.message => 'Paste the SMS or WhatsApp message',
      CheckKind.email => 'Paste the email (the full original if you can)',
    };
    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
          children: [
            Container(
              padding: const EdgeInsets.all(18),
              decoration: BoxDecoration(color: Brand.navy, borderRadius: BorderRadius.circular(18)),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.verified_user_outlined, color: Colors.greenAccent, size: 16),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          scope == null ? 'Personal protection' : '$scope workspace',
                          style: const TextStyle(color: Colors.white70, fontSize: 12),
                        ),
                      ),
                      if (_quota?.left != null)
                        Text(
                          '${_quota!.left} checks left ${_quota!.period == 'day' ? 'today' : 'this month'}',
                          style: const TextStyle(color: Colors.white54, fontSize: 11),
                        ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Text(
                    name.isEmpty
                        ? 'Got something suspicious?'
                        : 'Hi $name, got something suspicious?',
                    style: theme.textTheme.titleLarge?.copyWith(
                      color: Colors.white,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'Check it before you click, reply or pay.',
                    style: TextStyle(color: Colors.white70),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            SegmentedButton<CheckKind>(
              segments: const [
                ButtonSegment(value: CheckKind.link, label: Text('Link'), icon: Icon(Icons.link)),
                ButtonSegment(
                  value: CheckKind.message,
                  label: Text('Message'),
                  icon: Icon(Icons.sms_outlined),
                ),
                ButtonSegment(
                  value: CheckKind.email,
                  label: Text('Email'),
                  icon: Icon(Icons.mail_outline),
                ),
              ],
              selected: {_kind},
              onSelectionChanged: (s) => setState(() => _kind = s.first),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const ValueKey('check-input'),
              controller: _text,
              minLines: _kind == CheckKind.link ? 1 : 4,
              maxLines: _kind == CheckKind.link ? 3 : 10,
              keyboardType: _kind == CheckKind.link ? TextInputType.url : TextInputType.multiline,
              autocorrect: false,
              decoration: InputDecoration(
                hintText: hint,
                suffixIcon: IconButton(
                  tooltip: 'Paste',
                  icon: const Icon(Icons.content_paste),
                  onPressed: _paste,
                ),
              ),
            ),
            if (_kind == CheckKind.message) ...[
              const SizedBox(height: 10),
              TextField(
                controller: _sender,
                decoration: const InputDecoration(
                  labelText: 'Who sent it? (optional)',
                  hintText: '0244 123 456 or MobileMoney',
                ),
              ),
            ],
            const SizedBox(height: 6),
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              dense: true,
              controlAffinity: ListTileControlAffinity.leading,
              value: _external,
              onChanged: (v) => setState(() => _external = v ?? true),
              title: const Text('Also check with trusted outside services'),
              subtitle: const Text('Private tokens in links are removed first.'),
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
              ),
            FilledButton.icon(
              key: const ValueKey('check-button'),
              onPressed: _busy ? null : _submit,
              icon: _busy
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.search),
              label: Text(_busy ? 'Checking…' : 'Check now'),
              style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(52)),
            ),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: _busy ? null : _scanQr,
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Scan a QR code'),
              style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(48)),
            ),
            const SizedBox(height: 8),
            Text(
              scope == null
                  ? 'Saved to your private history. PINs, codes and card numbers are removed '
                        'before anything is saved.'
                  : 'Saved to $scope. Security staff in this workspace can see it.',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall,
            ),
            if (_warnings.isNotEmpty) ...[
              const SizedBox(height: 24),
              Text('Current scam warnings', style: theme.textTheme.titleMedium),
              const SizedBox(height: 8),
              for (final w in _warnings.take(3))
                Card(
                  child: ListTile(
                    leading: const Icon(Icons.campaign_outlined, color: Brand.suspicious),
                    title: Text(w.title),
                    subtitle: Text(w.summary),
                  ),
                ),
            ],
          ],
        ),
      ),
    );
  }
}
