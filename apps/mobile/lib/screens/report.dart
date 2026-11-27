import 'dart:math';

import 'package:flutter/material.dart';

import '../api/models.dart';
import '../core/session.dart';
import '../core/ui.dart';

/// "Report" tab: the person's reports and a button to report a new scam.
class ReportsScreen extends StatefulWidget {
  const ReportsScreen({super.key, required this.session});

  final Session session;

  @override
  State<ReportsScreen> createState() => _ReportsScreenState();
}

class _ReportsScreenState extends State<ReportsScreen> {
  final _loader = GlobalKey<LoaderState<List<ScamReport>>>();

  @override
  Widget build(BuildContext context) {
    final session = widget.session;
    return Scaffold(
      appBar: AppBar(title: const Text('Scam reports')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () async {
          final sent = await Navigator.of(context)
              .push<bool>(MaterialPageRoute(builder: (_) => ReportFormScreen(session: session)));
          if (sent == true) _loader.currentState?.reload();
        },
        icon: const Icon(Icons.flag_outlined),
        label: const Text('Report a scam'),
      ),
      body: Loader<List<ScamReport>>(
        key: _loader,
        load: () async =>
            (await session.api.get('/reports') as List).cast<Json>().map(ScamReport.new).toList(),
        builder: (context, reports, reload) {
          if (reports.isEmpty) {
            return const EmptyView(
              icon: Icons.flag_outlined,
              title: 'No reports yet',
              message: 'Received a scam? Report it — verified reports help us warn others.',
            );
          }
          return ListView.separated(
            padding: const EdgeInsets.only(bottom: 88),
            itemCount: reports.length,
            separatorBuilder: (_, _) => const Divider(height: 1),
            itemBuilder: (context, i) {
              final r = reports[i];
              return ListTile(
                title: Text(r.categoryLabel),
                subtitle: Text(
                  '${r.subject.isEmpty ? r.description : r.subject}\n${timeAgo(r.createdAt)}',
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                isThreeLine: true,
                trailing: Text(r.status.replaceAll('_', ' '), style: const TextStyle(fontSize: 12)),
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => ReportDetailScreen(session: session, reportId: r.id),
                  ),
                ),
              );
            },
          );
        },
      ),
    );
  }
}

class ReportFormScreen extends StatefulWidget {
  const ReportFormScreen({super.key, required this.session, this.scanId});

  final Session session;
  final String? scanId;

  @override
  State<ReportFormScreen> createState() => _ReportFormScreenState();
}

class _ReportFormScreenState extends State<ReportFormScreen> {
  final _form = GlobalKey<FormState>();
  final _url = TextEditingController();
  final _phone = TextEditingController();
  final _message = TextEditingController();
  final _description = TextEditingController();
  final _idempotency = List.generate(
    16,
    (_) => Random.secure().nextInt(16).toRadixString(16),
  ).join();
  String _category = 'momo';
  String _channel = 'sms';
  bool _moneyLost = false;
  bool _consent = false;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    for (final c in [_url, _phone, _message, _description]) {
      c.dispose();
    }
    super.dispose();
  }

  String? _orNull(TextEditingController c) => c.text.trim().isEmpty ? null : c.text.trim();

  Future<void> _submit() async {
    if (!_form.currentState!.validate()) return;
    if (!_consent) {
      setState(() => _error = 'Please confirm you agree to how reports are used.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.session.api.post(
        '/reports',
        body: {
          'category': _category,
          'channel': _channel,
          'url': _orNull(_url),
          'phone': _orNull(_phone),
          'message': _orNull(_message),
          'description': _description.text.trim(),
          'money_lost': _moneyLost,
          'scan_id': widget.scanId,
          'consent': true,
        },
        headers: {'idempotency-key': _idempotency},
      );
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          icon: const Icon(Icons.check_circle_outline, color: Brand.safe),
          title: const Text('Thank you'),
          content: const Text(
            "Your report is marked unverified until an analyst reviews it. Reports are never "
            'published as accusations.',
          ),
          actions: [
            FilledButton(onPressed: () => Navigator.pop(context), child: const Text('Done')),
          ],
        ),
      );
      if (mounted) Navigator.of(context).pop(true);
    } catch (e) {
      setState(() => _error = errorText(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('Report a scam')),
      body: Form(
        key: _form,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
          children: [
            DropdownButtonFormField<String>(
              initialValue: _category,
              isExpanded: true,
              decoration: const InputDecoration(labelText: 'What kind of scam?'),
              items: [
                for (final e in scamCategories.entries)
                  DropdownMenuItem(value: e.key, child: Text(e.value)),
              ],
              onChanged: (v) => setState(() => _category = v ?? 'other'),
            ),
            const SizedBox(height: 12),
            DropdownButtonFormField<String>(
              initialValue: _channel,
              isExpanded: true,
              decoration: const InputDecoration(labelText: 'How did it reach you?'),
              items: [
                for (final e in channels.entries)
                  DropdownMenuItem(value: e.key, child: Text(e.value)),
              ],
              onChanged: (v) => setState(() => _channel = v ?? 'other'),
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _url,
              keyboardType: TextInputType.url,
              decoration: const InputDecoration(labelText: 'Suspicious link (optional)'),
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _phone,
              keyboardType: TextInputType.phone,
              decoration: const InputDecoration(
                labelText: 'Phone number (optional)',
                helperText: 'Kept encrypted and never shown publicly',
              ),
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _message,
              minLines: 2,
              maxLines: 6,
              decoration: const InputDecoration(
                labelText: 'The message (optional)',
                helperText: 'PINs, codes and card numbers are removed before saving',
              ),
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _description,
              minLines: 3,
              maxLines: 6,
              decoration: const InputDecoration(labelText: 'What happened?'),
              validator: (v) => (v ?? '').trim().length < 10
                  ? 'Tell us a little more (at least 10 characters).'
                  : null,
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: _moneyLost,
              onChanged: (v) => setState(() => _moneyLost = v),
              title: const Text('I lost money or shared account details'),
            ),
            if (_moneyLost)
              Card(
                color: theme.colorScheme.errorContainer,
                child: const Padding(
                  padding: EdgeInsets.all(12),
                  child: Text(
                    'Call your bank or mobile money provider now to block the transaction, change '
                    'any password you shared, and report it to the Cyber Security Authority '
                    '(call or text 292) or the police.',
                  ),
                ),
              ),
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              value: _consent,
              onChanged: (v) => setState(() => _consent = v ?? false),
              title: const Text(
                'I agree that analysts may review this report and that verified links and numbers '
                'may be used to warn others. My details are never published.',
                style: TextStyle(fontSize: 13),
              ),
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
              ),
            FilledButton(
              onPressed: _busy ? null : _submit,
              style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
              child: Text(_busy ? 'Sending…' : 'Send report'),
            ),
          ],
        ),
      ),
    );
  }
}

class ReportDetailScreen extends StatelessWidget {
  const ReportDetailScreen({super.key, required this.session, required this.reportId});

  final Session session;
  final String reportId;

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Report')),
    body: Loader<ScamReport>(
      load: () async => ScamReport(await session.api.get('/reports/$reportId') as Json),
      builder: (context, r, _) => ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(r.categoryLabel, style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 4),
          Text('Reported ${formatDateTime(r.createdAt)}'),
          const SizedBox(height: 16),
          Card(
            child: ListTile(
              leading: const Icon(Icons.info_outline),
              title: Text(reportStatusLabels[r.status] ?? r.statusLabel),
              subtitle: r.publicNote == null ? null : Text(r.publicNote!),
            ),
          ),
          const SizedBox(height: 16),
          if (r.url != null) ListTile(title: const Text('Link'), subtitle: Text(r.url!)),
          if (r.phone != null) ListTile(title: const Text('Phone'), subtitle: Text(r.phone!)),
          ListTile(title: const Text('What happened'), subtitle: Text(r.description)),
          const SizedBox(height: 8),
          Text(
            'Unverified reports are never published. Your contact details stay private.',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
    ),
  );
}
