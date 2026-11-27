import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../api/models.dart';
import '../core/session.dart';
import '../core/ui.dart';
import 'report.dart';

/// The risk result: risk first, the evidence second, what to do next third.
class ScanResultScreen extends StatefulWidget {
  const ScanResultScreen({super.key, required this.session, required this.scanId});

  final Session session;
  final String scanId;

  @override
  State<ScanResultScreen> createState() => _ScanResultScreenState();
}

class _ScanResultScreenState extends State<ScanResultScreen> {
  ScanDetail? _scan;
  Object? _error;
  Timer? _poll;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final r = await widget.session.api.get('/scans/${widget.scanId}') as Json;
      if (!mounted) return;
      final scan = ScanDetail(r);
      setState(() {
        _scan = scan;
        _error = null;
      });
      if (scan.pending) {
        _poll?.cancel();
        _poll = Timer(const Duration(milliseconds: 1200), _load);
      }
    } catch (e) {
      if (mounted) setState(() => _error = e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final scan = _scan;
    return Scaffold(
      appBar: AppBar(title: const Text('Result')),
      body: _error != null && scan == null
          ? ErrorView(error: _error!, onRetry: _load)
          : scan == null || scan.pending
          ? _Checking(scan: scan)
          : scan.status == 'failed'
          ? EmptyView(
              icon: Icons.error_outline,
              title: "We couldn't finish this check",
              message: scan.error,
            )
          : _Result(scan: scan, session: widget.session, onChanged: _load),
    );
  }
}

class _Checking extends StatelessWidget {
  const _Checking({this.scan});

  final Scan? scan;

  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 16),
          Text('Checking…', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 6),
          const Text(
            'Looking at reputation, the address and common scam signs.',
            textAlign: TextAlign.center,
          ),
          if (scan != null) ...[
            const SizedBox(height: 12),
            Text(scan!.title, maxLines: 2, overflow: TextOverflow.ellipsis),
          ],
        ],
      ),
    ),
  );
}

class ScoreRing extends StatelessWidget {
  const ScoreRing({super.key, required this.score, required this.verdict});

  final int score;
  final String verdict;

  @override
  Widget build(BuildContext context) {
    final colour = Brand.verdict(verdict);
    final unknown = verdict == 'unknown';
    return SizedBox.square(
      dimension: 96,
      child: CustomPaint(
        painter: _Ring(unknown ? 0 : score / 100, colour, Theme.of(context).dividerColor),
        child: Center(
          child: unknown
              ? Icon(Icons.help_outline, size: 36, color: colour)
              : Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      '$score',
                      style: Theme.of(context).textTheme.headlineMedium
                          ?.copyWith(fontWeight: FontWeight.w700),
                    ),
                    Text('/ 100', style: Theme.of(context).textTheme.bodySmall),
                  ],
                ),
        ),
      ),
    );
  }
}

class _Ring extends CustomPainter {
  _Ring(this.value, this.colour, this.track);

  final double value;
  final Color colour;
  final Color track;

  @override
  void paint(Canvas canvas, Size size) {
    final rect = Offset.zero & size;
    final stroke = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 9
      ..strokeCap = StrokeCap.round;
    canvas.drawArc(rect.deflate(5), 0, math.pi * 2, false, stroke..color = track);
    canvas.drawArc(
      rect.deflate(5),
      -math.pi / 2,
      math.pi * 2 * value,
      false,
      stroke..color = colour,
    );
  }

  @override
  bool shouldRepaint(_Ring old) => old.value != value || old.colour != colour;
}

class _Result extends StatelessWidget {
  const _Result({required this.scan, required this.session, required this.onChanged});

  final ScanDetail scan;
  final Session session;
  final Future<void> Function() onChanged;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final verdict = scan.verdict ?? 'unknown';
    final colour = Brand.verdict(verdict);
    final risky = scan.evidence.where((e) => e.weight > 0).toList();
    final positive = scan.evidence.where((e) => e.layer == 'positive').toList();
    final link = scan.link;
    final web = link?['website'] as Json?;
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
      children: [
        // 1. The risk.
        Card(
          child: Container(
            decoration: BoxDecoration(
              border: Border(left: BorderSide(color: colour, width: 5)),
            ),
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    ScoreRing(score: scan.riskScore ?? 0, verdict: verdict),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            verdictLabels[verdict] ?? verdict,
                            key: const ValueKey('verdict-label'),
                            style: TextStyle(color: colour, fontWeight: FontWeight.w700),
                          ),
                          if (scan.confidence != null)
                            Text(
                              confidenceLabels[scan.confidence] ?? '',
                              style: theme.textTheme.bodySmall,
                            ),
                          if (scan.categoryLabel != null)
                            Text(scan.categoryLabel!, style: theme.textTheme.bodySmall),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Text(scan.headline ?? '', style: theme.textTheme.titleLarge),
                const SizedBox(height: 6),
                Text(scan.summary ?? ''),
                const SizedBox(height: 10),
                Text(
                  'The score is our assessment of the evidence available now, not a guarantee. '
                  '"Unknown" means no warning signs were found, not that it is safe.',
                  style: theme.textTheme.bodySmall,
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        // 2. The evidence.
        Text(
          risky.isEmpty ? 'What we checked' : 'Why we flagged it',
          style: theme.textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        if (risky.isEmpty && positive.isEmpty)
          const Text('No warning signs were found in the information available.'),
        for (final e in risky) _EvidenceTile(e),
        for (final e in positive)
          Card(
            child: ListTile(
              leading: const Icon(Icons.check_circle_outline, color: Brand.safe),
              title: Text(e.title),
              subtitle: Text(e.description),
            ),
          ),
        if (web != null) ...[
          const SizedBox(height: 16),
          Text('Website', style: theme.textTheme.titleMedium),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _Fact('Checked', '${link?['url'] ?? ''}'),
                  _Fact(
                    'Loaded',
                    web['reachable'] == true
                        ? 'Yes${web['title'] != null ? ' — "${web['title']}"' : ''}'
                        : "No — ${web['error'] ?? 'no response'}",
                  ),
                  if (web['final_url'] != null && web['final_url'] != link?['url'])
                    _Fact('Ends up at', '${web['final_url']}'),
                  if ((web['redirects'] as List?)?.length case final n? when n > 1)
                    _Fact('Redirects', '${n - 1}'),
                ],
              ),
            ),
          ),
        ],
        const SizedBox(height: 16),
        // 3. What to do.
        Text('What to do next', style: theme.textTheme.titleMedium),
        const SizedBox(height: 8),
        for (final (i, r) in scan.recommendations.indexed)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                CircleAvatar(
                  radius: 11,
                  child: Text('${i + 1}', style: const TextStyle(fontSize: 11)),
                ),
                const SizedBox(width: 10),
                Expanded(child: Text(r)),
              ],
            ),
          ),
        const SizedBox(height: 8),
        FilledButton.icon(
          onPressed: () => Navigator.of(context).push(
            MaterialPageRoute(
              builder: (_) => ReportFormScreen(session: session, scanId: scan.id),
            ),
          ),
          icon: const Icon(Icons.flag_outlined),
          label: const Text('Report this scam'),
          style: FilledButton.styleFrom(
            backgroundColor: scan.risky ? Brand.danger : null,
            minimumSize: const Size.fromHeight(48),
          ),
        ),
        const SizedBox(height: 16),
        _Feedback(scan: scan, session: session, onChanged: onChanged),
        const SizedBox(height: 12),
        Text('Checked ${formatDateTime(scan.createdAt)}', style: theme.textTheme.bodySmall),
      ],
    );
  }
}

class _Fact extends StatelessWidget {
  const _Fact(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(width: 90, child: Text(label, style: Theme.of(context).textTheme.bodySmall)),
        Expanded(child: Text(value)),
      ],
    ),
  );
}

class _EvidenceTile extends StatelessWidget {
  const _EvidenceTile(this.e);

  final Evidence e;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colour = Brand.severity[e.severity] ?? Brand.unknown;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.only(top: 5),
              child: CircleAvatar(radius: 5, backgroundColor: colour),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(e.title, style: const TextStyle(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 4),
                  Text(e.description),
                  const SizedBox(height: 6),
                  Text(
                    '${e.sourceLabel} · reliability ${e.reliability}',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: e.sourceKind == 'verified_intel' ? Brand.danger : null,
                      fontWeight: e.sourceKind == 'verified_intel' ? FontWeight.w600 : null,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _Feedback extends StatelessWidget {
  const _Feedback({required this.scan, required this.session, required this.onChanged});

  final ScanDetail scan;
  final Session session;
  final Future<void> Function() onChanged;

  Future<void> _send(BuildContext context, String kind) async {
    try {
      final r = await session.api.post('/scans/${scan.id}/feedback', body: {'kind': kind}) as Json;
      if (context.mounted) showMessage(context, r['message'] as String);
      await onChanged();
    } catch (e) {
      if (context.mounted) showMessage(context, errorText(e), error: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (scan.feedback != null) {
      return const Text('Thanks for your feedback on this result.');
    }
    return Wrap(
      spacing: 8,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        const Text('Is this right?'),
        OutlinedButton(onPressed: () => _send(context, 'correct'), child: const Text('Yes')),
        OutlinedButton(
          onPressed: () => _send(context, scan.risky ? 'false_positive' : 'false_negative'),
          child: Text(scan.risky ? "No, it's genuine" : "No, it's a scam"),
        ),
      ],
    );
  }
}
