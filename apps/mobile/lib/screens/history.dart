import 'package:flutter/material.dart';

import '../api/models.dart';
import '../core/session.dart';
import '../core/ui.dart';
import 'result.dart';

IconData kindIcon(String kind) => switch (kind) {
  'email' => Icons.mail_outline,
  'message' => Icons.sms_outlined,
  'qr' => Icons.qr_code,
  _ => Icons.link,
};

class VerdictChip extends StatelessWidget {
  const VerdictChip({super.key, required this.verdict, this.score});

  final String? verdict;
  final int? score;

  @override
  Widget build(BuildContext context) {
    final colour = Brand.verdict(verdict);
    final label = verdict == null ? 'Checking' : verdictLabels[verdict] ?? verdict!;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: colour.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        score != null && verdict != 'unknown' ? '$label · $score' : label,
        style: TextStyle(color: colour, fontSize: 12, fontWeight: FontWeight.w600),
      ),
    );
  }
}

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key, required this.session});

  final Session session;

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  final _loader = GlobalKey<LoaderState<PageOf<Scan>>>();
  String _filter = '';

  @override
  Widget build(BuildContext context) {
    final session = widget.session;
    return Scaffold(
      appBar: AppBar(
        title: Text(session.orgId == null ? 'Your history' : 'Workspace scans'),
        actions: [
          PopupMenuButton<String>(
            icon: const Icon(Icons.filter_list),
            initialValue: _filter,
            onSelected: (v) {
              setState(() => _filter = v);
              _loader.currentState?.reload();
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: '', child: Text('All results')),
              PopupMenuItem(value: 'high_risk', child: Text('High or critical risk')),
              PopupMenuItem(value: 'suspicious', child: Text('Suspicious')),
              PopupMenuItem(value: 'unknown', child: Text('Unknown')),
            ],
          ),
        ],
      ),
      body: Loader<PageOf<Scan>>(
        key: _loader,
        load: () async => PageOf(
          await session.api.get(
            '/scans',
            query: {'page_size': 50, if (_filter.isNotEmpty) 'verdict': _filter},
          ) as Json,
          Scan.new,
        ),
        builder: (context, page, reload) {
          if (page.items.isEmpty) {
            return const EmptyView(
              icon: Icons.history,
              title: 'Nothing checked yet',
              message: 'Links, messages, emails and QR codes you check appear here.',
            );
          }
          return ListView.separated(
            itemCount: page.items.length,
            separatorBuilder: (_, _) => const Divider(height: 1),
            itemBuilder: (context, i) {
              final s = page.items[i];
              return ListTile(
                leading: Icon(kindIcon(s.kind)),
                title: Text(s.title, maxLines: 1, overflow: TextOverflow.ellipsis),
                subtitle: Text([timeAgo(s.createdAt), ?s.submittedBy].join(' · ')),
                trailing: VerdictChip(
                  verdict: s.status == 'completed' ? s.verdict : null,
                  score: s.riskScore,
                ),
                onTap: () async {
                  await Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => ScanResultScreen(session: session, scanId: s.id),
                    ),
                  );
                  reload();
                },
              );
            },
          );
        },
      ),
    );
  }
}
