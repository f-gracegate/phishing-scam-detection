import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/app_lock.dart';
import '../core/push.dart';
import '../core/session.dart';
import 'check.dart';
import 'history.dart';
import 'more.dart';
import 'report.dart';
import 'result.dart';

/// Opens an in-app link from a notification, such as `/scans/ID` or `/reports/ID`.
void openLink(BuildContext context, Session session, String link) {
  final parts = Uri.parse(link).pathSegments;
  Widget? screen;
  if (parts.length >= 2 && parts[parts.length - 2] == 'scans') {
    screen = ScanResultScreen(session: session, scanId: parts.last);
  } else if (parts.length >= 2 && parts.first == 'reports') {
    screen = ReportDetailScreen(session: session, reportId: parts.last);
  }
  if (screen != null) {
    Navigator.of(context).push(MaterialPageRoute(builder: (_) => screen!));
  }
}

/// Text shared into the app from another app (Android "Share" → this app).
class ShareInbox {
  static const _channel = MethodChannel('com.gracegate.scamcheck/share');

  static Future<String?> take() async {
    try {
      return await _channel.invokeMethod<String>('takeSharedText');
    } on MissingPluginException {
      return null; // iOS (no share extension yet) and tests.
    } on PlatformException {
      return null;
    }
  }
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key, required this.session, required this.push, required this.lock});

  final Session session;
  final PushService push;
  final AppLock lock;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> with WidgetsBindingObserver {
  int _tab = 0;
  final _check = GlobalKey<CheckScreenState>();
  StreamSubscription<dynamic>? _foreground;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    widget.session.addListener(_onSession);
    widget.push.enable();
    _foreground = widget.push.foreground.stream.listen((m) {
      if (!mounted) return;
      final title = m.notification?.title ?? 'New notification';
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(title)));
    });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _onSession();
      _checkShared();
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    widget.session.removeListener(_onSession);
    _foreground?.cancel();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _checkShared();
  }

  Future<void> _checkShared() async {
    final text = await ShareInbox.take();
    if (text == null || text.trim().isEmpty || !mounted) return;
    setState(() => _tab = 0);
    _check.currentState?.prefill(text);
  }

  void _onSession() {
    final link = widget.session.takePendingLink();
    if (link != null && mounted) openLink(context, widget.session, link);
  }

  @override
  Widget build(BuildContext context) {
    final session = widget.session;
    return Scaffold(
      body: IndexedStack(
        index: _tab,
        children: [
          CheckScreen(key: _check, session: session),
          HistoryScreen(session: session),
          ReportsScreen(session: session),
          MoreScreen(session: session, push: widget.push, lock: widget.lock),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.shield_outlined), label: 'Check'),
          NavigationDestination(icon: Icon(Icons.history), label: 'History'),
          NavigationDestination(icon: Icon(Icons.flag_outlined), label: 'Report'),
          NavigationDestination(icon: Icon(Icons.more_horiz), label: 'More'),
        ],
      ),
    );
  }
}
