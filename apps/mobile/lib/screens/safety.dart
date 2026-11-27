import 'package:flutter/material.dart';

import '../core/ui.dart';

const _guides = [
  (
    'Fake MoMo reversals',
    [
      'Someone says they sent money to you by mistake and asks for it back.',
      "You're asked to dial a code or approve a prompt to \"reverse\" it.",
    ],
    [
      'Check your real balance in your MoMo menu or app.',
      'You never need your PIN to receive money. Never approve a prompt you didn’t start.',
    ],
  ),
  (
    'Fake bank and account alerts',
    [
      'Your account will be "blocked" unless you click a link.',
      "You're asked for your PIN, OTP, card number or password.",
    ],
    [
      'Call your bank on the number on your card.',
      'Never share one-time codes, even with "bank staff".',
    ],
  ),
  (
    'Government, delivery and fee scams',
    [
      'GRA, SSNIT or DVLA "penalties" paid through an SMS link.',
      'A parcel, job, loan or prize that needs a fee first.',
    ],
    [
      'Use the official .gov.gh website or visit an office.',
      "Don't pay to receive a job, loan, parcel or prize.",
    ],
  ),
  (
    'Investment and romance scams',
    ['Guaranteed returns or "double your money".', 'Someone you met online needs money urgently.'],
    [
      'Check investment companies with the SEC Ghana.',
      'Call the person on a number you already know.',
    ],
  ),
];

class SafetyScreen extends StatelessWidget {
  const SafetyScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('Safety centre')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          for (final (title, signs, actions) in _guides)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(14),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(title, style: theme.textTheme.titleMedium),
                      const SizedBox(height: 8),
                      for (final s in signs)
                        _Line(icon: Icons.cancel_outlined, colour: Brand.danger, text: s),
                      const SizedBox(height: 4),
                      for (final a in actions)
                        _Line(icon: Icons.check_circle_outline, colour: Brand.safe, text: a),
                    ],
                  ),
                ),
              ),
            ),
          Card(
            color: theme.colorScheme.errorContainer,
            child: const Padding(
              padding: EdgeInsets.all(14),
              child: Text(
                'Already sent money or shared details? Call your bank or mobile money provider '
                'immediately, change any password you shared, and report it to the Cyber '
                'Security Authority (call or text 292) or the police.',
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _Line extends StatelessWidget {
  const _Line({required this.icon, required this.colour, required this.text});

  final IconData icon;
  final Color colour;
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, size: 18, color: colour),
        const SizedBox(width: 8),
        Expanded(child: Text(text)),
      ],
    ),
  );
}
