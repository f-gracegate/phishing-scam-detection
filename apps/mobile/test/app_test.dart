import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:scam_check/api/api_client.dart';
import 'package:scam_check/core/app_lock.dart';
import 'package:scam_check/core/config.dart';
import 'package:scam_check/core/push.dart';
import 'package:scam_check/core/session.dart';
import 'package:scam_check/main.dart';
import 'package:scam_check/screens/check.dart';

const orgId = '11111111-1111-1111-1111-111111111111';

Map<String, dynamic> me({bool withOrg = true}) => {
  'user': {
    'id': 'u1',
    'email': 'ama@example.com',
    'full_name': 'Ama Mensah',
    'must_change_password': false,
    'mfa_enabled': false,
  },
  'memberships': [
    if (withOrg)
      {
        'organisation_id': orgId,
        'organisation_name': 'Acme Ltd',
        'role_label': 'Employee',
        'permissions': ['org:read', 'scans:submit'],
        'require_mfa': false,
      },
  ],
  'intel_permissions': <String>[],
  'personal_plan': 'free',
};

const tokens = {
  'access_token': 'access-1',
  'refresh_token': 'refresh-1',
  'token_type': 'bearer',
  'expires_in': 900,
};

Map<String, dynamic> scan(String status) => {
  'id': 's1',
  'kind': 'message',
  'source': 'mobile',
  'status': status,
  'title': 'MTN MoMo: GHS 450 was sent to you by mistake',
  'verdict': status == 'completed' ? 'high' : null,
  'verdict_label': status == 'completed' ? 'High risk' : null,
  'risk_score': status == 'completed' ? 86 : null,
  'confidence': status == 'completed' ? 'high' : null,
  'headline': status == 'completed' ? 'This message looks like a scam' : null,
  'summary': status == 'completed' ? 'We found 3 warning signs.' : null,
  'category': 'momo',
  'category_label': 'Mobile money scam',
  'recommendations': status == 'completed'
      ? ["Don't reply, click links or call numbers in this message."]
      : <String>[],
  'error': null,
  'created_at': DateTime.now().toIso8601String(),
  'completed_at': null,
  'organisation_id': null,
  'submitted_by': null,
  'artifacts': <String, dynamic>{},
  'evidence': status == 'completed'
      ? [
          {
            'layer': 'message',
            'code': 'momo_reversal',
            'severity': 'medium',
            'title': '"Money sent by mistake" or reversal story',
            'description': 'A classic mobile money scam.',
            'source_kind': 'model',
            'source_label': 'Our detection rules',
            'source_name': 'Detection rules',
            'reliability': 'medium',
            'weight': 45,
            'observed_at': DateTime.now().toIso8601String(),
            'data': <String, dynamic>{},
          },
        ]
      : <Map<String, dynamic>>[],
  'feedback': null,
  'content_available': true,
};

http.Response json(Object body, [int status = 200]) =>
    http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

http.Response error(int status, String code, String message) => json({
  'error': {'code': code, 'message': message},
}, status);

void main() {
  test('only HTTPS, or HTTP to the developer machine, is allowed', () {
    expect(AppConfig.isAllowedBaseUrl('https://api.example.com'), isTrue);
    expect(AppConfig.isAllowedBaseUrl('http://localhost:8200'), isTrue);
    expect(AppConfig.isAllowedBaseUrl('http://api.example.com'), isFalse);
  });

  test('shared text is recognised as a link or a message', () {
    expect(looksLikeLink('https://bit.ly/abc'), isTrue);
    expect(looksLikeLink('mtn-momo-refund.xyz/claim'), isTrue);
    expect(looksLikeLink('Your parcel is held, pay at dhl-gh.xyz'), isFalse);
  });

  test('an expired access token is refreshed once and the request retried', () async {
    final store = MemoryTokenStore()
      ..values[ApiClient.accessKey] = 'old'
      ..values[ApiClient.refreshKey] = 'refresh-0';
    var refreshes = 0;
    final client = MockClient((req) async {
      if (req.url.path.endsWith('/auth/refresh')) {
        refreshes++;
        return json({'message': 'refreshed', 'tokens': tokens});
      }
      if (req.headers['authorization'] == 'Bearer old') {
        return error(401, 'session_expired', 'Please sign in again.');
      }
      expect(req.headers['authorization'], 'Bearer access-1');
      return json({'ok': true});
    });
    final api = ApiClient(store: store, baseUrl: 'http://localhost:8200', client: client);
    expect(await api.get('/scans'), {'ok': true});
    expect(refreshes, 1);
    expect(store.values[ApiClient.refreshKey], 'refresh-1');
  });

  test('personal space is the default; a workspace is only used when chosen', () async {
    final seen = <String?>[];
    final client = MockClient((req) async {
      seen.add(req.headers['x-organisation-id']);
      if (req.url.path.endsWith('/auth/login')) {
        return json({'status': 'ok', 'me': me(), 'tokens': tokens});
      }
      return json({'items': [], 'total': 0});
    });
    final session = Session(
      ApiClient(store: MemoryTokenStore(), baseUrl: 'http://localhost:8200', client: client),
    );
    await session.signIn('ama@example.com', 'pw');
    expect(session.orgId, isNull);
    await session.api.get('/scans');
    session.selectOrganisation(orgId);
    await session.api.get('/scans');
    session.selectOrganisation(null);
    await session.api.get('/scans');
    expect(seen.skip(1).toList(), [null, orgId, null]);
  });

  testWidgets('sign in, check a message, see the risk and the reasons', (tester) async {
    tester.view.physicalSize = const Size(430, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    var polls = 0;
    Map<String, dynamic>? submitted;
    final client = MockClient((req) async {
      switch (req.url.path) {
        case '/api/v1/auth/login':
          final body = jsonDecode(req.body);
          expect(body['client'], 'mobile');
          if (body['password'] != 'right-password') {
            return error(401, 'invalid_credentials', 'Incorrect email/username or password.');
          }
          return json({'status': 'ok', 'me': me(withOrg: false), 'tokens': tokens});
        case '/api/v1/scans/quota':
          return json({'scope': 'personal', 'limit': 20, 'used': 3, 'period': 'day'});
        case '/api/v1/public/warnings':
          return json([
            {
              'id': 'w1',
              'title': 'Fake "money sent by mistake" messages',
              'summary': 'Check your balance only in your MoMo menu.',
              'category': 'momo',
              'category_label': 'Mobile money scam',
              'published_at': DateTime.now().toIso8601String(),
            },
          ]);
        case '/api/v1/scans/message':
          submitted = jsonDecode(req.body) as Map<String, dynamic>;
          expect(req.headers['x-organisation-id'], isNull);
          return json(scan('queued'), 201);
        case '/api/v1/scans/s1':
          polls++;
          return json(scan(polls == 1 ? 'running' : 'completed'));
      }
      return json({'items': [], 'total': 0, 'page': 1, 'page_size': 50, 'unread': 0});
    });
    final store = MemoryTokenStore();
    final session = Session(
      ApiClient(store: store, baseUrl: 'http://localhost:8200', client: client),
    );
    await session.start();
    await tester.pumpWidget(
      ScamCheckApp(session: session, push: PushService(session), lock: AppLock(store)),
    );

    await tester.enterText(find.byKey(const Key('identifier')), 'ama@example.com');
    await tester.enterText(find.byKey(const Key('password')), 'wrong');
    await tester.tap(find.byKey(const Key('sign-in')));
    await tester.pumpAndSettle();
    expect(find.text('Incorrect email/username or password.'), findsOneWidget);

    await tester.enterText(find.byKey(const Key('password')), 'right-password');
    await tester.tap(find.byKey(const Key('sign-in')));
    await tester.pumpAndSettle();
    expect(find.textContaining('Hi Ama'), findsOneWidget);
    expect(find.text('17 checks left today'), findsOneWidget);
    expect(find.text('Fake "money sent by mistake" messages'), findsOneWidget);

    await tester.tap(find.text('Message'));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const Key('check-input')),
      'MTN MoMo: GHS 450 was sent to you by mistake. Reverse it now.',
    );
    await tester.tap(find.byKey(const Key('check-button')));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    expect(submitted?['text'], startsWith('MTN MoMo'));
    expect(find.text('Checking…'), findsWidgets);

    await tester.pump(const Duration(milliseconds: 1300));
    await tester.pumpAndSettle();
    expect(find.text('High risk'), findsOneWidget);
    expect(find.text('86'), findsOneWidget);
    expect(find.text('This message looks like a scam'), findsOneWidget);
    expect(find.text('"Money sent by mistake" or reversal story'), findsOneWidget);
    expect(find.textContaining('Our detection rules'), findsOneWidget);
    expect(find.text('Report this scam'), findsOneWidget);
  });
}
