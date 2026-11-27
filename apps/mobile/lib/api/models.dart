/// Typed views over the API's JSON. Only the fields the app uses are mapped.
library;

typedef Json = Map<String, dynamic>;

DateTime? _date(Object? v) => v == null ? null : DateTime.tryParse(v as String)?.toLocal();

List<Json> _list(Object? v) => (v as List? ?? const []).cast<Json>();

List<String> _strings(Object? v) => (v as List? ?? const []).map((e) => '$e').toList();

class Membership {
  Membership(Json j)
    : organisationId = j['organisation_id'] as String,
      organisationName = j['organisation_name'] as String,
      roleLabel = j['role_label'] as String,
      permissions = (j['permissions'] as List).cast<String>().toSet(),
      requireMfa = j['require_mfa'] as bool? ?? false;

  final String organisationId;
  final String organisationName;
  final String roleLabel;
  final Set<String> permissions;
  final bool requireMfa;
}

class Me {
  Me(Json j)
    : id = j['user']['id'] as String,
      email = j['user']['email'] as String,
      fullName = j['user']['full_name'] as String,
      mustChangePassword = j['user']['must_change_password'] as bool,
      mfaEnabled = j['user']['mfa_enabled'] as bool,
      memberships = _list(j['memberships']).map(Membership.new).toList(),
      personalPlan = j['personal_plan'] as String? ?? 'free';

  final String id;
  final String email;
  final String fullName;
  final bool mustChangePassword;
  final bool mfaEnabled;
  final List<Membership> memberships;
  final String personalPlan;

  String get firstName => fullName.trim().split(' ').first;
}

class PageOf<T> {
  PageOf(Json j, T Function(Json) parse)
    : items = _list(j['items']).map(parse).toList(),
      total = j['total'] as int;

  final List<T> items;
  final int total;
}

class Scan {
  Scan(Json j)
    : id = j['id'] as String,
      kind = j['kind'] as String,
      status = j['status'] as String,
      title = j['title'] as String? ?? '',
      verdict = j['verdict'] as String?,
      riskScore = j['risk_score'] as int?,
      confidence = j['confidence'] as String?,
      headline = j['headline'] as String?,
      summary = j['summary'] as String?,
      categoryLabel = j['category_label'] as String?,
      recommendations = _strings(j['recommendations']),
      error = j['error'] as String?,
      createdAt = _date(j['created_at'])!,
      submittedBy = j['submitted_by'] as String?;

  final String id;
  final String kind;
  final String status;
  final String title;
  final String? verdict;
  final int? riskScore;
  final String? confidence;
  final String? headline;
  final String? summary;
  final String? categoryLabel;
  final List<String> recommendations;
  final String? error;
  final DateTime createdAt;
  final String? submittedBy;

  bool get pending => status == 'queued' || status == 'running';
  bool get risky => verdict == 'high' || verdict == 'critical' || verdict == 'suspicious';
}

class Evidence {
  Evidence(Json j)
    : layer = j['layer'] as String,
      code = j['code'] as String,
      severity = j['severity'] as String,
      title = j['title'] as String,
      description = j['description'] as String,
      sourceKind = j['source_kind'] as String,
      sourceLabel = j['source_label'] as String,
      reliability = j['reliability'] as String,
      weight = j['weight'] as int,
      observedAt = _date(j['observed_at'])!;

  final String layer;
  final String code;
  final String severity;
  final String title;
  final String description;
  final String sourceKind;
  final String sourceLabel;
  final String reliability;
  final int weight;
  final DateTime observedAt;
}

class ScanDetail extends Scan {
  ScanDetail(super.j)
    : evidence = _list(j['evidence']).map(Evidence.new).toList(),
      feedback = j['feedback'] as String?,
      artifacts = (j['artifacts'] as Json?) ?? const {};

  final List<Evidence> evidence;
  final String? feedback;
  final Json artifacts;

  Json? get link => artifacts['link'] as Json?;
  Json? get email => artifacts['email'] as Json?;
  Json? get extracted => artifacts['extracted'] as Json?;
}

class Quota {
  Quota(Json j)
    : limit = j['limit'] as int?,
      used = j['used'] as int? ?? 0,
      period = j['period'] as String? ?? 'day';

  final int? limit;
  final int used;
  final String period;

  int? get left => limit == null ? null : (limit! - used).clamp(0, limit!);
}

class Warning {
  Warning(Json j)
    : title = j['title'] as String? ?? '',
      summary = j['summary'] as String? ?? '',
      categoryLabel = j['category_label'] as String? ?? '';

  final String title;
  final String summary;
  final String categoryLabel;
}

class ScamReport {
  ScamReport(Json j)
    : id = j['id'] as String,
      categoryLabel = j['category_label'] as String,
      channel = j['channel'] as String,
      url = j['url'] as String?,
      phone = j['phone'] as String?,
      sender = j['sender'] as String?,
      description = j['description'] as String,
      status = j['status'] as String,
      statusLabel = j['status_label'] as String,
      publicNote = j['public_note'] as String?,
      createdAt = _date(j['created_at'])!;

  final String id;
  final String categoryLabel;
  final String channel;
  final String? url;
  final String? phone;
  final String? sender;
  final String description;
  final String status;
  final String statusLabel;
  final String? publicNote;
  final DateTime createdAt;

  String get subject => url ?? phone ?? sender ?? '';
}

class AppNotification {
  AppNotification(Json j)
    : title = j['title'] as String,
      body = j['body'] as String? ?? '',
      link = j['link'] as String?,
      severity = j['severity'] as String? ?? 'info',
      read = j['read'] as bool? ?? false,
      createdAt = _date(j['created_at'])!;

  final String title;
  final String body;
  final String? link;
  final String severity;
  final bool read;
  final DateTime createdAt;
}
