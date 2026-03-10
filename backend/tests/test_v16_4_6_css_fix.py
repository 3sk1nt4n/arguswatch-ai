"""v16.4.7 regression tests: CSS false-positive fix + action_generator sanitizer."""
import re
import pytest
from arguswatch.engine.pattern_matcher import scan_text


# ── Fix 1: CSS must NOT match as username_password_combo ──

CSS_SAMPLES = [
    "-webkit-transform:rotate(0);transform:rotate(0)}100%{-webkit-transform:rotate(360deg)}",
    "font-family:Arial;font-size:12px;color:#333333",
    ".class{background:url(test);display:block}",
    "animation:spin(360deg);duration:2s;iteration:infinite",
    "@keyframes fadeIn{0%{opacity:0}100%{opacity:1}}",
]

LEGIT_CREDS = [
    ("admin:password123:5f4dcc3b5aa765d61d8327deb882cf99", "username_password_combo"),
    ("root:toor1234:deadbeefcafe1234abcd", "username_password_combo"),
    ("john.doe:MyP@ssw0rd!:a1b2c3d4e5f6a1b2", "username_password_combo"),
]


class TestCSSFalsePositive:
    """CSS strings must never match as credential IOCs."""

    @pytest.mark.parametrize("css", CSS_SAMPLES)
    def test_css_not_matched_as_creds(self, css):
        results = scan_text(css)
        cred_types = {"username_password_combo", "email_password_combo", "email_hash_combo"}
        matched = [r for r in results if r.ioc_type in cred_types]
        assert matched == [], f"CSS matched as {[r.ioc_type for r in matched]}: {css[:60]}"

    @pytest.mark.parametrize("text,expected_type", LEGIT_CREDS)
    def test_legit_creds_still_match(self, text, expected_type):
        results = scan_text(text)
        types = [r.ioc_type for r in results]
        assert expected_type in types, f"Expected {expected_type} in {types}"


# ── Fix 2: action_generator sanitizer ──

from arguswatch.engine.action_generator import _strip_html, _safe_val, _title


class TestSanitizer:
    """HTML/CSS stripping + truncation safety net."""

    def test_normal_cve_unchanged(self):
        assert _safe_val("CVE-2024-21762") == "CVE-2024-21762"

    def test_normal_ip_unchanged(self):
        assert _safe_val("185.234.219.44") == "185.234.219.44"

    def test_normal_domain_unchanged(self):
        assert _safe_val("yahoo.com") == "yahoo.com"

    def test_css_blob_reduced(self):
        css = "-webkit-transform:rotate(0);transform:rotate(0)}" * 10
        result = _safe_val(css)
        assert len(result) <= 200

    def test_html_tags_stripped(self):
        html = "<b>CVE-2024-1234</b> is <i>critical</i>"
        result = _strip_html(html)
        assert "<" not in result
        assert "CVE-2024-1234" in result

    def test_none_returns_empty(self):
        assert _safe_val(None) == ""

    def test_truncation_at_max_len(self):
        long = "A" * 500
        assert len(_safe_val(long, max_len=200)) == 200

    def test_title_under_500(self):
        ctx = {
            "ioc_value": "X" * 400,
            "ioc_type": "cve_id",
            "customer": "Yahoo",
            "actor": "Lazarus",
            "matched_asset": "Horizon",
            "campaign": None,
        }
        title = _title("unpatched_cve", ctx)
        assert len(title) <= 490, f"Title {len(title)} chars, exceeds 490"
