"""Tests for crt.sh Certificate Transparency collector logic."""
import pytest


class TestCrtshParsing:
    """Test subdomain extraction from crt.sh JSON responses."""

    def _parse_certs(self, certs, domain):
        """Mirrors the parsing logic in collect_crtsh."""
        subs = set()
        for cert in certs[:500]:
            cn = (cert.get("common_name") or "").lower().strip()
            if cn and domain in cn and "*" not in cn and cn != domain and "@" not in cn and cn.endswith("." + domain):
                subs.add(cn)
            for name in (cert.get("name_value") or "").lower().split("\n"):
                name = name.strip()
                if name and domain in name and "*" not in name and name != domain and "@" not in name and name.endswith("." + domain):
                    subs.add(name)
        return subs

    def test_basic_subdomain(self):
        certs = [{"common_name": "api.yahoo.com", "name_value": "api.yahoo.com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert "api.yahoo.com" in subs

    def test_multiple_sans(self):
        """name_value can contain multiple SANs separated by newlines."""
        certs = [{"common_name": "yahoo.com",
                  "name_value": "api.yahoo.com\nwww.yahoo.com\nlogin.yahoo.com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert subs == {"api.yahoo.com", "www.yahoo.com", "login.yahoo.com"}

    def test_wildcard_excluded(self):
        certs = [{"common_name": "*.yahoo.com", "name_value": "*.yahoo.com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert len(subs) == 0

    def test_root_domain_excluded(self):
        """Don't add the root domain itself — it's already a customer asset."""
        certs = [{"common_name": "yahoo.com", "name_value": "yahoo.com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert len(subs) == 0

    def test_unrelated_domain_excluded(self):
        certs = [{"common_name": "evil.com", "name_value": "evil.com\nhack.evil.com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert len(subs) == 0

    def test_dedup_across_certs(self):
        """Same subdomain in multiple certs should appear once."""
        certs = [
            {"common_name": "api.yahoo.com", "name_value": "api.yahoo.com"},
            {"common_name": "api.yahoo.com", "name_value": "api.yahoo.com\nwww.yahoo.com"},
        ]
        subs = self._parse_certs(certs, "yahoo.com")
        assert subs == {"api.yahoo.com", "www.yahoo.com"}

    def test_deep_subdomain(self):
        certs = [{"common_name": "staging.internal.corp.yahoo.com",
                  "name_value": "staging.internal.corp.yahoo.com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert "staging.internal.corp.yahoo.com" in subs

    def test_case_insensitive(self):
        certs = [{"common_name": "API.Yahoo.COM", "name_value": "Staging.Yahoo.Com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert "api.yahoo.com" in subs
        assert "staging.yahoo.com" in subs

    def test_empty_response(self):
        subs = self._parse_certs([], "yahoo.com")
        assert len(subs) == 0

    def test_null_fields(self):
        certs = [{"common_name": None, "name_value": None}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert len(subs) == 0

    def test_email_addresses_excluded(self):
        """Bug fix: eshannamr@yahoo.com was being registered as subdomain."""
        certs = [{"common_name": "yahoo.com",
                  "name_value": "eshannamr@yahoo.com\nbigelok@yahoo.com\napi.yahoo.com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert "eshannamr@yahoo.com" not in subs
        assert "bigelok@yahoo.com" not in subs
        assert "api.yahoo.com" in subs

    def test_cross_domain_excluded(self):
        """gamma.verizon.edit.client.yahoo.com is valid, but evil-yahoo.com is not."""
        certs = [{"common_name": "evil-yahoo.com", "name_value": "notyahoo.com"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert len(subs) == 0

    def test_must_end_with_parent_domain(self):
        certs = [{"common_name": "sub.yahoo.com", "name_value": "deep.sub.yahoo.com\nyahoo.com.evil.net"}]
        subs = self._parse_certs(certs, "yahoo.com")
        assert "sub.yahoo.com" in subs
        assert "deep.sub.yahoo.com" in subs
        assert "yahoo.com.evil.net" not in subs

    def test_cap_at_500(self):
        """More than 500 certs should be truncated."""
        certs = [{"common_name": f"sub{i}.yahoo.com", "name_value": f"sub{i}.yahoo.com"} for i in range(600)]
        subs = self._parse_certs(certs, "yahoo.com")
        assert len(subs) == 500


class TestInterestingKeywords:
    KEYWORDS = ["admin", "vpn", "api", "staging", "dev", "test", "beta",
                "internal", "corp", "priv", "login", "sso", "auth", "portal",
                "jenkins", "gitlab", "grafana", "kibana", "elastic", "mongo",
                "redis", "phpmyadmin", "wp-admin", "backup", "db", "sql",
                "ftp", "sftp", "ssh", "rdp", "remote", "jump", "bastion"]

    def _is_interesting(self, subdomain):
        prefix = subdomain.split('.')[0]
        return any(kw in prefix for kw in self.KEYWORDS)

    def test_admin_is_interesting(self):
        assert self._is_interesting("admin.yahoo.com")

    def test_vpn_is_interesting(self):
        assert self._is_interesting("vpn-backup.yahoo.com")

    def test_staging_is_interesting(self):
        assert self._is_interesting("staging.yahoo.com")

    def test_www_is_not_interesting(self):
        assert not self._is_interesting("www.yahoo.com")

    def test_mail_is_not_interesting(self):
        assert not self._is_interesting("mail.yahoo.com")

    def test_jenkins_is_interesting(self):
        assert self._is_interesting("jenkins-ci.yahoo.com")

    def test_grafana_is_interesting(self):
        assert self._is_interesting("grafana-prod.yahoo.com")

    def test_bastion_is_interesting(self):
        assert self._is_interesting("bastion.yahoo.com")
