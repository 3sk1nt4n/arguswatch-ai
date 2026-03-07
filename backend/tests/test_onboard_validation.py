"""v16.4.6 onboarding safety tests: domain-name validation."""
import re
import pytest


def _domain_matches_name(domain: str, company_name: str) -> bool:
    """Mirror of the validation logic in main.py onboard endpoint."""
    d = domain.lower().replace("www.", "").split(".")[0]
    name_words = re.findall(r'[a-z0-9]{3,}', company_name.lower())
    if not name_words or not d:
        return True  # can't validate
    name_concat = "".join(name_words)
    acronym = "".join(w[0] for w in name_words) if len(name_words) >= 2 else ""
    return (
        any(w in d or d in w for w in name_words) or
        d in name_concat or name_concat in d or
        (acronym and (acronym == d or d.startswith(acronym)))
    )


class TestDomainNameValidation:
    """Prevent cross-company onboarding like PAYPAL → apple.com."""

    @pytest.mark.parametrize("name,domain", [
        ("PayPal", "paypal.com"),
        ("Yahoo", "yahoo.com"),
        ("Uber", "uber.com"),
        ("Uber Technologies", "uber.com"),
        ("GitHub", "github.com"),
        ("Starbucks", "starbucks.com"),
        ("Tesla", "tesla.com"),
        ("International Business Machines", "ibm.com"),
        ("VulnWeb Demo", "vulnweb.com"),
        ("Solvent CyberSecurity", "solventcyber.com"),
    ])
    def test_valid_pairs_pass(self, name, domain):
        assert _domain_matches_name(domain, name), f"{name} should match {domain}"

    @pytest.mark.parametrize("name,domain", [
        ("PayPal", "apple.com"),
        ("Tesla", "yahoo.com"),
        ("GitHub", "starbucks.com"),
        ("Uber", "microsoft.com"),
        ("Amazon", "google.com"),
        ("Shopify", "tesla.com"),
    ])
    def test_mismatched_pairs_fail(self, name, domain):
        assert not _domain_matches_name(domain, name), f"{name} should NOT match {domain}"
