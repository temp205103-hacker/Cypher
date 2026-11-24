import json

import pytest

from cypher.phish import reputation
from cypher.phish.analyzer import analyze_url


def test_local_allow_and_block_feedback_updates_analysis(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    domain = "paypal-login.invalid"

    reputation.set_domain_decision(domain, "allow")
    assert analyze_url(f"https://{domain}/login")["source"] == "user-allowlist"

    reputation.set_domain_decision(domain, "block")
    result = analyze_url(f"https://{domain}/login")
    assert result["source"] == "user-blocklist"
    assert result["verdict"] == "Phishing"
    assert domain not in reputation.user_allowed_domains()


def test_history_stores_domain_and_hash_not_full_url(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path))
    result = analyze_url("https://example.com/account?token=private-value")

    reputation.record_check(result)
    entries = reputation.history()

    assert len(entries) == 1
    assert entries[0]["domain"] == "example.com"
    assert entries[0]["url_hash"]
    assert "private-value" not in json.dumps(entries)


@pytest.mark.parametrize(
    "value",
    ["https://user@example.com", "example.com/path", "example.com:443", "127.0.0.1"],
)
def test_domain_feedback_rejects_non_domain_inputs(value) -> None:
    with pytest.raises(ValueError):
        reputation.normalize_domain(value)
