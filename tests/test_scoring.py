from cypher.phish.analyzer import analyze_url


def test_single_lexical_signal_cannot_reach_phishing_verdict() -> None:
    result = analyze_url("javascript:alert(1)")

    assert result["risk_score"] < 70
    assert result["verdict"] != "Phishing"


def test_lookalike_with_account_lure_is_suspicious_and_reproducible() -> None:
    url = "https://paypa1-login.invalid/verify-account"

    first = analyze_url(url)
    second = analyze_url(url)

    assert first == second
    assert first["verdict"] in {"Suspicious", "Phishing"}
    assert any(item["id"] == "brand-typosquat" for item in first["evidence"])
    assert first["network_contacted"] is False


def test_mixed_independent_evidence_has_bounded_score() -> None:
    result = analyze_url("http://user@192.0.2.10:8448/account/login")

    assert 0 <= result["risk_score"] <= 100
    assert result["verdict"] in {"Caution", "Suspicious", "Phishing"}
    assert len(result["groups"]) >= 2
