from cypher.phish.lookalike import analyze_lookalikes, edit_distance, registrable_domain


def test_domain_helpers_handle_typical_multi_label_suffixes() -> None:
    assert registrable_domain("login.example.co.uk") == "example.co.uk"
    assert edit_distance("paypa1", "paypal", 1) == 1


def test_typosquat_and_combosquat_are_reported_but_brand_subdomain_is_not() -> None:
    typosquat = analyze_lookalikes("paypa1-login.invalid")
    combosquat = analyze_lookalikes("paypal-secure.invalid")
    trusted_brand_subdomain = analyze_lookalikes("login.paypal.com")

    assert "brand-typosquat" in {item["id"] for item in typosquat}
    assert "brand-combosquat" in {item["id"] for item in combosquat}
    assert trusted_brand_subdomain == []
