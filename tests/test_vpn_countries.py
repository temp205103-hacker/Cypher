import pytest

from guardsnitch.vpn.countries import resolve_country


@pytest.mark.parametrize(
    "value, expected",
    [
        ("DE", "DE"),
        ("Germany", "DE"),
        ("deutschland", "DE"),
        ("germny", "DE"),
        ("US", "US"),
        ("United States of America", "US"),
        ("JP", "JP"),
        ("Japan", "JP"),
    ],
)
def test_resolve_country(value: str, expected: str) -> None:
    assert resolve_country(value).code == expected


def test_unknown_country_has_helpful_error() -> None:
    with pytest.raises(ValueError, match="Unknown country"):
        resolve_country("Atlantis")
