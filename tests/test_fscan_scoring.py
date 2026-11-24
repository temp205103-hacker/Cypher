import pytest

from cypher.fscan.engine import score_signals


@pytest.mark.parametrize(
    "score, verdict",
    [
        (0, "Clean"),
        (24, "Clean"),
        (25, "Low"),
        (44, "Low"),
        (45, "Suspicious"),
        (69, "Suspicious"),
        (70, "Dangerous"),
    ],
)
def test_score_boundaries(score, verdict) -> None:
    result = score_signals([{
        "id": f"signal-{score}",
        "group": "test",
        "weight": score,
        "evidence": "safe synthetic signal",
    }])

    if score >= 70:
        assert result["score"] == 69
        assert result["verdict"] == "Suspicious"
    else:
        assert result["score"] == score
        assert result["verdict"] == verdict


def test_dangerous_requires_independent_strong_signals() -> None:
    result = score_signals([
        {"id": "hash", "group": "reputation", "weight": 40, "evidence": "known test hash"},
        {"id": "script", "group": "content", "weight": 35, "evidence": "synthetic script pattern"},
    ])

    assert result["score"] == 75
    assert result["verdict"] == "Dangerous"
    assert result["confidence"] == "medium"


def test_duplicate_signal_cannot_inflate_score() -> None:
    signal = {"id": "same", "group": "location", "weight": 25, "evidence": "test"}

    result = score_signals([signal, signal])

    assert result["score"] == 25
    assert len(result["evidence"]) == 1
