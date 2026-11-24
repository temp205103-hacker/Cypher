from cypher.phish.scan import extract_urls, scan_path, scan_text


def test_text_scanner_extracts_unique_links_without_opening_them() -> None:
    result = scan_text(
        "See https://example.com and https://paypa1-login.invalid/verify. "
        "Again: https://example.com"
    )

    assert result["links_found"] == 2
    assert result["findings"][0]["verdict"] == "Safe"
    assert result["findings"][1]["verdict"] in {"Suspicious", "Phishing"}
    assert all(item["network_contacted"] is False for item in result["findings"])


def test_email_file_checks_reply_to_and_visible_link_mismatch(tmp_path) -> None:
    message = (
        "From: Bank Security <alert@sender.example>\n"
        "Reply-To: collector@reply.invalid\n"
        "Subject: Verify your account\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        '<a href="https://paypa1-login.invalid/verify">'
        "https://bank.example</a>"
    )
    path = tmp_path / "notice.eml"
    path.write_text(message, encoding="utf-8")

    result = scan_path(path)

    assert result["links_found"] == 1
    assert any("Reply-To" in item for item in result["message_evidence"])
    assert any("link text and destination" in item for item in result["message_evidence"])


def test_extract_urls_deduplicates() -> None:
    assert extract_urls("https://example.com, https://example.com") == [
        "https://example.com"
    ]
