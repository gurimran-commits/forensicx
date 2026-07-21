"""Unit tests for supported IOC regular-expression extractors."""

from __future__ import annotations

from forensicx.modules.ioc.extractors import extract_domains, extract_emails, extract_hashes, extract_ipv4, extract_urls


def test_ipv4_extractor_accepts_valid_addresses_and_rejects_invalid_ones() -> None:
    assert extract_ipv4("Connect to 203.0.113.42; ignore 999.1.1.1.") == {"203.0.113.42"}


def test_domain_extractor_accepts_fqdns_and_rejects_bare_labels() -> None:
    assert extract_domains("Beacon at Evil-Example.COM, not localhost or invalid_domain.") == {"evil-example.com"}


def test_url_extractor_accepts_http_urls_and_rejects_other_schemes() -> None:
    assert extract_urls("Visit https://example.com/path?q=1, not ftp://example.com.") == {"https://example.com/path?q=1"}


def test_email_extractor_accepts_mailboxes_and_rejects_invalid_addresses() -> None:
    assert extract_emails("Contact Analyst+IOC@Example.org; not analyst@localhost.") == {"analyst+ioc@example.org"}


def test_hash_extractor_identifies_each_supported_length_without_shorter_false_positives() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    hashes = extract_hashes(f"{md5} {sha1} {sha256} not-a-hash deadbeef")
    assert hashes == {"md5": {md5}, "sha1": {sha1}, "sha256": {sha256}}
