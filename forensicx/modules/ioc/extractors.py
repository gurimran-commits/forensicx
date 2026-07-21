"""Local regular-expression extractors for supported IOC types."""

from __future__ import annotations

import re


_IPV4_PATTERN = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}(?![\w.])")
_DOMAIN_PATTERN = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")
_URL_PATTERN = re.compile(r"https?://(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?::\d{1,5})?(?:/[^\s<>\"']*)?", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")
_MD5_PATTERN = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")
_SHA1_PATTERN = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")
_SHA256_PATTERN = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")


def extract_ipv4(text: str) -> set[str]:
    """Extract valid dotted-quad IPv4 addresses."""
    return set(_IPV4_PATTERN.findall(text))


def extract_domains(text: str) -> set[str]:
    """Extract domain names, excluding bare host labels and IP addresses."""
    return {match.lower() for match in _DOMAIN_PATTERN.findall(text)}


def extract_urls(text: str) -> set[str]:
    """Extract HTTP and HTTPS URLs with a domain host."""
    return {match.rstrip(".,;:!?)]}") for match in _URL_PATTERN.findall(text)}


def extract_emails(text: str) -> set[str]:
    """Extract mailbox addresses with a domain suffix."""
    return {match.lower() for match in _EMAIL_PATTERN.findall(text)}


def extract_hashes(text: str) -> dict[str, set[str]]:
    """Extract MD5, SHA-1, and SHA-256 hex digests."""
    return {
        "md5": {match.lower() for match in _MD5_PATTERN.findall(text)},
        "sha1": {match.lower() for match in _SHA1_PATTERN.findall(text)},
        "sha256": {match.lower() for match in _SHA256_PATTERN.findall(text)},
    }


def extract_iocs(text: str) -> dict[str, set[str]]:
    """Return every IOC type supported by the first extraction release."""
    return {
        "ipv4": extract_ipv4(text),
        "domain": extract_domains(text),
        "url": extract_urls(text),
        "email": extract_emails(text),
        **extract_hashes(text),
    }
