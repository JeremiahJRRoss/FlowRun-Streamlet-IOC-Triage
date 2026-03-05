# tests/test_classifier.py
# ─────────────────────────────────────────────────────────────────────────────
# Tests IOC type detection for all 7 IOC types + unknown.
# Uses the regex pre-classifier from agent/graph.py.
# ─────────────────────────────────────────────────────────────────────────────

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.graph import _regex_classify


class TestRegexClassifier:
    """Test the fast regex pre-classifier for all 7 IOC types."""

    # ── IPv4 ──────────────────────────────────────────────────────────────
    def test_ipv4_standard(self):
        assert _regex_classify("8.8.8.8") == "ip"

    def test_ipv4_private(self):
        assert _regex_classify("192.168.1.1") == "ip"

    def test_ipv4_full_range(self):
        assert _regex_classify("203.0.113.42") == "ip"

    # ── IPv6 ──────────────────────────────────────────────────────────────
    def test_ipv6_full(self):
        assert _regex_classify("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "ip"

    def test_ipv6_compressed(self):
        assert _regex_classify("2001:db8::1") == "ip"

    # ── Domain ────────────────────────────────────────────────────────────
    def test_domain_simple(self):
        assert _regex_classify("example.com") == "domain"

    def test_domain_subdomain(self):
        assert _regex_classify("malicious.subdomain.example.com") == "domain"

    def test_domain_wicar(self):
        assert _regex_classify("malware.wicar.org") == "domain"

    # ── URL ────────────────────────────────────────────────────────────────
    def test_url_https(self):
        assert _regex_classify("https://phishing-site.xyz/login") == "url"

    def test_url_http(self):
        assert _regex_classify("http://malware-host.com/payload") == "url"

    def test_url_ftp(self):
        assert _regex_classify("ftp://files.example.com/data.zip") == "url"

    # ── Hash MD5 ──────────────────────────────────────────────────────────
    def test_hash_md5(self):
        assert _regex_classify("44d88612fea8a8f36de82e1278abb02f") == "hash_md5"

    def test_hash_md5_uppercase(self):
        assert _regex_classify("44D88612FEA8A8F36DE82E1278ABB02F") == "hash_md5"

    # ── Hash SHA-1 ────────────────────────────────────────────────────────
    def test_hash_sha1(self):
        assert _regex_classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash_sha1"

    # ── Hash SHA-256 ──────────────────────────────────────────────────────
    def test_hash_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _regex_classify(h) == "hash_sha256"

    # ── CVE ────────────────────────────────────────────────────────────────
    def test_cve_standard(self):
        assert _regex_classify("CVE-2024-12345") == "cve"

    def test_cve_log4shell(self):
        assert _regex_classify("CVE-2021-44228") == "cve"

    def test_cve_lowercase(self):
        assert _regex_classify("cve-2024-99999") == "cve"

    # ── Unknown / inconclusive ────────────────────────────────────────────
    def test_garbage_string(self):
        # Strings with special chars that don't match any IOC type
        assert _regex_classify("!!!not_valid!!!") is None
        assert _regex_classify("") is None
        assert _regex_classify("   ") is None

    def test_bare_word_is_package_multi(self):
        # Plain words now classify as package_multi for multi-ecosystem scanning
        assert _regex_classify("not_a_valid_ioc") == "package_multi"

    def test_empty_string(self):
        assert _regex_classify("") is None

    def test_numeric_only(self):
        assert _regex_classify("12345") is None

    # ── Package ───────────────────────────────────────────────────────────
    def test_package_npm(self):
        assert _regex_classify("npm:postmark-mcp") == "package"

    def test_package_pypi(self):
        assert _regex_classify("pypi:requessts") == "package"

    def test_package_crates(self):
        assert _regex_classify("crates:serde") == "package"

    def test_package_go(self):
        assert _regex_classify("go:github.com/evil/pkg") == "package"

    def test_package_scoped_npm(self):
        assert _regex_classify("npm:@malicious/helper") == "package"

    # ── Expanded ecosystem prefixes ──────────────────────────────────────
    def test_package_rhel(self):
        assert _regex_classify("rhel:openssl") == "package"

    def test_package_debian(self):
        assert _regex_classify("debian:nginx") == "package"

    def test_package_ubuntu(self):
        assert _regex_classify("ubuntu:curl") == "package"

    def test_package_alpine(self):
        assert _regex_classify("alpine:busybox") == "package"

    def test_package_redhat_alias(self):
        assert _regex_classify("redhat:httpd") == "package"

    # ── Bare package name (multi-ecosystem scan) ─────────────────────────
    def test_bare_package_simple(self):
        assert _regex_classify("traceroute") == "package_multi"

    def test_bare_package_hyphen(self):
        assert _regex_classify("postmark-mcp") == "package_multi"

    def test_bare_package_underscore(self):
        assert _regex_classify("my_package") == "package_multi"

    def test_bare_package_express(self):
        assert _regex_classify("express") == "package_multi"

    def test_bare_package_lodash(self):
        assert _regex_classify("lodash") == "package_multi"

    # ── Edge cases: domain vs bare package ────────────────────────────────
    def test_domain_not_bare_package(self):
        # Has a dot → domain, not bare package
        assert _regex_classify("example.com") == "domain"

    def test_single_char_not_package(self):
        # Too short (min 2 chars after first letter)
        assert _regex_classify("a") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
