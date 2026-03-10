#!/usr/bin/env python3
"""Threat intelligence enrichment for XDR Bot.

Supports: file hashes, IPs, domains, URLs, email senders.
Real mode: VirusTotal API (VT_API_KEY env var).
Demo mode: Realistic synthetic intel responses.
"""

import argparse
import json
import os
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError


VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"


# ─── VirusTotal API ──────────────────────────────────────────────────────────

def _vt_get(endpoint: str) -> dict:
    """GET from VirusTotal API."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}
    url = f"{VT_BASE}/{endpoint}"
    req = Request(url, method="GET")
    req.add_header("x-apikey", VT_API_KEY)
    try:
        with urlopen(req) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        return {"error": True, "code": e.code}


def vt_file_report(sha256: str) -> dict:
    """Get VirusTotal file report."""
    data = _vt_get(f"files/{sha256}")
    if "error" in data:
        return data
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "type": "file",
        "hash": sha256,
        "known_malware": stats.get("malicious", 0) > 5,
        "reputation": "malicious" if stats.get("malicious", 0) > 5 else "clean",
        "vt_hits": stats.get("malicious", 0),
        "total_engines": sum(stats.values()),
        "family": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "unknown"),
        "file_type": attrs.get("type_description", "unknown"),
        "first_seen": attrs.get("first_submission_date", ""),
    }


def vt_ip_report(ip: str) -> dict:
    """Get VirusTotal IP report."""
    data = _vt_get(f"ip_addresses/{ip}")
    if "error" in data:
        return data
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "type": "ip",
        "ip": ip,
        "reputation": "malicious" if stats.get("malicious", 0) > 3 else "clean",
        "vt_hits": stats.get("malicious", 0),
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn", ""),
        "as_owner": attrs.get("as_owner", ""),
    }


# ─── Sample/Demo intel ───────────────────────────────────────────────────────

SAMPLE_HASHES = {
    "a1b2c3d4": {
        "type": "file", "hash": "a1b2c3d4...", "known_malware": True,
        "reputation": "malicious", "vt_hits": 52, "total_engines": 72,
        "family": "Emotet", "file_type": "PE32 executable",
        "first_seen": "2024-03-15T00:00:00Z",
        "campaigns": ["TA542 Emotet Campaign Q1 2024"],
    },
    "9f86d081": {
        "type": "file", "hash": "9f86d081...", "known_malware": False,
        "reputation": "trusted", "vt_hits": 0, "total_engines": 72,
        "signer": "Microsoft Corporation", "file_type": "PE64 executable",
    },
}

SAMPLE_IPS = {
    "185.220.101.42": {
        "type": "ip", "ip": "185.220.101.42", "reputation": "malicious",
        "asn": "AS205100", "as_owner": "F3 Netze e.V.",
        "country": "DE", "threat_type": "Tor Exit Node",
        "known_c2": True, "abuse_reports": 342,
        "tags": ["tor", "proxy", "scanner"],
    },
    "45.33.32.156": {
        "type": "ip", "ip": "45.33.32.156", "reputation": "suspicious",
        "asn": "AS63949", "as_owner": "Linode",
        "country": "US", "threat_type": "VPS/Hosting",
        "known_c2": False, "abuse_reports": 12,
        "tags": ["hosting", "vps"],
    },
}

SAMPLE_DOMAINS = {
    "login-contoso.evil.com": {
        "type": "domain", "domain": "login-contoso.evil.com",
        "reputation": "malicious", "category": "phishing",
        "registrar": "Namecheap",
        "created": "2026-03-04T00:00:00Z",  # Very recently registered
        "dns_a": ["185.220.101.42"],
        "ssl_issuer": "Let's Encrypt",
        "tags": ["phishing", "credential-harvesting", "brand-impersonation"],
        "similar_to": "contoso.com",
    },
}

SAMPLE_EMAILS = {
    "invoice@contoso-billing.com": {
        "type": "email_sender", "email": "invoice@contoso-billing.com",
        "reputation": "malicious", "category": "BEC",
        "domain_age_days": 3,
        "spf": "fail", "dkim": "none", "dmarc": "none",
        "similar_to": "contoso.com",
        "tags": ["bec", "invoice-fraud", "brand-impersonation"],
    },
}


def sample_lookup(query_type: str, value: str) -> dict:
    """Look up sample threat intel for demo mode."""
    if query_type == "hash":
        prefix = value[:8].lower()
        return SAMPLE_HASHES.get(prefix, {
            "type": "file", "hash": value, "known_malware": False,
            "reputation": "unknown", "vt_hits": 0,
        })
    elif query_type == "ip":
        return SAMPLE_IPS.get(value, {
            "type": "ip", "ip": value, "reputation": "clean",
            "asn": "AS15169", "as_owner": "Google LLC", "country": "US",
        })
    elif query_type == "domain":
        return SAMPLE_DOMAINS.get(value, {
            "type": "domain", "domain": value, "reputation": "unknown",
            "dns_a": ["1.2.3.4"],
        })
    elif query_type == "url":
        # Extract domain from URL for lookup
        from urllib.parse import urlparse
        domain = urlparse(value).hostname or value
        base = SAMPLE_DOMAINS.get(domain, {})
        return {**base, "type": "url", "url": value, "reputation": base.get("reputation", "unknown")}
    elif query_type == "email":
        return SAMPLE_EMAILS.get(value, {
            "type": "email_sender", "email": value, "reputation": "unknown",
            "spf": "unknown", "dkim": "unknown", "dmarc": "unknown",
        })
    return {"type": query_type, "value": value, "reputation": "unknown"}


def main():
    p = argparse.ArgumentParser(description="XDR threat intelligence enrichment")
    p.add_argument("--hash", help="SHA256 file hash")
    p.add_argument("--ip", help="IP address")
    p.add_argument("--domain", help="Domain name")
    p.add_argument("--url", help="URL")
    p.add_argument("--email", help="Email sender address")
    p.add_argument("--live", action="store_true", help="Use live VirusTotal API (requires VT_API_KEY)")
    args = p.parse_args()

    query_type = None
    value = None

    if args.hash:
        query_type, value = "hash", args.hash
    elif args.ip:
        query_type, value = "ip", args.ip
    elif args.domain:
        query_type, value = "domain", args.domain
    elif args.url:
        query_type, value = "url", args.url
    elif args.email:
        query_type, value = "email", args.email
    else:
        print(json.dumps({"error": "Provide --hash, --ip, --domain, --url, or --email"}, indent=2))
        return

    if args.live and VT_API_KEY:
        if query_type == "hash":
            intel = vt_file_report(value)
        elif query_type == "ip":
            intel = vt_ip_report(value)
        else:
            intel = sample_lookup(query_type, value)
            intel["note"] = "Live lookup not yet implemented for this type"
    else:
        intel = sample_lookup(query_type, value)

    intel["queried_at"] = datetime.now().isoformat() + "Z"
    print(json.dumps(intel, indent=2))


if __name__ == "__main__":
    main()
