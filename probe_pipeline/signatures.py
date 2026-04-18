from __future__ import annotations

import re
from typing import Any


SERVICE_PATTERNS: list[dict[str, Any]] = [
    {
        "service": "ssh",
        "pattern": re.compile(r"^SSH-(?P<version>[0-9.]+)-(?P<product>[^\r\n]+)", re.I | re.M),
        "cpe_template": "cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        "vendor_map": {
            "OpenSSH": "openbsd",
            "dropbear": "dropbear_ssh_project",
        },
    },
    {
        "service": "http",
        "pattern": re.compile(r"(?im)^server:\s*(?P<product>[A-Za-z0-9_.-]+)(?:/?(?P<version>[A-Za-z0-9_.-]+))?"),
        "cpe_template": "cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        "vendor_map": {
            "Apache": "apache",
            "nginx": "f5",
            "Caddy": "caddyserver",
            "Microsoft-IIS": "microsoft",
            "lighttpd": "lighttpd",
            "gunicorn": "gunicorn",
        },
    },
    {
        "service": "smtp",
        "pattern": re.compile(r"(?i)(postfix|exim|sendmail|opensmtpd)[^\r\n/ ]*(?:[ /](?P<version>[A-Za-z0-9_.-]+))?"),
        "cpe_template": "cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        "vendor_map": {
            "postfix": "postfix",
            "exim": "exim",
            "sendmail": "sendmail",
            "opensmtpd": "openbsd",
        },
    },
    {
        "service": "ftp",
        "pattern": re.compile(r"(?i)(vsftpd|proftpd|filezilla server|pure-ftpd)[^\r\n/ ]*(?:[ /](?P<version>[A-Za-z0-9_.-]+))?"),
        "cpe_template": "cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        "vendor_map": {
            "vsftpd": "vsftpd",
            "proftpd": "proftpd",
            "pure-ftpd": "pureftpd",
            "filezilla server": "filezilla-project",
        },
    },
    {
        "service": "redis",
        "pattern": re.compile(r"(?i)redis[_ -]?server(?:\s*v?(?P<version>[0-9.]+))?"),
        "cpe_template": "cpe:2.3:a:redislabs:redis:{version}:*:*:*:*:*:*:*",
    },
]


CERT_PRODUCT_PATTERNS: list[tuple[re.Pattern[str], dict[str, str]]] = [
    (
        re.compile(r"cloudflare", re.I),
        {
            "service": "https",
            "product": "Cloudflare",
            "vendor": "cloudflare",
        },
    ),
    (
        re.compile(r"nginx", re.I),
        {
            "service": "https",
            "product": "nginx",
            "vendor": "f5",
        },
    ),
]


def normalize_vendor_product(product: str | None) -> tuple[str | None, str | None]:
    if not product:
        return None, None
    normalized = product.strip()
    vendor = normalized.lower().replace(" ", "_").replace("/", "_")
    product_token = normalized.lower().replace(" ", "_").replace("/", "_")
    return vendor, product_token


def build_cpe(product: str | None, version: str | None, vendor_hint: str | None = None) -> str | None:
    vendor, product_token = normalize_vendor_product(product)
    if not product_token:
        return None
    version_value = version or "*"
    vendor_value = vendor_hint or vendor or "*"
    return f"cpe:2.3:a:{vendor_value}:{product_token}:{version_value}:*:*:*:*:*:*:*"


def detect_from_text(blob: str) -> dict[str, Any]:
    for signature in SERVICE_PATTERNS:
        match = signature["pattern"].search(blob)
        if not match:
            continue
        product = match.groupdict().get("product") or match.group(1)
        version = match.groupdict().get("version")
        vendor_map = signature.get("vendor_map", {})
        vendor_hint = vendor_map.get(product, vendor_map.get(product.lower() if isinstance(product, str) else "", None))
        cpe = build_cpe(product, version, vendor_hint)
        return {
            "service": signature["service"],
            "product": product,
            "version": version,
            "cpe": [cpe] if cpe else [],
            "confidence": 0.82 if version else 0.68,
        }
    return {}


def detect_from_tls_cert(subject: str, issuer: str) -> dict[str, Any]:
    blob = f"{subject}\n{issuer}"
    for pattern, meta in CERT_PRODUCT_PATTERNS:
        if pattern.search(blob):
            cpe = build_cpe(meta["product"], None, meta["vendor"])
            return {
                "service": meta["service"],
                "product": meta["product"],
                "version": None,
                "cpe": [cpe] if cpe else [],
                "confidence": 0.45,
            }
    return {}
