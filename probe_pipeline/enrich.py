from __future__ import annotations

import os
import time
from typing import Any

import requests

from .models import CVERecord, EnrichedRecord, FingerprintRecord


class Enricher:
    def __init__(self, config: dict) -> None:
        self.config = config["enrich"]
        self.api_key = os.getenv("NVD_API_KEY")

    def run(self, records: list[FingerprintRecord]) -> list[EnrichedRecord]:
        enriched: list[EnrichedRecord] = []
        cache: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            status = "skipped"
            cves: list[dict[str, Any]] = []
            query_keys = self._build_query_keys(record)
            if query_keys:
                status = "ok"
                for query_key in query_keys:
                    if query_key not in cache:
                        cache[query_key] = self.lookup_cves(query_key, record)
                        time.sleep(float(self.config["query_delay_seconds"]))
                    cves = merge_cves(cves, cache[query_key], int(self.config["max_cves_per_match"]))
                    if cves and query_key.startswith("cpe="):
                        break
            enriched.append(
                EnrichedRecord(
                    **record.to_dict(),
                    cves=cves,
                    enrichment_status=status,
                )
            )
        return enriched

    def _build_query_keys(self, record: FingerprintRecord) -> list[str]:
        query_keys: list[str] = []
        for cpe in record.cpe:
            normalized = normalize_cpe(cpe)
            if normalized:
                query_keys.append(f"cpe={normalized}")
        if query_keys:
            return dedupe(query_keys)
        if self.config.get("allow_keyword_fallback") and record.product:
            keyword = f"{record.product} {record.version or ''}".strip()
            if keyword:
                query_keys.append(f"keyword={keyword}")
        return query_keys

    def lookup_cves(self, query_key: str, record: FingerprintRecord) -> list[dict[str, Any]]:
        reason, value = query_key.split("=", 1)
        if reason == "cpe":
            params = {"cpeName": value}
        elif reason == "keyword":
            params = {"keywordSearch": value}
        else:
            return []

        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            response = requests.get(
                self.config["nvd_api_base"],
                params=params,
                headers=headers,
                timeout=float(self.config["request_timeout_seconds"]),
            )
            response.raise_for_status()
        except requests.RequestException:
            return []

        payload = response.json()
        vulns = payload.get("vulnerabilities", [])[: int(self.config["max_cves_per_match"])]
        results: list[dict[str, Any]] = []
        for item in vulns:
            cve = item.get("cve", {})
            descriptions = cve.get("descriptions", [])
            description = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), None)
            metrics = cve.get("metrics", {})
            severity, score = extract_cvss(metrics)
            results.append(
                CVERecord(
                    cve_id=cve.get("id", ""),
                    severity=severity,
                    score=score,
                    published=cve.get("published"),
                    last_modified=cve.get("lastModified"),
                    description=description,
                    match_reason=query_key,
                ).to_dict()
            )
        if reason == "keyword":
            return filter_keyword_hits(results, record)
        return results


def normalize_cpe(cpe: str) -> str | None:
    value = cpe.strip()
    if not value:
        return None
    if value.startswith("cpe:2.3:"):
        return value
    if not value.startswith("cpe:/"):
        return None

    parts = value[5:].split(":")
    if len(parts) < 3:
        return None
    part = parts[0] or "*"
    vendor = parts[1] or "*"
    product = parts[2] or "*"
    version = parts[3] if len(parts) > 3 and parts[3] else "*"
    update = parts[4] if len(parts) > 4 and parts[4] else "*"
    edition = parts[5] if len(parts) > 5 and parts[5] else "*"
    language = parts[6] if len(parts) > 6 and parts[6] else "*"
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:*:*:*:*"


def filter_keyword_hits(cves: list[dict[str, Any]], record: FingerprintRecord) -> list[dict[str, Any]]:
    required_terms = [term.lower() for term in (record.product or "").split() if term]
    if record.version:
        required_terms.append(record.version.lower())
    if not required_terms:
        return []

    filtered: list[dict[str, Any]] = []
    for item in cves:
        blob = " ".join(
            str(item.get(field, "")).lower()
            for field in ("description", "match_reason")
        )
        if all(term in blob for term in required_terms):
            filtered.append(item)
    return filtered


def merge_cves(
    existing: list[dict[str, Any]],
    new_items: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    merged = {item.get("cve_id"): item for item in existing}
    for item in new_items:
        cve_id = item.get("cve_id")
        if cve_id and cve_id not in merged:
            merged[cve_id] = item
        elif cve_id:
            merged[cve_id] = merged[cve_id] | {"match_reason": merged[cve_id]["match_reason"]}
    return list(merged.values())[:limit]


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def extract_cvss(metrics: dict[str, Any]) -> tuple[str | None, float | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        metric = entries[0]
        data = metric.get("cvssData", {})
        severity = data.get("baseSeverity") or metric.get("baseSeverity")
        score = data.get("baseScore")
        return severity, score
    return None, None
