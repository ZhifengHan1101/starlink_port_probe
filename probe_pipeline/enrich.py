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
            query_key = self._build_query_key(record)
            if query_key:
                if query_key not in cache:
                    cache[query_key] = self.lookup_cves(record)
                    time.sleep(float(self.config["query_delay_seconds"]))
                cves = cache[query_key]
                status = "ok"
            enriched.append(
                EnrichedRecord(
                    **record.to_dict(),
                    cves=cves,
                    enrichment_status=status,
                )
            )
        return enriched

    def _build_query_key(self, record: FingerprintRecord) -> str | None:
        if record.cpe:
            return record.cpe[0]
        if record.product:
            return f"{record.product}:{record.version or '*'}"
        return None

    def lookup_cves(self, record: FingerprintRecord) -> list[dict[str, Any]]:
        if record.cpe:
            params = {"cpeName": record.cpe[0]}
            reason = f"cpe={record.cpe[0]}"
        elif record.product:
            keyword = f"{record.product} {record.version or ''}".strip()
            params = {"keywordSearch": keyword}
            reason = f"keyword={keyword}"
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
                    match_reason=reason,
                ).to_dict()
            )
        return results


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
