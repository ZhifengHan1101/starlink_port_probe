from __future__ import annotations

from collections import Counter
from pathlib import Path

from .models import EnrichedRecord, FingerprintRecord, OpenPortRecord


def render_report(
    run_id: str,
    scan_rows: list[OpenPortRecord],
    fp_rows: list[FingerprintRecord],
    enriched_rows: list[EnrichedRecord],
    output_path: str | Path,
    config: dict,
) -> None:
    product_counter = Counter(row.product or "unknown" for row in fp_rows if row.service)
    service_counter = Counter(row.service or "unknown" for row in fp_rows)
    os_hosts = best_os_by_host(fp_rows)
    os_detected_hosts = {
        ip: row
        for ip, row in os_hosts.items()
        if row.os_name or row.os_family or row.os_vendor or row.os_cpe
    }
    os_name_counter = Counter(row.os_name or "unknown" for row in os_detected_hosts.values())
    os_family_counter = Counter(row.os_family or "unknown" for row in os_detected_hosts.values())
    os_vendor_counter = Counter(row.os_vendor or "unknown" for row in os_detected_hosts.values())
    os_cpe_counter = Counter(cpe for row in os_detected_hosts.values() for cpe in row.os_cpe)
    cve_counter = Counter()
    for row in enriched_rows:
        for cve in row.cves:
            cve_counter[cve.get("cve_id", "unknown")] += 1

    lines: list[str] = []
    lines.append(f"# Starlink Port Probe Report")
    lines.append("")
    lines.append(f"- Run ID: `{run_id}`")
    lines.append(f"- Open TCP endpoints: `{len(scan_rows)}`")
    lines.append(f"- Fingerprinted endpoints: `{len(fp_rows)}`")
    lines.append(f"- Enriched endpoints: `{len(enriched_rows)}`")
    lines.append("")
    lines.append("## Top Services")
    lines.append("")
    for service, count in service_counter.most_common(20):
        lines.append(f"- `{service}`: {count}")
    lines.append("")
    lines.append("## Top Products")
    lines.append("")
    for product, count in product_counter.most_common(int(config["report"]["top_n_products"])):
        lines.append(f"- `{product}`: {count}")
    lines.append("")
    if os_detected_hosts:
        total_hosts = len({row.ip for row in fp_rows})
        unknown_hosts = max(0, total_hosts - len(os_detected_hosts))
        lines.append("## OS Summary")
        lines.append("")
        lines.append(f"- Hosts with OS fingerprint: `{len(os_detected_hosts)}`")
        lines.append(f"- Hosts without OS fingerprint: `{unknown_hosts}`")
        lines.append("")
        lines.append("### Top OS Names")
        lines.append("")
        for os_name, count in os_name_counter.most_common(20):
            lines.append(f"- `{os_name}`: {count}")
        lines.append("")
        lines.append("### Top OS Families")
        lines.append("")
        for os_family, count in os_family_counter.most_common(20):
            lines.append(f"- `{os_family}`: {count}")
        lines.append("")
        lines.append("### Top OS Vendors")
        lines.append("")
        for os_vendor, count in os_vendor_counter.most_common(20):
            lines.append(f"- `{os_vendor}`: {count}")
        if os_cpe_counter:
            lines.append("")
            lines.append("### Top OS CPEs")
            lines.append("")
            for os_cpe, count in os_cpe_counter.most_common(20):
                lines.append(f"- `{os_cpe}`: {count}")
        lines.append("")
    lines.append("## Top CVEs")
    lines.append("")
    if cve_counter:
        for cve_id, count in cve_counter.most_common(int(config["report"]["top_n_cves"])):
            lines.append(f"- `{cve_id}`: {count}")
    else:
        lines.append("- No CVEs matched.")
    lines.append("")
    lines.append("## Sample Findings")
    lines.append("")
    for row in enriched_rows[:20]:
        cve_ids = ", ".join(cve["cve_id"] for cve in row.cves[:5]) or "none"
        lines.append(
            f"- `{row.ip}:{row.port}` -> service=`{row.service or 'unknown'}`, "
            f"product=`{row.product or 'unknown'}`, version=`{row.version or 'unknown'}`, "
            f"os=`{row.os_name or row.os_family or 'unknown'}`, "
            f"confidence=`{row.confidence:.2f}`, cves=`{cve_ids}`"
        )
    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def best_os_by_host(fp_rows: list[FingerprintRecord]) -> dict[str, FingerprintRecord]:
    rows_by_host: dict[str, FingerprintRecord] = {}
    for row in fp_rows:
        current = rows_by_host.get(row.ip)
        if current is None or os_score(row) > os_score(current):
            rows_by_host[row.ip] = row
    return rows_by_host


def os_score(row: FingerprintRecord) -> tuple[int, float, int]:
    has_os = int(bool(row.os_name or row.os_family or row.os_vendor or row.os_cpe))
    return has_os, row.os_accuracy, len(row.os_cpe)
