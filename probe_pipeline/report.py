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
