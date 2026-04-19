from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_config
from .enrich import Enricher
from .fingerprinter import Fingerprinter
from .io_utils import (
    default_run_id,
    discover_input_files,
    ensure_dir,
    load_ips_from_csv,
    utc_timestamp,
    write_csv,
    write_jsonl,
)
from .models import EnrichedRecord, FingerprintRecord, OpenPortRecord
from .report import render_report
from .scanner import scan_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Starlink TCP port probe pipeline")
    parser.add_argument("--config", default="/home/ubuntu/hzf/starlink_port_probe/config.yaml")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("scan", "fingerprint", "enrich", "report", "all"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--run-id", default=None)
        sub.add_argument("--input", action="append", default=None)
        sub.add_argument("--limit", type=int, default=None)
        sub.add_argument("--workers", type=int, default=None)
        if name in ("fingerprint", "all"):
            sub.add_argument(
                "--no-os",
                action="store_true",
                help="Run only nmap -sV service fingerprinting and skip nmap -O OS detection.",
            )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config)
    if args.command in ("fingerprint", "enrich", "report") and not args.run_id:
        raise RuntimeError(f"The {args.command} subcommand requires --run-id to point to an existing scan output directory.")
    run_id = args.run_id or default_run_id()
    run_dir = ensure_dir(Path(config["project"]["output_root"]) / run_id)

    if args.command in ("scan", "all"):
        scan_rows = run_scan(config, run_id, run_dir, args.input, args.limit)
    else:
        scan_rows = load_open_ports(run_dir)

    if args.command in ("fingerprint", "all"):
        fp_rows = run_fingerprint(config, run_id, run_dir, args.workers, no_os=getattr(args, "no_os", False))
    elif args.command in ("enrich", "report"):
        fp_rows = load_fingerprints(run_dir)
    else:
        fp_rows = []

    if args.command in ("enrich", "all"):
        enriched_rows = run_enrich(config, run_dir, args.workers)
    elif args.command == "report":
        enriched_rows = load_enriched(run_dir)
    else:
        enriched_rows = []

    if args.command == "report":
        render_report(run_id, scan_rows, fp_rows, enriched_rows, run_dir / "report.md", config)
    elif args.command == "all":
        render_report(run_id, scan_rows, fp_rows, enriched_rows, run_dir / "report.md", config)

    print(f"[{utc_timestamp()}] completed command={args.command} run_id={run_id} output={run_dir}")
    return 0


def run_scan(
    config: dict,
    run_id: str,
    run_dir: Path,
    input_files: list[str] | None,
    limit: int | None,
) -> list[OpenPortRecord]:
    files = discover_input_files(input_files, config["project"]["default_input_glob"])
    if not files:
        raise RuntimeError("No input IPv4 CSV files were found.")
    targets: list[dict[str, str]] = []
    for file_path in files:
        targets.extend(load_ips_from_csv(file_path, limit=None))
    if limit is not None:
        targets = targets[:limit]
    rows = scan_targets(config, run_id, targets, run_dir)
    rows_dicts = [row.to_dict() for row in rows]
    write_jsonl(run_dir / "open_ports.jsonl", rows_dicts)
    write_csv(run_dir / "open_ports.csv", rows_dicts)
    return rows


def run_fingerprint(
    config: dict,
    run_id: str,
    run_dir: Path,
    workers: int | None,
    no_os: bool = False,
) -> list[FingerprintRecord]:
    scan_rows = load_open_ports(run_dir)
    if no_os:
        config["fingerprint"]["os_detection"] = False
    fingerprinter = Fingerprinter(config, run_id, run_dir)
    rows = fingerprinter.run(scan_rows, workers=workers)
    row_dicts = [row.to_dict() for row in rows]
    write_jsonl(run_dir / "fingerprints.jsonl", row_dicts)
    write_csv(run_dir / "fingerprints.csv", row_dicts)
    return rows


def run_enrich(config: dict, run_dir: Path, workers: int | None) -> list[EnrichedRecord]:
    fp_rows = load_fingerprints(run_dir)
    enricher = Enricher(config, workers=workers)
    rows = enricher.run(fp_rows)
    row_dicts = [row.to_dict() for row in rows]
    write_jsonl(run_dir / "enriched.jsonl", row_dicts)
    write_csv(run_dir / "enriched.csv", row_dicts)
    return rows


def load_open_ports(run_dir: Path) -> list[OpenPortRecord]:
    path = run_dir / "open_ports.jsonl"
    if not path.exists():
        return []
    rows: list[OpenPortRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(OpenPortRecord(**json.loads(line)))
    return rows


def load_fingerprints(run_dir: Path) -> list[FingerprintRecord]:
    path = run_dir / "fingerprints.jsonl"
    if not path.exists():
        return []
    rows: list[FingerprintRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(FingerprintRecord(**json.loads(line)))
    return rows


def load_enriched(run_dir: Path) -> list[EnrichedRecord]:
    path = run_dir / "enriched.jsonl"
    if not path.exists():
        return []
    rows: list[EnrichedRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(EnrichedRecord(**json.loads(line)))
    return rows
