#!/usr/bin/env python3
"""Run the full probe pipeline for today's Starshield IPv4 addresses.

Input : ~/hzf/starshield-probe/results/active_ipv4_{today}.csv
Output: ~/hzf/starlink_port_probe/runs/{run_id}/
"""

from __future__ import annotations

import os
import pwd
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_pipeline.config import load_config
from probe_pipeline.io_utils import (
    default_run_id,
    ensure_dir,
)
from probe_pipeline.cli import run_enrich, run_fingerprint, run_scan
from probe_pipeline.report import render_report


def _real_home() -> Path:
    """Return the real user's home directory, even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


INPUT_DIR = _real_home() / "hzf" / "starshield-probe" / "results"


def find_today_input() -> Path:
    today = datetime.now(timezone.utc).strftime("%Y_%m_%d")
    pattern = f"active_ipv4_{today}.csv"
    path = INPUT_DIR / pattern
    if not path.exists():
        # Fall back to the most recent file
        candidates = sorted(INPUT_DIR.glob("active_ipv4_*.csv"))
        if not candidates:
            raise FileNotFoundError(f"No active_ipv4 CSV found in {INPUT_DIR}")
        print(f"Today's file not found, using latest: {candidates[-1].name}")
        return candidates[-1]
    return path


def main() -> int:
    config_path = Path(__file__).resolve().parent / "config.yaml"
    config = load_config(str(config_path))
    run_id = default_run_id()
    run_dir = ensure_dir(Path(config["project"]["output_root"]) / run_id)

    input_file = find_today_input()
    print(f"Input : {input_file}")
    print(f"Run ID: {run_id}")
    print(f"Output: {run_dir}")

    print("Stage: scan (port profile: full)")
    scan_rows = run_scan(config, run_id, run_dir, [str(input_file)], limit=None, port_profile="full")
    print(f"Found {len(scan_rows)} open ports across {len({r.ip for r in scan_rows})} hosts")

    print("Stage: fingerprint")
    fp_rows = run_fingerprint(config, run_id, run_dir, workers=None)
    print(f"Fingerprinted {len(fp_rows)} endpoints")

    print("Stage: enrich")
    enriched_rows = run_enrich(config, run_dir, workers=None)
    print(f"Enriched {len(enriched_rows)} endpoints")

    print("Stage: report")
    render_report(run_id, scan_rows, fp_rows, enriched_rows, run_dir / "report.md", config)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
