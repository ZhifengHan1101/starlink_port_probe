#!/usr/bin/env python3
"""Scan today's Starlink IPv4 addresses on the top 1000 TCP ports using xmap.

Input : ~/hzf/starlink_as_probe/as14593/results/active_ipv4_{today}.csv
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
    load_ips_from_csv,
    write_csv,
    write_jsonl,
)
from probe_pipeline.scanner import scan_targets


def _real_home() -> Path:
    """Return the real user's home directory, even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


INPUT_DIR = _real_home() / "hzf" / "starlink_as_probe" / "as14593" / "results"


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

    targets = load_ips_from_csv(str(input_file))
    print(f"Loaded {len(targets)} target IPs")

    rows = scan_targets(config, run_id, targets, run_dir, port_profile="top1000")
    print(f"Found {len(rows)} open ports across {len({r.ip for r in rows})} hosts")

    rows_dicts = [r.to_dict() for r in rows]
    write_jsonl(run_dir / "open_ports.jsonl", rows_dicts)
    write_csv(run_dir / "open_ports.csv", rows_dicts)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
