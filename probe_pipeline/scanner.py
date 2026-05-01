from __future__ import annotations

import csv
import os
import shutil
import subprocess
from pathlib import Path

from .io_utils import ensure_dir, load_ports, save_json, utc_timestamp
from .models import OpenPortRecord


def scan_targets(
    config: dict,
    run_id: str,
    targets: list[dict[str, str]],
    run_dir: Path,
    port_profile: str | None = None,
) -> list[OpenPortRecord]:
    scan_cfg = config["scan"]
    project_cfg = config["project"]
    configured_profiles = project_cfg.get("port_profiles") or {}
    selected_profile = port_profile or project_cfg.get("default_port_profile")

    if configured_profiles:
        if not selected_profile:
            raise RuntimeError("No port profile selected. Set project.default_port_profile or pass --port-profile.")
        if selected_profile not in configured_profiles:
            valid_profiles = ", ".join(sorted(configured_profiles))
            raise RuntimeError(f"Unknown port profile {selected_profile!r}. Available profiles: {valid_profiles}")
        port_file = configured_profiles[selected_profile]
    else:
        # Backward-compatible fallback for older configs.
        port_file = project_cfg["port_list_file"]
        selected_profile = selected_profile or "custom"

    ports = load_ports(port_file)
    raw_dir = ensure_dir(run_dir / "raw" / "xmap_scan")
    target_file = raw_dir / "targets.txt"
    output_file = raw_dir / "results.csv"
    metadata_file = raw_dir / "scan_metadata.json"
    command_file = raw_dir / "command_metadata.json"
    lookup = {item["ip"]: item for item in targets}

    if not targets:
        return []
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("The xmap TCP SYN scan requires root privileges. Run the scan/all stage as root.")

    configured_xmap = str(scan_cfg.get("xmap_path", "xmap"))
    xmap_binary = configured_xmap
    if os.path.sep in configured_xmap and not Path(configured_xmap).exists():
        discovered = shutil.which(Path(configured_xmap).name)
        if discovered:
            xmap_binary = discovered
    elif os.path.sep not in configured_xmap:
        discovered = shutil.which(configured_xmap)
        if discovered:
            xmap_binary = discovered

    target_file.write_text("\n".join(item["ip"] for item in targets) + "\n", encoding="utf-8")
    port_arg = ",".join(str(port) for port in ports)
    command = [
        xmap_binary,
        "-4",
        "-I",
        str(target_file),
        "-M",
        str(scan_cfg.get("probe_module", "tcp_syn")),
        "-p",
        port_arg,
        "-O",
        "csv",
        "-B",
        str(scan_cfg.get("bandwidth", "10M")),
        "--cooldown-secs",
        str(scan_cfg.get("cooldown_secs", 10)),
        "--output-fields",
        "saddr,sport,dport,clas,success,repeat,timestamp_str",
        "--output-filter",
        "success = 1 && repeat = 0",
        "-o",
        str(output_file),
        "-m",
        str(metadata_file),
    ]

    sender_threads = scan_cfg.get("sender_threads")
    if sender_threads is not None:
        command.extend(["-T", str(sender_threads)])
    if scan_cfg.get("batch"):
        command.append(f"--batch={scan_cfg['batch']}")
    if scan_cfg.get("probes"):
        command.append(f"--probes={scan_cfg['probes']}")
    if scan_cfg.get("retries") is not None:
        command.append(f"--retries={scan_cfg['retries']}")
    if scan_cfg.get("source_port"):
        command.extend(["-s", str(scan_cfg["source_port"])])
    if scan_cfg.get("interface"):
        command.extend(["-i", str(scan_cfg["interface"])])
    if scan_cfg.get("gateway_mac"):
        command.extend(["-G", str(scan_cfg["gateway_mac"])])
    if scan_cfg.get("source_ip"):
        command.extend(["-S", str(scan_cfg["source_ip"])])
    if scan_cfg.get("notes"):
        command.extend(["--notes", str(scan_cfg["notes"])])
    if scan_cfg.get("quiet", True):
        command.append("-q")

    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"xmap is not executable. The current xmap_path is {configured_xmap!r}; "
            "set it to the correct path or make sure xmap is available in PATH."
        ) from exc

    save_json(
        command_file,
        {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "target_count": len(targets),
            "port_profile": selected_profile,
            "port_file": str(port_file),
            "ports": ports,
        },
    )
    if completed.returncode != 0:
        raise RuntimeError(f"xmap scan failed. See {command_file} for details.")
    if not output_file.exists():
        return []
    return parse_xmap_csv(output_file, run_id, lookup)


def parse_xmap_csv(
    csv_path: str | Path,
    run_id: str,
    lookup: dict[str, dict[str, str]],
) -> list[OpenPortRecord]:
    rows: list[OpenPortRecord] = []
    with Path(csv_path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if str(row.get("success", "")).strip() not in {"1", "true", "True"}:
                continue
            ip = (row.get("saddr") or "").strip()
            port_text = (row.get("sport") or "").strip()
            if not ip or not port_text:
                continue
            meta = lookup.get(ip, {})
            timestamp = (row.get("timestamp_str") or "").strip() or utc_timestamp()
            rows.append(
                OpenPortRecord(
                    run_id=run_id,
                    source_file=meta.get("source_file", ""),
                    source_group=meta.get("source_group", ""),
                    ip=ip,
                    port=int(port_text),
                    protocol="tcp",
                    state="open",
                    scan_tool="xmap",
                    timestamp=timestamp,
                )
            )

    dedup: dict[tuple[str, int], OpenPortRecord] = {(item.ip, item.port): item for item in rows}
    return sorted(dedup.values(), key=lambda item: (item.ip, item.port))
