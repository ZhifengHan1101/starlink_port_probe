from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from .io_utils import ensure_dir, load_ports, save_json, utc_timestamp
from .models import OpenPortRecord


def chunked(values: list[int], size: int) -> list[list[int]]:
    if size <= 0:
        return [values]
    return [values[index:index + size] for index in range(0, len(values), size)]


def scan_targets(
    config: dict,
    run_id: str,
    targets: list[dict[str, str]],
    run_dir: Path,
) -> list[OpenPortRecord]:
    scan_cfg = config["scan"]
    port_file = config["project"]["port_list_file"]
    ports = load_ports(port_file)
    raw_dir = ensure_dir(run_dir / "raw" / "nmap_scan")
    target_file = run_dir / "targets.txt"
    target_file.write_text("\n".join(item["ip"] for item in targets) + "\n", encoding="utf-8")

    port_chunk_size = int(scan_cfg.get("ports_per_chunk", 0) or 0)
    lookup = {item["ip"]: item for item in targets}
    results: list[OpenPortRecord] = []

    for index, port_chunk in enumerate(chunked(ports, port_chunk_size)):
        xml_path = raw_dir / f"scan_chunk_{index:03d}.xml"
        meta_path = raw_dir / f"scan_chunk_{index:03d}_metadata.json"
        command = [
            str(scan_cfg.get("nmap_path", "nmap")),
            "-Pn",
            "-n",
            "-sT",
            "--open",
            "-oX",
            str(xml_path),
            "-iL",
            str(target_file),
            "-p",
            ",".join(str(port) for port in port_chunk),
        ]
        if scan_cfg.get("timing_template"):
            command.append(str(scan_cfg["timing_template"]))
        if scan_cfg.get("max_retries") is not None:
            command.extend(["--max-retries", str(scan_cfg["max_retries"])])
        if scan_cfg.get("host_timeout"):
            command.extend(["--host-timeout", str(scan_cfg["host_timeout"])])
        if scan_cfg.get("min_rate"):
            command.extend(["--min-rate", str(scan_cfg["min_rate"])])

        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
        except FileNotFoundError as exc:
            raise RuntimeError("nmap 未安装或不在 PATH 中，无法执行 scan 阶段。") from exc

        save_json(
            meta_path,
            {
                "command": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            },
        )
        if completed.returncode != 0:
            raise RuntimeError(f"nmap 扫描失败，详见 {meta_path}")
        if not xml_path.exists():
            continue
        results.extend(parse_nmap_scan_xml(xml_path, run_id, lookup))

    dedup: dict[tuple[str, int], OpenPortRecord] = {(item.ip, item.port): item for item in results}
    return sorted(dedup.values(), key=lambda item: (item.ip, item.port))


def parse_nmap_scan_xml(
    xml_path: str | Path,
    run_id: str,
    lookup: dict[str, dict[str, str]],
) -> list[OpenPortRecord]:
    rows: list[OpenPortRecord] = []
    root = ET.parse(xml_path).getroot()
    finished = root.find("./runstats/finished")
    timestamp = utc_timestamp()
    if finished is not None and finished.get("time"):
        try:
            timestamp = datetime.fromtimestamp(int(finished.get("time", "0")), tz=timezone.utc).isoformat()
        except ValueError:
            timestamp = utc_timestamp()

    for host in root.findall("host"):
        if host.find("./status[@state='up']") is None:
            continue
        address = host.find("./address[@addrtype='ipv4']")
        if address is None:
            continue
        ip = address.get("addr", "").strip()
        if not ip:
            continue

        meta = lookup.get(ip, {})
        for port in host.findall("./ports/port"):
            if port.get("protocol") != "tcp":
                continue
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid", "").strip()
            if not port_id:
                continue
            rows.append(
                OpenPortRecord(
                    run_id=run_id,
                    source_file=meta.get("source_file", ""),
                    source_group=meta.get("source_group", ""),
                    ip=ip,
                    port=int(port_id),
                    protocol="tcp",
                    state="open",
                    scan_tool="nmap",
                    timestamp=timestamp,
                )
            )

    dedup: dict[tuple[str, int], OpenPortRecord] = {(item.ip, item.port): item for item in rows}
    return sorted(dedup.values(), key=lambda item: (item.ip, item.port))
