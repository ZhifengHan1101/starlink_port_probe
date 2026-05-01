from __future__ import annotations

import csv
import glob
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: str | Path) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def load_ports(port_file: str | Path) -> list[int]:
    data = Path(port_file).read_text(encoding="utf-8").strip()
    ports = []
    for chunk in data.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start = int(start_text.strip())
            end = int(end_text.strip())
            if start > end:
                start, end = end, start
            for value in range(start, end + 1):
                if 1 <= value <= 65535:
                    ports.append(value)
            continue
        value = int(chunk)
        if 1 <= value <= 65535:
            ports.append(value)
    return sorted(set(ports))


def discover_input_files(input_files: list[str] | None, input_glob: str) -> list[Path]:
    if input_files:
        return sorted(Path(item).expanduser().resolve() for item in input_files)
    return sorted(Path(item).resolve() for item in glob.glob(input_glob))


def infer_source_group(path: Path) -> str:
    match = re.search(r"/(as\d+)/results/", str(path))
    return match.group(1) if match else path.stem


def load_ips_from_csv(csv_path: str | Path, limit: int | None = None) -> list[dict[str, str]]:
    path = Path(csv_path)
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows: list[dict[str, str]] = []
        for row in reader:
            ip = (row.get("saddr") or row.get("ip") or "").strip()
            if not ip:
                continue
            rows.append(
                {
                    "ip": ip,
                    "source_file": str(path),
                    "source_group": infer_source_group(path),
                }
            )
            if limit is not None and len(rows) >= limit:
                break
    return rows


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
    target = Path(path)
    with target.open("w", encoding="utf-8", newline="") as handle:
        if not rows:
            handle.write("")
            return
        flat_rows = [flatten_dict(row) for row in rows]
        fieldnames = sorted({key for row in flat_rows for key in row.keys()})
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(flat_rows)


def flatten_dict(data: dict[str, Any]) -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, (list, dict)):
            flat[key] = sanitize_csv_value(json.dumps(value, ensure_ascii=False))
        else:
            flat[key] = sanitize_csv_value(value)
    return flat


def sanitize_csv_value(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    cleaned = value.replace("\x00", "\\0")
    cleaned = "".join(
        char if char in ("\t", "\r", "\n") or ord(char) >= 32 else f"\\x{ord(char):02x}"
        for char in cleaned
    )
    return cleaned


def save_json(path: str | Path, payload: dict[str, Any]) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
