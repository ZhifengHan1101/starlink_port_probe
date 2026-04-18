from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .io_utils import ensure_dir, save_json
from .models import FingerprintRecord, OpenPortRecord


def chunked(values: list[str], size: int) -> list[list[str]]:
    if size <= 0:
        return [values]
    return [values[index:index + size] for index in range(0, len(values), size)]


@dataclass(slots=True)
class FingerprintBatch:
    batch_index: int
    port: int
    hosts: list[str]


class Fingerprinter:
    def __init__(self, config: dict, run_id: str, run_dir: Path) -> None:
        self.config = config
        self.run_id = run_id
        self.run_dir = run_dir
        self.fp_cfg = config["fingerprint"]
        self.evidence_dir = ensure_dir(run_dir / "raw" / "evidence")
        self.raw_dir = ensure_dir(run_dir / "raw" / "nmap_service")

    def run(self, records: list[OpenPortRecord], workers: int | None = None) -> list[FingerprintRecord]:
        if not records:
            return []

        records_by_host: dict[str, list[OpenPortRecord]] = {}
        hosts_by_port: dict[int, set[str]] = {}
        for record in records:
            records_by_host.setdefault(record.ip, []).append(record)
            hosts_by_port.setdefault(record.port, set()).add(record.ip)

        hosts = sorted(records_by_host)
        hosts_per_batch = int(self.fp_cfg.get("hosts_per_batch", 0) or 0)
        batches = self._build_batches(hosts_by_port, hosts_per_batch)
        max_workers = workers or int(self.fp_cfg["workers"])

        services_by_host_port: dict[tuple[str, int], dict[str, Any]] = {}
        batch_errors: dict[tuple[str, int], str] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self.fingerprint_batch, batch)
                for batch in batches
            ]
            for future in as_completed(futures):
                parsed_services, parsed_errors = future.result()
                services_by_host_port.update(parsed_services)
                batch_errors.update(parsed_errors)

        results: list[FingerprintRecord] = []
        for ip in hosts:
            for record in sorted(records_by_host[ip], key=lambda item: item.port):
                batch_error = batch_errors.get((record.ip, record.port))
                service_info = services_by_host_port.get((record.ip, record.port), {})
                evidence = self._build_evidence(record.ip, record.port, service_info, batch_error)
                evidence_path = self.evidence_dir / f"{record.ip}_{record.port}.json"
                save_json(evidence_path, evidence)
                results.append(self._build_record(record, service_info, evidence_path, batch_error))
        return results

    def fingerprint_batch(
        self,
        batch: FingerprintBatch,
    ) -> tuple[dict[tuple[str, int], dict[str, Any]], dict[tuple[str, int], str]]:
        batch_dir = ensure_dir(self.raw_dir / f"port_{batch.port:05d}" / f"batch_{batch.batch_index:03d}")
        target_file = batch_dir / "targets.txt"
        target_file.write_text("\n".join(batch.hosts) + "\n", encoding="utf-8")

        xml_path = batch_dir / "service.xml"
        meta_path = batch_dir / "service_metadata.json"

        command = [
            str(self.fp_cfg.get("nmap_path", "nmap")),
            "-Pn",
            "-n",
            "-sV",
            "-oX",
            str(xml_path),
            "-iL",
            str(target_file),
            "-p",
            str(batch.port),
        ]
        if self.fp_cfg.get("timing_template"):
            command.append(str(self.fp_cfg["timing_template"]))
        if self.fp_cfg.get("version_intensity") is not None:
            command.extend(["--version-intensity", str(self.fp_cfg["version_intensity"])])
        if self.fp_cfg.get("host_timeout"):
            command.extend(["--host-timeout", str(self.fp_cfg["host_timeout"])])
        if self.fp_cfg.get("script_timeout"):
            command.extend(["--script-timeout", str(self.fp_cfg["script_timeout"])])
        if self.fp_cfg.get("min_hostgroup"):
            command.extend(["--min-hostgroup", str(self.fp_cfg["min_hostgroup"])])
        if self.fp_cfg.get("max_hostgroup"):
            command.extend(["--max-hostgroup", str(self.fp_cfg["max_hostgroup"])])

        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
        except FileNotFoundError as exc:
            raise RuntimeError("nmap 未安装或不在 PATH 中，无法执行 fingerprint 阶段。") from exc

        save_json(
            meta_path,
            {
                "command": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "hosts": batch.hosts,
                "port": batch.port,
            },
        )

        if completed.returncode != 0 or not xml_path.exists():
            error = f"nmap -sV 执行失败，详见 {meta_path}"
            return {}, {(host, batch.port): error for host in batch.hosts}

        return self._parse_nmap_service_xml(xml_path), {}

    def _build_batches(self, hosts_by_port: dict[int, set[str]], hosts_per_batch: int) -> list[FingerprintBatch]:
        batches: list[FingerprintBatch] = []
        batch_index = 0
        for port in sorted(hosts_by_port):
            for host_batch in chunked(sorted(hosts_by_port[port]), hosts_per_batch):
                batches.append(FingerprintBatch(batch_index=batch_index, port=port, hosts=host_batch))
                batch_index += 1
        return batches

    def _parse_nmap_service_xml(self, xml_path: Path) -> dict[tuple[str, int], dict[str, Any]]:
        services: dict[tuple[str, int], dict[str, Any]] = {}
        root = ET.parse(xml_path).getroot()
        for host in root.findall("host"):
            address = host.find("./address[@addrtype='ipv4']")
            if address is None:
                continue
            ip = address.get("addr", "").strip()
            if not ip:
                continue
            for port in host.findall("./ports/port"):
                if port.get("protocol") != "tcp":
                    continue
                port_id = port.get("portid")
                if not port_id:
                    continue
                service = port.find("service")
                scripts = []
                for script in port.findall("script"):
                    scripts.append(
                        {
                            "id": script.get("id"),
                            "output": script.get("output"),
                        }
                    )
                services[(ip, int(port_id))] = {
                    "port_state": (port.find("state").attrib if port.find("state") is not None else {}),
                    "service": (service.attrib if service is not None else {}),
                    "cpes": [item.text for item in port.findall("./service/cpe") if item.text],
                    "scripts": scripts,
                }
        return services

    def _build_evidence(
        self,
        ip: str,
        port: int,
        service_info: dict[str, Any],
        parse_error: str | None,
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "ip": ip,
            "port": port,
            "transport": "tcp",
            "scan_tool": "nmap",
            "steps": [],
        }
        if parse_error:
            evidence["steps"].append({"step": "nmap_service_probe", "status": "error", "error": parse_error})
            return evidence

        service_attrs = service_info.get("service", {})
        step: dict[str, Any] = {
            "step": "nmap_service_probe",
            "status": "ok" if service_attrs else "empty",
            "port_state": service_info.get("port_state", {}),
            "service": service_attrs,
            "cpes": service_info.get("cpes", []),
            "scripts": service_info.get("scripts", []),
        }
        evidence["steps"].append(step)
        summary = self._build_summary(service_attrs)
        if summary:
            evidence["summary"] = summary
        return evidence

    def _build_record(
        self,
        record: OpenPortRecord,
        service_info: dict[str, Any],
        evidence_path: Path,
        parse_error: str | None,
    ) -> FingerprintRecord:
        service_attrs = service_info.get("service", {})
        cpes = service_info.get("cpes", [])
        notes: list[str] = []

        service_name = service_attrs.get("name") or None
        if service_attrs.get("tunnel") == "ssl" and service_name and not service_name.startswith("ssl/"):
            service_name = f"ssl/{service_name}"
        product = service_attrs.get("product") or None
        version = service_attrs.get("version") or None
        extrainfo = service_attrs.get("extrainfo") or None
        confidence = self._service_confidence(service_attrs)

        if parse_error:
            notes.append(parse_error)
        elif not service_attrs:
            notes.append("nmap -sV 未返回明确的服务识别结果。")
        elif extrainfo:
            notes.append(f"nmap extra info: {extrainfo}")

        return FingerprintRecord(
            run_id=self.run_id,
            source_file=record.source_file,
            source_group=record.source_group,
            ip=record.ip,
            port=record.port,
            transport=record.protocol,
            service=service_name,
            product=product,
            version=version,
            cpe=cpes,
            confidence=confidence,
            evidence_path=str(evidence_path),
            fingerprint_method=["nmap_sV"],
            notes=notes,
            raw_summary=self._build_summary(service_attrs),
        )

    @staticmethod
    def _service_confidence(service_attrs: dict[str, Any]) -> float:
        conf_text = service_attrs.get("conf")
        if conf_text is None:
            return 0.0
        try:
            conf = max(0, min(10, int(conf_text)))
        except (TypeError, ValueError):
            return 0.0
        return conf / 10.0

    @staticmethod
    def _build_summary(service_attrs: dict[str, Any]) -> str | None:
        parts = [
            service_attrs.get("name"),
            service_attrs.get("product"),
            service_attrs.get("version"),
            service_attrs.get("extrainfo"),
        ]
        summary = " | ".join(part for part in parts if part)
        return summary or None
