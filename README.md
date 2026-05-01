# Starlink Port Probe

A TCP service discovery and enrichment pipeline for active Starlink IPv4 inventories.

The pipeline has five stages:

1. `scan`: runs an `xmap` TCP SYN scan against the input IP list across the configured TCP port profile. By default this is the top 1000 TCP ports, but it can be switched to all 65535 TCP ports.
2. `fingerprint`: runs `nmap -sV` on open ports and optionally runs `nmap -O` for host OS detection. It extracts service, product, version, CPE, and OS metadata while preserving raw evidence.
3. `enrich`: maps extracted CPE and product metadata to CVEs.
4. `report`: renders a Markdown report.
5. `all`: runs the full pipeline in sequence.

The project intentionally relies on `xmap` for high-speed open-port discovery and `nmap -sV` for service fingerprinting instead of maintaining custom protocol probes. This keeps the implementation easier to audit and reduces false positives from hand-written probe logic.

## Project Layout

```text
starlink_port_probe/
├── README.md
├── requirements.txt
├── config.yaml
├── main.py
└── probe_pipeline/
    ├── __init__.py
    ├── cli.py
    ├── config.py
    ├── io_utils.py
    ├── models.py
    ├── scanner.py
    ├── fingerprinter.py
    ├── enrich.py
    └── report.py
```

## Installation

```bash
cd /home/ubuntu/hzf/starlink_port_probe
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The default configuration uses the `xmap` `tcp_syn` module for large-scale port discovery, so the `scan` and `all` stages require root privileges.

```yaml
scan:
  engine: xmap
  xmap_path: /usr/local/sbin/xmap
  probe_module: tcp_syn
  bandwidth: 10M
  cooldown_secs: 10
```

## Input

By default, the pipeline discovers the latest active IPv4 CSV files from:

```text
/home/ubuntu/hzf/starlink_as_probe/as*/results/active_ipv4_*.csv
```

Each CSV must include at least one `saddr` column. A column named `ip` is also accepted.

You can also pass one or more input files explicitly:

```bash
python3 main.py scan --input /path/to/active_ipv4.csv
python3 main.py scan --input a.csv --input b.csv
```

## Usage

```bash
python3 main.py scan
python3 main.py scan --port-profile full
python3 main.py fingerprint --run-id 20260418T120000Z
python3 main.py enrich --run-id 20260418T120000Z
python3 main.py report --run-id 20260418T120000Z
python3 main.py all
python3 main.py all --port-profile full
```

Common options:

```bash
python3 main.py all --config config.yaml --limit 100
python3 main.py all --port-profile top1000
python3 main.py all --port-profile full
python3 main.py scan --run-id test-run --input /home/ubuntu/hzf/starlink_as_probe/as149662/results/active_ipv4_2026_04_18.csv
python3 main.py fingerprint --run-id test-run --workers 4
python3 main.py fingerprint --run-id test-run --workers 4 --no-os
```

The `scan` stage submits the full input IP list and the full selected TCP port list to a single `xmap` run. It does not split targets or ports in Python; packet sending and response collection are handled by `xmap`.

The default port profile is configured in `config.yaml`:

```yaml
project:
  default_port_profile: top1000
  port_profiles:
    top1000: /home/ubuntu/hzf/starlink_port_probe/nmap_top1000_tcp_ports.txt
    full: /home/ubuntu/hzf/starlink_port_probe/all_tcp_ports.txt
```

Port profile files may contain comma-separated port numbers and ranges such as `80,443,8000-8100` or `1-65535`.

The `fingerprint` stage groups open endpoints by port, then sends each host batch to `nmap -sV -p <port>`. This avoids broadcasting the union of a batch's open ports back across every host in that batch.

By default, `version_intensity` is set to `3` and `hosts_per_batch` is set to `512`. This reduces the chance that weakly responsive hosts slow down `nmap -sV`, and it also cuts down on frequent Nmap process startup overhead. The `fingerprint` stage also runs host-batched `nmap -O` OS detection unless disabled.

If port scanning is already complete and you only want to rerun service fingerprinting without OS detection, use:

```bash
python3 main.py fingerprint --run-id <run_id> --no-os
```

The `--workers` option controls concurrent batches in the `fingerprint` and `enrich` stages. It is not a per-IP thread count.

## Output

Each run creates an isolated output directory under `runs/<run_id>/` by default:

```text
runs/<run_id>/
├── open_ports.jsonl
├── open_ports.csv
├── fingerprints.jsonl
├── fingerprints.csv
├── enriched.jsonl
├── enriched.csv
├── report.md
└── raw/
    ├── xmap_scan/
    │   ├── targets.txt
    │   ├── results.csv
    │   ├── scan_metadata.json
    │   └── command_metadata.json
    ├── nmap_service/
    │   └── port_*/batch_*/
    │       ├── service.xml
    │       ├── service_metadata.json
    │       └── targets.txt
    └── evidence/
        └── *.json
```

Output files:

- `open_ports.*`: open TCP endpoint results from `xmap`.
- `fingerprints.*`: `nmap -sV` service fingerprints, including `service`, `product`, `version`, `cpe`, and `confidence`.
- `fingerprints.*`: OS metadata from `nmap -O`, including `os_name`, `os_vendor`, `os_family`, `os_generation`, `os_accuracy`, and `os_cpe`.
- `enriched.*`: fingerprint records with attached `cves`.
- `raw/xmap_scan/results.csv`: raw results from the single `xmap` TCP SYN scan.
- `raw/xmap_scan/scan_metadata.json`: native scan metadata emitted by `xmap`.
- `raw/xmap_scan/command_metadata.json`: executed command, return code, target count, and port list.
- `raw/nmap_service/port_*/batch_*/service.xml`: raw `nmap -sV` XML for each port-grouped batch.
- `raw/evidence/*.json`: per-`ip:port` evidence assembled from Nmap service, CPE, script, and OS output.

## NVD CVE Enrichment

The `enrich` stage queries the NVD API by default. It prefetches unique query keys with bounded concurrency so cold-cache runs do not block on fully serial lookups.

Optionally set an NVD API key:

```bash
export NVD_API_KEY=your_api_key
```

The `enrich.rate_limit_qps` setting controls the total request rate. Keep this value conservative when no API key is configured. With an API key, you can raise it according to the current NVD limits.

If the network is unavailable, the pipeline continues running. CVE lists may be empty, and the record keeps an `enrichment_status` field.

By default, enrichment only uses precise CPE queries and does not fall back to broad `keywordSearch` queries. If keyword fallback is required, set `enrich.allow_keyword_fallback` to `true` in `config.yaml`.

## Dependencies

- `xmap`: high-speed open-port discovery.
- `nmap`: service and OS fingerprinting.
- Python dependencies listed in `requirements.txt`.

## Design Principles

- Keep open-port discovery and service fingerprinting separate.
- Use one full `xmap` scan for port discovery instead of external Python-side batching.
- Group service fingerprinting by open port to avoid probing large numbers of known-closed ports.
- Use a lower default `version_intensity` and larger host batches to reduce slowdowns from weakly responsive hosts and repeated process startup.
- Preserve raw XML and evidence JSON for review and downstream analysis.
- Emit JSONL, CSV, and Markdown outputs for post-processing and reporting.
