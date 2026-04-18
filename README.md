# Starlink Port Probe

一个面向 Starlink 活跃 IPv4 清单的 TCP 服务探测项目。流程分为五个阶段：

1. `scan`: 对输入 IP 列表执行 `nmap` TCP 端口扫描，覆盖 top 1000 TCP 端口，只负责发现开放端口。
2. `fingerprint`: 对开放端口执行 `nmap -sV` 服务识别，提取服务、产品、版本、CPE，并保存原始证据。
3. `enrich`: 基于提取出的 CPE / 产品信息关联 CVE。
4. `report`: 生成 Markdown 报告。
5. `all`: 串行执行以上全部步骤。

项目不再维护自定义协议探针逻辑，而是直接复用 `nmap` 和 `nmap -sV` 的成熟识别能力，减少误判和维护成本。

## 目录

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
    ├── report.py
    └── signatures.py
```

## 安装

```bash
cd /home/ubuntu/hzf/starlink_port_probe
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

默认配置使用 `nmap -sT` 做端口发现，因此不依赖 `xmap`。如果后续你想切到 `nmap -sS`，通常需要 root 或 `CAP_NET_RAW` 权限。

```yaml
scan:
  engine: nmap
  nmap_path: /usr/bin/nmap
  timing_template: -T4
```

## 输入

默认会从 `/home/ubuntu/hzf/starlink_as_probe/*/results/active_ipv4_*.csv` 自动收集最新的 IPv4 活跃地址。CSV 至少需要包含一列 `saddr`。

也可以显式指定一个或多个输入文件：

```bash
python3 main.py scan --input /path/to/active_ipv4.csv
python3 main.py scan --input a.csv --input b.csv
```

## 用法

```bash
python3 main.py scan
python3 main.py fingerprint --run-id 20260418T120000Z
python3 main.py enrich --run-id 20260418T120000Z
python3 main.py report --run-id 20260418T120000Z
python3 main.py all
```

常用参数：

```bash
python3 main.py all --config config.yaml --limit 100
python3 main.py scan --run-id test-run --input /home/ubuntu/hzf/starlink_as_probe/as149662/results/active_ipv4_2026_04_18.csv
python3 main.py fingerprint --run-id test-run --workers 100
```

## 输出

每次运行会创建一个独立目录，默认在 `runs/<run_id>/`：

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
    ├── nmap_scan/
    │   ├── scan.xml
    │   └── scan_metadata.json
    ├── nmap_service/
    │   ├── *.xml
    │   └── *_metadata.json
    └── evidence/
        └── *.json
```

字段说明：

- `open_ports.*`: `nmap` 开放端口结果。
- `fingerprints.*`: `nmap -sV` 服务识别结果，包含 `service`, `product`, `version`, `cpe`, `confidence`。
- `enriched.*`: 在指纹结果基础上附加 `cves`。
- `raw/nmap_scan/scan.xml`: 原始 `nmap` 端口扫描 XML。
- `raw/nmap_scan/scan_metadata.json`: 端口扫描命令、返回码和标准输出。
- `raw/nmap_service/*.xml`: 每台主机一次 `nmap -sV` 的原始 XML。
- `raw/evidence/*.json`: 每个 `ip:port` 的服务识别证据，主要来自 `nmap -sV` 的 service/cpe/script 输出。

## NVD CVE 查询

`enrich` 默认会调用 NVD API。可选地设置环境变量：

```bash
export NVD_API_KEY=your_api_key
```

如果网络不可达，流程不会中断，但 `cves` 可能为空，并在结果中保留 `enrichment_status`。

## 依赖说明

- `nmap`: 用于开放端口发现和服务识别。
- Python 依赖见 `requirements.txt`。

## 设计原则

- 开放端口发现和服务识别解耦。
- 服务识别尽量复用成熟扫描器而不是自维护协议指纹。
- 保留原始 XML 与证据 JSON，便于复核与二次分析。
- 输出 JSONL/CSV/Markdown，适合后处理和报告交付。
