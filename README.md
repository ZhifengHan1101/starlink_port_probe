# Starlink Port Probe

一个面向 Starlink 活跃 IPv4 清单的 TCP 服务探测项目。流程分为五个阶段：

1. `scan`: 对输入 IP 列表执行 `xmap` TCP SYN 端口扫描，覆盖 top 1000 TCP 端口，只负责发现开放端口。
2. `fingerprint`: 对开放端口执行 `nmap -sV` 服务识别，并对主机执行 `nmap -O` 操作系统识别，提取服务、产品、版本、CPE、OS 信息，并保存原始证据。
3. `enrich`: 基于提取出的 CPE / 产品信息关联 CVE。
4. `report`: 生成 Markdown 报告。
5. `all`: 串行执行以上全部步骤。

项目不再维护自定义协议探针逻辑，而是直接复用 `xmap` 做高速开放端口发现，再用 `nmap -sV` 做服务识别，减少误判和维护成本。

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
    └── report.py
```

## 安装

```bash
cd /home/ubuntu/hzf/starlink_port_probe
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

默认配置使用 `xmap` 的 `tcp_syn` 模块做端口发现，适合大规模目标的高速探测，因此需要 root 权限。

```yaml
scan:
  engine: xmap
  xmap_path: /usr/bin/xmap
  probe_module: tcp_syn
  bandwidth: 10M
  cooldown_secs: 10
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
python3 main.py fingerprint --run-id test-run --workers 4
```

`scan` 阶段会把整份输入 IP 和整份 top 1000 TCP 端口一次性交给 `xmap`，不再做任何目标分块或端口分块，直接由 `xmap` 自己负责高速发包与接收。

`fingerprint` 阶段会先按开放端口分组，再把对应 IP 按批次送入 `nmap -sV -p <port>`，避免把某批主机的端口并集再次广播到所有主机上。

默认将 `version_intensity` 下调到 `3`，并把 `hosts_per_batch` 提高到 `512`，降低弱响应主机拖慢 `nmap -sV` 的概率，同时减少 Python 侧频繁拉起 Nmap 进程的开销。`fingerprint` 还会额外做一轮按主机批处理的 `nmap -O`，把 OS 名称、家族、代际版本和 CPE 一起写入结果。

`--workers` 表示 `fingerprint` 或 `enrich` 阶段的并发批次数，而非线程内的逐 IP 探测数。

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

字段说明：

- `open_ports.*`: `xmap` 开放端口结果。
- `fingerprints.*`: `nmap -sV` 服务识别结果，包含 `service`, `product`, `version`, `cpe`, `confidence`。
- `fingerprints.*` 还会包含 `os_name`, `os_vendor`, `os_family`, `os_generation`, `os_accuracy`, `os_cpe`。
- `enriched.*`: 在指纹结果基础上附加 `cves`。
- `raw/xmap_scan/results.csv`: 单次 `xmap` TCP SYN 扫描的原始结果。
- `raw/xmap_scan/scan_metadata.json`: `xmap` 原生输出的扫描元数据。
- `raw/xmap_scan/command_metadata.json`: 本次调用命令、返回码、目标数和端口列表。
- `raw/nmap_service/port_*/batch_*/service.xml`: 每个端口分组批次的 `nmap -sV` 原始 XML。
- `raw/evidence/*.json`: 每个 `ip:port` 的服务识别证据，主要来自 `nmap -sV` 的 service/cpe/script 输出。

## NVD CVE 查询

`enrich` 默认会调用 NVD API，并以受限并发方式预取唯一查询键，避免冷缓存时串行阻塞过久。可选地设置环境变量：

```bash
export NVD_API_KEY=your_api_key
```

配置中的 `enrich.rate_limit_qps` 用于控制总请求速率。无 API Key 时建议保持保守值；有 API Key 时可以按 NVD 当前限制上调到 `5`。

如果网络不可达，流程不会中断，但 `cves` 可能为空，并在结果中保留 `enrichment_status`。

默认仅使用 CPE 进行精确查询，不再默认退回宽泛的 `keywordSearch`。如确有需要，可在 `config.yaml` 中将 `enrich.allow_keyword_fallback` 改为 `true`。

## 依赖说明

- `xmap`: 用于高速开放端口发现。
- `nmap`: 用于服务识别。
- Python 依赖见 `requirements.txt`。

## 设计原则

- 开放端口发现和服务识别解耦。
- 端口发现使用单次 `xmap` 全量高速扫描，不做外部 Python 分块。
- 服务识别按端口聚合目标，避免对大量已知关闭端口做二次无效探测。
- 服务识别默认降低 `version_intensity` 并提高每批主机数，降低弱响应主机和频繁进程启动带来的拖慢效应。
- 保留原始 XML 与证据 JSON，便于复核与二次分析。
- 输出 JSONL/CSV/Markdown，适合后处理和报告交付。
