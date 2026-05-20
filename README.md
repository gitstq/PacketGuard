# PacketGuard

PacketGuard - 轻量级开源包供应链安全威胁检测引擎
Lightweight Open-Source Package Supply Chain Security Threat Detection Engine

## Features

- Typosquatting Detection
- Starjacking Detection
- Malware Pattern Scanning
- Dependency Analysis
- Threat Intelligence
- Multi-format Reports (Text/JSON/SARIF/Markdown/HTML)

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan a package
packetguard scan express

# Scan a PyPI package
packetguard scan requests -e pypi

# Scan a project directory
packetguard scan ./my-project

# Quick check
packetguard check lodash

# Full audit
packetguard audit ./my-project

# Export report
packetguard scan express -f json -o report
```

## License

MIT
