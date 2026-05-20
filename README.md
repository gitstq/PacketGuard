<div align="center">

<a href="#简体中文">简体中文</a> | <a href="#English">English</a> | <a href="#繁體中文">繁體中文</a>

<br/><br/>

# 🛡️ PacketGuard

**轻量级开源包供应链安全威胁检测引擎**
**Lightweight Open-Source Package Supply Chain Security Threat Detection Engine**

<br/>

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-success.svg)
![77 Tests](https://img.shields.io/badge/Tests-77%20Passed-brightgreen.svg)

<br/>

[GitHub 仓库](https://github.com/gitstq/PacketGuard) | [报告问题](https://github.com/gitstq/PacketGuard/issues) | [贡献指南](#-贡献指南)

</div>

---

## 简体中文

### 🎉 项目介绍

PacketGuard 是一款专为开发者打造的**轻量级开源包供应链安全威胁检测引擎**。在当今软件供应链攻击频发的背景下，恶意包投毒、包名拼写劫持（Typosquatting）、Star 数伪造（Starjacking）等攻击手段层出不穷，严重威胁着开源生态的安全。

PacketGuard 旨在为开发者提供一个**零外部依赖、开箱即用**的安全扫描工具，帮助你在安装和使用开源包之前快速识别潜在的安全威胁。无论是个人开发者还是团队协作，PacketGuard 都能无缝融入你的开发工作流。

**核心价值：**
- 🔍 **全面检测** — 覆盖 Typosquatting、Starjacking、恶意包特征、依赖分析、威胁情报五大维度
- ⚡ **极致轻量** — 零外部依赖，纯 Python 标准库实现，安装即用
- 🎯 **精准高效** — 基于多种编辑距离算法和模式匹配引擎，兼顾准确率与性能
- 🔧 **灵活配置** — 支持 YAML 配置文件、白名单/黑名单、规则开关等精细化控制
- 📊 **多格式报告** — 终端彩色输出、JSON、SARIF、Markdown、HTML 五种报告格式

**自研差异化亮点：**
- 同时支持 **npm** 和 **PyPI** 两大主流包生态系统
- 内置 **61 条恶意包数据库**，无需联网即可完成基础威胁检测
- 生成的 **SARIF 报告**可直接集成到 GitHub Code Scanning 工作流
- 支持 **package.json**、**requirements.txt**、**Pipfile** 等多种依赖文件解析

---

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔤 **Typosquatting 检测** | 基于 Levenshtein 和 Damerau-Levenshtein 编辑距离算法，精准识别包名拼写劫持攻击，支持邻键、位交换等多种变体检测 |
| ⭐ **Starjacking 检测** | 通过 GitHub API 交叉验证包声明的 star 数真实性，揭露伪造 GitHub 仓库引用的欺诈行为 |
| 🦠 **恶意包特征扫描** | 5 大类模式检测引擎：网络请求、文件系统操作、命令执行、代码混淆、恶意域名，全面覆盖已知攻击手法 |
| 🌳 **依赖分析** | 智能解析 package.json / requirements.txt / Pipfile，构建完整依赖树，自动检测循环依赖和风险依赖 |
| 🕵️ **威胁情报** | 内置 61 条恶意包数据库，版本异常检测，新包风险评估，离线也能完成基础安全检查 |
| 📋 **多格式报告** | 终端彩色输出、JSON、SARIF（兼容 GitHub Code Scanning）、Markdown、HTML，满足不同场景需求 |

---

### 🚀 快速开始

#### 环境要求

- **Python** 3.8 或更高版本
- **零外部依赖** — 仅使用 Python 标准库
- **操作系统** — 支持 Linux、macOS、Windows

#### 安装

**方式一：通过 pip 安装（推荐）**

```bash
pip install packetguard
```

**方式二：从源码安装**

```bash
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard
pip install .
```

**方式三：直接运行（无需安装）**

```bash
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard
python -m packetguard --version
```

#### 快速使用

```bash
# 扫描一个 npm 包
packetguard scan express

# 扫描一个 PyPI 包
packetguard scan requests -e pypi

# 快速检查单个包是否安全
packetguard check lodash

# 扫描项目目录下的所有依赖
packetguard audit ./my-project

# 生成 JSON 格式报告
packetguard report express -f json -o ./report

# 只显示高危及以上级别的威胁
packetguard scan ./project -s high

# 生成 SARIF 报告并集成到 GitHub Actions
packetguard audit ./project -f sarif -o ./results
```

---

### 📖 详细使用指南

#### 命令一览

PacketGuard 提供四个核心子命令：

| 命令 | 说明 | 适用场景 |
|------|------|----------|
| `scan` | 扫描包或项目 | 日常安全检查，扫描单个包或整个项目 |
| `check` | 快速检查单个包 | CI/CD 流水线中快速验证包安全性 |
| `audit` | 全面审计项目目录 | 深度安全审计，适合发布前检查 |
| `report` | 生成指定格式报告 | 需要导出报告文件时使用 |

#### 参数说明

**通用参数：**

| 参数 | 缩写 | 说明 | 默认值 | 可选值 |
|------|------|------|--------|--------|
| `--ecosystem` | `-e` | 指定包生态系统 | `auto` | `npm` / `pypi` / `auto` |
| `--format` | `-f` | 输出报告格式 | `text` | `text` / `json` / `sarif` / `markdown` / `html` |
| `--severity` | `-s` | 最低报告威胁等级 | `low` | `low` / `medium` / `high` / `critical` |
| `--config` | `-c` | 指定配置文件路径 | 自动查找 `.packetguard.yaml` | 任意文件路径 |
| `--output` | `-o` | 输出文件路径（不含扩展名） | 标准输出 | 任意文件路径 |
| `--timeout` | — | HTTP 请求超时时间（秒） | `10` | 正整数 |
| `--no-color` | — | 禁用彩色终端输出 | 启用彩色 | — |
| `--version` | `-v` | 显示版本号 | — | — |

#### 配置文件

在项目根目录创建 `.packetguard.yaml` 文件即可自定义 PacketGuard 的行为：

```yaml
# 通用设置
general:
  ecosystem: auto           # 默认生态系统: auto / npm / pypi
  output_format: text       # 输出格式: text / json / sarif / markdown / html
  min_severity: low         # 最低报告等级: low / medium / high / critical
  timeout: 10               # HTTP 请求超时（秒）
  verbose: false            # 是否启用详细输出

# 检测规则开关
rules:
  typosquat: true           # Typosquatting 检测
  starjacking: true         # Starjacking 检测
  malware: true             # 恶意包特征扫描
  dependency: true          # 依赖分析
  intelligence: true        # 威胁情报检查

# 白名单 — 这些包将被跳过扫描
whitelist:
  - express
  - lodash
  - react
  - flask
  - requests

# 黑名单 — 这些包将被标记为恶意
blacklist:
  - crossenv
  - event-stream3

# 恶意包扫描详细配置
malware_scan:
  check_network: true       # 检测网络请求
  check_filesystem: true    # 检测文件系统操作
  check_execution: true     # 检测命令执行
  check_obfuscation: true   # 检测代码混淆
  check_domains: true       # 检测可疑域名
```

#### 典型场景示例

**场景一：在 CI/CD 中集成安全检查**

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install packetguard
      - run: packetguard audit . -f sarif -o ./results
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./results.sarif
```

**场景二：只关注高危威胁**

```bash
packetguard scan ./my-project -s high -e npm
```

**场景三：扫描并导出 HTML 报告**

```bash
packetguard report ./my-project -f html -o ./security-report
```

---

### 💡 设计思路与迭代规划

#### 设计理念

PacketGuard 的设计遵循以下核心原则：

1. **零依赖哲学** — 全部基于 Python 标准库实现，消除供应链中的信任传递风险。安全工具本身不应该引入额外的供应链风险。
2. **离线优先** — 内置威胁情报数据库，即使在没有网络连接的环境中也能完成基础安全检查。
3. **渐进式检测** — 从快速检查到深度审计，用户可以根据场景选择不同粒度的安全扫描。
4. **可扩展架构** — 模块化的检测引擎设计，便于后续添加新的检测规则和包生态系统支持。

#### 技术选型原因

| 技术决策 | 原因 |
|----------|------|
| 纯 Python 标准库 | 零外部依赖，降低供应链攻击面，安装即用 |
| Levenshtein / Damerau-Levenshtein | 业界成熟的编辑距离算法，对 Typosquatting 检测效果优异 |
| YAML 配置文件 | 人类可读、支持注释，适合作为项目级配置 |
| SARIF 报告格式 | GitHub Code Scanning 原生支持，CI/CD 集成零成本 |
| argparse CLI 框架 | Python 标准库内置，无额外依赖 |

#### 后续功能计划

- [ ] 🌐 支持 **Go Modules**、**Cargo**（Rust）、**Maven**（Java）等更多包生态系统
- [ ] 📈 **SBOM（软件物料清单）** 生成，兼容 SPDX 和 CycloneDX 标准
- [ ] 🔗 **许可证合规检查**，自动识别依赖的许可证类型和兼容性
- [ ] 🧪 **沙箱动态分析**，在隔离环境中实际运行包以检测运行时恶意行为
- [ ] 📡 **在线威胁情报同步**，支持从远程源更新恶意包数据库
- [ ] 🖥️ **Web UI 界面**，提供可视化的扫描结果展示和管理面板

---

### 📦 安装与部署指南

#### pip 安装（推荐）

```bash
# 从 PyPI 安装
pip install packetguard

# 验证安装
packetguard --version
```

#### 从源码安装

```bash
# 克隆仓库
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard

# 安装到当前环境
pip install .

# 或使用开发模式安装（方便修改源码后立即生效）
pip install -e .
```

#### Docker 使用（可选）

```bash
# 构建镜像
docker build -t packetguard .

# 扫描项目
docker run --rm -v $(pwd):/app packetguard audit /app -f json -o /app/report
```

#### CI/CD 集成

PacketGuard 可轻松集成到主流 CI/CD 平台：

**GitHub Actions：**

```yaml
- run: pip install packetguard
- run: packetguard audit . -s high
```

**GitLab CI：**

```yaml
security_scan:
  stage: test
  script:
    - pip install packetguard
    - packetguard audit . -f json -o report
  artifacts:
    paths:
      - report.json
```

---

### 🤝 贡献指南

我们欢迎并感谢所有形式的贡献！无论是提交 Bug 报告、改进文档，还是贡献代码。

#### 提交 Issue

- 使用 **清晰的标题** 描述问题
- 提供 **复现步骤** 和 **期望行为**
- 附上 **运行环境信息**（Python 版本、操作系统等）
- 如有可能，附上 **错误日志** 或 **截图**

#### 提交 Pull Request

1. **Fork** 本仓库
2. 创建特性分支：`git checkout -b feature/your-feature-name`
3. 编写代码并确保通过所有测试：`python -m pytest tests/`
4. 提交变更：`git commit -m "feat: 描述你的改动"`
5. 推送分支：`git push origin feature/your-feature-name`
6. 提交 **Pull Request**

#### 开发环境搭建

```bash
# 克隆仓库
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard

# 安装开发依赖
pip install -e .

# 运行测试
python -m pytest tests/ -v

# 运行单个测试文件
python -m pytest tests/test_typosquat.py -v
```

#### 代码规范

- 遵循 **PEP 8** 编码规范
- 为所有公开函数编写 **docstring**
- 确保所有测试通过后再提交 PR
- Commit 信息建议使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式

---

### 📄 开源协议

PacketGuard 基于 [MIT License](https://opensource.org/licenses/MIT) 开源。

```
MIT License

Copyright (c) 2024 PacketGuard Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

这意味着你可以自由地使用、复制、修改、合并、发布、分发、再授权和/或销售本软件，唯一的条件是保留版权声明和许可声明。

---

## English

### 🎉 Introduction

PacketGuard is a **lightweight open-source package supply chain security threat detection engine** built for developers. In an era where software supply chain attacks are increasingly common — from malicious package typosquatting to star count forgery (Starjacking) — the security of the open-source ecosystem is under serious threat.

PacketGuard provides developers with a **zero-dependency, ready-to-use** security scanning tool to quickly identify potential threats before installing and using open-source packages. Whether you're an individual developer or part of a team, PacketGuard integrates seamlessly into your development workflow.

**Core Values:**
- 🔍 **Comprehensive Detection** — Covers five dimensions: Typosquatting, Starjacking, malware signatures, dependency analysis, and threat intelligence
- ⚡ **Ultra Lightweight** — Zero external dependencies, built entirely on the Python standard library
- 🎯 **Accurate & Efficient** — Leverages multiple edit-distance algorithms and pattern-matching engines for optimal precision and performance
- 🔧 **Flexible Configuration** — YAML config files, whitelist/blacklist, rule toggles, and fine-grained control
- 📊 **Multi-Format Reports** — Colorized terminal output, JSON, SARIF, Markdown, and HTML

**What Makes PacketGuard Different:**
- Dual-ecosystem support for both **npm** and **PyPI**
- Built-in **61-entry malicious package database** for offline threat detection
- **SARIF report** output for direct integration with GitHub Code Scanning
- Parses **package.json**, **requirements.txt**, **Pipfile**, and more

---

### ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🔤 **Typosquatting Detection** | Identifies package name hijacking attacks using Levenshtein and Damerau-Levenshtein edit-distance algorithms, with support for adjacent-key and transposition variants |
| ⭐ **Starjacking Detection** | Cross-validates claimed GitHub star counts via the GitHub API, exposing fraudulent repository references |
| 🦠 **Malware Signature Scanning** | 5-category pattern detection engine: network requests, filesystem operations, command execution, code obfuscation, and malicious domains |
| 🌳 **Dependency Analysis** | Intelligently parses package.json / requirements.txt / Pipfile, builds complete dependency trees, and detects circular and risky dependencies |
| 🕵️ **Threat Intelligence** | Built-in 61-entry malicious package database with version anomaly detection and new package risk assessment — works offline |
| 📋 **Multi-Format Reports** | Colorized terminal output, JSON, SARIF (GitHub Code Scanning compatible), Markdown, and HTML |

---

### 🚀 Quick Start

#### Prerequisites

- **Python** 3.8 or later
- **Zero external dependencies** — uses only the Python standard library
- **OS Support** — Linux, macOS, Windows

#### Installation

**Option 1: Install via pip (Recommended)**

```bash
pip install packetguard
```

**Option 2: Install from source**

```bash
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard
pip install .
```

**Option 3: Run directly (No installation required)**

```bash
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard
python -m packetguard --version
```

#### Quick Usage

```bash
# Scan an npm package
packetguard scan express

# Scan a PyPI package
packetguard scan requests -e pypi

# Quick-check a single package
packetguard check lodash

# Audit all dependencies in a project directory
packetguard audit ./my-project

# Generate a JSON report
packetguard report express -f json -o ./report

# Show only high-severity and above
packetguard scan ./project -s high

# Generate a SARIF report for GitHub Actions integration
packetguard audit ./project -f sarif -o ./results
```

---

### 📖 Detailed Usage Guide

#### Command Reference

PacketGuard provides four core subcommands:

| Command | Description | Best For |
|---------|-------------|----------|
| `scan` | Scan packages or projects | Routine security checks on single packages or entire projects |
| `check` | Quick-check a single package | Fast package validation in CI/CD pipelines |
| `audit` | Comprehensive project audit | Deep security audit, ideal for pre-release checks |
| `report` | Generate a formatted report | Exporting scan results to a file |

#### Parameter Reference

**Global Options:**

| Parameter | Short | Description | Default | Options |
|-----------|-------|-------------|---------|---------|
| `--ecosystem` | `-e` | Specify package ecosystem | `auto` | `npm` / `pypi` / `auto` |
| `--format` | `-f` | Output report format | `text` | `text` / `json` / `sarif` / `markdown` / `html` |
| `--severity` | `-s` | Minimum threat severity to report | `low` | `low` / `medium` / `high` / `critical` |
| `--config` | `-c` | Path to configuration file | Auto-detect `.packetguard.yaml` | Any file path |
| `--output` | `-o` | Output file path (without extension) | stdout | Any file path |
| `--timeout` | — | HTTP request timeout (seconds) | `10` | Positive integer |
| `--no-color` | — | Disable colorized terminal output | Colors enabled | — |
| `--version` | `-v` | Show version number | — | — |

#### Configuration File

Create a `.packetguard.yaml` file in your project root to customize PacketGuard's behavior:

```yaml
# General settings
general:
  ecosystem: auto           # Default ecosystem: auto / npm / pypi
  output_format: text       # Output format: text / json / sarif / markdown / html
  min_severity: low         # Minimum severity: low / medium / high / critical
  timeout: 10               # HTTP request timeout (seconds)
  verbose: false            # Enable verbose output

# Detection rule toggles
rules:
  typosquat: true           # Typosquatting detection
  starjacking: true         # Starjacking detection
  malware: true             # Malware signature scanning
  dependency: true          # Dependency analysis
  intelligence: true        # Threat intelligence

# Whitelist — these packages will be skipped
whitelist:
  - express
  - lodash
  - react
  - flask
  - requests

# Blacklist — these packages will be flagged as malicious
blacklist:
  - crossenv
  - event-stream3

# Malware scan detailed configuration
malware_scan:
  check_network: true       # Detect network requests
  check_filesystem: true    # Detect filesystem operations
  check_execution: true     # Detect command execution
  check_obfuscation: true   # Detect code obfuscation
  check_domains: true       # Detect suspicious domains
```

#### Usage Scenarios

**Scenario 1: Integrate security scanning in CI/CD**

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install packetguard
      - run: packetguard audit . -f sarif -o ./results
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./results.sarif
```

**Scenario 2: Focus on high-severity threats only**

```bash
packetguard scan ./my-project -s high -e npm
```

**Scenario 3: Scan and export an HTML report**

```bash
packetguard report ./my-project -f html -o ./security-report
```

---

### 💡 Design Philosophy & Roadmap

#### Design Principles

PacketGuard is built on the following core principles:

1. **Zero-Dependency Philosophy** — Built entirely on the Python standard library to eliminate trust-propagation risks in the supply chain. A security tool should not introduce additional supply chain risks of its own.
2. **Offline-First** — Ships with a built-in threat intelligence database, enabling basic security checks even in air-gapped environments.
3. **Progressive Detection** — From quick checks to deep audits, users can choose the right level of scanning granularity for their scenario.
4. **Extensible Architecture** — Modular detection engine design makes it easy to add new detection rules and package ecosystem support.

#### Technical Decisions

| Decision | Rationale |
|----------|-----------|
| Pure Python standard library | Zero external dependencies, reduced attack surface, install-and-go |
| Levenshtein / Damerau-Levenshtein | Industry-proven edit-distance algorithms with excellent typosquatting detection |
| YAML configuration | Human-readable, supports comments, ideal for project-level config |
| SARIF report format | Natively supported by GitHub Code Scanning for zero-cost CI/CD integration |
| argparse CLI framework | Built into Python standard library, no extra dependencies |

#### Roadmap

- [ ] 🌐 Support for **Go Modules**, **Cargo** (Rust), **Maven** (Java), and more ecosystems
- [ ] 📈 **SBOM (Software Bill of Materials)** generation, compatible with SPDX and CycloneDX
- [ ] 🔗 **License compliance checking** with automatic identification of dependency license types
- [ ] 🧪 **Sandbox dynamic analysis** — execute packages in isolated environments to detect runtime malicious behavior
- [ ] 📡 **Online threat intelligence sync** — update the malicious package database from remote sources
- [ ] 🖥️ **Web UI** — a visual dashboard for scan results and management

---

### 📦 Installation & Deployment

#### pip Installation (Recommended)

```bash
# Install from PyPI
pip install packetguard

# Verify installation
packetguard --version
```

#### Install from Source

```bash
# Clone the repository
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard

# Install into the current environment
pip install .

# Or install in editable mode (changes take effect immediately)
pip install -e .
```

#### Docker Usage (Optional)

```bash
# Build the image
docker build -t packetguard .

# Scan a project
docker run --rm -v $(pwd):/app packetguard audit /app -f json -o /app/report
```

#### CI/CD Integration

PacketGuard integrates easily with mainstream CI/CD platforms:

**GitHub Actions:**

```yaml
- run: pip install packetguard
- run: packetguard audit . -s high
```

**GitLab CI:**

```yaml
security_scan:
  stage: test
  script:
    - pip install packetguard
    - packetguard audit . -f json -o report
  artifacts:
    paths:
      - report.json
```

---

### 🤝 Contributing

We welcome and appreciate contributions of all kinds — bug reports, documentation improvements, and code contributions alike.

#### Submitting Issues

- Use a **clear, descriptive title**
- Include **steps to reproduce** and **expected behavior**
- Attach **environment details** (Python version, OS, etc.)
- Include **error logs** or **screenshots** when possible

#### Submitting Pull Requests

1. **Fork** this repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Write code and ensure all tests pass: `python -m pytest tests/`
4. Commit your changes: `git commit -m "feat: describe your changes"`
5. Push the branch: `git push origin feature/your-feature-name`
6. Open a **Pull Request**

#### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard

# Install in editable mode
pip install -e .

# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_typosquat.py -v
```

#### Code Standards

- Follow **PEP 8** coding conventions
- Write **docstrings** for all public functions
- Ensure all tests pass before submitting a PR
- Use [Conventional Commits](https://www.conventionalcommits.org/) format for commit messages

---

### 📄 License

PacketGuard is released under the [MIT License](https://opensource.org/licenses/MIT).

```
MIT License

Copyright (c) 2024 PacketGuard Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, provided that the copyright notice and permission notice are preserved.

---

## 繁體中文

### 🎉 專案介紹

PacketGuard 是一款專為開發者打造的**輕量級開源套件供應鏈安全威脅偵測引擎**。在當今軟體供應鏈攻擊頻發的背景下，惡意套件投毒、套件名拼寫劫持（Typosquatting）、Star 數偽造（Starjacking）等攻擊手法層出不窮，嚴重威脅著開源生態的安全。

PacketGuard 旨在為開發者提供一個**零外部依賴、開箱即用**的安全掃描工具，幫助你在安裝和使用開源套件之前快速識別潛在的安全威脅。無論是個人開發者還是團隊協作，PacketGuard 都能無縫融入你的開發工作流程。

**核心價值：**
- 🔍 **全面偵測** — 涵蓋 Typosquatting、Starjacking、惡意套件特徵、依賴分析、威脅情報五大維度
- ⚡ **極致輕量** — 零外部依賴，純 Python 標準函式庫實作，安裝即用
- 🎯 **精準高效** — 基於多種編輯距離演算法與模式比對引擎，兼顧準確率與效能
- 🔧 **靈活配置** — 支援 YAML 設定檔、白名單/黑名單、規則開關等精細化控制
- 📊 **多格式報告** — 終端機彩色輸出、JSON、SARIF、Markdown、HTML 五種報告格式

**自研差異化亮點：**
- 同時支援 **npm** 和 **PyPI** 兩大主流套件生態系統
- 內建 **61 筆惡意套件資料庫**，無需連網即可完成基礎威脅偵測
- 產生的 **SARIF 報告**可直接整合至 GitHub Code Scanning 工作流程
- 支援 **package.json**、**requirements.txt**、**Pipfile** 等多種依賴檔案解析

---

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔤 **Typosquatting 偵測** | 基於 Levenshtein 和 Damerau-Levenshtein 編輯距離演算法，精準識別套件名拼寫劫持攻擊，支援鄰鍵、位交換等多種變體偵測 |
| ⭐ **Starjacking 偵測** | 透過 GitHub API 交叉驗證套件聲明的 star 數真實性，揭穿偽造 GitHub 倉庫引用的詐欺行為 |
| 🦠 **惡意套件特徵掃描** | 5 大類模式偵測引擎：網路請求、檔案系統操作、命令執行、程式碼混淆、惡意網域，全面涵蓋已知攻擊手法 |
| 🌳 **依賴分析** | 智慧解析 package.json / requirements.txt / Pipfile，建構完整依賴樹，自動偵測循環依賴與風險依賴 |
| 🕵️ **威脅情報** | 內建 61 筆惡意套件資料庫，版本異常偵測，新套件風險評估，離線也能完成基礎安全檢查 |
| 📋 **多格式報告** | 終端機彩色輸出、JSON、SARIF（相容 GitHub Code Scanning）、Markdown、HTML，滿足不同場景需求 |

---

### 🚀 快速開始

#### 環境需求

- **Python** 3.8 或更高版本
- **零外部依賴** — 僅使用 Python 標準函式庫
- **作業系統** — 支援 Linux、macOS、Windows

#### 安裝

**方式一：透過 pip 安裝（推薦）**

```bash
pip install packetguard
```

**方式二：從原始碼安裝**

```bash
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard
pip install .
```

**方式三：直接執行（無需安裝）**

```bash
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard
python -m packetguard --version
```

#### 快速使用

```bash
# 掃描一個 npm 套件
packetguard scan express

# 掃描一個 PyPI 套件
packetguard scan requests -e pypi

# 快速檢查單個套件是否安全
packetguard check lodash

# 掃描專案目錄下的所有依賴
packetguard audit ./my-project

# 產生 JSON 格式報告
packetguard report express -f json -o ./report

# 只顯示高危及以上級別的威脅
packetguard scan ./project -s high

# 產生 SARIF 報告並整合至 GitHub Actions
packetguard audit ./project -f sarif -o ./results
```

---

### 📖 詳細使用指南

#### 命令一覽

PacketGuard 提供四個核心子命令：

| 命令 | 說明 | 適用場景 |
|------|------|----------|
| `scan` | 掃描套件或專案 | 日常安全檢查，掃描單個套件或整個專案 |
| `check` | 快速檢查單個套件 | CI/CD 流水線中快速驗證套件安全性 |
| `audit` | 全面審計專案目錄 | 深度安全審計，適合發布前檢查 |
| `report` | 產生指定格式報告 | 需要匯出報告檔案時使用 |

#### 參數說明

**通用參數：**

| 參數 | 縮寫 | 說明 | 預設值 | 可選值 |
|------|------|------|--------|--------|
| `--ecosystem` | `-e` | 指定套件生態系統 | `auto` | `npm` / `pypi` / `auto` |
| `--format` | `-f` | 輸出報告格式 | `text` | `text` / `json` / `sarif` / `markdown` / `html` |
| `--severity` | `-s` | 最低報告威脅等級 | `low` | `low` / `medium` / `high` / `critical` |
| `--config` | `-c` | 指定設定檔路徑 | 自動尋找 `.packetguard.yaml` | 任意檔案路徑 |
| `--output` | `-o` | 輸出檔案路徑（不含副檔名） | 標準輸出 | 任意檔案路徑 |
| `--timeout` | — | HTTP 請求逾時時間（秒） | `10` | 正整數 |
| `--no-color` | — | 停用彩色終端機輸出 | 啟用彩色 | — |
| `--version` | `-v` | 顯示版本號 | — | — |

#### 設定檔

在專案根目錄建立 `.packetguard.yaml` 檔案即可自訂 PacketGuard 的行為：

```yaml
# 通用設定
general:
  ecosystem: auto           # 預設生態系統: auto / npm / pypi
  output_format: text       # 輸出格式: text / json / sarif / markdown / html
  min_severity: low         # 最低報告等級: low / medium / high / critical
  timeout: 10               # HTTP 請求逾時（秒）
  verbose: false            # 是否啟用詳細輸出

# 偵測規則開關
rules:
  typosquat: true           # Typosquatting 偵測
  starjacking: true         # Starjacking 偵測
  malware: true             # 惡意套件特徵掃描
  dependency: true          # 依賴分析
  intelligence: true        # 威脅情報檢查

# 白名單 — 這些套件將被跳過掃描
whitelist:
  - express
  - lodash
  - react
  - flask
  - requests

# 黑名單 — 這些套件將被標記為惡意
blacklist:
  - crossenv
  - event-stream3

# 惡意套件掃描詳細設定
malware_scan:
  check_network: true       # 偵測網路請求
  check_filesystem: true    # 偵測檔案系統操作
  check_execution: true     # 偵測命令執行
  check_obfuscation: true   # 偵測程式碼混淆
  check_domains: true       # 偵測可疑網域
```

#### 典型場景範例

**場景一：在 CI/CD 中整合安全檢查**

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install packetguard
      - run: packetguard audit . -f sarif -o ./results
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./results.sarif
```

**場景二：只關注高危威脅**

```bash
packetguard scan ./my-project -s high -e npm
```

**場景三：掃描並匯出 HTML 報告**

```bash
packetguard report ./my-project -f html -o ./security-report
```

---

### 💡 設計思路與迭代規劃

#### 設計理念

PacketGuard 的設計遵循以下核心原則：

1. **零依賴哲學** — 全部基於 Python 標準函式庫實作，消除供應鏈中的信任傳遞風險。安全工具本身不應該引入額外的供應鏈風險。
2. **離線優先** — 內建威脅情報資料庫，即使在没有網路連線的環境中也能完成基礎安全檢查。
3. **漸進式偵測** — 從快速檢查到深度審計，使用者可以根據場景選擇不同粒度的安全掃描。
4. **可擴展架構** — 模組化的偵測引擎設計，便於後續新增偵測規則和套件生態系統支援。

#### 技術選型原因

| 技術決策 | 原因 |
|----------|------|
| 純 Python 標準函式庫 | 零外部依賴，降低供應鏈攻擊面，安裝即用 |
| Levenshtein / Damerau-Levenshtein | 業界成熟的編輯距離演算法，對 Typosquatting 偵測效果優異 |
| YAML 設定檔 | 人類可讀、支援註解，適合作為專案級設定 |
| SARIF 報告格式 | GitHub Code Scanning 原生支援，CI/CD 整合零成本 |
| argparse CLI 框架 | Python 標準函式庫內建，無額外依賴 |

#### 後續功能計畫

- [ ] 🌐 支援 **Go Modules**、**Cargo**（Rust）、**Maven**（Java）等更多套件生態系統
- [ ] 📈 **SBOM（軟體物料清單）** 產生，相容 SPDX 和 CycloneDX 標準
- [ ] 🔗 **授權條款合規檢查**，自動識別依賴的授權條款類型和相容性
- [ ] 🧪 **沙箱動態分析**，在隔離環境中實際執行套件以偵測執行期惡意行為
- [ ] 📡 **線上威脅情報同步**，支援從遠端來源更新惡意套件資料庫
- [ ] 🖥️ **Web UI 介面**，提供視覺化的掃描結果展示和管理面板

---

### 📦 安裝與部署指南

#### pip 安裝（推薦）

```bash
# 從 PyPI 安裝
pip install packetguard

# 驗證安裝
packetguard --version
```

#### 從原始碼安裝

```bash
# 複製倉庫
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard

# 安裝到當前環境
pip install .

# 或使用開發模式安裝（方便修改原始碼後立即生效）
pip install -e .
```

#### Docker 使用（選配）

```bash
# 建置映像檔
docker build -t packetguard .

# 掃描專案
docker run --rm -v $(pwd):/app packetguard audit /app -f json -o /app/report
```

#### CI/CD 整合

PacketGuard 可輕鬆整合至主流 CI/CD 平台：

**GitHub Actions：**

```yaml
- run: pip install packetguard
- run: packetguard audit . -s high
```

**GitLab CI：**

```yaml
security_scan:
  stage: test
  script:
    - pip install packetguard
    - packetguard audit . -f json -o report
  artifacts:
    paths:
      - report.json
```

---

### 🤝 貢獻指南

我們歡迎並感謝所有形式的貢獻！無論是提交 Bug 回報、改進文件，還是貢獻程式碼。

#### 提交 Issue

- 使用 **清晰的標題** 描述問題
- 提供 **重現步驟** 和 **預期行為**
- 附上 **執行環境資訊**（Python 版本、作業系統等）
- 如有可能，附上 **錯誤日誌** 或 **截圖**

#### 提交 Pull Request

1. **Fork** 本倉庫
2. 建立特性分支：`git checkout -b feature/your-feature-name`
3. 撰寫程式碼並確保通過所有測試：`python -m pytest tests/`
4. 提交變更：`git commit -m "feat: 描述你的變更"`
5. 推送分支：`git push origin feature/your-feature-name`
6. 提交 **Pull Request**

#### 開發環境建置

```bash
# 複製倉庫
git clone https://github.com/gitstq/PacketGuard.git
cd PacketGuard

# 安裝開發依賴
pip install -e .

# 執行測試
python -m pytest tests/ -v

# 執行單一測試檔案
python -m pytest tests/test_typosquat.py -v
```

#### 程式碼規範

- 遵循 **PEP 8** 編碼規範
- 為所有公開函式撰寫 **docstring**
- 確保所有測試通過後再提交 PR
- Commit 訊息建議使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式

---

### 📄 開源協議

PacketGuard 基於 [MIT License](https://opensource.org/licenses/MIT) 開源。

```
MIT License

Copyright (c) 2024 PacketGuard Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

這意味著你可以自由地使用、複製、修改、合併、發布、分發、再授權和/或銷售本軟體，唯一的條件是保留著作權聲明和許可聲明。

---

<div align="center">

**Made with ❤️ by [PacketGuard Team](https://github.com/gitstq/PacketGuard)**

</div>
