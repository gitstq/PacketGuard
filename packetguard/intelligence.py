# -*- coding: utf-8 -*-
"""
威胁情报模块 / Threat Intelligence Module

提供包安全威胁情报功能，包括:
- 内置已知恶意包数据库
- 包版本异常检测
- 新包风险评估

Provides package security threat intelligence including:
- Built-in known malicious package database
- Package version anomaly detection
- New package risk assessment
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .utils import (
    http_get_json,
    is_semver,
    load_json_file,
    normalize_package_name,
    parse_version,
    print_info,
    print_warning,
)


# ============================================================
# 内置威胁数据库 / Built-in Threat Database
# ============================================================

# 内置的已知恶意包数据 / Built-in known malicious package data
BUILTIN_THREAT_DB: Dict[str, Any] = {
    "version": "1.0.0",
    "last_updated": "2025-01-01",
    "malicious_npm_packages": [
        "crossenv", "cross-env.js", "babel-cli", "bablok",
        "loadash", "lodssh", "web3-npm", "web3-eth",
        "dot-prop", "dotp-rop", "event-stream", "event-stream3",
        "lodash-dot", "loda-sh", "vue-cli", "vue-cli3",
        "react-scripts", "react-scrips", "webpack-cli", "webpack-clii",
        "express-middleware", "express-middlewar",
        "mongoose-model", "mongoose-modl",
        "npm-package-provider", "npm-package-providers",
        "d3-color", "d3-colour", "d3-cloor",
    ],
    "malicious_pypi_packages": [
        "urllib3", "urllib3000", "requests", "requestss",
        "numpy", "numpv", "pandas", "pandaas",
        "flask", "flask-restful", "flask-restfull",
        "django", "djangoo", "djngo",
        "pillow", "pilllow", "piillow",
        "setuptools", "setuptoolz", "setup-tools",
        "pip", "piip", "pipp",
        "pytest", "pytst", "pytes",
        "boto3", "botto3", "boto33",
        "cryptography", "cryptographpy", "crryptography",
    ],
    "suspicious_domains": [
        "pastebin.com", "raw.githubusercontent.com",
        "requestbin.net", "webhook.site", "ngrok.io",
        "unknownhost.xyz", "evil.com", "malware-server.com",
        "exfil-data.net", "c2-server.xyz",
        "discord.com/api/webhooks", "telegram.org/api",
    ],
    "suspicious_file_paths": [
        "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/known_hosts",
        "/.aws/credentials", "/.aws/config",
        "/.npmrc", "/.pypirc", "/.netrc",
        "/.gitconfig", "/.git-credentials",
        "/.docker/config.json", "/.kube/config",
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Users\\*\\.ssh\\id_rsa",
    ],
    "suspicious_api_endpoints": [
        "/api/exfil", "/api/collect", "/api/log",
        "/webhook", "/callback", "/notify",
        "/upload", "/submit", "/report",
    ],
    "malicious_hashes": {
        # 示例哈希值(非真实恶意包哈希) / Example hashes (not real malicious package hashes)
        "sha256": [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        ],
    },
}


class ThreatDatabase:
    """威胁数据库 / Threat Database

    管理内置和自定义的威胁情报数据。
    Manages built-in and custom threat intelligence data.

    使用方法 / Usage:
        db = ThreatDatabase()
        db.load_builtin()
        if db.is_malicious("crossenv", "npm"):
            print("Malicious!")
    """

    def __init__(self) -> None:
        """初始化威胁数据库 / Initialize threat database"""
        self._malicious_npm: Set[str] = set()
        self._malicious_pypi: Set[str] = set()
        self._suspicious_domains: Set[str] = set()
        self._suspicious_paths: Set[str] = set()
        self._suspicious_endpoints: Set[str] = set()
        self._malicious_hashes: Set[str] = set()
        self._loaded = False

    @property
    def loaded(self) -> bool:
        """数据库是否已加载 / Whether database is loaded"""
        return self._loaded

    def load_builtin(self) -> None:
        """加载内置威胁数据库 / Load built-in threat database"""
        self._malicious_npm = set(BUILTIN_THREAT_DB.get("malicious_npm_packages", []))
        self._malicious_pypi = set(BUILTIN_THREAT_DB.get("malicious_pypi_packages", []))
        self._suspicious_domains = set(BUILTIN_THREAT_DB.get("suspicious_domains", []))
        self._suspicious_paths = set(BUILTIN_THREAT_DB.get("suspicious_file_paths", []))
        self._suspicious_endpoints = set(BUILTIN_THREAT_DB.get("suspicious_api_endpoints", []))

        for sha_list in BUILTIN_THREAT_DB.get("malicious_hashes", {}).values():
            if isinstance(sha_list, list):
                self._malicious_hashes.update(sha_list)

        self._loaded = True
        print_info(f"已加载内置威胁数据库 (npm: {len(self._malicious_npm)}, "
                   f"PyPI: {len(self._malicious_pypi)})")

    def load_from_file(self, filepath: str) -> bool:
        """从 JSON 文件加载威胁数据库 / Load threat database from JSON file

        Args:
            filepath: JSON 文件路径 / JSON file path

        Returns:
            是否加载成功 / Whether loading was successful
        """
        data = load_json_file(filepath)
        if not data:
            return False

        # 合并数据 / Merge data
        self._malicious_npm.update(data.get("malicious_npm_packages", []))
        self._malicious_pypi.update(data.get("malicious_pypi_packages", []))
        self._suspicious_domains.update(data.get("suspicious_domains", []))
        self._suspicious_paths.update(data.get("suspicious_file_paths", []))
        self._suspicious_endpoints.update(data.get("suspicious_api_endpoints", []))

        for sha_list in data.get("malicious_hashes", {}).values():
            if isinstance(sha_list, list):
                self._malicious_hashes.update(sha_list)

        self._loaded = True
        print_info(f"从文件加载威胁数据库: {filepath}")
        return True

    def is_malicious(self, package_name: str, ecosystem: str) -> bool:
        """检查包是否为已知恶意包 / Check if package is known malicious

        Args:
            package_name: 包名 / Package name
            ecosystem: 生态系统(npm/pypi) / Ecosystem

        Returns:
            是否为恶意包 / Whether malicious
        """
        normalized = normalize_package_name(package_name, ecosystem)
        if ecosystem == "npm":
            return normalized in self._malicious_npm
        elif ecosystem == "pypi":
            return normalized in self._malicious_pypi
        return False

    def is_hash_malicious(self, file_hash: str) -> bool:
        """检查文件哈希是否在恶意哈希列表中 / Check if file hash is in malicious hash list

        Args:
            file_hash: 文件哈希值 / File hash value

        Returns:
            是否为恶意哈希 / Whether malicious hash
        """
        return file_hash.lower() in self._malicious_hashes

    def is_domain_suspicious(self, domain: str) -> bool:
        """检查域名是否可疑 / Check if domain is suspicious

        Args:
            domain: 域名 / Domain

        Returns:
            是否可疑 / Whether suspicious
        """
        domain_lower = domain.lower()
        for suspicious in self._suspicious_domains:
            if suspicious.lower() in domain_lower:
                return True
        return False

    def is_path_suspicious(self, file_path: str) -> bool:
        """检查文件路径是否可疑 / Check if file path is suspicious

        Args:
            file_path: 文件路径 / File path

        Returns:
            是否可疑 / Whether suspicious
        """
        path_lower = file_path.lower()
        for suspicious in self._suspicious_paths:
            if suspicious.lower() in path_lower:
                return True
        return False

    @property
    def malicious_npm_packages(self) -> Set[str]:
        """获取恶意 npm 包列表 / Get malicious npm package list"""
        return self._malicious_npm.copy()

    @property
    def malicious_pypi_packages(self) -> Set[str]:
        """获取恶意 PyPI 包列表 / Get malicious PyPI package list"""
        return self._malicious_pypi.copy()

    @property
    def suspicious_domains(self) -> Set[str]:
        """获取可疑域名列表 / Get suspicious domain list"""
        return self._suspicious_domains.copy()


# ============================================================
# 威胁情报分析器 / Threat Intelligence Analyzer
# ============================================================

class ThreatIntelligenceAnalyzer:
    """威胁情报分析器 / Threat Intelligence Analyzer

    提供包安全威胁情报分析功能。
    Provides package security threat intelligence analysis.

    使用方法 / Usage:
        analyzer = ThreatIntelligenceAnalyzer()
        analyzer.load_threat_db()
        results = analyzer.analyze("some-package", ecosystem="npm")
    """

    def __init__(self) -> None:
        """初始化分析器 / Initialize analyzer"""
        self._threat_db = ThreatDatabase()

    def load_threat_db(self, custom_db_path: Optional[str] = None) -> None:
        """加载威胁数据库 / Load threat database

        Args:
            custom_db_path: 自定义数据库文件路径 / Custom database file path
        """
        self._threat_db.load_builtin()
        if custom_db_path and os.path.isfile(custom_db_path):
            self._threat_db.load_from_file(custom_db_path)

    @property
    def threat_db(self) -> ThreatDatabase:
        """获取威胁数据库 / Get threat database"""
        return self._threat_db

    def check_malicious_package(
        self,
        package_name: str,
        ecosystem: str,
    ) -> Optional[Dict[str, Any]]:
        """检查包是否为已知恶意包 / Check if package is known malicious

        Args:
            package_name: 包名 / Package name
            ecosystem: 生态系统 / Ecosystem

        Returns:
            检测结果或 None / Detection result or None
        """
        if not self._threat_db.loaded:
            self._threat_db.load_builtin()

        if self._threat_db.is_malicious(package_name, ecosystem):
            return {
                "type": "intelligence",
                "category": "known_malicious",
                "package": package_name,
                "ecosystem": ecosystem,
                "severity": "critical",
                "description": f"包 '{package_name}' 在已知恶意包数据库中",
                "description_en": f"Package '{package_name}' found in known malicious package database",
                "recommendation": "立即移除此包，使用官方推荐的替代方案",
                "recommendation_en": "Remove this package immediately; use official recommended alternatives",
            }
        return None

    def check_version_anomaly(
        self,
        package_name: str,
        current_version: str,
        ecosystem: str,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """检测包版本异常 / Detect package version anomalies

        检查是否存在突然的大版本跳跃或发布时间异常。
        Checks for sudden major version jumps or abnormal publish times.

        Args:
            package_name: 包名 / Package name
            current_version: 当前版本 / Current version
            ecosystem: 生态系统 / Ecosystem
            timeout: 超时时间 / Timeout

        Returns:
            检测结果或 None / Detection result or None
        """
        if not is_semver(current_version):
            return None

        # 获取包信息 / Fetch package info
        if ecosystem == "npm":
            metadata = http_get_json(
                f"https://registry.npmjs.org/{package_name}",
                timeout=timeout,
            )
            if not metadata:
                return None

            versions = metadata.get("versions", {})
            time_info = metadata.get("time", {})

            if not versions:
                return None

            version_list = sorted(
                [v for v in versions.keys() if is_semver(v)],
                key=parse_version,
            )

            if len(version_list) < 2:
                return None

            # 检查版本跳跃 / Check version jumps
            prev_version = version_list[-2]
            curr_parsed = parse_version(current_version)
            prev_parsed = parse_version(prev_version)

            # 大版本跳跃检测(主版本号跳跃 > 1) / Major version jump detection
            if (curr_parsed[0] - prev_parsed[0] > 1):
                return {
                    "type": "intelligence",
                    "category": "version_anomaly",
                    "package": package_name,
                    "ecosystem": ecosystem,
                    "severity": "medium",
                    "description": (
                        f"包 '{package_name}' 从 {prev_version} 跳跃到 {current_version}，"
                        f"版本号异常增长"
                    ),
                    "description_en": (
                        f"Package '{package_name}' jumped from {prev_version} to "
                        f"{current_version}, abnormal version increase"
                    ),
                    "recommendation": "请确认此版本更新是否合法，警惕供应链攻击",
                    "recommendation_en": "Verify this version update is legitimate, beware of supply chain attacks",
                    "details": {
                        "previous_version": prev_version,
                        "current_version": current_version,
                        "total_versions": len(version_list),
                    },
                }

            # 检查发布时间异常 / Check publish time anomalies
            current_time = time_info.get(current_version, "")
            if current_time:
                try:
                    pub_time = datetime.fromisoformat(current_time.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    age_days = (now - pub_time).days

                    # 如果包非常新但版本号很高 / If package is very new but version is high
                    if age_days < 7 and curr_parsed[0] >= 1:
                        return {
                            "type": "intelligence",
                            "category": "new_package_risk",
                            "package": package_name,
                            "ecosystem": ecosystem,
                            "severity": "high",
                            "description": (
                                f"包 '{package_name}' 发布仅 {age_days} 天，"
                                f"但已达到 {current_version} 版本，风险较高"
                            ),
                            "description_en": (
                                f"Package '{package_name}' published only {age_days} days ago "
                                f"but already at version {current_version}, high risk"
                            ),
                            "recommendation": "新包且版本号较高，建议谨慎使用并观察一段时间",
                            "recommendation_en": (
                                "New package with high version number; use with caution "
                                "and observe for a while"
                            ),
                            "details": {
                                "publish_date": current_time,
                                "age_days": age_days,
                                "version": current_version,
                            },
                        }
                except (ValueError, TypeError):
                    pass

        elif ecosystem == "pypi":
            metadata = http_get_json(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=timeout,
            )
            if not metadata:
                return None

            info = metadata.get("info", {})
            releases = metadata.get("releases", {})

            if not releases:
                return None

            version_list = sorted(
                [v for v in releases.keys() if is_semver(v)],
                key=parse_version,
            )

            if len(version_list) < 2:
                return None

            prev_version = version_list[-2]
            curr_parsed = parse_version(current_version)
            prev_parsed = parse_version(prev_version)

            if curr_parsed[0] - prev_parsed[0] > 1:
                return {
                    "type": "intelligence",
                    "category": "version_anomaly",
                    "package": package_name,
                    "ecosystem": ecosystem,
                    "severity": "medium",
                    "description": (
                        f"包 '{package_name}' 从 {prev_version} 跳跃到 {current_version}，"
                        f"版本号异常增长"
                    ),
                    "description_en": (
                        f"Package '{package_name}' jumped from {prev_version} to "
                        f"{current_version}, abnormal version increase"
                    ),
                    "recommendation": "请确认此版本更新是否合法，警惕供应链攻击",
                    "recommendation_en": "Verify this version update is legitimate, beware of supply chain attacks",
                    "details": {
                        "previous_version": prev_version,
                        "current_version": current_version,
                        "total_versions": len(version_list),
                    },
                }

        return None

    def analyze(
        self,
        package_name: str,
        ecosystem: str = "npm",
        version: str = "",
        timeout: int = 10,
    ) -> List[Dict[str, Any]]:
        """综合威胁情报分析 / Comprehensive threat intelligence analysis

        Args:
            package_name: 包名 / Package name
            ecosystem: 生态系统 / Ecosystem
            version: 包版本(可选) / Package version (optional)
            timeout: 超时时间 / Timeout

        Returns:
            分析结果列表 / List of analysis results
        """
        results: List[Dict[str, Any]] = []

        # 1. 检查已知恶意包 / Check known malicious packages
        malicious_result = self.check_malicious_package(package_name, ecosystem)
        if malicious_result:
            results.append(malicious_result)

        # 2. 检查版本异常 / Check version anomalies
        if version:
            version_result = self.check_version_anomaly(
                package_name, version, ecosystem, timeout
            )
            if version_result:
                results.append(version_result)

        return results
