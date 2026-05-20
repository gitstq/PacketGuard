# -*- coding: utf-8 -*-
"""
扫描器主引擎 / Scanner Main Engine

整合所有检测模块，提供统一的扫描接口。
Integrates all detection modules and provides a unified scanning interface.
"""

import os
from typing import Any, Dict, List, Optional, Set

from .config import Config
from .dependency import DependencyAnalyzer
from .intelligence import ThreatIntelligenceAnalyzer
from .malware import MalwareScanner
from .report import ReportGenerator, ScanResult
from .starjacking import StarjackDetector
from .typosquat import TyposquatDetector
from .utils import (
    ProgressBar,
    normalize_package_name,
    print_error,
    print_info,
    print_success,
    print_warning,
)


class PacketGuardScanner:
    """PacketGuard 扫描器主引擎 / PacketGuard Scanner Main Engine

    整合所有检测模块，提供统一的扫描入口。
    Integrates all detection modules and provides a unified scanning entry point.

    使用方法 / Usage:
        scanner = PacketGuardScanner()
        scanner.load_config()
        result = scanner.scan_package("express", ecosystem="npm")
        report = scanner.generate_report(result, format="text")
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        """初始化扫描器 / Initialize scanner

        Args:
            config: 配置对象(如为 None 则使用默认配置) / Config object (uses defaults if None)
        """
        self._config = config or Config()
        self._typosquat_detector = TyposquatDetector()
        self._starjack_detector = StarjackDetector()
        self._malware_scanner = MalwareScanner()
        self._dependency_analyzer = DependencyAnalyzer()
        self._intelligence_analyzer = ThreatIntelligenceAnalyzer()
        self._report_generator = ReportGenerator()
        self._threat_db_loaded = False

    @property
    def config(self) -> Config:
        """获取配置 / Get configuration"""
        return self._config

    def load_config(self, config_path: Optional[str] = None) -> None:
        """加载配置文件 / Load configuration file

        Args:
            config_path: 配置文件路径(如为 None 则自动查找) /
                         Config file path (auto-detects if None)
        """
        if config_path:
            self._config.load_from_file(config_path)
        else:
            # 从当前目录向上查找配置文件 / Search for config file from current dir upward
            current = os.getcwd()
            for _ in range(5):  # 最多向上查找 5 层 / Search up to 5 levels
                config_file = os.path.join(current, ".packetguard.yaml")
                if os.path.isfile(config_file):
                    self._config.load_from_file(config_file)
                    print_info(f"已加载配置文件 / Config loaded: {config_file}")
                    break
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent

        # 根据配置更新扫描器设置 / Update scanner settings based on config
        self._update_scanner_from_config()

    def _update_scanner_from_config(self) -> None:
        """根据配置更新扫描器设置 / Update scanner settings from config"""
        malware_config = self._config.get("malware_scan", {})
        self._malware_scanner = MalwareScanner(
            check_network=self._config.get("malware_scan.check_network", True),
            check_filesystem=self._config.get("malware_scan.check_filesystem", True),
            check_execution=self._config.get("malware_scan.check_execution", True),
            check_obfuscation=self._config.get("malware_scan.check_obfuscation", True),
            check_domains=self._config.get("malware_scan.check_domains", True),
        )

    def _ensure_threat_db(self) -> None:
        """确保威胁数据库已加载 / Ensure threat database is loaded"""
        if not self._threat_db_loaded:
            self._intelligence_analyzer.load_threat_db()
            self._threat_db_loaded = True

            # 将已知包添加到 typosquat 检测器的已知包列表
            # Add known packages to typosquat detector's known list
            threat_db = self._intelligence_analyzer.threat_db
            known_packages: List[str] = []
            known_packages.extend(threat_db.malicious_npm_packages)
            known_packages.extend(threat_db.malicious_pypi_packages)
            self._typosquat_detector.add_known_packages(known_packages)

    def scan_package(
        self,
        package_name: str,
        ecosystem: str = "auto",
        version: str = "",
    ) -> ScanResult:
        """扫描单个包 / Scan a single package

        Args:
            package_name: 包名 / Package name
            ecosystem: 生态系统(npm/pypi/auto) / Ecosystem
            version: 包版本(可选) / Package version (optional)

        Returns:
            扫描结果 / Scan result
        """
        # 自动检测生态系统 / Auto-detect ecosystem
        if ecosystem == "auto":
            ecosystem = self._detect_ecosystem(package_name)

        result = ScanResult(
            target=package_name,
            ecosystem=ecosystem,
        )

        print_info(f"开始扫描包 / Scanning package: {package_name} ({ecosystem})")

        # 检查白名单 / Check whitelist
        if self._config.is_whitelisted(package_name):
            print_success(f"包 '{package_name}' 在白名单中，跳过扫描")
            result.metadata["whitelisted"] = True
            return result

        # 检查黑名单 / Check blacklist
        if self._config.is_blacklisted(package_name):
            print_warning(f"包 '{package_name}' 在黑名单中")
            result.add_finding({
                "type": "blacklist",
                "package": package_name,
                "severity": "critical",
                "description": f"包 '{package_name}' 在用户自定义黑名单中",
                "description_en": f"Package '{package_name}' is in user-defined blacklist",
                "recommendation": "请移除此包或确认黑名单配置正确",
                "recommendation_en": "Remove this package or verify blacklist configuration",
            })

        # 1. 威胁情报检查 / Threat intelligence check
        if self._config.is_rule_enabled("intelligence"):
            self._ensure_threat_db()
            print_info("执行威胁情报检查 / Running threat intelligence check")
            intel_results = self._intelligence_analyzer.analyze(
                package_name, ecosystem, version, self._config.timeout
            )
            result.add_findings(intel_results)

        # 2. Typosquatting 检测 / Typosquatting detection
        if self._config.is_rule_enabled("typosquat"):
            print_info("执行 Typosquatting 检测 / Running typosquatting detection")
            typo_results = self._typosquat_detector.check(
                package_name, ecosystem, max_distance=2
            )
            result.add_findings(typo_results)

        # 3. Starjacking 检测 / Starjacking detection
        if self._config.is_rule_enabled("starjacking"):
            print_info("执行 Starjacking 检测 / Running starjacking detection")
            star_result = self._starjack_detector.check(
                package_name, ecosystem, self._config.timeout
            )
            if star_result.get("has_risk"):
                result.add_finding(star_result)

        # 4. 版本异常检测 / Version anomaly detection
        if version and self._config.is_rule_enabled("intelligence"):
            print_info("执行版本异常检测 / Running version anomaly detection")
            version_result = self._intelligence_analyzer.check_version_anomaly(
                package_name, version, ecosystem, self._config.timeout
            )
            if version_result:
                result.add_finding(version_result)

        print_success(f"扫描完成 / Scan complete: {result.total_findings} 个发现")
        return result

    def scan_file(self, filepath: str, ecosystem: str = "auto") -> ScanResult:
        """扫描依赖文件 / Scan a dependency file

        Args:
            filepath: 文件路径 / File path
            ecosystem: 生态系统 / Ecosystem

        Returns:
            扫描结果 / Scan result
        """
        if not os.path.isfile(filepath):
            print_error(f"文件不存在 / File not found: {filepath}")
            return ScanResult(target=filepath, ecosystem="unknown")

        # 自动检测生态系统 / Auto-detect ecosystem
        if ecosystem == "auto":
            ecosystem = self._detect_ecosystem_from_file(filepath)

        result = ScanResult(
            target=filepath,
            ecosystem=ecosystem,
        )

        print_info(f"扫描依赖文件 / Scanning dependency file: {filepath}")

        # 1. 解析依赖 / Parse dependencies
        if self._config.is_rule_enabled("dependency"):
            dep_result = self._dependency_analyzer.analyze_file(filepath)
            result.dependency_info = dep_result

            # 扫描每个依赖包 / Scan each dependency
            deps = dep_result.get("dependencies", [])
            if deps:
                print_info(f"发现 {len(deps)} 个依赖，开始逐个扫描 / Found {len(deps)} dependencies, scanning each")
                bar = ProgressBar(total=len(deps), prefix="扫描进度 / Progress")

                for i, dep in enumerate(deps):
                    pkg_name = dep.get("name", "")
                    pkg_version = dep.get("version", "")

                    if self._config.is_whitelisted(pkg_name):
                        bar.update(i + 1)
                        continue

                    # 威胁情报检查 / Threat intelligence check
                    if self._config.is_rule_enabled("intelligence"):
                        self._ensure_threat_db()
                        intel = self._intelligence_analyzer.check_malicious_package(
                            pkg_name, ecosystem
                        )
                        if intel:
                            result.add_finding(intel)

                    bar.update(i + 1)

                bar.finish()

        # 2. 恶意包特征扫描(如果是 package.json) / Malware scan (if package.json)
        filename = os.path.basename(filepath)
        if filename == "package.json" and self._config.is_rule_enabled("malware"):
            print_info("扫描 package.json 脚本 / Scanning package.json scripts")
            malware_results = self._malware_scanner.scan_package_json_scripts(filepath)
            result.add_findings(malware_results)

        print_success(f"文件扫描完成 / File scan complete: {result.total_findings} 个发现")
        return result

    def scan_directory(self, directory: str, ecosystem: str = "auto") -> ScanResult:
        """扫描项目目录 / Scan a project directory

        Args:
            directory: 项目目录路径 / Project directory path
            ecosystem: 生态系统 / Ecosystem

        Returns:
            扫描结果 / Scan result
        """
        if not os.path.isdir(directory):
            print_error(f"目录不存在 / Directory not found: {directory}")
            return ScanResult(target=directory, ecosystem="unknown")

        result = ScanResult(
            target=directory,
            ecosystem=ecosystem,
        )

        print_info(f"扫描项目目录 / Scanning project directory: {directory}")

        # 1. 依赖分析 / Dependency analysis
        if self._config.is_rule_enabled("dependency"):
            dep_result = self._dependency_analyzer.analyze_project(directory)
            result.dependency_info = dep_result
            result.ecosystem = dep_result.get("ecosystem", ecosystem)

            actual_ecosystem = result.ecosystem

            # 扫描每个依赖 / Scan each dependency
            deps = dep_result.get("dependencies", [])
            if deps:
                print_info(f"发现 {len(deps)} 个直接依赖 / Found {len(deps)} direct dependencies")
                bar = ProgressBar(total=len(deps), prefix="扫描进度 / Progress")

                for i, dep in enumerate(deps):
                    pkg_name = dep.get("name", "")
                    pkg_version = dep.get("version", "")

                    if self._config.is_whitelisted(pkg_name):
                        bar.update(i + 1)
                        continue

                    # 威胁情报检查 / Threat intelligence check
                    if self._config.is_rule_enabled("intelligence"):
                        self._ensure_threat_db()
                        intel = self._intelligence_analyzer.check_malicious_package(
                            pkg_name, actual_ecosystem
                        )
                        if intel:
                            result.add_finding(intel)

                    bar.update(i + 1)

                bar.finish()

        # 2. 恶意包特征扫描 / Malware pattern scanning
        if self._config.is_rule_enabled("malware"):
            print_info("执行恶意包特征扫描 / Running malware pattern scanning")
            malware_results = self._malware_scanner.scan_directory(directory)
            result.add_findings(malware_results)

        # 3. 扫描 package.json 脚本 / Scan package.json scripts
        package_json = os.path.join(directory, "package.json")
        if os.path.isfile(package_json) and self._config.is_rule_enabled("malware"):
            print_info("扫描 package.json 脚本 / Scanning package.json scripts")
            script_results = self._malware_scanner.scan_package_json_scripts(package_json)
            result.add_findings(script_results)

        print_success(f"目录扫描完成 / Directory scan complete: {result.total_findings} 个发现")
        return result

    def quick_check(self, package_name: str, ecosystem: str = "auto") -> ScanResult:
        """快速检查包安全性 / Quick check package safety

        只执行威胁情报检查，速度最快。
        Only runs threat intelligence check, fastest mode.

        Args:
            package_name: 包名 / Package name
            ecosystem: 生态系统 / Ecosystem

        Returns:
            扫描结果 / Scan result
        """
        if ecosystem == "auto":
            ecosystem = self._detect_ecosystem(package_name)

        result = ScanResult(
            target=package_name,
            ecosystem=ecosystem,
        )

        self._ensure_threat_db()

        # 检查黑名单 / Check blacklist
        if self._config.is_blacklisted(package_name):
            result.add_finding({
                "type": "blacklist",
                "package": package_name,
                "severity": "critical",
                "description": f"包 '{package_name}' 在黑名单中",
                "description_en": f"Package '{package_name}' is in blacklist",
            })
            return result

        # 检查白名单 / Check whitelist
        if self._config.is_whitelisted(package_name):
            result.metadata["whitelisted"] = True
            return result

        # 威胁情报检查 / Threat intelligence check
        intel = self._intelligence_analyzer.check_malicious_package(package_name, ecosystem)
        if intel:
            result.add_finding(intel)

        return result

    def generate_report(
        self,
        result: ScanResult,
        fmt: str = "text",
        output_path: Optional[str] = None,
        min_severity: str = "low",
    ) -> str:
        """生成扫描报告 / Generate scan report

        Args:
            result: 扫描结果 / Scan result
            fmt: 输出格式 / Output format
            output_path: 输出文件路径(可选) / Output file path (optional)
            min_severity: 最低严重等级 / Minimum severity

        Returns:
            报告文本 / Report text
        """
        if output_path:
            filepath = self._report_generator.export(
                result, fmt, output_path, min_severity
            )
            if filepath:
                print_success(f"报告已导出 / Report exported: {filepath}")
                return filepath
            return ""

        return self._report_generator.generate(result, fmt, min_severity)

    def audit(
        self,
        directory: str,
        ecosystem: str = "auto",
    ) -> ScanResult:
        """审计项目安全 / Audit project security

        执行全面的安全审计，包括所有检测模块。
        Performs comprehensive security audit with all detection modules.

        Args:
            directory: 项目目录路径 / Project directory path
            ecosystem: 生态系统 / Ecosystem

        Returns:
            扫描结果 / Scan result
        """
        print_info("开始全面安全审计 / Starting comprehensive security audit")
        return self.scan_directory(directory, ecosystem)

    @staticmethod
    def _detect_ecosystem(package_name: str) -> str:
        """根据包名猜测生态系统 / Guess ecosystem from package name

        Args:
            package_name: 包名 / Package name

        Returns:
            生态系统(npm/pypi) / Ecosystem
        """
        # 包含 @scope/ 格式通常是 npm / @scope/ format is usually npm
        if package_name.startswith("@"):
            return "npm"
        # 包含下划线和连字符混合的短名可能是 npm / Short names with mixed _ and - might be npm
        if "-" in package_name and len(package_name) < 30:
            return "npm"
        # 默认返回 npm / Default to npm
        return "npm"

    @staticmethod
    def _detect_ecosystem_from_file(filepath: str) -> str:
        """根据文件名检测生态系统 / Detect ecosystem from filename

        Args:
            filepath: 文件路径 / File path

        Returns:
            生态系统 / Ecosystem
        """
        filename = os.path.basename(filepath).lower()
        if filename in ("package.json", "package-lock.json", "yarn.lock"):
            return "npm"
        elif filename in ("requirements.txt", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg", "pyproject.toml"):
            return "pypi"
        return "unknown"
