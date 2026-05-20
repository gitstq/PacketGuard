# -*- coding: utf-8 -*-
"""
配置管理模块 / Configuration Management Module

管理 PacketGuard 的运行时配置，包括:
- 从 .packetguard.yaml 加载配置
- 检测规则开关
- 白名单/黑名单管理
- 默认配置值

Manages PacketGuard runtime configuration including:
- Loading from .packetguard.yaml
- Detection rule toggles
- Whitelist/blacklist management
- Default configuration values
"""

import os
from typing import Any, Dict, List, Optional, Set

from .utils import parse_yaml, print_warning


# ============================================================
# 默认配置 / Default Configuration
# ============================================================

DEFAULT_CONFIG: Dict[str, Any] = {
    "general": {
        "ecosystem": "auto",           # 默认生态系统: auto/npm/pypi / Default ecosystem
        "output_format": "text",       # 输出格式: text/json/sarif/markdown/html / Output format
        "min_severity": "low",         # 最低报告等级 / Minimum severity to report
        "timeout": 10,                 # HTTP 请求超时(秒) / HTTP timeout in seconds
        "verbose": False,              # 详细输出 / Verbose output
    },
    "rules": {
        "typosquat": True,             # 启用 Typosquatting 检测 / Enable typosquatting detection
        "starjacking": True,           # 启用 Starjacking 检测 / Enable starjacking detection
        "malware": True,               # 启用恶意包特征扫描 / Enable malware scanning
        "dependency": True,            # 启用依赖分析 / Enable dependency analysis
        "intelligence": True,          # 启用威胁情报检查 / Enable threat intelligence
    },
    "whitelist": [],                   # 白名单包名 / Whitelisted package names
    "blacklist": [],                   # 黑名单包名/模式 / Blacklisted package names/patterns
    "malware_scan": {
        "check_network": True,         # 检测网络请求 / Check network requests
        "check_filesystem": True,      # 检测文件系统操作 / Check filesystem operations
        "check_execution": True,       # 检测命令执行 / Check command execution
        "check_obfuscation": True,     # 检测代码混淆 / Check code obfuscation
        "check_domains": True,         # 检测可疑域名 / Check suspicious domains
    },
}


class Config:
    """PacketGuard 配置管理器 / PacketGuard Configuration Manager

    加载和管理用户配置，合并默认配置和用户自定义配置。
    Loads and manages user configuration, merging defaults with custom settings.

    使用方法 / Usage:
        config = Config()
        config.load_from_file(".packetguard.yaml")
        if config.is_rule_enabled("typosquat"):
            ...
    """

    def __init__(self) -> None:
        """初始化配置 / Initialize configuration"""
        self._config: Dict[str, Any] = {}
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._loaded = False

    @property
    def loaded(self) -> bool:
        """配置是否已加载 / Whether configuration has been loaded"""
        return self._loaded

    def load_from_file(self, filepath: str) -> bool:
        """从 YAML 文件加载配置 / Load configuration from YAML file

        Args:
            filepath: 配置文件路径 / Configuration file path

        Returns:
            是否加载成功 / Whether loading was successful
        """
        if not os.path.isfile(filepath):
            print_warning(f"配置文件不存在 / Config file not found: {filepath}")
            return False

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            user_config = parse_yaml(content)
            self._merge_config(user_config)
            self._loaded = True
            return True
        except (OSError, ValueError) as e:
            print_warning(f"配置文件加载失败 / Config file load failed: {filepath} - {e}")
            return False

    def load_from_dict(self, config_dict: Dict[str, Any]) -> None:
        """从字典加载配置 / Load configuration from dictionary

        Args:
            config_dict: 配置字典 / Configuration dictionary
        """
        self._merge_config(config_dict)
        self._loaded = True

    def _merge_config(self, user_config: Dict[str, Any]) -> None:
        """合并用户配置到默认配置 / Merge user config into default config

        Args:
            user_config: 用户配置字典 / User configuration dictionary
        """
        # 深度合并 / Deep merge
        self._config = self._deep_merge(DEFAULT_CONFIG.copy(), user_config)

        # 处理白名单 / Process whitelist
        wl = self._config.get("whitelist", [])
        if isinstance(wl, list):
            self._whitelist = set(str(item).lower() for item in wl)

        # 处理黑名单 / Process blacklist
        bl = self._config.get("blacklist", [])
        if isinstance(bl, list):
            self._blacklist = set(str(item).lower() for item in bl)

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """深度合并两个字典 / Deep merge two dictionaries

        Args:
            base: 基础字典 / Base dictionary
            override: 覆盖字典 / Override dictionary

        Returns:
            合并后的字典 / Merged dictionary
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值 / Get configuration value

        支持点号分隔的嵌套键 / Supports dot-separated nested keys

        Args:
            key: 配置键(支持嵌套，如 "general.ecosystem") / Config key (supports nesting)
            default: 默认值 / Default value

        Returns:
            配置值 / Configuration value
        """
        if not self._config:
            self._config = DEFAULT_CONFIG.copy()

        keys = key.split(".")
        value: Any = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        """设置配置值 / Set configuration value

        Args:
            key: 配置键 / Config key
            value: 配置值 / Config value
        """
        if not self._config:
            self._config = DEFAULT_CONFIG.copy()

        keys = key.split(".")
        config = self._config
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value

    # ============================================================
    # 规则管理 / Rule Management
    # ============================================================

    def is_rule_enabled(self, rule_name: str) -> bool:
        """检查检测规则是否启用 / Check if a detection rule is enabled

        Args:
            rule_name: 规则名称 / Rule name

        Returns:
            是否启用 / Whether enabled
        """
        return bool(self.get(f"rules.{rule_name}", True))

    def enable_rule(self, rule_name: str) -> None:
        """启用检测规则 / Enable detection rule

        Args:
            rule_name: 规则名称 / Rule name
        """
        self.set(f"rules.{rule_name}", True)

    def disable_rule(self, rule_name: str) -> None:
        """禁用检测规则 / Disable detection rule

        Args:
            rule_name: 规则名称 / Rule name
        """
        self.set(f"rules.{rule_name}", False)

    # ============================================================
    # 白名单/黑名单 / Whitelist/Blacklist
    # ============================================================

    def is_whitelisted(self, package_name: str) -> bool:
        """检查包是否在白名单中 / Check if package is whitelisted

        Args:
            package_name: 包名 / Package name

        Returns:
            是否在白名单中 / Whether whitelisted
        """
        return package_name.lower() in self._whitelist

    def is_blacklisted(self, package_name: str) -> bool:
        """检查包是否在黑名单中 / Check if package is blacklisted

        Args:
            package_name: 包名 / Package name

        Returns:
            是否在黑名单中 / Whether blacklisted
        """
        return package_name.lower() in self._blacklist

    def add_to_whitelist(self, package_name: str) -> None:
        """添加包到白名单 / Add package to whitelist

        Args:
            package_name: 包名 / Package name
        """
        self._whitelist.add(package_name.lower())

    def add_to_blacklist(self, package_name: str) -> None:
        """添加包到黑名单 / Add package to blacklist

        Args:
            package_name: 包名 / Package name
        """
        self._blacklist.add(package_name.lower())

    @property
    def whitelist(self) -> Set[str]:
        """获取白名单 / Get whitelist"""
        return self._whitelist.copy()

    @property
    def blacklist(self) -> Set[str]:
        """获取黑名单 / Get blacklist"""
        return self._blacklist.copy()

    # ============================================================
    # 便捷属性 / Convenience Properties
    # ============================================================

    @property
    def ecosystem(self) -> str:
        """默认生态系统 / Default ecosystem"""
        return str(self.get("general.ecosystem", "auto"))

    @ecosystem.setter
    def ecosystem(self, value: str) -> None:
        self.set("general.ecosystem", value)

    @property
    def output_format(self) -> str:
        """输出格式 / Output format"""
        return str(self.get("general.output_format", "text"))

    @output_format.setter
    def output_format(self, value: str) -> None:
        self.set("general.output_format", value)

    @property
    def min_severity(self) -> str:
        """最低报告等级 / Minimum severity to report"""
        return str(self.get("general.min_severity", "low"))

    @min_severity.setter
    def min_severity(self, value: str) -> None:
        self.set("general.min_severity", value)

    @property
    def timeout(self) -> int:
        """HTTP 请求超时 / HTTP request timeout"""
        return int(self.get("general.timeout", 10))

    @timeout.setter
    def timeout(self, value: int) -> None:
        self.set("general.timeout", value)

    @property
    def verbose(self) -> bool:
        """详细输出模式 / Verbose output mode"""
        return bool(self.get("general.verbose", False))

    @verbose.setter
    def verbose(self, value: bool) -> None:
        self.set("general.verbose", value)

    def to_dict(self) -> Dict[str, Any]:
        """导出配置为字典 / Export configuration as dictionary

        Returns:
            配置字典 / Configuration dictionary
        """
        if not self._config:
            return DEFAULT_CONFIG.copy()
        return self._config.copy()

    def __repr__(self) -> str:
        return f"Config(ecosystem={self.ecosystem}, format={self.output_format})"
