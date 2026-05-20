# -*- coding: utf-8 -*-
"""
工具函数模块 / Utility Functions Module

提供项目中通用的工具函数，包括:
- ANSI 终端颜色控制
- 简单的 YAML 解析器
- HTTP 请求封装
- 文件哈希计算
- 进度条显示
- 通用辅助函数

Utility functions including:
- ANSI terminal color control
- Simple YAML parser
- HTTP request wrapper
- File hash calculation
- Progress bar display
- General helper functions
"""

import hashlib
import json
import os
import re
import sys
import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# ANSI 终端颜色 / ANSI Terminal Colors
# ============================================================

class Colors:
    """ANSI 终端颜色代码 / ANSI terminal color codes"""

    # 重置 / Reset
    RESET = "\033[0m"

    # 前景色 / Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # 亮色 / Bright foreground colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # 背景色 / Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    # 样式 / Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    @classmethod
    def disable(cls) -> None:
        """禁用颜色输出(用于不支持ANSI的终端) / Disable color output"""
        for attr in dir(cls):
            if attr.isupper():
                setattr(cls, attr, "")

    @classmethod
    def colored(cls, text: str, color: str) -> str:
        """为文本添加颜色 / Add color to text

        Args:
            text: 要着色的文本 / Text to color
            color: 颜色代码 / Color code

        Returns:
            着色后的文本 / Colored text
        """
        return f"{color}{text}{cls.RESET}"


def color_text(text: str, color: str) -> str:
    """为文本添加颜色的便捷函数 / Convenience function to color text

    Args:
        text: 要着色的文本 / Text to color
        color: 颜色代码(如 Colors.RED) / Color code (e.g., Colors.RED)

    Returns:
        着色后的文本 / Colored text
    """
    return Colors.colored(text, color)


def print_error(msg: str) -> None:
    """打印错误信息 / Print error message"""
    print(color_text(f"[ERROR] {msg}", Colors.BRIGHT_RED), file=sys.stderr)


def print_warning(msg: str) -> None:
    """打印警告信息 / Print warning message"""
    print(color_text(f"[WARNING] {msg}", Colors.BRIGHT_YELLOW), file=sys.stderr)


def print_success(msg: str) -> None:
    """打印成功信息 / Print success message"""
    print(color_text(f"[OK] {msg}", Colors.BRIGHT_GREEN))


def print_info(msg: str) -> None:
    """打印信息 / Print info message"""
    print(color_text(f"[INFO] {msg}", Colors.BRIGHT_CYAN))


# ============================================================
# 简单 YAML 解析器 / Simple YAML Parser
# ============================================================

def parse_yaml(content: str) -> Dict[str, Any]:
    """解析简单的 YAML 配置文件 / Parse simple YAML configuration file

    支持的格式 / Supported formats:
    - 键值对(缩进表示层级) / Key-value pairs (indentation for hierarchy)
    - 列表(使用 - 前缀) / Lists (using - prefix)
    - 字符串、数字、布尔值 / Strings, numbers, booleans
    - 注释(# 开头) / Comments (starting with #)

    Args:
        content: YAML 文件内容 / YAML file content

    Returns:
        解析后的字典 / Parsed dictionary
    """
    result: Dict[str, Any] = {}
    current_dict = result
    stack: List[Tuple[Dict[str, Any], str]] = []
    last_key: Optional[str] = None

    for line in content.split("\n"):
        # 去除行尾注释 / Strip trailing comments
        stripped = line.split("#")[0].rstrip()
        if not stripped:
            continue

        # 计算缩进级别 / Calculate indentation level
        indent = len(stripped) - len(stripped.lstrip())
        content_part = stripped.lstrip()

        # 跳过注释行 / Skip comment lines
        if content_part.startswith("#"):
            continue

        # 处理列表项 / Handle list items
        if content_part.startswith("- "):
            list_value = content_part[2:].strip()
            parsed_value = _parse_value(list_value)
            if last_key and last_key in current_dict:
                if isinstance(current_dict[last_key], list):
                    current_dict[last_key].append(parsed_value)
                else:
                    current_dict[last_key] = [current_dict[last_key], parsed_value]
            continue

        # 处理键值对 / Handle key-value pairs
        if ":" in content_part:
            key_part, _, value_part = content_part.partition(":")
            key = key_part.strip()
            value = value_part.strip()

            # 调整层级 / Adjust hierarchy level
            while stack and stack[-1][1] >= indent:
                _, _ = stack.pop()
                if stack:
                    current_dict = stack[-1][0]

            if value:
                # 有值的键值对 / Key-value pair with value
                current_dict[key] = _parse_value(value)
                last_key = key
            else:
                # 嵌套字典开始 / Start of nested dict
                current_dict[key] = {}
                stack.append((current_dict, indent))
                current_dict = current_dict[key]
                last_key = key

    return result


def _parse_value(value: str) -> Any:
    """解析 YAML 值 / Parse YAML value

    Args:
        value: 字符串值 / String value

    Returns:
        解析后的值(可能是 str, int, float, bool, list) /
        Parsed value (could be str, int, float, bool, list)
    """
    value = value.strip()

    # 布尔值 / Boolean values
    if value.lower() in ("true", "yes", "on"):
        return True
    if value.lower() in ("false", "no", "off"):
        return False

    # 数字 / Numbers
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass

    # 列表(方括号格式) / Lists (bracket format)
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if inner:
            return [_parse_value(item.strip()) for item in inner.split(",")]
        return []

    # 去除引号 / Strip quotes
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return value[1:-1]

    return value


# ============================================================
# HTTP 请求封装 / HTTP Request Wrapper
# ============================================================

def http_get(url: str, timeout: int = 10, headers: Optional[Dict[str, str]] = None) -> Optional[str]:
    """发送 HTTP GET 请求 / Send HTTP GET request

    Args:
        url: 请求的 URL / Request URL
        timeout: 超时时间(秒) / Timeout in seconds
        headers: 自定义请求头 / Custom headers

    Returns:
        响应文本或 None / Response text or None
    """
    default_headers = {
        "User-Agent": "PacketGuard/1.0 (Supply Chain Security Scanner)",
        "Accept": "application/json",
    }
    if headers:
        default_headers.update(headers)

    req = urllib.request.Request(url, headers=default_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        print_warning(f"HTTP 请求失败 / HTTP request failed: {url} - {e}")
        return None


def http_get_json(url: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """发送 HTTP GET 请求并解析 JSON 响应 / Send HTTP GET request and parse JSON response

    Args:
        url: 请求的 URL / Request URL
        timeout: 超时时间(秒) / Timeout in seconds

    Returns:
        解析后的 JSON 字典或 None / Parsed JSON dict or None
    """
    text = http_get(url, timeout=timeout)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError) as e:
        print_warning(f"JSON 解析失败 / JSON parse failed: {e}")
        return None


# ============================================================
# 文件哈希 / File Hash
# ============================================================

def calculate_file_hash(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """计算文件的哈希值 / Calculate file hash

    Args:
        filepath: 文件路径 / File path
        algorithm: 哈希算法(sha256, sha1, md5) / Hash algorithm

    Returns:
        哈希值的十六进制字符串或 None / Hex string of hash or None
    """
    if not os.path.isfile(filepath):
        return None

    try:
        hasher = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, ValueError) as e:
        print_warning(f"文件哈希计算失败 / File hash calculation failed: {filepath} - {e}")
        return None


def calculate_string_hash(text: str, algorithm: str = "sha256") -> str:
    """计算字符串的哈希值 / Calculate string hash

    Args:
        text: 输入字符串 / Input string
        algorithm: 哈希算法 / Hash algorithm

    Returns:
        哈希值的十六进制字符串 / Hex string of hash
    """
    hasher = hashlib.new(algorithm)
    hasher.update(text.encode("utf-8"))
    return hasher.hexdigest()


# ============================================================
# 进度条 / Progress Bar
# ============================================================

class ProgressBar:
    """简单的文本进度条 / Simple text progress bar

    使用方法 / Usage:
        bar = ProgressBar(total=100, prefix="扫描中")
        for i in range(100):
            bar.update(i + 1)
        bar.finish()
    """

    def __init__(self, total: int = 100, prefix: str = "", width: int = 40) -> None:
        """初始化进度条 / Initialize progress bar

        Args:
            total: 总数 / Total count
            prefix: 前缀文本 / Prefix text
            width: 进度条宽度(字符数) / Progress bar width in characters
        """
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0

    def update(self, current: int) -> None:
        """更新进度条 / Update progress bar

        Args:
            current: 当前进度 / Current progress
        """
        self.current = current
        if self.total == 0:
            percent = 100.0
        else:
            percent = (current / self.total) * 100

        filled = int(self.width * current / self.total) if self.total > 0 else self.width
        bar = "█" * filled + "░" * (self.width - filled)

        sys.stdout.write(
            f"\r{self.prefix} |{color_text(bar, Colors.BRIGHT_CYAN)}| "
            f"{percent:5.1f}% ({current}/{self.total})"
        )
        sys.stdout.flush()

    def finish(self) -> None:
        """完成进度条 / Finish progress bar"""
        self.update(self.total)
        print()


# ============================================================
# 通用辅助函数 / General Helper Functions
# ============================================================

def normalize_package_name(name: str, ecosystem: str) -> str:
    """规范化包名 / Normalize package name

    Args:
        name: 原始包名 / Original package name
        ecosystem: 生态系统(npm/pypi) / Ecosystem

    Returns:
        规范化后的包名 / Normalized package name
    """
    if ecosystem == "npm":
        # npm 包名不区分大小写，使用小写 / npm names are case-insensitive
        return name.lower().strip()
    elif ecosystem == "pypi":
        # PyPI 包名规范化: 小写, 连字符/点/下划线统一为连字符
        # PyPI normalization: lowercase, hyphens/dots/underscores to hyphens
        return re.sub(r"[-_.]+", "-", name).lower().strip()
    return name.lower().strip()


def load_json_file(filepath: str) -> Optional[Dict[str, Any]]:
    """加载 JSON 文件 / Load JSON file

    Args:
        filepath: 文件路径 / File path

    Returns:
        解析后的字典或 None / Parsed dict or None
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print_warning(f"JSON 文件加载失败 / JSON file load failed: {filepath} - {e}")
        return None


def severity_to_color(severity: str) -> str:
    """将严重等级映射为颜色 / Map severity level to color

    Args:
        severity: 严重等级(low/medium/high/critical) / Severity level

    Returns:
        ANSI 颜色代码 / ANSI color code
    """
    mapping = {
        "low": Colors.BRIGHT_BLUE,
        "medium": Colors.BRIGHT_YELLOW,
        "high": Colors.BRIGHT_RED,
        "critical": Colors.BG_RED + Colors.WHITE,
    }
    return mapping.get(severity.lower(), Colors.WHITE)


def severity_to_int(severity: str) -> int:
    """将严重等级映射为数值 / Map severity level to integer

    Args:
        severity: 严重等级 / Severity level

    Returns:
        数值(0-3) / Integer (0-3)
    """
    mapping = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }
    return mapping.get(severity.lower(), 0)


def is_semver(version: str) -> bool:
    """检查是否为语义化版本号 / Check if string is a semantic version

    Args:
        version: 版本字符串 / Version string

    Returns:
        是否为有效语义版本 / Whether valid semver
    """
    pattern = r"^\d+\.\d+\.\d+([a-zA-Z0-9.+-]*)?$"
    return bool(re.match(pattern, version.strip()))


def parse_version(version: str) -> Tuple[int, ...]:
    """解析版本号为可比较的元组 / Parse version into comparable tuple

    Args:
        version: 版本字符串 / Version string

    Returns:
        版本号元组 / Version tuple
    """
    # 提取数字部分 / Extract numeric parts
    numbers = re.findall(r"\d+", version)
    return tuple(int(n) for n in numbers) if numbers else (0,)
