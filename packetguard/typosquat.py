# -*- coding: utf-8 -*-
"""
Typosquatting 检测模块 / Typosquatting Detection Module

基于编辑距离(Levenshtein)算法检测包名拼写劫持。
支持字符替换、删除、插入、相邻字符交换(swapping)等变异。

Detects package name typosquatting based on Levenshtein distance algorithm.
Supports character substitution, deletion, insertion, and adjacent swapping mutations.
"""

import json
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Set, Tuple

from .utils import http_get_json, normalize_package_name, print_info, print_warning


# ============================================================
# Levenshtein 距离计算 / Levenshtein Distance Calculation
# ============================================================

def levenshtein_distance(s1: str, s2: str) -> int:
    """计算两个字符串之间的 Levenshtein 编辑距离 / Calculate Levenshtein edit distance

    使用动态规划算法，时间复杂度 O(m*n)，空间复杂度 O(min(m,n))。
    Uses dynamic programming, O(m*n) time, O(min(m,n)) space.

    Args:
        s1: 第一个字符串 / First string
        s2: 第二个字符串 / Second string

    Returns:
        编辑距离 / Edit distance
    """
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    # 优化空间: 使用较短字符串作为列 / Optimize space: use shorter string as column
    if len(s1) > len(s2):
        s1, s2 = s2, s1

    previous_row = list(range(len(s1) + 1))

    for j, c2 in enumerate(s2):
        current_row = [j + 1]
        for i, c1 in enumerate(s1):
            # 计算三个操作的代价 / Calculate cost of three operations
            insertions = previous_row[i + 1] + 1      # 插入 / Insert
            deletions = current_row[i] + 1             # 删除 / Delete
            substitutions = previous_row[i] + (c1 != c2)  # 替换 / Substitute
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """计算 Damerau-Levenshtein 距离(支持相邻字符交换) /
    Calculate Damerau-Levenshtein distance (supports adjacent transposition)

    在标准 Levenshtein 基础上增加了相邻字符交换(transposition)操作。
    Adds adjacent character transposition to standard Levenshtein.

    Args:
        s1: 第一个字符串 / First string
        s2: 第二个字符串 / Second string

    Returns:
        编辑距离 / Edit distance
    """
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    len1 = len(s1)
    len2 = len(s2)

    # 创建距离矩阵 / Create distance matrix
    d: List[List[int]] = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    # 初始化 / Initialize
    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    # 填充矩阵 / Fill matrix
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # 删除 / Delete
                d[i][j - 1] + 1,       # 插入 / Insert
                d[i - 1][j - 1] + cost  # 替换 / Substitute
            )
            # 相邻字符交换 / Adjacent transposition
            if (i > 1 and j > 1 and
                    s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)

    return d[len1][len2]


# ============================================================
# 变异生成 / Mutation Generation
# ============================================================

def generate_typosquat_variants(name: str) -> List[str]:
    """生成包名的拼写劫持变体 / Generate typosquatting variants of a package name

    生成策略包括:
    - 单字符删除 / Single character deletion
    - 单字符替换(相邻键位) / Single character substitution (adjacent keys)
    - 单字符插入 / Single character insertion
    - 相邻字符交换 / Adjacent character swap
    - 常见前缀/后缀添加 / Common prefix/suffix addition

    Args:
        name: 原始包名 / Original package name

    Returns:
        变体列表 / List of variants
    """
    variants: Set[str] = set()
    name_lower = name.lower()

    if not name_lower:
        return []

    # 键盘相邻键映射 / Keyboard adjacent key mapping
    adjacent_keys: Dict[str, str] = {
        "a": "sqz", "b": "vghn", "c": "xvdf", "d": "sferfc",
        "e": "wrsdf", "f": "dgrtv", "g": "fhtyvb", "h": "gjyubn",
        "i": "ujklo", "j": "hikmn", "k": "jilmn", "l": "komp",
        "m": "njk", "n": "bmhj", "o": "ipkl", "p": "ol",
        "q": "wa", "r": "etdf", "s": "awedxz", "t": "ryfg",
        "u": "yihj", "v": "cfgb", "w": "qase", "x": "zsdca",
        "y": "tuhg", "z": "xas",
        "1": "2q", "2": "13wq", "3": "24we", "4": "35re",
        "5": "46rt", "6": "57ty", "7": "68yu", "8": "79ui",
        "9": "80io", "0": "9-p",
    }

    # 1. 单字符删除 / Single character deletion
    for i in range(len(name_lower)):
        variants.add(name_lower[:i] + name_lower[i + 1:])

    # 2. 单字符替换(使用相邻键) / Single character substitution (adjacent keys)
    for i, char in enumerate(name_lower):
        if char in adjacent_keys:
            for replacement in adjacent_keys[char]:
                variants.add(name_lower[:i] + replacement + name_lower[i + 1:])

    # 3. 相邻字符交换 / Adjacent character swap
    for i in range(len(name_lower) - 1):
        swapped = list(name_lower)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        variants.add("".join(swapped))

    # 4. 常见前缀/后缀添加 / Common prefix/suffix addition
    common_prefixes = ["", "node-", "python-", "py-", "js-"]
    common_suffixes = ["", "-js", "-py", "js", "py", "npm", "lib", "util"]

    for prefix in common_prefixes:
        for suffix in common_suffixes:
            if prefix or suffix:
                variants.add(prefix + name_lower + suffix)

    # 5. 分隔符变体 / Separator variants
    # 将连字符替换为点或下划线 / Replace hyphens with dots or underscores
    for sep_from, sep_to in [("-", "_"), ("-", "."), ("_", "-"), ("_", "."), (".", "-"), (".", "_")]:
        variants.add(name_lower.replace(sep_from, sep_to))

    # 移除原始包名 / Remove original package name
    variants.discard(name_lower)

    return list(variants)


# ============================================================
# 已知包名获取 / Known Package Name Fetching
# ============================================================

def fetch_npm_package_names(query: str) -> Optional[List[str]]:
    """从 npm registry 搜索包名 / Search package names from npm registry

    Args:
        query: 搜索关键词 / Search query

    Returns:
        匹配的包名列表或 None / List of matching package names or None
    """
    url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(query)}&size=20"
    data = http_get_json(url, timeout=10)
    if data and "objects" in data:
        return [obj.get("package", {}).get("name", "") for obj in data["objects"] if obj.get("package")]
    return None


def fetch_pypi_package_names(query: str) -> Optional[List[str]]:
    """从 PyPI 搜索包名 / Search package names from PyPI

    Args:
        query: 搜索关键词 / Search query

    Returns:
        匹配的包名列表或 None / List of matching package names or None
    """
    url = f"https://pypi.org/pypi/{urllib.parse.quote(query)}/json"
    data = http_get_json(url, timeout=10)
    if data and "info" in data:
        return [data["info"].get("name", "")]
    return None


# ============================================================
# Typosquatting 检测器 / Typosquatting Detector
# ============================================================

class TyposquatDetector:
    """Typosquatting 检测器 / Typosquatting Detector

    检测给定包名是否存在拼写劫持风险。
    Detects whether a given package name has typosquatting risks.

    使用方法 / Usage:
        detector = TyposquatDetector()
        results = detector.check("express", ecosystem="npm")
    """

    # 默认的编辑距离阈值 / Default edit distance thresholds
    DISTANCE_THRESHOLDS = {
        "low": 3,       # 低风险阈值 / Low risk threshold
        "medium": 2,    # 中风险阈值 / Medium risk threshold
        "high": 1,      # 高风险阈值 / High risk threshold
    }

    def __init__(self, known_packages: Optional[Set[str]] = None) -> None:
        """初始化检测器 / Initialize detector

        Args:
            known_packages: 已知合法包名集合 / Set of known legitimate package names
        """
        self._known_packages: Set[str] = set()
        if known_packages:
            self._known_packages = {name.lower() for name in known_packages}

    def add_known_packages(self, packages: List[str]) -> None:
        """添加已知合法包名 / Add known legitimate package names

        Args:
            packages: 包名列表 / List of package names
        """
        for pkg in packages:
            self._known_packages.add(pkg.lower())

    def check(
        self,
        package_name: str,
        ecosystem: str = "npm",
        max_distance: int = 2,
    ) -> List[Dict[str, any]]:
        """检查包名是否存在 typosquatting 风险 / Check package for typosquatting risks

        Args:
            package_name: 要检查的包名 / Package name to check
            ecosystem: 生态系统(npm/pypi) / Ecosystem
            max_distance: 最大编辑距离 / Maximum edit distance

        Returns:
            威胁结果列表 / List of threat results
        """
        results: List[Dict[str, any]] = []
        normalized = normalize_package_name(package_name, ecosystem)

        # 生成变体 / Generate variants
        variants = generate_typosquat_variants(normalized)
        print_info(f"生成 {len(variants)} 个拼写变体 / Generated {len(variants)} typo variants")

        # 检查每个变体是否与已知包匹配 / Check each variant against known packages
        checked = 0
        for variant in variants:
            checked += 1
            if variant in self._known_packages:
                distance = levenshtein_distance(normalized, variant)
                dl_distance = damerau_levenshtein_distance(normalized, variant)

                if distance <= max_distance:
                    # 确定严重等级 / Determine severity
                    if distance <= 1:
                        severity = "high"
                    elif distance <= 2:
                        severity = "medium"
                    else:
                        severity = "low"

                    results.append({
                        "type": "typosquatting",
                        "package": package_name,
                        "similar_to": variant,
                        "levenshtein_distance": distance,
                        "damerau_levenshtein_distance": dl_distance,
                        "severity": severity,
                        "description": (
                            f"包名 '{package_name}' 与已知包 '{variant}' 相似 "
                            f"(编辑距离: {distance})"
                        ),
                        "description_en": (
                            f"Package '{package_name}' is similar to known package "
                            f"'{variant}' (edit distance: {distance})"
                        ),
                        "recommendation": (
                            f"请确认是否为正确的包名，可能是 '{variant}' 的拼写劫持"
                        ),
                        "recommendation_en": (
                            f"Verify this is the correct package; may be a typosquat "
                            f"of '{variant}'"
                        ),
                    })

        # 同时检查: 当前包名是否是某个已知包的变体
        # Also check: is current package name a variant of a known package?
        for known_pkg in self._known_packages:
            distance = levenshtein_distance(normalized, known_pkg)
            if 0 < distance <= max_distance and known_pkg != normalized:
                # 检查是否已存在该结果 / Check if result already exists
                already_found = any(
                    r["similar_to"] == known_pkg for r in results
                )
                if not already_found:
                    if distance <= 1:
                        severity = "high"
                    elif distance <= 2:
                        severity = "medium"
                    else:
                        severity = "low"

                    results.append({
                        "type": "typosquatting",
                        "package": package_name,
                        "similar_to": known_pkg,
                        "levenshtein_distance": distance,
                        "damerau_levenshtein_distance": damerau_levenshtein_distance(normalized, known_pkg),
                        "severity": severity,
                        "description": (
                            f"包名 '{package_name}' 与已知包 '{known_pkg}' 相似 "
                            f"(编辑距离: {distance})"
                        ),
                        "description_en": (
                            f"Package '{package_name}' is similar to known package "
                            f"'{known_pkg}' (edit distance: {distance})"
                        ),
                        "recommendation": (
                            f"请确认是否为正确的包名，可能是 '{known_pkg}' 的拼写劫持"
                        ),
                        "recommendation_en": (
                            f"Verify this is the correct package; may be a typosquat "
                            f"of '{known_pkg}'"
                        ),
                    })

        # 按严重程度排序 / Sort by severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        results.sort(key=lambda x: severity_order.get(x["severity"], 3))

        return results
