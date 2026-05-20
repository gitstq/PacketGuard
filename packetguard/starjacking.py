# -*- coding: utf-8 -*-
"""
Starjacking 检测模块 / Starjacking Detection Module

检测包是否虚假声明 GitHub star 数。
通过对比 npm/PyPI 元数据中的 repository 字段与实际 GitHub 仓库，验证 star 数一致性。

Detects packages that falsely claim GitHub star counts.
Compares repository fields in npm/PyPI metadata with actual GitHub repositories
to verify star count consistency.
"""

import json
import re
import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Dict, Optional, Tuple

from .utils import http_get_json, print_info, print_warning


# ============================================================
# GitHub 仓库信息获取 / GitHub Repository Info Fetching
# ============================================================

def parse_github_repo_url(repo_url: str) -> Optional[Tuple[str, str]]:
    """从 URL 中提取 GitHub 仓库的 owner 和 repo 名称 /
    Extract GitHub repo owner and name from URL

    支持的格式 / Supported formats:
    - https://github.com/owner/repo
    - git://github.com/owner/repo.git
    - git+https://github.com/owner/repo.git
    - owner/repo (简写格式 / shorthand)

    Args:
        repo_url: 仓库 URL / Repository URL

    Returns:
        (owner, repo) 元组或 None / (owner, repo) tuple or None
    """
    if not repo_url:
        return None

    # 移除 .git 后缀 / Remove .git suffix
    url = re.sub(r"\.git$", "", repo_url.strip())

    # 尝试匹配 GitHub URL 格式 / Try matching GitHub URL format
    patterns = [
        r"https?://github\.com/([^/]+)/([^/#?]+)",
        r"git://github\.com/([^/]+)/([^/#?]+)",
        r"git\+https?://github\.com/([^/]+)/([^/#?]+)",
        r"ssh://git@github\.com/([^/]+)/([^/#?]+)",
        r"git@github\.com:([^/]+)/([^/#?]+)",
    ]

    for pattern in patterns:
        match = re.match(pattern, url)
        if match:
            return (match.group(1), match.group(2))

    # 尝试 owner/repo 简写格式 / Try owner/repo shorthand
    if "/" in url and len(url.split("/")) == 2:
        parts = url.split("/")
        if parts[0] and parts[1]:
            return (parts[0], parts[1])

    return None


def fetch_github_repo_stars(owner: str, repo: str, timeout: int = 10) -> Optional[int]:
    """获取 GitHub 仓库的实际 star 数 / Fetch actual GitHub repo star count

    使用 GitHub API (不需要认证的公开端点)。
    Uses GitHub API (public endpoint, no auth required).

    Args:
        owner: 仓库所有者 / Repository owner
        repo: 仓库名称 / Repository name
        timeout: 超时时间(秒) / Timeout in seconds

    Returns:
        star 数或 None / Star count or None
    """
    url = f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "PacketGuard/1.0 (Supply Chain Security Scanner)",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
            return data.get("stargazers_count")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as e:
        print_warning(f"GitHub API 请求失败 / GitHub API request failed: {owner}/{repo} - {e}")
        return None


# ============================================================
# npm/PyPI 元数据获取 / npm/PyPI Metadata Fetching
# ============================================================

def fetch_npm_metadata(package_name: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """获取 npm 包的元数据 / Fetch npm package metadata

    Args:
        package_name: 包名 / Package name
        timeout: 超时时间(秒) / Timeout in seconds

    Returns:
        元数据字典或 None / Metadata dict or None
    """
    url = f"https://registry.npmjs.org/{urllib.parse.quote(package_name)}"
    return http_get_json(url, timeout=timeout)


def fetch_pypi_metadata(package_name: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """获取 PyPI 包的元数据 / Fetch PyPI package metadata

    Args:
        package_name: 包名 / Package name
        timeout: 超时时间(秒) / Timeout in seconds

    Returns:
        元数据字典或 None / Metadata dict or None
    """
    url = f"https://pypi.org/pypi/{urllib.parse.quote(package_name)}/json"
    return http_get_json(url, timeout=timeout)


# ============================================================
# Starjacking 检测器 / Starjacking Detector
# ============================================================

class StarjackDetector:
    """Starjacking 检测器 / Starjacking Detector

    检测包是否虚假声明 GitHub star 数。
    Detects packages that falsely claim GitHub star counts.

    使用方法 / Usage:
        detector = StarjackDetector()
        results = detector.check("some-package", ecosystem="npm")
    """

    def __init__(self) -> None:
        """初始化检测器 / Initialize detector"""
        pass

    def _extract_repo_url_from_npm(self, metadata: Dict[str, Any]) -> Optional[str]:
        """从 npm 元数据中提取仓库 URL / Extract repo URL from npm metadata

        Args:
            metadata: npm 包元数据 / npm package metadata

        Returns:
            仓库 URL 或 None / Repository URL or None
        """
        # 检查最新版本的 repository 字段 / Check latest version's repository field
        latest = metadata.get("dist-tags", {}).get("latest", "")
        if latest and latest in metadata.get("versions", {}):
            version_data = metadata["versions"][latest]
            repo = version_data.get("repository", {})
            if isinstance(repo, dict):
                return repo.get("url", "")
            elif isinstance(repo, str):
                return repo

        # 检查顶层的 repository 字段 / Check top-level repository field
        repo = metadata.get("repository", {})
        if isinstance(repo, dict):
            return repo.get("url", "")
        elif isinstance(repo, str):
            return repo

        return None

    def _extract_repo_url_from_pypi(self, metadata: Dict[str, Any]) -> Optional[str]:
        """从 PyPI 元数据中提取仓库 URL / Extract repo URL from PyPI metadata

        Args:
            metadata: PyPI 包元数据 / PyPI package metadata

        Returns:
            仓库 URL 或 None / Repository URL or None
        """
        info = metadata.get("info", {})

        # 检查 project_urls / Check project_urls
        project_urls = info.get("project_urls", {}) or {}
        for key, url in project_urls.items():
            if url and "github.com" in str(url):
                return str(url)

        # 检查 home_page / Check home_page
        home_page = info.get("home_page", "")
        if home_page and "github.com" in str(home_page):
            return str(home_page)

        return None

    def _extract_claimed_stars(self, metadata: Dict[str, Any], ecosystem: str) -> Optional[int]:
        """从包元数据中提取声称的 star 数 / Extract claimed star count from package metadata

        Args:
            metadata: 包元数据 / Package metadata
            ecosystem: 生态系统 / Ecosystem

        Returns:
            声称的 star 数或 None / Claimed star count or None
        """
        if ecosystem == "npm":
            # npm 包可能在 description 或 readme 中声称 star 数
            # npm packages may claim stars in description or readme
            readme = metadata.get("readme", "") or ""
            description = metadata.get("description", "") or ""

            # 搜索 "X stars" 或 "X ★" 模式 / Search for "X stars" or "X ★" patterns
            for text in [description, readme[:2000]]:  # 只检查 readme 前 2000 字符
                patterns = [
                    r"(\d[\d,]*)\s*(?:★|stars|star|⭐)",
                    r"(?:★|⭐)\s*(\d[\d,]*)",
                ]
                for pattern in patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        try:
                            return int(match.group(1).replace(",", ""))
                        except ValueError:
                            continue

        elif ecosystem == "pypi":
            info = metadata.get("info", {})
            description = info.get("description", "") or ""
            summary = info.get("summary", "") or ""

            for text in [summary, description[:2000]]:
                patterns = [
                    r"(\d[\d,]*)\s*(?:★|stars|star|⭐)",
                    r"(?:★|⭐)\s*(\d[\d,]*)",
                ]
                for pattern in patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        try:
                            return int(match.group(1).replace(",", ""))
                        except ValueError:
                            continue

        return None

    def check(
        self,
        package_name: str,
        ecosystem: str = "npm",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """检查包是否存在 starjacking 风险 / Check package for starjacking risks

        Args:
            package_name: 包名 / Package name
            ecosystem: 生态系统(npm/pypi) / Ecosystem
            timeout: 超时时间(秒) / Timeout in seconds

        Returns:
            检测结果字典 / Detection result dict
        """
        result: Dict[str, Any] = {
            "type": "starjacking",
            "package": package_name,
            "ecosystem": ecosystem,
            "has_risk": False,
            "severity": "low",
            "description": "",
            "description_en": "",
            "recommendation": "",
            "recommendation_en": "",
            "details": {},
        }

        print_info(f"正在检查 Starjacking: {package_name} ({ecosystem})")

        # 获取包元数据 / Fetch package metadata
        if ecosystem == "npm":
            metadata = fetch_npm_metadata(package_name, timeout=timeout)
            if not metadata:
                result["description"] = f"无法获取 npm 包 '{package_name}' 的元数据"
                result["description_en"] = f"Failed to fetch npm metadata for '{package_name}'"
                return result
            repo_url = self._extract_repo_url_from_npm(metadata)
        elif ecosystem == "pypi":
            metadata = fetch_pypi_metadata(package_name, timeout=timeout)
            if not metadata:
                result["description"] = f"无法获取 PyPI 包 '{package_name}' 的元数据"
                result["description_en"] = f"Failed to fetch PyPI metadata for '{package_name}'"
                return result
            repo_url = self._extract_repo_url_from_pypi(metadata)
        else:
            result["description"] = f"不支持的生态系统: {ecosystem}"
            result["description_en"] = f"Unsupported ecosystem: {ecosystem}"
            return result

        result["details"]["repo_url"] = repo_url

        if not repo_url:
            result["description"] = "未找到 GitHub 仓库 URL，无法进行 Starjacking 检测"
            result["description_en"] = "No GitHub repository URL found, cannot check for starjacking"
            return result

        # 解析 GitHub 仓库信息 / Parse GitHub repo info
        github_info = parse_github_repo_url(repo_url)
        if not github_info:
            result["description"] = f"无法解析 GitHub 仓库 URL: {repo_url}"
            result["description_en"] = f"Cannot parse GitHub repo URL: {repo_url}"
            return result

        owner, repo = github_info
        result["details"]["github_owner"] = owner
        result["details"]["github_repo"] = repo

        # 获取实际 star 数 / Fetch actual star count
        actual_stars = fetch_github_repo_stars(owner, repo, timeout=timeout)
        result["details"]["actual_stars"] = actual_stars

        if actual_stars is None:
            result["description"] = f"无法获取 GitHub 仓库 {owner}/{repo} 的 star 数"
            result["description_en"] = f"Failed to fetch star count for GitHub repo {owner}/{repo}"
            return result

        # 提取声称的 star 数 / Extract claimed star count
        claimed_stars = self._extract_claimed_stars(metadata, ecosystem)
        result["details"]["claimed_stars"] = claimed_stars

        if claimed_stars is None:
            result["description"] = (
                f"GitHub 仓库 {owner}/{repo} 有 {actual_stars} 个 star，"
                f"包元数据中未发现 star 数声明"
            )
            result["description_en"] = (
                f"GitHub repo {owner}/{repo} has {actual_stars} stars, "
                f"no star count claim found in package metadata"
            )
            return result

        # 比较 star 数 / Compare star counts
        result["details"]["star_discrepancy"] = claimed_stars - actual_stars

        if claimed_stars > actual_stars:
            discrepancy = claimed_stars - actual_stars
            # 如果声称的 star 数比实际多超过 50%，认为是 starjacking
            # If claimed stars exceed actual by more than 50%, flag as starjacking
            if actual_stars > 0 and discrepancy / actual_stars > 0.5:
                result["has_risk"] = True
                result["severity"] = "high" if discrepancy / actual_stars > 2.0 else "medium"
                result["description"] = (
                    f"Starjacking 检测: 包声称 {claimed_stars} 个 star，"
                    f"但 GitHub 仓库实际只有 {actual_stars} 个 "
                    f"(差异: +{discrepancy})"
                )
                result["description_en"] = (
                    f"Starjacking detected: Package claims {claimed_stars} stars, "
                    f"but GitHub repo actually has {actual_stars} "
                    f"(discrepancy: +{discrepancy})"
                )
                result["recommendation"] = (
                    f"该包可能存在 Starjacking 行为，实际 star 数远低于声称值"
                )
                result["recommendation_en"] = (
                    f"This package may be starjacking; actual star count is "
                    f"significantly lower than claimed"
                )
            elif actual_stars == 0 and claimed_stars > 0:
                result["has_risk"] = True
                result["severity"] = "critical"
                result["description"] = (
                    f"Starjacking 检测: 包声称 {claimed_stars} 个 star，"
                    f"但 GitHub 仓库实际 star 数为 0"
                )
                result["description_en"] = (
                    f"Starjacking detected: Package claims {claimed_stars} stars, "
                    f"but GitHub repo actually has 0 stars"
                )
                result["recommendation"] = (
                    f"该包存在严重的 Starjacking 行为，GitHub 仓库没有任何 star"
                )
                result["recommendation_en"] = (
                    f"This package has severe starjacking; the GitHub repo has zero stars"
                )
            else:
                result["description"] = (
                    f"Star 数轻微差异: 声称 {claimed_stars}，实际 {actual_stars}"
                )
                result["description_en"] = (
                    f"Minor star count discrepancy: claimed {claimed_stars}, actual {actual_stars}"
                )
        else:
            result["description"] = (
                f"Star 数一致: 声称 {claimed_stars}，实际 {actual_stars}"
            )
            result["description_en"] = (
                f"Star count consistent: claimed {claimed_stars}, actual {actual_stars}"
            )

        return result
