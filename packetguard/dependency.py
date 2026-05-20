# -*- coding: utf-8 -*-
"""
依赖分析模块 / Dependency Analysis Module

解析和项目依赖文件，构建依赖树，检测循环依赖。
Supports package.json, requirements.txt, Pipfile, Pipfile.lock.

Parses project dependency files, builds dependency trees, detects circular dependencies.
Supports package.json, requirements.txt, Pipfile, Pipfile.lock.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .utils import load_json_file, normalize_package_name, print_info, print_warning


# ============================================================
# 依赖项数据结构 / Dependency Data Structure
# ============================================================

class DependencyNode:
    """依赖树节点 / Dependency tree node

    表示一个依赖包及其元信息。
    Represents a dependency package and its metadata.
    """

    def __init__(
        self,
        name: str,
        version: str = "",
        source: str = "",
        is_dev: bool = False,
    ) -> None:
        """初始化依赖节点 / Initialize dependency node

        Args:
            name: 包名 / Package name
            version: 版本约束 / Version constraint
            source: 来源文件 / Source file
            is_dev: 是否为开发依赖 / Whether dev dependency
        """
        self.name = name
        self.version = version
        self.source = source
        self.is_dev = is_dev
        self.children: List["DependencyNode"] = []
        self.depth: int = 0

    def add_child(self, child: "DependencyNode") -> None:
        """添加子依赖 / Add child dependency

        Args:
            child: 子依赖节点 / Child dependency node
        """
        child.depth = self.depth + 1
        self.children.append(child)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典 / Convert to dictionary

        Returns:
            字典表示 / Dictionary representation
        """
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "is_dev": self.is_dev,
            "depth": self.depth,
            "children": [child.to_dict() for child in self.children],
        }

    def __repr__(self) -> str:
        return f"DependencyNode(name={self.name}, version={self.version})"


# ============================================================
# 依赖文件解析器 / Dependency File Parsers
# ============================================================

def parse_package_json(filepath: str) -> Tuple[List[DependencyNode], List[DependencyNode]]:
    """解析 package.json 文件 / Parse package.json file

    Args:
        filepath: package.json 文件路径 / package.json file path

    Returns:
        (生产依赖列表, 开发依赖列表) / (production deps, dev deps)
    """
    prod_deps: List[DependencyNode] = []
    dev_deps: List[DependencyNode] = []

    data = load_json_file(filepath)
    if not data:
        return prod_deps, dev_deps

    # 解析生产依赖 / Parse production dependencies
    for section in ["dependencies", "peerDependencies", "optionalDependencies"]:
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name, version in deps.items():
                prod_deps.append(DependencyNode(
                    name=name,
                    version=str(version),
                    source=filepath,
                    is_dev=False,
                ))

    # 解析开发依赖 / Parse dev dependencies
    dev_section = data.get("devDependencies", {})
    if isinstance(dev_section, dict):
        for name, version in dev_section.items():
            dev_deps.append(DependencyNode(
                name=name,
                version=str(version),
                source=filepath,
                is_dev=True,
            ))

    return prod_deps, dev_deps


def parse_requirements_txt(filepath: str) -> List[DependencyNode]:
    """解析 requirements.txt 文件 / Parse requirements.txt file

    支持的格式 / Supported formats:
    - package==version
    - package>=version
    - package~=version
    - package  (无版本约束 / no version constraint)
    - -r other_file.txt  (引用其他文件 / reference other file)
    - # 注释 / comments

    Args:
        filepath: requirements.txt 文件路径 / requirements.txt file path

    Returns:
        依赖列表 / List of dependencies
    """
    deps: List[DependencyNode] = []

    if not os.path.isfile(filepath):
        return deps

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        print_warning(f"无法读取文件 / Cannot read file: {filepath} - {e}")
        return deps

    for line in lines:
        line = line.strip()

        # 跳过空行和注释 / Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # 处理文件引用 / Handle file references
        if line.startswith("-r ") or line.startswith("--requirement "):
            ref_file = line.split(None, 1)[-1].strip()
            ref_path = os.path.join(os.path.dirname(filepath), ref_file)
            if os.path.isfile(ref_path):
                deps.extend(parse_requirements_txt(ref_path))
            continue

        # 处理选项行 / Handle option lines
        if line.startswith("-"):
            continue

        # 解析包名和版本 / Parse package name and version
        # 匹配包名模式: 字母、数字、连字符、下划线、点
        match = re.match(
            r"^([a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)"
            r"\s*(.*)?$",
            line
        )
        if match:
            name = match.group(1).strip()
            version = match.group(3).strip() if match.group(3) else ""
            deps.append(DependencyNode(
                name=name,
                version=version,
                source=filepath,
                is_dev=False,
            ))

    return deps


def parse_pipfile(filepath: str) -> Tuple[List[DependencyNode], List[DependencyNode]]:
    """解析 Pipfile 文件 / Parse Pipfile file

    Args:
        filepath: Pipfile 文件路径 / Pipfile file path

    Returns:
        (生产依赖列表, 开发依赖列表) / (production deps, dev deps)
    """
    prod_deps: List[DependencyNode] = []
    dev_deps: List[DependencyNode] = []

    if not os.path.isfile(filepath):
        return prod_deps, dev_deps

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        print_warning(f"无法读取文件 / Cannot read file: {filepath} - {e}")
        return prod_deps, dev_deps

    # 简单解析 Pipfile (TOML 格式的子集) / Simple Pipfile parsing (TOML subset)
    current_section = ""
    for line in content.split("\n"):
        stripped = line.strip()

        # 识别 section / Identify section
        if stripped.startswith("[") and stripped.endswith("]"):
            section_name = stripped[1:-1].strip()
            if section_name == "packages":
                current_section = "prod"
            elif section_name == "dev-packages":
                current_section = "dev"
            else:
                current_section = ""
            continue

        # 跳过空行和注释 / Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        # 解析包定义 / Parse package definition
        match = re.match(
            r'([a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)\s*=\s*["\'](.+?)["\']',
            stripped
        )
        if match and current_section:
            name = match.group(1)
            version = match.group(3)
            dep = DependencyNode(
                name=name,
                version=version,
                source=filepath,
                is_dev=(current_section == "dev"),
            )
            if current_section == "prod":
                prod_deps.append(dep)
            else:
                dev_deps.append(dep)

    return prod_deps, dev_deps


# ============================================================
# 依赖分析器 / Dependency Analyzer
# ============================================================

class DependencyAnalyzer:
    """依赖分析器 / Dependency Analyzer

    分析项目依赖关系，构建依赖树，检测循环依赖。
    Analyzes project dependencies, builds dependency trees, detects circular dependencies.

    使用方法 / Usage:
        analyzer = DependencyAnalyzer()
        result = analyzer.analyze_project("/path/to/project")
    """

    def __init__(self) -> None:
        """初始化分析器 / Initialize analyzer"""
        self._all_packages: Dict[str, DependencyNode] = {}
        self._dependency_graph: Dict[str, Set[str]] = {}

    def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """分析项目目录的依赖 / Analyze project directory dependencies

        自动检测项目类型(npm/Python)并解析相应的依赖文件。
        Automatically detects project type and parses corresponding dependency files.

        Args:
            project_path: 项目目录路径 / Project directory path

        Returns:
            分析结果字典 / Analysis result dict
        """
        result: Dict[str, Any] = {
            "project_path": project_path,
            "ecosystem": "unknown",
            "dependencies": [],
            "dev_dependencies": [],
            "total_direct": 0,
            "total_transitive": 0,
            "circular_dependencies": [],
            "has_circular": False,
            "dependency_files": [],
        }

        if not os.path.isdir(project_path):
            print_warning(f"项目目录不存在 / Project directory not found: {project_path}")
            return result

        # 检测项目类型并解析依赖 / Detect project type and parse dependencies
        package_json = os.path.join(project_path, "package.json")
        requirements_txt = os.path.join(project_path, "requirements.txt")
        pipfile = os.path.join(project_path, "Pipfile")

        if os.path.isfile(package_json):
            result["ecosystem"] = "npm"
            result["dependency_files"].append(package_json)
            prod, dev = parse_package_json(package_json)
            result["dependencies"] = [d.to_dict() for d in prod]
            result["dev_dependencies"] = [d.to_dict() for d in dev]
            print_info(f"从 package.json 解析到 {len(prod)} 个生产依赖, {len(dev)} 个开发依赖")

        if os.path.isfile(requirements_txt):
            result["ecosystem"] = "pypi"
            result["dependency_files"].append(requirements_txt)
            deps = parse_requirements_txt(requirements_txt)
            result["dependencies"] = [d.to_dict() for d in deps]
            print_info(f"从 requirements.txt 解析到 {len(deps)} 个依赖")

        if os.path.isfile(pipfile):
            if result["ecosystem"] == "unknown":
                result["ecosystem"] = "pypi"
            result["dependency_files"].append(pipfile)
            prod, dev = parse_pipfile(pipfile)
            result["dependencies"].extend([d.to_dict() for d in prod])
            result["dev_dependencies"].extend([d.to_dict() for d in dev])
            print_info(f"从 Pipfile 解析到 {len(prod)} 个生产依赖, {len(dev)} 个开发依赖")

        # 统计 / Statistics
        result["total_direct"] = len(result["dependencies"])

        # 构建依赖图(用于循环检测) / Build dependency graph (for cycle detection)
        self._build_dependency_graph(result["dependencies"])
        circular = self._detect_circular_dependencies()
        result["circular_dependencies"] = circular
        result["has_circular"] = len(circular) > 0

        if circular:
            print_warning(f"检测到 {len(circular)} 个循环依赖")

        return result

    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """分析单个依赖文件 / Analyze a single dependency file

        Args:
            filepath: 文件路径 / File path

        Returns:
            分析结果字典 / Analysis result dict
        """
        result: Dict[str, Any] = {
            "file": filepath,
            "ecosystem": "unknown",
            "dependencies": [],
            "dev_dependencies": [],
            "total_direct": 0,
            "circular_dependencies": [],
            "has_circular": False,
        }

        if not os.path.isfile(filepath):
            return result

        filename = os.path.basename(filepath)

        if filename == "package.json":
            result["ecosystem"] = "npm"
            prod, dev = parse_package_json(filepath)
            result["dependencies"] = [d.to_dict() for d in prod]
            result["dev_dependencies"] = [d.to_dict() for d in dev]

        elif filename == "requirements.txt":
            result["ecosystem"] = "pypi"
            deps = parse_requirements_txt(filepath)
            result["dependencies"] = [d.to_dict() for d in deps]

        elif filename == "Pipfile":
            result["ecosystem"] = "pypi"
            prod, dev = parse_pipfile(filepath)
            result["dependencies"] = [d.to_dict() for d in prod]
            result["dev_dependencies"] = [d.to_dict() for d in dev]

        result["total_direct"] = len(result["dependencies"])

        return result

    def _build_dependency_graph(self, dependencies: List[Dict[str, Any]]) -> None:
        """构建依赖图 / Build dependency graph

        Args:
            dependencies: 依赖列表 / Dependency list
        """
        self._dependency_graph = {}
        for dep in dependencies:
            name = dep.get("name", "").lower()
            self._dependency_graph[name] = set()
            # 子依赖信息在实际场景中需要从 registry 获取
            # Child dependency info needs to be fetched from registry in real scenarios
            for child in dep.get("children", []):
                self._dependency_graph[name].add(child.get("name", "").lower())

    def _detect_circular_dependencies(self) -> List[List[str]]:
        """检测循环依赖 / Detect circular dependencies

        使用 DFS 算法检测有向图中的环。
        Uses DFS to detect cycles in directed graph.

        Returns:
            循环依赖路径列表 / List of circular dependency paths
        """
        cycles: List[List[str]] = []
        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        path: List[str] = []

        def dfs(node: str) -> None:
            """深度优先搜索 / Depth-first search"""
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in self._dependency_graph.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    # 找到环 / Found cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    cycles.append(cycle)

            path.pop()
            rec_stack.remove(node)

        for node in self._dependency_graph:
            if node not in visited:
                dfs(node)

        return cycles

    def get_dependency_summary(self, analysis_result: Dict[str, Any]) -> str:
        """生成依赖分析摘要 / Generate dependency analysis summary

        Args:
            analysis_result: 分析结果 / Analysis result

        Returns:
            摘要文本 / Summary text
        """
        lines: List[str] = []
        lines.append(f"项目: {analysis_result.get('project_path', 'N/A')}")
        lines.append(f"生态系统: {analysis_result.get('ecosystem', 'unknown')}")
        lines.append(f"直接依赖: {analysis_result.get('total_direct', 0)}")
        lines.append(f"开发依赖: {len(analysis_result.get('dev_dependencies', []))}")

        if analysis_result.get("has_circular"):
            lines.append(f"循环依赖: {len(analysis_result.get('circular_dependencies', []))}")
            for cycle in analysis_result.get("circular_dependencies", []):
                lines.append(f"  - {' -> '.join(cycle)}")
        else:
            lines.append("循环依赖: 无")

        return "\n".join(lines)
