# -*- coding: utf-8 -*-
"""
依赖分析模块单元测试 / Unit tests for Dependency analysis module
"""

import json
import os
import tempfile
import unittest
import sys

# 将父目录添加到路径 / Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetguard.dependency import (
    DependencyNode,
    parse_package_json,
    parse_requirements_txt,
    parse_pipfile,
    DependencyAnalyzer,
)


class TestDependencyNode(unittest.TestCase):
    """DependencyNode 测试 / DependencyNode tests"""

    def test_create_node(self) -> None:
        """创建节点 / Create node"""
        node = DependencyNode(name="express", version="^4.18.0")
        self.assertEqual(node.name, "express")
        self.assertEqual(node.version, "^4.18.0")
        self.assertFalse(node.is_dev)

    def test_add_child(self) -> None:
        """添加子节点 / Add child node"""
        parent = DependencyNode(name="express", version="^4.18.0")
        child = DependencyNode(name="body-parser", version="^1.19.0")
        parent.add_child(child)
        self.assertEqual(len(parent.children), 1)
        self.assertEqual(child.depth, 1)

    def test_to_dict(self) -> None:
        """转换为字典 / Convert to dict"""
        node = DependencyNode(name="express", version="^4.18.0")
        d = node.to_dict()
        self.assertEqual(d["name"], "express")
        self.assertEqual(d["version"], "^4.18.0")
        self.assertEqual(d["children"], [])

    def test_repr(self) -> None:
        """字符串表示 / String representation"""
        node = DependencyNode(name="express", version="^4.18.0")
        self.assertIn("express", repr(node))


class TestParsePackageJson(unittest.TestCase):
    """package.json 解析测试 / package.json parsing tests"""

    def test_parse_basic(self) -> None:
        """基本解析 / Basic parsing"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "dependencies": {
                    "express": "^4.18.0",
                    "lodash": "^4.17.21",
                },
                "devDependencies": {
                    "jest": "^29.0.0",
                },
            }, f)
            f.flush()
            prod, dev = parse_package_json(f.name)

        self.assertEqual(len(prod), 2)
        self.assertEqual(len(dev), 1)
        self.assertEqual(prod[0].name, "express")
        self.assertEqual(dev[0].name, "jest")
        os.unlink(f.name)

    def test_parse_empty(self) -> None:
        """空文件解析 / Empty file parsing"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            f.flush()
            prod, dev = parse_package_json(f.name)

        self.assertEqual(len(prod), 0)
        self.assertEqual(len(dev), 0)
        os.unlink(f.name)

    def test_parse_nonexistent(self) -> None:
        """不存在的文件 / Nonexistent file"""
        prod, dev = parse_package_json("/nonexistent/package.json")
        self.assertEqual(len(prod), 0)
        self.assertEqual(len(dev), 0)

    def test_parse_with_peer_deps(self) -> None:
        """解析 peerDependencies / Parse peerDependencies"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "peerDependencies": {
                    "react": ">=16.0.0",
                },
            }, f)
            f.flush()
            prod, dev = parse_package_json(f.name)

        self.assertEqual(len(prod), 1)
        self.assertEqual(prod[0].name, "react")
        os.unlink(f.name)


class TestParseRequirementsTxt(unittest.TestCase):
    """requirements.txt 解析测试 / requirements.txt parsing tests"""

    def test_parse_basic(self) -> None:
        """基本解析 / Basic parsing"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("flask==2.3.0\n")
            f.write("requests>=2.28.0\n")
            f.write("numpy\n")
            f.flush()
            deps = parse_requirements_txt(f.name)

        self.assertEqual(len(deps), 3)
        self.assertEqual(deps[0].name, "flask")
        self.assertEqual(deps[0].version, "==2.3.0")
        self.assertEqual(deps[2].name, "numpy")
        self.assertEqual(deps[2].version, "")
        os.unlink(f.name)

    def test_parse_comments_and_empty(self) -> None:
        """注释和空行 / Comments and empty lines"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("\n")
            f.write("flask==2.3.0\n")
            f.write("# Another comment\n")
            f.flush()
            deps = parse_requirements_txt(f.name)

        self.assertEqual(len(deps), 1)
        os.unlink(f.name)

    def test_parse_with_extras(self) -> None:
        """带 extras 的包 / Package with extras"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests[security]>=2.28.0\n")
            f.flush()
            deps = parse_requirements_txt(f.name)

        self.assertEqual(len(deps), 1)
        self.assertIn("requests", deps[0].name)
        os.unlink(f.name)

    def test_parse_nonexistent(self) -> None:
        """不存在的文件 / Nonexistent file"""
        deps = parse_requirements_txt("/nonexistent/requirements.txt")
        self.assertEqual(len(deps), 0)


class TestParsePipfile(unittest.TestCase):
    """Pipfile 解析测试 / Pipfile parsing tests"""

    def test_parse_basic(self) -> None:
        """基本解析 / Basic parsing"""
        with tempfile.NamedTemporaryFile(mode="w", suffix="", delete=False) as f:
            f.write('[packages]\n')
            f.write('flask = "*"\n')
            f.write('requests = ">=2.28.0"\n')
            f.write('\n')
            f.write('[dev-packages]\n')
            f.write('pytest = "*"\n')
            f.flush()
            prod, dev = parse_pipfile(f.name)

        self.assertEqual(len(prod), 2)
        self.assertEqual(len(dev), 1)
        self.assertEqual(prod[0].name, "flask")
        self.assertEqual(dev[0].name, "pytest")
        os.unlink(f.name)

    def test_parse_nonexistent(self) -> None:
        """不存在的文件 / Nonexistent file"""
        prod, dev = parse_pipfile("/nonexistent/Pipfile")
        self.assertEqual(len(prod), 0)
        self.assertEqual(len(dev), 0)


class TestDependencyAnalyzer(unittest.TestCase):
    """DependencyAnalyzer 测试 / DependencyAnalyzer tests"""

    def test_analyze_nonexistent_dir(self) -> None:
        """不存在的目录 / Nonexistent directory"""
        analyzer = DependencyAnalyzer()
        result = analyzer.analyze_project("/nonexistent/dir")
        self.assertEqual(result["ecosystem"], "unknown")
        self.assertEqual(result["total_direct"], 0)

    def test_analyze_npm_project(self) -> None:
        """分析 npm 项目 / Analyze npm project"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_json = os.path.join(tmpdir, "package.json")
            with open(pkg_json, "w") as f:
                json.dump({
                    "dependencies": {
                        "express": "^4.18.0",
                        "lodash": "^4.17.21",
                    },
                    "devDependencies": {
                        "jest": "^29.0.0",
                    },
                }, f)

            analyzer = DependencyAnalyzer()
            result = analyzer.analyze_project(tmpdir)

            self.assertEqual(result["ecosystem"], "npm")
            self.assertEqual(result["total_direct"], 2)

    def test_analyze_pypi_project(self) -> None:
        """分析 PyPI 项目 / Analyze PyPI project"""
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = os.path.join(tmpdir, "requirements.txt")
            with open(req_file, "w") as f:
                f.write("flask==2.3.0\n")
                f.write("requests>=2.28.0\n")

            analyzer = DependencyAnalyzer()
            result = analyzer.analyze_project(tmpdir)

            self.assertEqual(result["ecosystem"], "pypi")
            self.assertEqual(result["total_direct"], 2)

    def test_dependency_summary(self) -> None:
        """依赖摘要 / Dependency summary"""
        analyzer = DependencyAnalyzer()
        result = {
            "project_path": "/test",
            "ecosystem": "npm",
            "total_direct": 5,
            "dev_dependencies": [],
            "has_circular": False,
            "circular_dependencies": [],
        }
        summary = analyzer.get_dependency_summary(result)
        self.assertIn("5", summary)
        self.assertIn("npm", summary)


if __name__ == "__main__":
    unittest.main()
