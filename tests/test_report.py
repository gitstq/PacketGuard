# -*- coding: utf-8 -*-
"""
报告生成模块单元测试 / Unit tests for Report generation module
"""

import json
import os
import tempfile
import unittest
import sys

# 将父目录添加到路径 / Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetguard.report import ScanResult, ReportGenerator


class TestScanResult(unittest.TestCase):
    """ScanResult 测试 / ScanResult tests"""

    def test_create_empty(self) -> None:
        """创建空结果 / Create empty result"""
        result = ScanResult(target="express", ecosystem="npm")
        self.assertEqual(result.target, "express")
        self.assertEqual(result.ecosystem, "npm")
        self.assertEqual(result.total_findings, 0)
        self.assertFalse(result.has_critical)

    def test_add_finding(self) -> None:
        """添加发现 / Add finding"""
        result = ScanResult()
        result.add_finding({
            "type": "malware",
            "severity": "high",
            "description": "Test finding",
        })
        self.assertEqual(result.total_findings, 1)
        self.assertEqual(result.high_count, 1)

    def test_add_findings_batch(self) -> None:
        """批量添加发现 / Add findings in batch"""
        result = ScanResult()
        findings = [
            {"type": "test", "severity": "high"},
            {"type": "test", "severity": "medium"},
            {"type": "test", "severity": "low"},
        ]
        result.add_findings(findings)
        self.assertEqual(result.total_findings, 3)
        self.assertEqual(result.high_count, 1)
        self.assertEqual(result.medium_count, 1)
        self.assertEqual(result.low_count, 1)

    def test_severity_counts(self) -> None:
        """严重等级计数 / Severity counts"""
        result = ScanResult()
        result.add_findings([
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
        ])
        self.assertEqual(result.critical_count, 2)
        self.assertEqual(result.high_count, 1)
        self.assertEqual(result.medium_count, 1)
        self.assertEqual(result.low_count, 1)

    def test_filter_by_severity(self) -> None:
        """按严重等级过滤 / Filter by severity"""
        result = ScanResult()
        result.add_findings([
            {"severity": "low", "description": "low"},
            {"severity": "medium", "description": "medium"},
            {"severity": "high", "description": "high"},
            {"severity": "critical", "description": "critical"},
        ])

        high_and_above = result.get_findings_by_severity("high")
        self.assertEqual(len(high_and_above), 2)

        critical_only = result.get_findings_by_severity("critical")
        self.assertEqual(len(critical_only), 1)

    def test_to_dict(self) -> None:
        """转换为字典 / Convert to dict"""
        result = ScanResult(target="test", ecosystem="npm")
        result.add_finding({"severity": "high", "type": "test"})
        d = result.to_dict()
        self.assertEqual(d["target"], "test")
        self.assertEqual(d["summary"]["total"], 1)
        self.assertEqual(d["summary"]["high"], 1)


class TestReportGeneratorText(unittest.TestCase):
    """文本报告生成测试 / Text report generation tests"""

    def setUp(self) -> None:
        """设置测试 / Set up tests"""
        self.generator = ReportGenerator()

    def test_empty_report(self) -> None:
        """空报告 / Empty report"""
        result = ScanResult(target="express", ecosystem="npm")
        report = self.generator.generate(result, fmt="text")
        self.assertIn("PacketGuard", report)
        self.assertIn("express", report)
        self.assertIn("0", report)

    def test_report_with_findings(self) -> None:
        """有发现的报告 / Report with findings"""
        result = ScanResult(target="test-pkg", ecosystem="npm")
        result.add_finding({
            "type": "malware",
            "severity": "high",
            "description": "Malicious pattern detected",
            "file": "index.js",
            "line": 42,
            "match": "eval(",
            "recommendation": "Remove malicious code",
        })
        report = self.generator.generate(result, fmt="text")
        self.assertIn("malware", report)
        self.assertIn("HIGH", report)
        self.assertIn("index.js", report)

    def test_severity_filter(self) -> None:
        """严重等级过滤 / Severity filter"""
        result = ScanResult(target="test", ecosystem="npm")
        result.add_findings([
            {"severity": "low", "description": "low finding", "type": "test"},
            {"severity": "high", "description": "high finding", "type": "test"},
        ])
        report = self.generator.generate(result, fmt="text", min_severity="high")
        self.assertIn("high finding", report)
        self.assertNotIn("low finding", report)


class TestReportGeneratorJson(unittest.TestCase):
    """JSON 报告生成测试 / JSON report generation tests"""

    def setUp(self) -> None:
        """设置测试 / Set up tests"""
        self.generator = ReportGenerator()

    def test_valid_json(self) -> None:
        """有效的 JSON / Valid JSON"""
        result = ScanResult(target="test", ecosystem="npm")
        result.add_finding({"severity": "high", "type": "test"})
        report = self.generator.generate(result, fmt="json")
        data = json.loads(report)
        self.assertEqual(data["scan"]["target"], "test")
        self.assertEqual(data["summary"]["total_findings"], 1)

    def test_json_structure(self) -> None:
        """JSON 结构 / JSON structure"""
        result = ScanResult()
        report = self.generator.generate(result, fmt="json")
        data = json.loads(report)
        self.assertIn("version", data)
        self.assertIn("tool", data)
        self.assertIn("scan", data)
        self.assertIn("summary", data)
        self.assertIn("findings", data)


class TestReportGeneratorSarif(unittest.TestCase):
    """SARIF 报告生成测试 / SARIF report generation tests"""

    def setUp(self) -> None:
        """设置测试 / Set up tests"""
        self.generator = ReportGenerator()

    def test_valid_sarif(self) -> None:
        """有效的 SARIF / Valid SARIF"""
        result = ScanResult(target="test", ecosystem="npm")
        result.add_finding({
            "type": "malware",
            "severity": "high",
            "description": "Test",
            "file": "index.js",
            "line": 10,
        })
        report = self.generator.generate(result, fmt="sarif")
        data = json.loads(report)
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("runs", data)
        self.assertGreater(len(data["runs"][0]["results"]), 0)

    def test_sarif_severity_mapping(self) -> None:
        """SARIF 严重等级映射 / SARIF severity mapping"""
        result = ScanResult()
        result.add_finding({
            "type": "test",
            "severity": "critical",
            "description": "Critical issue",
        })
        report = self.generator.generate(result, fmt="sarif")
        data = json.loads(report)
        self.assertEqual(data["runs"][0]["results"][0]["level"], "error")


class TestReportGeneratorMarkdown(unittest.TestCase):
    """Markdown 报告生成测试 / Markdown report generation tests"""

    def setUp(self) -> None:
        """设置测试 / Set up tests"""
        self.generator = ReportGenerator()

    def test_markdown_structure(self) -> None:
        """Markdown 结构 / Markdown structure"""
        result = ScanResult(target="test", ecosystem="npm")
        report = self.generator.generate(result, fmt="markdown")
        self.assertIn("# PacketGuard", report)
        self.assertIn("## Summary", report)

    def test_markdown_with_findings(self) -> None:
        """有发现的 Markdown / Markdown with findings"""
        result = ScanResult(target="test", ecosystem="npm")
        result.add_finding({
            "type": "malware",
            "severity": "critical",
            "description": "Critical finding",
        })
        report = self.generator.generate(result, fmt="markdown")
        self.assertIn("CRITICAL", report)
        self.assertIn("Critical finding", report)


class TestReportGeneratorHtml(unittest.TestCase):
    """HTML 报告生成测试 / HTML report generation tests"""

    def setUp(self) -> None:
        """设置测试 / Set up tests"""
        self.generator = ReportGenerator()

    def test_valid_html(self) -> None:
        """有效的 HTML / Valid HTML"""
        result = ScanResult(target="test", ecosystem="npm")
        report = self.generator.generate(result, fmt="html")
        self.assertIn("<!DOCTYPE html>", report)
        self.assertIn("</html>", report)
        self.assertIn("PacketGuard", report)

    def test_html_with_findings(self) -> None:
        """有发现的 HTML / HTML with findings"""
        result = ScanResult(target="test", ecosystem="npm")
        result.add_finding({
            "type": "malware",
            "severity": "high",
            "description": "High severity finding",
            "file": "index.js",
            "line": 42,
        })
        report = self.generator.generate(result, fmt="html")
        self.assertIn("High severity finding", report)
        self.assertIn("index.js", report)


class TestReportExport(unittest.TestCase):
    """报告导出测试 / Report export tests"""

    def setUp(self) -> None:
        """设置测试 / Set up tests"""
        self.generator = ReportGenerator()

    def test_export_json(self) -> None:
        """导出 JSON 文件 / Export JSON file"""
        result = ScanResult(target="test", ecosystem="npm")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report")
            filepath = self.generator.export(result, fmt="json", output_path=output_path)
            self.assertTrue(os.path.isfile(filepath))
            with open(filepath, "r") as f:
                data = json.load(f)
            self.assertEqual(data["scan"]["target"], "test")

    def test_export_html(self) -> None:
        """导出 HTML 文件 / Export HTML file"""
        result = ScanResult(target="test", ecosystem="npm")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report")
            filepath = self.generator.export(result, fmt="html", output_path=output_path)
            self.assertTrue(os.path.isfile(filepath))
            with open(filepath, "r") as f:
                content = f.read()
            self.assertIn("<!DOCTYPE html>", content)

    def test_export_markdown(self) -> None:
        """导出 Markdown 文件 / Export Markdown file"""
        result = ScanResult(target="test", ecosystem="npm")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report")
            filepath = self.generator.export(result, fmt="markdown", output_path=output_path)
            self.assertTrue(os.path.isfile(filepath))


if __name__ == "__main__":
    unittest.main()
