# -*- coding: utf-8 -*-
"""
Typosquatting 检测模块单元测试 / Unit tests for Typosquatting detection module
"""

import unittest
import sys
import os

# 将父目录添加到路径 / Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetguard.typosquat import (
    levenshtein_distance,
    damerau_levenshtein_distance,
    generate_typosquat_variants,
    TyposquatDetector,
)


class TestLevenshteinDistance(unittest.TestCase):
    """Levenshtein 距离计算测试 / Levenshtein distance calculation tests"""

    def test_identical_strings(self) -> None:
        """相同字符串距离为 0 / Identical strings have distance 0"""
        self.assertEqual(levenshtein_distance("express", "express"), 0)

    def test_empty_strings(self) -> None:
        """空字符串测试 / Empty string tests"""
        self.assertEqual(levenshtein_distance("", ""), 0)
        self.assertEqual(levenshtein_distance("abc", ""), 3)
        self.assertEqual(levenshtein_distance("", "abc"), 3)

    def test_single_character(self) -> None:
        """单字符差异 / Single character difference"""
        self.assertEqual(levenshtein_distance("a", "b"), 1)

    def test_insertion(self) -> None:
        """插入操作 / Insertion operation"""
        self.assertEqual(levenshtein_distance("cat", "cats"), 1)
        self.assertEqual(levenshtein_distance("cat", "scat"), 1)

    def test_deletion(self) -> None:
        """删除操作 / Deletion operation"""
        self.assertEqual(levenshtein_distance("cats", "cat"), 1)
        self.assertEqual(levenshtein_distance("scat", "cat"), 1)

    def test_substitution(self) -> None:
        """替换操作 / Substitution operation"""
        self.assertEqual(levenshtein_distance("cat", "bat"), 1)
        self.assertEqual(levenshtein_distance("cat", "car"), 1)

    def test_complex(self) -> None:
        """复杂情况 / Complex cases"""
        self.assertEqual(levenshtein_distance("kitten", "sitting"), 3)
        self.assertEqual(levenshtein_distance("saturday", "sunday"), 3)

    def test_unicode(self) -> None:
        """Unicode 字符 / Unicode characters"""
        self.assertEqual(levenshtein_distance("cafe", "cafe"), 0)


class TestDamerauLevenshteinDistance(unittest.TestCase):
    """Damerau-Levenshtein 距离计算测试 / Damerau-Levenshtein distance tests"""

    def test_identical(self) -> None:
        """相同字符串 / Identical strings"""
        self.assertEqual(damerau_levenshtein_distance("abc", "abc"), 0)

    def test_transposition(self) -> None:
        """相邻字符交换 / Adjacent transposition"""
        # "ab" -> "ba" 应该距离为 1 (Damerau-Levenshtein)
        self.assertEqual(damerau_levenshtein_distance("ab", "ba"), 1)
        # "teh" -> "the" 应该距离为 1
        self.assertEqual(damerau_levenshtein_distance("teh", "the"), 1)

    def test_regular_edit(self) -> None:
        """常规编辑操作 / Regular edit operations"""
        self.assertEqual(damerau_levenshtein_distance("cat", "car"), 1)
        self.assertEqual(damerau_levenshtein_distance("cat", "cats"), 1)


class TestGenerateVariants(unittest.TestCase):
    """变体生成测试 / Variant generation tests"""

    def test_generates_variants(self) -> None:
        """应该生成变体 / Should generate variants"""
        variants = generate_typosquat_variants("express")
        self.assertIsInstance(variants, list)
        self.assertGreater(len(variants), 0)

    def test_no_self_variant(self) -> None:
        """不应包含原始包名 / Should not include original package name"""
        variants = generate_typosquat_variants("express")
        self.assertNotIn("express", variants)

    def test_deletion_variants(self) -> None:
        """应包含删除变体 / Should include deletion variants"""
        variants = generate_typosquat_variants("ab")
        # 删除一个字符后应该是 "a" 或 "b"
        self.assertIn("a", variants)
        self.assertIn("b", variants)

    def test_swap_variants(self) -> None:
        """应包含交换变体 / Should include swap variants"""
        variants = generate_typosquat_variants("ab")
        self.assertIn("ba", variants)

    def test_empty_string(self) -> None:
        """空字符串应返回空列表 / Empty string should return empty list"""
        variants = generate_typosquat_variants("")
        self.assertEqual(variants, [])


class TestTyposquatDetector(unittest.TestCase):
    """TyposquatDetector 测试 / TyposquatDetector tests"""

    def setUp(self) -> None:
        """设置测试 / Set up tests"""
        self.detector = TyposquatDetector(
            known_packages={"express", "lodash", "react", "vue"}
        )

    def test_exact_match_no_result(self) -> None:
        """精确匹配不应产生结果 / Exact match should not produce results"""
        results = self.detector.check("express", ecosystem="npm")
        # express 本身在已知包中，不应产生 typosquat 结果
        typo_results = [r for r in results if r["type"] == "typosquatting"]
        # express 和 express 的距离为 0，不应被报告
        self.assertEqual(len(typo_results), 0)

    def test_similar_package_detected(self) -> None:
        """相似包名应被检测到 / Similar package names should be detected"""
        # "expres" 与 "express" 距离为 1
        results = self.detector.check("expres", ecosystem="npm", max_distance=2)
        typo_results = [r for r in results if r["type"] == "typosquatting"]
        self.assertGreater(len(typo_results), 0)

    def test_no_known_packages(self) -> None:
        """无已知包时不应产生结果 / No results when no known packages"""
        detector = TyposquatDetector()
        results = detector.check("express", ecosystem="npm")
        self.assertEqual(len(results), 0)

    def test_severity_levels(self) -> None:
        """严重等级应正确 / Severity levels should be correct"""
        results = self.detector.check("expres", ecosystem="npm", max_distance=2)
        for result in results:
            self.assertIn(result["severity"], ["low", "medium", "high", "critical"])


if __name__ == "__main__":
    unittest.main()
