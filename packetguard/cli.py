# -*- coding: utf-8 -*-
"""
CLI 命令行接口 / CLI Command Line Interface

使用 argparse 实现命令行接口，支持以下子命令:
- scan: 扫描包或项目
- report: 生成报告
- audit: 全面审计
- check: 快速检查

Implements CLI using argparse with the following subcommands:
- scan: Scan packages or projects
- report: Generate reports
- audit: Comprehensive audit
- check: Quick check
"""

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .config import Config
from .scanner import PacketGuardScanner
from .utils import Colors, print_error, print_info, print_success


def create_parser() -> argparse.ArgumentParser:
    """创建命令行参数解析器 / Create CLI argument parser

    Returns:
        ArgumentParser 实例 / ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog="packetguard",
        description="PacketGuard - 轻量级开源包供应链安全威胁检测引擎\n"
                    "Lightweight Open-Source Package Supply Chain Security Threat Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例 / Examples:
  packetguard scan express                     扫描 npm 包 / Scan npm package
  packetguard scan requests -e pypi            扫描 PyPI 包 / Scan PyPI package
  packetguard scan ./project                   扫描项目目录 / Scan project directory
  packetguard scan package.json                扫描依赖文件 / Scan dependency file
  packetguard check lodash                     快速检查 / Quick check
  packetguard audit ./project                  全面审计 / Full audit
  packetguard scan express -f json -o report   导出 JSON 报告 / Export JSON report
  packetguard scan express -s high             只显示高危及以上 / Show high severity only
        """,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"PacketGuard v{__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令 / Available commands")

    # ============================================================
    # scan 子命令 / scan subcommand
    # ============================================================
    scan_parser = subparsers.add_parser(
        "scan",
        help="扫描包或项目 / Scan packages or projects",
        description="扫描指定的包名、依赖文件或项目目录",
    )
    scan_parser.add_argument(
        "target",
        help="扫描目标: 包名、依赖文件路径或项目目录 / Target: package name, dep file, or project dir",
    )
    scan_parser.add_argument(
        "-e", "--ecosystem",
        choices=["npm", "pypi", "auto"],
        default="auto",
        help="指定生态系统 / Specify ecosystem (default: auto)",
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "sarif", "markdown", "html"],
        default="text",
        help="输出格式 / Output format (default: text)",
    )
    scan_parser.add_argument(
        "-o", "--output",
        default=None,
        help="输出文件路径(不含扩展名) / Output file path (without extension)",
    )
    scan_parser.add_argument(
        "-s", "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="最低报告等级 / Minimum severity to report (default: low)",
    )
    scan_parser.add_argument(
        "-c", "--config",
        default=None,
        help="配置文件路径 / Configuration file path",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="HTTP 请求超时时间(秒) / HTTP request timeout in seconds",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出 / Disable colored output",
    )

    # ============================================================
    # check 子命令 / check subcommand
    # ============================================================
    check_parser = subparsers.add_parser(
        "check",
        help="快速检查包安全性 / Quick check package safety",
        description="快速检查指定包是否在已知恶意包数据库中",
    )
    check_parser.add_argument(
        "target",
        help="包名 / Package name",
    )
    check_parser.add_argument(
        "-e", "--ecosystem",
        choices=["npm", "pypi", "auto"],
        default="auto",
        help="指定生态系统 / Specify ecosystem (default: auto)",
    )
    check_parser.add_argument(
        "-c", "--config",
        default=None,
        help="配置文件路径 / Configuration file path",
    )
    check_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出 / Disable colored output",
    )

    # ============================================================
    # audit 子命令 / audit subcommand
    # ============================================================
    audit_parser = subparsers.add_parser(
        "audit",
        help="全面审计项目安全 / Comprehensive project security audit",
        description="对项目目录执行全面的安全审计",
    )
    audit_parser.add_argument(
        "target",
        help="项目目录路径 / Project directory path",
    )
    audit_parser.add_argument(
        "-e", "--ecosystem",
        choices=["npm", "pypi", "auto"],
        default="auto",
        help="指定生态系统 / Specify ecosystem (default: auto)",
    )
    audit_parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "sarif", "markdown", "html"],
        default="text",
        help="输出格式 / Output format (default: text)",
    )
    audit_parser.add_argument(
        "-o", "--output",
        default=None,
        help="输出文件路径(不含扩展名) / Output file path (without extension)",
    )
    audit_parser.add_argument(
        "-s", "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="最低报告等级 / Minimum severity to report (default: low)",
    )
    audit_parser.add_argument(
        "-c", "--config",
        default=None,
        help="配置文件路径 / Configuration file path",
    )
    audit_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="HTTP 请求超时时间(秒) / HTTP request timeout in seconds",
    )
    audit_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出 / Disable colored output",
    )

    # ============================================================
    # report 子命令 / report subcommand
    # ============================================================
    report_parser = subparsers.add_parser(
        "report",
        help="生成安全报告 / Generate security report",
        description="从扫描结果生成指定格式的安全报告",
    )
    report_parser.add_argument(
        "target",
        help="扫描目标 / Scan target",
    )
    report_parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "sarif", "markdown", "html"],
        default="text",
        help="输出格式 / Output format (default: text)",
    )
    report_parser.add_argument(
        "-o", "--output",
        required=True,
        help="输出文件路径(不含扩展名) / Output file path (without extension)",
    )
    report_parser.add_argument(
        "-e", "--ecosystem",
        choices=["npm", "pypi", "auto"],
        default="auto",
        help="指定生态系统 / Specify ecosystem (default: auto)",
    )
    report_parser.add_argument(
        "-s", "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="最低报告等级 / Minimum severity to report (default: low)",
    )
    report_parser.add_argument(
        "-c", "--config",
        default=None,
        help="配置文件路径 / Configuration file path",
    )
    report_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出 / Disable colored output",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI 主入口 / CLI main entry point

    Args:
        argv: 命令行参数(如为 None 则使用 sys.argv) /
              Command line arguments (uses sys.argv if None)

    Returns:
        退出码(0=成功, 1=错误, 2=发现威胁) / Exit code (0=success, 1=error, 2=threats found)
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    # 如果没有指定命令，显示帮助 / Show help if no command specified
    if not args.command:
        parser.print_help()
        return 0

    # 处理 --no-color / Handle --no-color
    if hasattr(args, "no_color") and args.no_color:
        Colors.disable()

    # 创建配置 / Create configuration
    config = Config()
    config_path = getattr(args, "config", None)

    # 创建扫描器 / Create scanner
    scanner = PacketGuardScanner(config)

    # 加载配置文件 / Load configuration file
    if config_path:
        if not scanner.load_config(config_path):
            print_error(f"无法加载配置文件 / Cannot load config file: {config_path}")
            return 1
    else:
        scanner.load_config()

    # 应用命令行参数覆盖 / Apply CLI argument overrides
    if hasattr(args, "timeout") and args.timeout:
        scanner.config.timeout = args.timeout

    try:
        # ============================================================
        # scan 命令 / scan command
        # ============================================================
        if args.command == "scan":
            target = args.target

            # 判断扫描目标类型 / Determine scan target type
            if os.path.isdir(target):
                result = scanner.scan_directory(target, args.ecosystem)
            elif os.path.isfile(target):
                result = scanner.scan_file(target, args.ecosystem)
            else:
                result = scanner.scan_package(target, args.ecosystem)

            # 生成报告 / Generate report
            report = scanner.generate_report(
                result,
                fmt=args.format,
                output_path=args.output,
                min_severity=args.severity,
            )

            if report and not args.output:
                print(report)

            return 2 if result.total_findings > 0 else 0

        # ============================================================
        # check 命令 / check command
        # ============================================================
        elif args.command == "check":
            result = scanner.quick_check(args.target, args.ecosystem)

            if result.metadata.get("whitelisted"):
                print_success(f"包 '{args.target}' 在白名单中，安全")
                return 0

            if result.total_findings > 0:
                print_error(f"包 '{args.target}' 存在安全威胁!")
                for finding in result.findings:
                    print(f"  - [{finding.get('severity', 'unknown').upper()}] "
                          f"{finding.get('description', '')}")
                return 2
            else:
                print_success(f"包 '{args.target}' 未发现已知安全威胁")
                return 0

        # ============================================================
        # audit 命令 / audit command
        # ============================================================
        elif args.command == "audit":
            if not os.path.isdir(args.target):
                print_error(f"目录不存在 / Directory not found: {args.target}")
                return 1

            result = scanner.audit(args.target, args.ecosystem)

            report = scanner.generate_report(
                result,
                fmt=args.format,
                output_path=args.output,
                min_severity=args.severity,
            )

            if report and not args.output:
                print(report)

            return 2 if result.total_findings > 0 else 0

        # ============================================================
        # report 命令 / report command
        # ============================================================
        elif args.command == "report":
            target = args.target

            if os.path.isdir(target):
                result = scanner.scan_directory(target, args.ecosystem)
            elif os.path.isfile(target):
                result = scanner.scan_file(target, args.ecosystem)
            else:
                result = scanner.scan_package(target, args.ecosystem)

            filepath = scanner.generate_report(
                result,
                fmt=args.format,
                output_path=args.output,
                min_severity=args.severity,
            )

            if filepath:
                print_success(f"报告已生成 / Report generated: {filepath}")
                return 0
            else:
                print_error("报告生成失败 / Report generation failed")
                return 1

        return 0

    except KeyboardInterrupt:
        print("\n操作已取消 / Operation cancelled")
        return 130
    except Exception as e:
        print_error(f"发生未预期的错误 / Unexpected error: {e}")
        if scanner.config.verbose:
            import traceback
            traceback.print_exc()
        return 1
