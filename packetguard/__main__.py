# -*- coding: utf-8 -*-
"""
PacketGuard 模块入口 / PacketGuard Module Entry Point

支持通过 python -m packetguard 运行。
Supports running via python -m packetguard.
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
