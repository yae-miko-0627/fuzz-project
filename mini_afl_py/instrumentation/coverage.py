"""AFL 适配的覆盖工具。

本模块聚焦于基于 edge id 的覆盖表示（AFL 位图 / afl-showmap 输出）。
已移除基于 Python `trace` 的文本解析与源码行号覆盖表示，优先使用 AFL 的
edge/bitmap 模型。
"""

from __future__ import annotations

import os
from typing import Set


class CoverageData:
    """存储整数形式 edge id 的覆盖容器（AFL 风格）。

    内部 `points` 为整数集合，每个整数表示一个被命中的 edge id。
    """

    def __init__(self) -> None:
        self.points: Set[int] = set()

    def add_edge(self, edge_id: int) -> None:
        try:
            self.points.add(int(edge_id))
        except Exception:
            pass

    def merge(self, other: "CoverageData") -> None:
        self.points.update(other.points)

    def __len__(self) -> int:
        return len(self.points)

    def to_bitmap(self, size: int = 65536) -> bytearray:
        """从整数 edge id 生成简易位图。

        使用取模将 edge id 映射到位图索引，产生用于快速比较的紧凑表示。
        """
        bitmap = bytearray(size)
        for e in self.points:
            try:
                idx = int(e) % size
                bitmap[idx] = 1
            except Exception:
                continue
        return bitmap

def parse_afl_map(path: str) -> CoverageData:
    """解析 afl-showmap 的输出（文本或二进制格式），返回 CoverageData。

    兼容策略：
    - 尝试按文本解析每行内的整数（十进制或 0x 十六进制），将其视为 edge id。
    - 若文本解析失败且文件为二进制，则按字节位图解析：每个非零字节的位置视为被命中 edge。
    """
    cov = CoverageData()
    if not os.path.exists(path):
        return cov

    # 优先尝试文本解析
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            any_found = False
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # 提取行中出现的十进制或 0x 十六进制的整数
                parts = line.replace(',', ' ').split()
                for p in parts:
                    try:
                        if p.startswith("0x") or p.startswith("0X"):
                            val = int(p, 16)
                        else:
                            val = int(p)
                        cov.add_edge(val)
                        any_found = True
                    except Exception:
                        continue
            if any_found:
                return cov
    except Exception:
        pass

    # 文本解析未发现内容，尝试二进制位图解析
    try:
        with open(path, "rb") as f:
            data = f.read()
            for i, b in enumerate(data):
                if b != 0:
                    cov.add_edge(i)
    except Exception:
        pass

    return cov
__all__ = ["CoverageData", "parse_afl_map"]
