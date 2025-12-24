"""AFL 适配的覆盖工具。

本模块聚焦于基于 edge id 的覆盖表示（AFL 位图 / afl-showmap 输出）。
已移除基于 Python `trace` 的文本解析与源码行号覆盖表示，优先使用 AFL 的
edge/bitmap 模型。
"""

from __future__ import annotations

import os
from typing import Set

BITMAP_SIZE = 65536


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

    def to_bitmap(self, size: int = BITMAP_SIZE) -> bytearray:
        """从整数 edge id 生成简易位图（更快的本地变量/无异常路径）。"""
        bitmap = bytearray(size)
        if not self.points:
            return bitmap
        b = bitmap  # local ref
        for e in self.points:
            try:
                idx = int(e) % size
            except Exception:
                continue
            b[idx] = 1
        return bitmap


def parse_afl_map(path: str) -> CoverageData:
    cov = CoverageData()
    if not os.path.exists(path):
        return cov

    # 首先按文本尝试解析（快速跳过大文件）
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            found = False
            for line in f:
                for tok in line.replace(",", " ").split():
                    if not tok:
                        continue
                    try:
                        val = int(tok, 0)  # 支持十进制与 0x 十六进制
                        cov.add_edge(val)
                        found = True
                    except Exception:
                        continue
            if found:
                return cov
    except Exception:
        pass

    # 二进制位图解析：非零字节位置即视为命中 edge
    try:
        with open(path, "rb") as f:
            data = f.read()
            mv = memoryview(data)
            for i, byte in enumerate(mv):
                if byte:
                    cov.add_edge(i)
    except Exception:
        pass

    return cov


__all__ = ["CoverageData", "parse_afl_map"]
