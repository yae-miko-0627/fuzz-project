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
    """高性能覆盖容器（基于位图）。

    为了在长时间运行中保持合并性能，内部使用固定大小位图（bytearray）
    存储覆盖位点（与 AFL 的位图大小一致）。也提供向后兼容的
    `points` 视图（延迟计算），但主要操作使用位图进行快速 OR/计数。
    """

    def __init__(self, size: int = BITMAP_SIZE) -> None:
        self.size = int(size)
        self.bitmap = bytearray(self.size)
        # 延迟构建的 points 视图（仅在显式需要时填充/更新）
        self._points_cache = None

    def add_edge(self, edge_id: int) -> None:
        try:
            idx = int(edge_id) % self.size
            self.bitmap[idx] = 1
            self._points_cache = None
        except Exception:
            pass

    def merge(self, other: "CoverageData") -> None:
        """把另一个 CoverageData 的位图合并进来（按位 OR）。"""
        try:
            if not isinstance(other, CoverageData):
                return
            # 位图按位合并
            for i in range(min(self.size, other.size)):
                if other.bitmap[i]:
                    self.bitmap[i] = 1
            self._points_cache = None
        except Exception:
            pass

    def merge_and_count_new(self, other: "CoverageData") -> int:
        """合并并返回新增命中数（新位为 1 的数量）。"""
        new = 0
        try:
            if not isinstance(other, CoverageData):
                return 0
            msize = min(self.size, other.size)
            for i in range(msize):
                if other.bitmap[i] and not self.bitmap[i]:
                    self.bitmap[i] = 1
                    new += 1
            self._points_cache = None
        except Exception:
            return 0
        return new

    def __len__(self) -> int:
        # 统计位图中为 1 的字节数量（视作覆盖点数）
        return sum(1 for b in self.bitmap if b)

    def to_bitmap(self, size: int = BITMAP_SIZE) -> bytearray:
        """返回位图副本（长度为 size）。"""
        if size == self.size:
            return bytearray(self.bitmap)
        # 若需要不同大小，则按索引映射
        out = bytearray(size)
        for i, b in enumerate(self.bitmap):
            if b:
                out[i % size] = 1
        return out

    @property
    def points(self) -> Set[int]:
        """按需构建并返回整数点集合（仅在显式访问时计算）。"""
        if self._points_cache is None:
            s = set()
            for i, b in enumerate(self.bitmap):
                if b:
                    s.add(i)
            self._points_cache = s
        return self._points_cache


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
