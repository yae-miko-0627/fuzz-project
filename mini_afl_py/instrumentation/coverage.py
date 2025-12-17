"""
轻量级覆盖数据收集器（占位实现）。

目的：
- 提供一个最小的 CoverageData / CoverageCollector API，供后续把覆盖信息纳入 `Scheduler.calculate_score()`。
- 当前实现提供：从 trace 输出文件的占位解析、合并覆盖集合、导出简单哈希位图（用于快速比较/去重）。

说明：不同插装/工具会输出不同格式（gcov、llvm-cov、trace 模块、lcov 等），本模块可逐步扩展解析器以适配项目需要。
"""
from __future__ import annotations

import hashlib
import os
from typing import Set, Tuple, Iterable


class CoverageData:
    """存储覆盖位置的简单容器。

    内部以 (filename, lineno) 的元组集合保存。提供合并与到位图的导出。
    """

    def __init__(self) -> None:
        self.points: Set[Tuple[str, int]] = set()

    def add(self, filename: str, lineno: int) -> None:
        self.points.add((os.path.normpath(filename), int(lineno)))

    def merge(self, other: "CoverageData") -> None:
        self.points.update(other.points)

    def __len__(self) -> int:
        return len(self.points)

    def to_bitmap(self, size: int = 65536) -> bytearray:
        """基于文件名+行号的哈希，生成固定大小的位图（字节数组），用于快速比较/去重。

        这不是高保真的位图，而是用于调度器在没有精确工具时的近似判别。
        """
        bitmap = bytearray(size)
        for fname, ln in self.points:
            h = hashlib.sha1(f"{fname}:{ln}".encode("utf-8")).digest()
            idx = int.from_bytes(h[:4], "little") % size
            bitmap[idx] = 1
        return bitmap


def parse_trace_count_file(path: str) -> CoverageData:
    """尝试解析 trace 模块输出的计数文件（占位解析）。

    注意：不同 python trace/coverage 的输出格式不同。本实现做尽可能稳健的解析：
    - 如果 `path` 是目录，将扫描目录下所有以 `.cover` 或 `.cov` 结尾的文件并尝试解析行号。
    - 如果是单个文件，会尝试解析每一行，匹配 `filename:lineno` 风格的记录（若无法识别则返回空）。
    """
    cov = CoverageData()
    if not os.path.exists(path):
        return cov

    if os.path.isdir(path):
        for fn in os.listdir(path):
            if fn.endswith(".cover") or fn.endswith(".cov") or fn.endswith(".txt"):
                p = os.path.join(path, fn)
                _parse_text_file_into(p, cov)
        return cov

    # 单文件解析尝试
    _parse_text_file_into(path, cov)
    return cov


def _parse_text_file_into(path: str, cov: CoverageData) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                # 常见风格： '  filename:lineno: ...' 或 'filename: lineno: ...'
                parts = line.split(":")
                if len(parts) >= 2:
                    fname = parts[0].strip()
                    try:
                        ln = int(parts[1].strip())
                        cov.add(fname, ln)
                        continue
                    except Exception:
                        pass
                # 无法解析则跳过
    except Exception:
        return


__all__ = ["CoverageData", "parse_trace_count_file"]
