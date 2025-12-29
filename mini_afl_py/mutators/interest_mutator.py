"""
Interesting-values mutator

用一组“有趣值”（例如 0、-1 较大/较小边界值等）替换输入中的字节/多字节字段。

用途：有趣值通常能触发边界条件、溢出或特殊逻辑分支。
"""
from typing import Iterable, Optional, Sequence
import struct
import random


class InterestMutator:
    """用一组有趣值替换单字节/多字节字段。

    内部常量：`INTERESTING_8/16/32` 定义了常用的替换常量集合。
    """

    # 常用有趣值集合（按位宽分组）
    INTERESTING_8 = [0, 1, 0x7f, 0x80, 0xff]
    INTERESTING_16 = [0, 1, 0x7fff, 0x8000, 0xffff]
    INTERESTING_32 = [0, 1, 0x7fffffff, 0x80000000, 0xffffffff]

    def __init__(self, max_positions: int = 32, extra_values: Sequence[int] = None, endian: str = 'little'):
        # 限制尝试替换的位置数，避免对长输入做全覆盖
        self.max_positions = max_positions
        # 支持额外的有趣值集合（例如从字典/项目中提取的边界值）
        self.extra_values = list(extra_values) if extra_values else []
        # 端序，可用于 pack/unpack
        self.endian = endian

    def _replace_word(self, data: bytearray, off: int, size: int, value: int):
        """在偏移 off 处以宽度 size 替换为 value，返回新的 bytes 或 None。

        细节：对单字节直接赋值，多字节使用 struct.pack（小端）。
        """
        if off + size > len(data):
            return None
        out = bytearray(data)
        fmt = {1: 'B', 2: ('<H' if self.endian == 'little' else '>H'), 4: ('<I' if self.endian == 'little' else '>I')}[size]
        if size == 1:
            out[off] = value & 0xFF
        else:
            out[off:off+size] = struct.pack(fmt, value & ((1 << (size*8))-1))
        return bytes(out)

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """遍历输入的若干位置并替换为各类有趣值，yield 变体。"""
        if not data:
            return
        max_pos = min(len(data), self.max_positions)
        # 单字节替换（包含额外有趣值以及 +/-1 邻近变体）
        for pos in range(max_pos):
            pool8 = list(self.INTERESTING_8) + [v & 0xFF for v in self.extra_values]
            for v in pool8:
                res = self._replace_word(bytearray(data), pos, 1, v)
                if res is not None:
                    yield res
                # 邻近值
                for off in (-1, 1):
                    nv = (v + off) & 0xFF
                    res2 = self._replace_word(bytearray(data), pos, 1, nv)
                    if res2 is not None:
                        yield res2
        # 2 字节替换（按可能的起始位置尝试）
        # 2 字节替换（尝试常用值与其 +/-1 邻近、并为 signed 视角添加符号边界）
        for pos in range(0, len(data)-1):
            if pos >= self.max_positions:
                break
            pool16 = list(self.INTERESTING_16) + [v & 0xFFFF for v in self.extra_values]
            for v in pool16:
                for v2 in (v, (v - 1) & 0xFFFF, (v + 1) & 0xFFFF):
                    res = self._replace_word(bytearray(data), pos, 2, v2)
                    if res is not None:
                        yield res
        # 4 字节替换
        # 4 字节替换（包含一些负数/边界值的变体）
        for pos in range(0, len(data)-3):
            if pos >= self.max_positions:
                break
            pool32 = list(self.INTERESTING_32) + [v & 0xFFFFFFFF for v in self.extra_values]
            for v in pool32:
                for v2 in (v, (v - 1) & 0xFFFFFFFF, (v + 1) & 0xFFFFFFFF):
                    res = self._replace_word(bytearray(data), pos, 4, v2)
                    if res is not None:
                        yield res
