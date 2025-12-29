"""
Arithmetic mutator

对输入数据的单字节、2字节、4字节字段做小幅加减的变换。

用途：模拟溢出/边界值附近的整数变化，常用于触发整数相关的 bug 或代码路径。
"""
from typing import Iterable, Optional, Sequence
import struct
import random


class ArithMutator:
    """对字节/2字节/4字节值做小幅加减变换。

    参数:
      max_positions: 在输入前部尝试的字节位置上限（避免处理过长的输入全部位置）。
    """

    def __init__(self, max_positions: int = 32, sizes: Sequence[int] = (1, 2, 4), endian: str = 'little', wrap: bool = True):
        # 为性能考虑，限制尝试的位置数量
        self.max_positions = max_positions
        # 支持的字宽（字节）集合
        self.sizes = tuple(sizes)
        # 字节序：'little' 或 'big'
        self.endian = endian
        # 是否按位宽环绕（wrap）或饱和（saturate）
        self.wrap = bool(wrap)
        # 默认增量集合（含小幅/较大/边界附近的值）
        self.default_deltas = [1, -1, 2, -2, 8, -8, 16, -16, 127, -128, 255, -255]

    def _apply_word(self, data: bytearray, off: int, size: int, delta: int):
        """在偏移 off 处按字节宽度 size 应用增量 delta，返回新的 bytes 或 None。

        说明：
        - 使用小端（little-endian）进行打包/解包以保持与常见 fuzzer 行为一致。
        - 仅在字段完整（长度足够）时进行替换，否则返回 None。
        """
        slice_ = data[off:off+size]
        if len(slice_) < size:
            return None
        # 处理单字节的简单情况
        if size == 1:
            val = slice_[0]
            if self.wrap:
                new = (val + delta) & 0xFF
            else:
                new = max(0, min(255, val + delta))
            out = bytearray(data)
            out[off] = new
            return bytes(out)
        # 使用 int.from_bytes / to_bytes 提高可读性（小端）
        if size in self.sizes:
            # 从字节序列解出整数（可配置端序）
            val = int.from_bytes(slice_, byteorder=self.endian, signed=False)
            mask = (1 << (size * 8)) - 1
            if self.wrap:
                new = (val + delta) & mask
            else:
                new = max(0, min(mask, val + delta))
            out = bytearray(data)
            out[off:off+size] = new.to_bytes(size, byteorder=self.endian, signed=False)
            return bytes(out)
        # 若 size 非 1/2/4，则不支持
        return None

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """生成若干对输入中不同位置、不同宽度应用小幅算术变换的变体。"""
        if not data:
            return
        # 随机采样位置以避免对超长输入穷举
        length = len(data)
        positions = list(range(length))
        random.shuffle(positions)
        positions = positions[:min(self.max_positions, length)]
        # 组合 deltas：默认 + 随机更大步长
        deltas = list(self.default_deltas)
        deltas += [random.randint(-1000, 1000) for _ in range(4)]
        # 对每个选定的位置和每个宽度尝试若干增量
        for pos in positions:
            for size in self.sizes:
                if pos + size > length:
                    continue
                # 随机打乱 deltas 以提高多样性
                random.shuffle(deltas)
                for d in deltas[:8]:
                    res = self._apply_word(bytearray(data), pos, size, d)
                    if res is not None:
                        yield res
