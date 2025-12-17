"""
Arithmetic mutator

对输入数据的单字节、2字节、4字节字段做小幅加减的变换。

用途：模拟溢出/边界值附近的整数变化，常用于触发整数相关的 bug 或代码路径。
"""
from typing import Iterable
import struct


class ArithMutator:
    """对字节/2字节/4字节值做小幅加减变换。

    参数:
      max_positions: 在输入前部尝试的字节位置上限（避免处理过长的输入全部位置）。
    """

    def __init__(self, max_positions: int = 32):
        # 为性能考虑，限制尝试的位置数量
        self.max_positions = max_positions

    def _apply_word(self, data: bytearray, off: int, size: int, delta: int):
        """在偏移 off 处按字节宽度 size 应用增量 delta，返回新的 bytes 或 None。

        说明：
        - 使用 little-endian 进行打包/解包以保持与常见 fuzzer 行为一致。
        - 仅在字段完整（长度足够）时进行替换，否则返回 None。
        """
        slice_ = data[off:off+size]
        if len(slice_) < size:
            return None
        # 处理单字节的简单情况
        if size == 1:
            val = slice_[0]
            new = (val + delta) & 0xFF
            out = bytearray(data)
            out[off] = new
            return bytes(out)
        # 使用 int.from_bytes / to_bytes 提高可读性（小端 little-endian）
        if size in (2, 4):
            # 从字节序列解出整数（小端）
            val = int.from_bytes(slice_, byteorder='little', signed=False)
            mask = (1 << (size * 8)) - 1
            # 应用增量并按位宽环绕（保持与原先行为一致）
            new = (val + delta) & mask
            out = bytearray(data)
            out[off:off+size] = new.to_bytes(size, byteorder='little', signed=False)
            return bytes(out)
        # 若 size 非 1/2/4，则不支持
        return None

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """生成若干对输入中不同位置、不同宽度应用小幅算术变换的变体。"""
        if not data:
            return
        max_pos = min(len(data), self.max_positions)
        # 常用的小增量/减量集合，可根据需要扩展
        deltas = [1, -1, 2, -2, 8, -8, 16, -16]
        # 单字节变换
        for pos in range(max_pos):
            for d in deltas:
                res = self._apply_word(bytearray(data), pos, 1, d)
                if res is not None:
                    yield res
        # 多字节（2字节、4字节）变换：按可能的对齐位置尝试
        for size in (2, 4):
            for pos in range(0, len(data)-size+1):
                if pos >= self.max_positions:
                    break
                for d in deltas:
                    res = self._apply_word(bytearray(data), pos, size, d)
                    if res is not None:
                        yield res
