"""
Bit-flip mutator

逐位翻转变异器。对输入数据中的若干比特位逐一取反，生成若干候选样本。

设计要点：
- 为避免产生过多变体，仅翻转输入的前 `max_bits` 个比特（默认 64）。
- 翻转按位（bit）进行，但实现中直接按字节索引并使用位运算修改单个比特。

输出：对于每一次翻转，产出一条新的 bytes 对象作为候选样本。
"""
from typing import Iterable


class BitflipMutator:
    """生成若干基于逐位翻转的变体。

    参数:
      max_bits: 最多尝试翻转的比特数（从输入开头计数），以限制产出数量。
    """

    def __init__(self, max_bits: int = 64):
        # 限制翻转的比特总数，避免爆炸性输出
        self.max_bits = max_bits
        # 支持额外模式：单比特、双比特、整字节、跨字节窗口
        # 这些模式会按顺序产出，增加变异多样性
        self.modes = ['single_bit', 'two_bits', 'byte', 'window']
        # 窗口大小（字节数）用于 window 模式
        self.window_sizes = [2, 4]

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """对输入数据逐位翻转并 yield 每个翻转后的变体。

        注意：如果传入空数据，函数直接返回（不产生任何候选）。
        """
        if not data:
            return

        if not data:
            return

        total_bits = len(data) * 8
        # 统一上限，避免输出过大
        limit = min(total_bits, self.max_bits)

        # 1) 单比特翻转（覆盖输入各处，按 limit 限制）
        for bit in range(limit):
            byte_idx = bit // 8
            bit_idx = bit % 8
            b = data[byte_idx]
            flipped = bytes([b ^ (1 << bit_idx)])
            out = bytearray(data)
            out[byte_idx:byte_idx+1] = flipped
            yield bytes(out)

        # 2) 双比特（在同一字节内翻转两个不同位）
        for bit in range(min(limit, total_bits)):
            byte_idx = bit // 8
            if len(data) == 0:
                break
            b = data[byte_idx]
            # 翻转当前位和下一个位（循环到字节边界）
            bit_idx = bit % 8
            bit_idx2 = (bit_idx + 1) % 8
            flipped = bytes([b ^ ((1 << bit_idx) | (1 << bit_idx2))])
            out = bytearray(data)
            out[byte_idx:byte_idx+1] = flipped
            yield bytes(out)

        # 3) 整字节翻转（将某个字节取反）
        for i in range(min(len(data), max(1, self.max_bits // 8))):
            out = bytearray(data)
            out[i] = out[i] ^ 0xFF
            yield bytes(out)

        # 4) 窗口翻转：对连续字节窗口做随机翻转（尝试一组窗口大小）
        for w in self.window_sizes:
            if len(data) < w:
                continue
            for start in range(0, len(data) - w + 1):
                out = bytearray(data)
                for j in range(start, start + w):
                    out[j] = out[j] ^ 0xFF
                yield bytes(out)
