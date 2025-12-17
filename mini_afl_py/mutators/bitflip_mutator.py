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

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """对输入数据逐位翻转并 yield 每个翻转后的变体。

        注意：如果传入空数据，函数直接返回（不产生任何候选）。
        """
        if not data:
            return

        total_bits = len(data) * 8
        # 实际翻转数量为总比特数与 max_bits 的最小值
        limit = min(total_bits, self.max_bits)
        for bit in range(limit):
            byte_idx = bit // 8
            bit_idx = bit % 8
            # 读取目标字节并翻转指定比特
            b = data[byte_idx]
            flipped = bytes([b ^ (1 << bit_idx)])
            out = bytearray(data)
            out[byte_idx:byte_idx+1] = flipped
            # 返回新的 bytes 对象，保持原数据不变
            yield bytes(out)
