"""
Bit-flip mutator

逐位翻转变异器。对输入数据中的若干比特位逐一取反，生成若干候选样本。

设计要点：
- 为避免产生过多变体，仅翻转输入的前 `max_bits` 个比特（默认 64）。
- 翻转按位（bit）进行，但实现中直接按字节索引并使用位运算修改单个比特。

输出：对于每一次翻转，产出一条新的 bytes 对象作为候选样本。
"""
from typing import Iterable, Optional
import random
import math


class BitflipMutator:
    """生成若干基于逐位翻转的变体。

    参数:
      max_bits: 最多尝试翻转的比特数（从输入开头计数），以限制产出数量。
    """

    def __init__(self, max_bits: int = 256, sample_limit: int = 256):
        # 限制尝试翻转的比特总数，避免爆炸性输出
        self.max_bits = max_bits
        # 对于过长输入，采样时的变体上限
        self.sample_limit = sample_limit
        # 支持多种变异模式
        self.modes = ['single_bit', 'multi_bit', 'byte', 'burst', 'window']
        self.window_sizes = [2, 4, 8]

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """对输入数据逐位翻转并 yield 每个翻转后的变体。

        注意：如果传入空数据，函数直接返回（不产生任何候选）。
        """
        if not data:
            return

        total_bits = len(data) * 8
        # 对大输入做采样
        limit = min(total_bits, self.max_bits)

        # 以熵/多样性为线索选取更“有趣”的字节位置：简单启发式
        def byte_score(b: int) -> float:
            # 非 0 / 0xff 的字节更可能包含信息
            if b == 0 or b == 0xFF:
                return 0.1
            # 越靠近 ASCII 可打印范围得分越高一点
            if 32 <= b <= 126:
                return 1.0
            return 0.5

        scores = [byte_score(b) for b in data]
        # 生成位置池，按分数加权采样
        positions = list(range(len(data)))
        if len(positions) > 0:
            weights = [s + 0.01 for s in scores]
            # 采样若干位置作为翻转候选（有放回）
            chosen = random.choices(positions, weights=weights, k=min(len(positions), self.sample_limit))
        else:
            chosen = []

        # single_bit / multi_bit / burst / byte / window 模式的混合采样
        yielded = 0
        for pos in chosen:
            if yielded >= self.sample_limit:
                break
            # 单比特翻转在该字节的随机位
            bit_idx = random.randrange(8)
            out = bytearray(data)
            out[pos] ^= (1 << bit_idx)
            yield bytes(out)
            yielded += 1

            # multi_bit：在附近字节跨位翻转若干位
            if yielded < self.sample_limit and random.random() < 0.3:
                nbits = random.choice([2, 3, 4, 5])
                out = bytearray(data)
                for _ in range(nbits):
                    p = min(len(data)-1, max(0, pos + random.randint(-2, 2)))
                    bidx = random.randrange(8)
                    out[p] ^= (1 << bidx)
                yield bytes(out)
                yielded += 1

            # byte: 取反整个字节
            if yielded < self.sample_limit and random.random() < 0.25:
                out = bytearray(data)
                out[pos] ^= 0xFF
                yield bytes(out)
                yielded += 1

            # burst: 翻转一个连续位段（随机长度）
            if yielded < self.sample_limit and random.random() < 0.15:
                w = random.choice(self.window_sizes)
                if pos + w <= len(data):
                    out = bytearray(data)
                    for j in range(pos, pos + w):
                        out[j] ^= 0xFF
                    yield bytes(out)
                    yielded += 1

        # 若仍不足，做少量全局随机 N-bit 翻转
        while yielded < min(self.sample_limit, 16):
            out = bytearray(data)
            bits = random.randint(1, 16)
            for _ in range(bits):
                p = random.randrange(len(data))
                bidx = random.randrange(8)
                out[p] ^= (1 << bidx)
            yield bytes(out)
            yielded += 1
