"""
Splice mutator

从语料库中抽取另一条样本，与当前样本在随机断点处拼接，生成混合样本。

用途：将两条输入的有用片段合并，可能构造出触发新路径或边界条件的组合输入。
"""
from typing import Iterable, Sequence
import random


class SpliceMutator:
    """从给定语料池中选取另一条样本并在随机断点拼接。

    参数:
      corpus: 可选的语料列表（bytes 序列）。
      attempts: 每次 mutate 时尝试拼接的次数。
    """

    def __init__(self, corpus: Sequence[bytes] = None, attempts: int = 8):
        # 将语料保存为列表以便随机选择
        self.corpus = list(corpus) if corpus else []
        self.attempts = attempts

    def set_corpus(self, corpus: Sequence[bytes]):
        """更新语料池（可在运行时注入外部 corpus）。"""
        self.corpus = list(corpus)

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """对当前输入尝试与语料中其他样本拼接，yield 拼接结果。

        - 若语料为空，则不产生任何变体。
        - 每次选择一条随机样本 `other`，随机选择 `data` 和 `other` 的断点并拼接。
        """
        if not self.corpus:
            return
        for _ in range(self.attempts):
            other = random.choice(self.corpus)
            if not other:
                continue
            # 随机断点（允许断点为 0 或 len，以支持前缀/后缀拼接）
            a_split = random.randint(0, len(data))
            b_split = random.randint(0, len(other))
            out = data[:a_split] + other[b_split:]
            yield out
