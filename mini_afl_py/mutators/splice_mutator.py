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
        align: 对齐字节数（例如 2/4）以避免破坏多字节边界。
        similarity_threshold: 选择拼接样本时希望与当前样本的最小不同度（0-1），越高越偏好差异更大的样本。
    """

    def __init__(self, corpus: Sequence[bytes] = None, attempts: int = 8, min_out: int = 1, max_out: int = 4096, align: int = 1, similarity_threshold: float = 0.1):
        # 将语料保存为列表以便随机选择
        self.corpus = list(corpus) if corpus else []
        self.attempts = attempts
        # 输出长度限制，避免产生过长或过短样本
        self.min_out = min_out
        self.max_out = max_out
        # 对齐边界（字节数），在选择断点时会对齐到此边界
        self.align = max(1, int(align))
        # 期望拼接对象与当前样本的最小差异比例（0..1）
        self.similarity_threshold = float(similarity_threshold)
        # 保存原始参数以便激进模式下放大/恢复
        self._orig = {
            'attempts': int(self.attempts),
            'min_out': int(self.min_out),
            'max_out': int(self.max_out),
            'align': int(self.align),
            'similarity_threshold': float(self.similarity_threshold)
        }

    def apply_aggression(self, scale: float) -> None:
        """在激进模式下增加拼接尝试次数并放宽相似度约束以鼓励更多拼接。"""
        try:
            s = max(1.0, float(scale))
            self.attempts = max(1, int(self._orig['attempts'] * s))
            # 放宽相似度阈值（更容易选择差异较小的样本以提高拼接机会）
            self.similarity_threshold = max(0.0, float(self._orig['similarity_threshold'] * (1.0 - 0.25 * (s - 1.0))))
            # 允许更大的输出长度
            self.max_out = max(self._orig['max_out'], int(self._orig['max_out'] * s))
            # 在激进模式下可能增加对齐宽度以尝试跨边界拼接
            self.align = max(1, int(self._orig['align']))
        except Exception:
            pass

    def clear_aggression(self) -> None:
        try:
            self.attempts = int(self._orig['attempts'])
            self.min_out = int(self._orig['min_out'])
            self.max_out = int(self._orig['max_out'])
            self.align = int(self._orig['align'])
            self.similarity_threshold = float(self._orig['similarity_threshold'])
        except Exception:
            pass

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
            # 尝试挑选一个与当前不同的样本，优先选择与当前差异度较高的样本
            if not self.corpus:
                return
            candidates = self.corpus
            # 随机采样若干候选以评估相似性
            sample_k = min(len(candidates), 8)
            sample = random.sample(candidates, sample_k)
            # 计算简单相似度（前缀相同长度占比作为近似）
            def similarity(a: bytes, b: bytes) -> float:
                if not a or not b:
                    return 0.0
                # prefix length
                m = min(len(a), len(b))
                i = 0
                while i < m and a[i] == b[i]:
                    i += 1
                return i / max(len(a), len(b))

            # 从样本中尽量挑选与 data 相似度低于阈值的 other
            other = None
            random.shuffle(sample)
            for cand in sample:
                if cand is None or cand == data:
                    continue
                sim = similarity(data, cand)
                if sim <= self.similarity_threshold:
                    other = cand
                    break
            # 若未找到足够不同的，退回为任意不同样本
            if other is None:
                for cand in sample:
                    if cand and cand != data:
                        other = cand
                        break
            if other is None:
                continue

            # 多种拼接策略：前缀+后缀、保持前缀、保持后缀、交叉
            strategy = random.choice(['prefix_suffix', 'keep_prefix', 'keep_suffix', 'crossover'])
            if strategy == 'prefix_suffix':
                # 对断点应用对齐
                a_split = random.randint(0, len(data))
                a_split = (a_split // self.align) * self.align
                b_split = random.randint(0, len(other))
                b_split = (b_split // self.align) * self.align
                out = data[:a_split] + other[b_split:]
            elif strategy == 'keep_prefix':
                a_split = random.randint(0, len(data))
                a_split = (a_split // self.align) * self.align
                out = data[:a_split] + other
            elif strategy == 'keep_suffix':
                b_split = random.randint(0, len(other))
                b_split = (b_split // self.align) * self.align
                out = data + other[b_split:]
            else:  # crossover
                # 选择交叉点并拼接中间片段
                if len(data) == 0 or len(other) == 0:
                    continue
                a_split = random.randint(0, len(data)-1)
                a_split = (a_split // self.align) * self.align
                b_split = random.randint(1, len(other))
                b_split = (b_split // self.align) * self.align
                out = data[:a_split] + other[b_split:]

            # 长度约束过滤
            if len(out) < self.min_out or len(out) > self.max_out:
                continue
            yield out
