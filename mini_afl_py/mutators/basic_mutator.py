"""
基础变异器占位实现

提供一个简单的变异器类接口，实际变异策略将在此基础上扩展或替换。
"""

from typing import Iterable


class BasicMutator:
    """占位变异器：接收 bytes，返回可迭代的变异候选 bytes。"""

    def __init__(self):
        pass

    def mutate(self, data: bytes) -> Iterable[bytes]:
        """返回对 data 的若干变体（占位）。"""
        # 占位：直接返回原数据的单元素迭代
        yield data
