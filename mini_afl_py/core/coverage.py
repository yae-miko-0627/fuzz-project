"""
覆盖/追踪收集占位模块

负责定义覆盖数据结构、采集接口和简单的封装。具体的采集实现（例如内存映射、追踪后端）由 instrumentation 子模块提供。
"""

from typing import Any, Dict


class Coverage:
    """覆盖信息占位类。"""

    def __init__(self) -> None:
        self.data: Dict[int, int] = {}

    def merge(self, other: "Coverage") -> None:
        """合并另一个覆盖对象（占位）。"""
        for k, v in other.data.items():
            self.data[k] = max(self.data.get(k, 0), v)
