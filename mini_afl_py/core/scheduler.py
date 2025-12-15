"""
调度器占位模块

调度器负责：
- 管理种子/输入队列
- 选择待变异样本
- 调用变异器生成候选输入
- 调用执行模块运行目标并收集覆盖信息
- 基于能量调度策略调整变异次数/优先级

此处仅提供接口说明和占位类，具体实现将在后续开发中填充。
"""

from typing import Any, Iterable


class Scheduler:
    """调度器占位类。

    方法说明：
    - add_seed(seed): 将新的种子加入队列
    - next_candidate(): 返回下一个待变异/执行的样本
    - report_result(result): 接收执行结果以便调度决策
    """

    def __init__(self) -> None:
        # 在未来这里初始化队列、状态、统计信息等
        self._queue = []

    def add_seed(self, seed: bytes) -> None:
        """将种子加入调度队列（占位）。"""
        self._queue.append(seed)

    def next_candidate(self) -> Any:
        """返回下一个候选输入（占位）。"""
        if self._queue:
            return self._queue.pop(0)
        return None

    def report_result(self, result: Any) -> None:
        """接收执行结果以便更新状态（占位）。"""
        pass
