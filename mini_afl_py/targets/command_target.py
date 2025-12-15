"""
命令行目标适配器（占位）

此类用于以命令行方式运行被测程序并收集执行结果/崩溃信息。
"""

from typing import List, Dict, Any


class CommandTarget:
    """占位的命令行目标封装器。

    方法示例：
    - run(input_bytes): 将输入传给目标并返回执行结果摘要
    """

    def __init__(self, cmd: List[str]):
        self.cmd = cmd

    def run(self, input_data: bytes) -> Dict[str, Any]:
        """运行目标并返回结果（占位）。"""
        return {"status": "ok", "signal": None}
