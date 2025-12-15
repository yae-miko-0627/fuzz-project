"""
mini_afl_py

MiniAFL 的 Python 包入口（占位）。

本文件仅包含包级说明，实际实现分散在子模块中：
- core: 模糊引擎核心和调度器
- instrumentation: 插装/埋点适配层
- mutators: 变异器集合与插件接口
- targets: 被测目标适配器（命令行/文件/网络等）
- utils: 公共工具与配置

所有子模块当前均为占位，实现将来补充。
"""

__all__ = [
    "core",
    "instrumentation",
    "mutators",
    "targets",
    "utils",
]

__version__ = "0.0.0"
