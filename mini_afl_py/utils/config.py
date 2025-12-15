"""
配置占位模块

提供默认配置和简单的解析接口，实际配置项将在开发过程中扩展。
"""

DEFAULTS = {
    "fuzz_time": 3600,  # 默认模糊运行秒数
    "max_inputs": 10000,
}


def load_config(path: str) -> dict:
    """从文件加载配置（占位实现）。

    当前版本仅返回 DEFAULTS，后续会实现文件解析和覆盖。
    """
    return DEFAULTS.copy()
