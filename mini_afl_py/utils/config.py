"""
配置占位模块

提供默认配置和简单的解析接口，实际配置项将在开发过程中扩展。
"""

DEFAULTS = {
    "fuzz_time": 3600,  # 默认模糊运行秒数
    "max_inputs": 10000,
}

# 与 AFL++ 相关的默认配置
DEFAULTS.update({
    # instrumentation_mode: 'none'|'python-trace'|'afl'|'shm_py'
    # 默认采用 Python SHM 管理（shm_py），兼容 afl-cc 插装
    "instrumentation_mode": "shm_py",
    # 系统上 afl-showmap 的命令（可被覆盖）
    "afl_showmap_path": "afl-showmap",
    # 系统上 afl-cc 的命令（用于构建目标，可为空，表示手动构建）
    "afl_cc_path": "afl-cc",
    # 如果要从 AFL queue 导入种子，可配置队列路径（默认为 None，不自动导入）
    "afl_queue_dir": None,
})


def load_config(path: str) -> dict:
    """从文件加载配置（占位实现）。

    当前版本仅返回 DEFAULTS。
    """
    return DEFAULTS.copy()
