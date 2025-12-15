"""
编译期插装占位模块

此处用于放置将目标编译为带插装二进制的辅助函数，例如 wrapper 脚本、编译选项构建等。
"""

def prepare_compile_args(source_path: str) -> dict:
    """返回用于插装编译的参数（占位）。"""
    return {"source": source_path, "cflags": ["-g"]}
