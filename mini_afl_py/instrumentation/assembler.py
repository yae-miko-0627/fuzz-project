"""AFL++ 编译命令生成器（最小实现，仅构造 afl-cc 命令）。

该模块仅提供用于生成 `afl-cc` 编译命令的函数，调用方负责在适当环境
（容器或主机）上执行该命令。移除所有运行时包装和 Python trace 回退逻辑。
"""

from __future__ import annotations

from typing import List, Optional, Dict


def afl_cc_command(source_files: str | List[str], out_binary: str,
                   cflags: Optional[List[str]] = None,
                   ldflags: Optional[List[str]] = None,
                   afl_cc_path: Optional[str] = None,
                   extra_env: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """构造用于通过 `afl-cc` 编译的命令与环境描述（不执行）。

    返回格式：{"cmd": [...], "env": {...}}
    """
    afl_cc = afl_cc_path or "afl-cc"
    files = source_files if isinstance(source_files, (list, tuple)) else [source_files]
    cmd: List[str] = [afl_cc]
    if cflags:
        cmd += list(cflags)
    cmd += ["-o", out_binary]
    cmd += list(files)
    if ldflags:
        cmd += list(ldflags)
    env = dict(extra_env) if extra_env else {}
    return {"cmd": cmd, "env": env}


def prepare_afl_cc_compile(source_path: str, out_binary: str, afl_cc_path: Optional[str] = None) -> Dict[str, object]:
    """兼容别名：简单调用 `afl_cc_command`。"""
    return afl_cc_command(source_path, out_binary, afl_cc_path=afl_cc_path)
