"""
编译期插装占位模块

此处用于放置将目标编译为带插装二进制的辅助函数，例如 wrapper 脚本、编译选项构建等。
"""

def prepare_compile_args(source_path: str) -> dict:
    """返回用于插装编译的参数（占位）。"""
    return {"source": source_path, "cflags": ["-g"]}


def prepare_instrumented_run(cmd: list, mode: str = "none", out_dir: str | None = None) -> tuple:
    """
    为运行目标构造插装命令与环境。

    参数:
      - cmd: 原始命令（列表形式），例如 `[python, script.py, ...]` 或可执行二进制路径开头。
      - mode: 插装模式，当前支持：
          * "none" - 不做插装，直接返回原始 cmd 与空 env。
          * "python-trace" - 对以 Python 解释器为首的命令，使用 `python -m trace --count` 进行计数插装，生成覆盖输出文件到 `out_dir`。
      - out_dir: 插装输出目录（trace 文件写入位置）。若为 None 且 mode != 'none'，会默认为当前目录。

    返回 (cmd2, env) : 可直接传给 `subprocess` 的命令列表和环境覆盖字典（只包含需要设置/覆盖的键）。

    注意：该函数尽量提供通用的包装策略，但对复杂的目标或非 Python 程序需使用外部专用插装工具（如 afl-gcc、clang 插装、qemu 模式等）。
    """
    if mode is None:
        mode = "none"

    if mode == "none":
        return cmd, {}

    if mode == "python-trace":
        # 仅在命令以 Python 可执行为首时进行包装
        if not cmd:
            return cmd, {}
        exe = cmd[0]
        # 简单判断：文件名包含 'python' 或以 'py' 结尾
        if "python" in exe.lower() or exe.lower().endswith("python.exe") or exe.lower().endswith("python"):
            out_dir = out_dir or "."
            trace_out = f"{out_dir}/trace.count"
            # trace 模块的 --count 会在当前目录生成 `.cover` 文件；为简单起见我们使用 --outfile 参数
            wrapped = [exe, "-m", "trace", "--count", "--outfile", trace_out, "--"] + cmd[1:]
            env = {}
            return wrapped, env
        else:
            # 非 Python 二进制暂不支持自动插装
            return cmd, {}

    # 未知模式 -> 不插装
    return cmd, {}
