"""
最小化的 CommandTarget 实现（针对 Ubuntu Docker 环境）。

职责：
- 启动子进程运行被测程序（每次单独新进程），
- 支持 `stdin` 和 `file` 两种输入方式，
- 处理超时（kill 进程组），
- 返回最小且稳定的运行结果供上层调度器/评估器使用。
"""

from dataclasses import dataclass
import subprocess
import tempfile
import os
import time
from typing import List, Optional
from ..utils.config import DEFAULTS
from ..instrumentation.coverage import parse_afl_map, CoverageData
from ..instrumentation.shm_manager import run_target_with_shm


@dataclass
class CommandTargetResult:
    """最小化的运行结果结构。

    字段：
    - status: 'ok'|'crash'|'hang'|'error'
    - exit_code: 退出码（若可得）
    - timed_out: 是否超时
    - stdout/stderr: 子进程输出（bytes）
    - wall_time: 运行耗时（秒）
    - artifact_path: 若发生崩溃，保存触发输入的文件路径
    """

    status: str
    exit_code: Optional[int] = None
    timed_out: bool = False
    stdout: Optional[bytes] = None
    stderr: Optional[bytes] = None
    wall_time: float = 0.0
    artifact_path: Optional[str] = None
    # 可选的覆盖信息（由 instrumentation 提供），通常为 CoverageData
    coverage: Optional[object] = None


class CommandTarget:
    """简化版 CommandTarget。

    参数：
    - cmd: 命令列表，例如 ['/workspace/examples/test-instr']
    - workdir: 工作目录（默认使用临时目录）
    - timeout_default: 默认超时（秒）

    注意：覆盖信息不在此处收集，留给 instrumentation 模块。
    """

    def __init__(self, cmd: List[str], workdir: Optional[str] = None, timeout_default: float = 1.0):
        self.cmd = cmd
        self.workdir = workdir
        self.timeout_default = timeout_default

    def run(self, input_data: bytes, mode: str = "stdin", timeout: Optional[float] = None,
            extra_args: Optional[List[str]] = None) -> CommandTargetResult:
        """执行目标并返回最小结果。

        简要流程：
        1) 确定工作目录（默认临时目录），并在 file 模式下写入输入文件；
        2) 使用 subprocess.Popen 启动子进程（在 Unix 上创建新进程组以便 kill）；
        3) 使用 communicate() 带 timeout 捕获 stdout/stderr；超时时 kill 进程组并标记 hang；
        4) 若 returncode 显示异常（<0 或 >0），把输入保存为 artifact；
        5) 返回 CommandTargetResult。
        """

        timeout = timeout if timeout is not None else self.timeout_default
        extra_args = extra_args or []

        # 1) 工作目录与输入准备
        tmpdir = None
        if self.workdir is None:
            tmpdir = tempfile.TemporaryDirectory(prefix="miniafl_run_")
            run_workdir = tmpdir.name
        else:
            run_workdir = self.workdir

        input_path = None
        if mode == "file":
            # 在工作目录中写入临时输入文件
            fd, input_path = tempfile.mkstemp(prefix="input_", dir=run_workdir)
            os.close(fd)
            with open(input_path, "wb") as f:
                f.write(input_data)

        # 插装模式（当前仅支持 'shm_py' 或 'none'）
        instr_mode = DEFAULTS.get("instrumentation_mode")
        map_out = os.path.join(run_workdir, "afl_showmap.out")

        # 构造命令行
        cmd = list(self.cmd) + extra_args
        if mode == "file" and input_path is not None:
            # 约定：把文件路径作为最后一个参数传入目标
            cmd = cmd + [input_path]

        # 2) 启动子进程（在 Unix 上使用 setsid 创建新进程组）
        use_preexec = hasattr(os, "setsid")
        preexec_fn = (lambda: os.setsid()) if use_preexec else None

        start = time.time()
        try:
            # 使用 Python SHM 管理器（shm_py）创建 System V SHM 并运行目标
            if instr_mode == "shm_py":
                exit_code, timed_out, out, err, map_out_path = run_target_with_shm(cmd,
                                                                                   input_data=input_data,
                                                                                   mode=mode,
                                                                                   timeout=timeout,
                                                                                   workdir=run_workdir,
                                                                                   map_out=map_out)
            else:
                # 默认直接执行目标子进程（无覆盖采集）
                proc = subprocess.Popen(cmd,
                                        stdin=subprocess.PIPE if mode == "stdin" else None,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        cwd=run_workdir,
                                        preexec_fn=preexec_fn)

                # 发送输入（stdin 模式）并等待结果，处理超时
                try:
                    out, err = proc.communicate(input=input_data if mode == "stdin" else None, timeout=timeout)
                    timed_out = False
                except subprocess.TimeoutExpired:
                    timed_out = True
                    # 超时：先尝试终止，再强杀整个进程组
                    try:
                        if use_preexec:
                            os.killpg(os.getpgid(proc.pid), 15)  # SIGTERM
                        else:
                            proc.terminate()
                    except Exception:
                        pass
                    try:
                        out, err = proc.communicate(timeout=0.5)
                    except Exception:
                        try:
                            if use_preexec:
                                os.killpg(os.getpgid(proc.pid), 9)  # SIGKILL
                            else:
                                proc.kill()
                        except Exception:
                            pass
                        out, err = proc.communicate()

                exit_code = proc.returncode
        except Exception as e:
            # 启动失败视为 error
            end = time.time()
            if tmpdir:
                tmpdir.cleanup()
            return CommandTargetResult(status="error", exit_code=None, timed_out=False,
                                       stdout=None, stderr=str(e).encode(), wall_time=end - start,
                                       artifact_path=None)

        end = time.time()
        wall_time = end - start

        # 4) 决定状态并在崩溃时保存触发输入
        status = "ok"
        artifact_path = None
        if timed_out:
            status = "hang"
        else:
            # 若进程由信号结束（returncode < 0）或非零退出码，可视为 crash（简化策略）
            if exit_code is None:
                status = "error"
            elif exit_code != 0:
                status = "crash"
                try:
                    artifact_dir = os.path.join(run_workdir, "artifacts")
                    os.makedirs(artifact_dir, exist_ok=True)
                    artifact_path = os.path.join(artifact_dir, f"crash_input_{int(time.time()*1000)}.bin")
                    with open(artifact_path, "wb") as f:
                        f.write(input_data)
                except Exception:
                    artifact_path = None

        # 5) 返回最小结果
        result = CommandTargetResult(status=status,
                                     exit_code=exit_code,
                                     timed_out=timed_out,
                                     stdout=out,
                                     stderr=err,
                                     wall_time=wall_time,
                                     artifact_path=artifact_path)

        # 如果有 afl_showmap 或 shm_py 输出文件，尝试解析并把 CoverageData 放入 result.coverage
        try:
            if instr_mode == "afl" and os.path.exists(map_out):
                cov = parse_afl_map(map_out)
                result.coverage = cov
            if instr_mode == "shm_py" and os.path.exists(map_out):
                cov = parse_afl_map(map_out)
                result.coverage = cov
        except Exception:
            pass
        return result

