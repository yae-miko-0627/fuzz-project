"""AFL helper utilities: locate, build and invoke `afl-cc`.

新增 `ensure_afl_built()`：在容器/镜像内尝试自动构建 AFL++（若源码存在），并返回可执行的 `afl-cc` 路径。

设计原则：在容器内优先自动化构建（默认查找 `AFLplusplus-stable` 目录并运行 `make distrib`），
在构建失败或未提供源码时，返回明确的错误提示，指导用户如何手动处理。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import List, Optional


def find_afl_cc(known_dirs: Optional[List[str]] = None) -> Optional[str]:
    """查找 afl-cc 可执行文件。

    搜索顺序：
      1. 环境变量 `AFL_CC_PATH`
      2. PATH（`shutil.which('afl-cc')`）
      3. 在 `known_dirs` 列表中查找 `afl-cc` 或 `afl-cc.exe`
    """
    env_path = os.environ.get("AFL_CC_PATH")
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path

    which_path = shutil.which("afl-cc")
    if which_path:
        return which_path

    if known_dirs:
        for d in known_dirs:
            p1 = os.path.join(d, "afl-cc")
            p2 = os.path.join(d, "afl-cc.exe")
            if os.path.isfile(p1) and os.access(p1, os.X_OK):
                return p1
            if os.path.isfile(p2) and os.access(p2, os.X_OK):
                return p2

    return None


def compile_with_afl_cc(afl_cc_path: Optional[str], src_path: str, out_path: str,
                        extra_args: Optional[List[str]] = None,
                        cwd: Optional[str] = None, env: Optional[dict] = None) -> subprocess.CompletedProcess:
    """使用 afl-cc 编译源文件到可执行文件。

    若 `afl_cc_path` 为 None，会尝试 `find_afl_cc()` 查找并在失败时抛出 RuntimeError。
    返回 subprocess.CompletedProcess（不自动抛出 CalledProcessError）。
    """
    if not afl_cc_path:
        afl_cc_path = find_afl_cc()
    if not afl_cc_path:
        raise RuntimeError("afl-cc not found; call ensure_afl_built() or set AFL_CC_PATH")

    cmd = [afl_cc_path, "-o", out_path, src_path]
    if extra_args:
        cmd.extend(extra_args)

    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)

    completed = subprocess.run(cmd, cwd=cwd, env=proc_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return completed


def ensure_afl_built(known_dirs: Optional[List[str]] = None, build_dir: Optional[str] = None,
                     install_prefix: str = "/opt/afl", build_cmd: Optional[List[str]] = None,
                     timeout: int = 600) -> str:
    """确保 afl-cc 可用：先查找，若未找到且存在 AFL++ 源，则尝试构建。

    参数:
      known_dirs: 额外的目录列表用于查找已存在的 afl-cc 或 AFL++ 源（相对或绝对路径）。
      build_dir: 指定 AFL++ 源目录（若未提供，会在 `known_dirs` 中查找名为 'AFLplusplus-stable' 的目录）。
      install_prefix: 构建后复制可执行/工具的目标前缀（默认 /opt/afl）。
      build_cmd: 覆盖默认的构建命令（默认 ['make','distrib'] 或 ['make']）。
      timeout: 子进程超时（秒）。

    返回 afl-cc 的可执行路径。
    抛出 RuntimeError 若构建或查找失败。
    """
    # 1) 先尝试直接查找
    afl = find_afl_cc(known_dirs=known_dirs)
    if afl:
        return afl

    # 2) 找到可能的源码目录
    candidates = []
    if build_dir:
        candidates.append(build_dir)
    if known_dirs:
        candidates.extend(known_dirs)

    # 默认查找常见目录名
    repo_root = os.getcwd()
    candidates.append(os.path.join(repo_root, "AFLplusplus-stable"))
    candidates.append(os.path.join(repo_root, "AFLplusplus"))

    src_dir = None
    for c in candidates:
        if c and os.path.isdir(c):
            # 判断是否包含 Makefile
            if os.path.isfile(os.path.join(c, "Makefile")) or os.path.isfile(os.path.join(c, "GNUmakefile")):
                src_dir = c
                break

    if not src_dir:
        raise RuntimeError("AFL++ source not found; set 'build_dir' or place AFLplusplus-stable in repo root")

    # 3) 执行构建
    # 默认使用 make distrib 或 make
    if not build_cmd:
        build_cmd = ["make", "distrib"]

    try:
        proc = subprocess.run(build_cmd, cwd=src_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Building AFL++ timed out after {timeout}s: {e}")

    if proc.returncode != 0:
        # 尝试 fallback build: make
        fallback = subprocess.run(["make"], cwd=src_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if fallback.returncode != 0:
            raise RuntimeError(f"AFL++ build failed. stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}\n\nFallback stdout:\n{fallback.stdout}\n\nFallback stderr:\n{fallback.stderr}")

    # 4) 尝试在 install_prefix 或 src_dir 中查找 afl-cc
    possible = [os.path.join(install_prefix, "afl-cc"), os.path.join(src_dir, "afl-cc"), shutil.which("afl-cc")]
    for p in possible:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p

    # 5) 如果在构建目录下生成了工具层次，尝试拷贝到 install_prefix
    # （尽量保证 install_prefix 可写）
    try:
        bin_candidates = []
        for root, dirs, files in os.walk(src_dir):
            for name in files:
                if name == 'afl-cc' or name == 'afl-cc.exe':
                    bin_candidates.append(os.path.join(root, name))
        if bin_candidates:
            os.makedirs(install_prefix, exist_ok=True)
            for b in bin_candidates:
                shutil.copy2(b, install_prefix)
            afl_after = os.path.join(install_prefix, 'afl-cc')
            if os.path.isfile(afl_after) and os.access(afl_after, os.X_OK):
                return afl_after
    except Exception:
        pass

    raise RuntimeError("afl-cc not found after build; inspect build logs in AFL++ source directory")


__all__ = ["find_afl_cc", "compile_with_afl_cc", "ensure_afl_built"]
