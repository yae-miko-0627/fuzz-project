"""
在 Linux 平台上用于 AFL 风格共享内存的 Python 管理器。

功能：
- 创建 System V 共享内存段；
- 将共享内存 id 通过环境变量 `__AFL_SHM_ID` 传递给子进程（被测程序由 afl-cc 插装后会向该内存写位图）；
- 启动目标进程并等待其完成；
- 运行结束后读取共享内存中的覆盖位图（默认 65536 字节）并写入到指定的 map 文件。

该实现避免依赖外部二进制 shim，可直接在 Python 中使用，适用于 Ubuntu 22.04。
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import tempfile
from typing import Optional, Tuple

# Constants
MAP_SIZE = 65536

# Load libc for System V shm calls
libc = ctypes.CDLL("libc.so.6")

# shmget, shmat, shmdt, shmctl
shmget = libc.shmget
shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
shmget.restype = ctypes.c_int

shmat = libc.shmat
shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
shmat.restype = ctypes.c_void_p

shmdt = libc.shmdt
shmdt.argtypes = [ctypes.c_void_p]
shmdt.restype = ctypes.c_int

shmctl = libc.shmctl
shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
shmctl.restype = ctypes.c_int

# IPC_RMID constant
IPC_RMID = 0


def create_shm(size: int = MAP_SIZE) -> int:
    """创建 System V 共享内存段并返回其 shmid（整数）。

    - 使用 IPC_PRIVATE 表示内核分配一个新的、唯一的共享内存段（匿名、不可预测的 key），
      这对于每次运行都使用独立 SHM 的场景非常合适，避免与其他进程冲突。
    - 权限采用 0600（仅当前用户可读写），以降低跨用户访问风险。
    - 如果创建失败（返回负值），抛出 OSError 以便上层进行错误处理或重试。
    """
    IPC_PRIVATE = 0
    IPC_CREAT = 0o1000
    perms = 0o600
    # 调用 libc.shmget 创建共享内存，返回的是一个整数 id（shmid）
    shmid = shmget(IPC_PRIVATE, size, IPC_CREAT | perms)
    if shmid < 0:
        # shmget 返回负值表示失败（例如权限不足或内核限制），抛出异常
        raise OSError("shmget failed, check permissions and kernel settings")
    return int(shmid)


def read_shm_to_bytes(shmid: int, size: int = MAP_SIZE) -> bytes:
    """挂接指定的 shmid，读取指定大小字节并返回 bytes，然后分离（detach）。

    步骤说明：
    1. 调用 `shmat(shmid, NULL, 0)` 将共享内存映射到当前进程地址空间，返回地址指针；
    2. 检查返回值是否等于 (void *) -1，若是则表示挂接失败；
    3. 通过 ctypes 把该地址视作字符数组并读取 `size` 字节内容；
    4. 无论读取成功与否，都必须调用 `shmdt` 解除挂接以避免资源泄露。
    """
    addr = shmat(shmid, None, 0)
    # shmat 返回 (void *) -1 表示失败，转换为 ctypes.c_void_p 进行比较
    if ctypes.c_void_p(addr).value == ctypes.c_void_p(-1).value:
        raise OSError("shmat failed")
    try:
        # 把返回地址包装为 ctypes 字节数组视图，直接从共享内存读取数据
        buf = (ctypes.c_char * size).from_address(addr)
        data = bytes(buf[:size])
    finally:
        # 无论如何都要解除挂接
        shmdt(addr)
    return data


def remove_shm(shmid: int) -> None:
    """标记共享内存段为删除（IPC_RMID）。

    注意：IPC_RMID 不会立即销毁在其他进程仍然 attached 的内存，
    而是当最后一个进程 detach 后内核回收该段。因此此调用是安全的
    清理手段；同时若父进程异常退出，内核也会在进程全部结束后释放。
    """
    shmctl(shmid, IPC_RMID, None)


def run_target_with_shm(cmd: list, input_data: Optional[bytes] = None,
                        mode: str = "stdin", timeout: Optional[float] = None,
                        workdir: Optional[str] = None, map_out: Optional[str] = None) -> Tuple[int, bool, bytes, bytes, Optional[str]]:
    # 1) 创建共享内存并把 shmid 注入到子进程的环境变量中
    #    AFL 插装运行时会读取 __AFL_SHM_ID 并把位图写入对应的共享内存段。
    shmid = create_shm(MAP_SIZE)
    env = os.environ.copy()
    env["__AFL_SHM_ID"] = str(shmid)

    # 2) 准备工作目录：若外部未指定，则创建临时目录用于运行与输出 map 文件
    tmpdir = None
    if workdir is None:
        tmpdir = tempfile.TemporaryDirectory(prefix="miniafl_shm_")
        workdir = tmpdir.name

    input_path = None
    # 3) 若使用 file 模式，把输入写入临时文件并把路径作为最后一个参数传给被测程序
    if mode == "file" and input_data is not None:
        fd, input_path = tempfile.mkstemp(prefix="input_", dir=workdir)
        os.close(fd)
        with open(input_path, "wb") as f:
            f.write(input_data)

    if mode == "file" and input_path is not None:
        proc_cmd = list(cmd) + [input_path]
    else:
        proc_cmd = list(cmd)

    # 4) 启动被测程序（子进程），并把修改好的 env 传递进去（包含 __AFL_SHM_ID）
    proc = subprocess.Popen(proc_cmd, stdin=subprocess.PIPE if mode == "stdin" else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=workdir, env=env)
    timed_out = False
    # 5) 等待子进程完成，支持超时处理：先发送 terminate，再等待短暂时间，最后 kill
    try:
        out, err = proc.communicate(input=input_data if mode == "stdin" else None, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            out, err = proc.communicate(timeout=0.5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
            out, err = proc.communicate()

    exit_code = proc.returncode

    # 6) 子进程结束后，读取共享内存中的位图并写入 map_out 文件
    #    若用户未提供 map_out，则在 workdir 下创建临时文件保存位图
    if map_out is None:
        map_fd, map_path = tempfile.mkstemp(prefix="afl_map_", dir=workdir)
        os.close(map_fd)
    else:
        map_path = map_out

    try:
        # 从 SHM 中读取固定大小的位图字节并写入文件，供 parse_afl_map() 使用
        data = read_shm_to_bytes(shmid, MAP_SIZE)
        with open(map_path, "wb") as f:
            f.write(data)
    except Exception:
        # 读取失败时返回 None 表示没有 map 输出
        data = b""
        map_path = None

    # 7) 清理：标记共享内存删除，并清理临时目录（若创建过）
    try:
        remove_shm(shmid)
    except Exception:
        pass

    if tmpdir:
        tmpdir.cleanup()

    return exit_code if exit_code is not None else -1, timed_out, out, err, map_path


__all__ = ["run_target_with_shm", "create_shm", "read_shm_to_bytes"]
