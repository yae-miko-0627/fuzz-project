"""
简单的 fuzzer 入口，整合 `afl-cc` 插装（可选编译步骤）和 mini_afl_py 的 Python 运行/监控/覆盖采集。

功能：
- 可选使用系统上的 `afl-cc` 编译源文件为插装二进制
- 加载种子目录并循环执行目标
- 使用已有的 `CommandTarget` 与 `shm_manager`（通过 `instrumentation_mode=shm_py`）采集覆盖
- 使用 `Monitor` 记录运行并导出覆盖曲线 CSV

用法示例：
    python fuzzer.py --compile examples/test-instr.c --out ./bin/test-instr --seeds seeds/ --time 60

注意：在容器（Ubuntu 22.04）中运行被测目标并确保 `afl-cc` 可用。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
import random
from typing import List, Optional
import threading
import sys

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mini_afl_py.targets.command_target import CommandTarget
from mini_afl_py.core.monitor import Monitor
from mini_afl_py.core.eval import export_curve_csv, coverage_curve
from mini_afl_py.utils.config import DEFAULTS
from mini_afl_py.instrumentation.coverage import CoverageData


def run_afl_cc(source: str, out_bin: str, afl_cc_cmd: str = "afl-cc") -> None:
    """使用 afl-cc 编译源文件为插装二进制（最小封装）。"""
    cmd = [afl_cc_cmd, "-o", out_bin, source]
    print("[fuzzer] running:", " ".join(cmd))
    subprocess.check_call(cmd)


def load_seeds(seeds_dir: str) -> List[bytes]:
    p = Path(seeds_dir)
    if not p.exists():
        raise FileNotFoundError(f"seeds dir not found: {seeds_dir}")
    files = sorted([x for x in p.iterdir() if x.is_file()])
    seeds: List[bytes] = []
    for f in files:
        try:
            seeds.append(f.read_bytes())
        except Exception:
            continue
    if not seeds:
        raise RuntimeError("no seed files found in seeds dir")
    return seeds


def simple_fuzz_loop(cmd: List[str], seeds: List[bytes], out_dir: str,
                     time_limit: float = 60.0, mode: str = "stdin", timeout: float = 1.0,
                     status_interval: float = 5.0) -> None:
    monitor = Monitor(out_dir=out_dir)
    target = CommandTarget(cmd, workdir=None, timeout_default=timeout)

    start = time.time()
    iter_count = [0]
    iter_lock = threading.Lock()

    stop_ev = threading.Event()

    # 最小变异器：对原始种子进行简单的随机字节变异（byte flip/insert/delete）
    def mutate(data: bytes) -> bytes:
        if not data:
            # 生成一个小随机输入
            return bytes([random.randint(1, 255) for _ in range(8)])

        b = bytearray(data)
        ops = ["flip", "insert", "delete"]
        # 每次随机 1-3 次变异
        for _ in range(random.randint(1, 3)):
            op = random.choice(ops)
            if op == "flip" and len(b) > 0:
                idx = random.randrange(len(b))
                b[idx] = b[idx] ^ (1 << random.randint(0, 7))
            elif op == "insert":
                idx = random.randrange(len(b) + 1)
                b.insert(idx, random.randint(1, 255))
            elif op == "delete" and len(b) > 1:
                idx = random.randrange(len(b))
                del b[idx]
        return bytes(b)

    # 新增：计算覆盖率百分比（基于已发现路径数/65536）
    def _cov_percent():
        return min(100.0, 100.0 * len(monitor.cumulative_cov.points) / 65536.0)

    def _status_printer():
        while not stop_ev.wait(status_interval):
            with iter_lock:
                iters = iter_count[0]
            elapsed = time.time() - start
            rate = iters / elapsed if elapsed > 0 else 0.0
            seeds_count = len(seeds)
            new_paths = len(monitor.cumulative_cov.points)
            cov_pct = _cov_percent()
            crashes = sum(1 for r in monitor.records if r.status == "crash")
            line = (f"[status] elapsed={elapsed:.1f}s execs={iters} rate={rate:.1f}/s "
                    f"seeds={seeds_count} new_paths={new_paths} cov={cov_pct:.2f}% "
                    f"crashes={crashes}")
            sys.stdout.write("\x1b[2K\r" + line)
            sys.stdout.flush()

    printer_thr = None
    if status_interval and status_interval > 0:
        printer_thr = threading.Thread(target=_status_printer, daemon=True)
        printer_thr.start()

    try:
        while True:
            if time.time() - start >= time_limit:
                break
            for i, s in enumerate(seeds):
                st = time.time()
                # 生成变异样本而非仅重放原始种子
                sample = mutate(s)
                res = target.run(sample, mode=mode, timeout=timeout)
                cov = None
                if hasattr(res, "coverage") and isinstance(res.coverage, CoverageData):
                    cov = res.coverage

                monitor.record_run(sample_id=iter_count[0], sample=sample, status=res.status,
                                   wall_time=res.wall_time, cov=cov,
                                   artifact_path=res.artifact_path)

                with iter_lock:
                    iter_count[0] += 1
                # 每 N 次导出一次覆盖曲线
                if iter_count[0] % 50 == 0:
                    curve = coverage_curve(monitor)
                    csvp = os.path.join(out_dir, "coverage_curve.csv")
                    export_curve_csv(curve, csvp)
    except KeyboardInterrupt:
        print("[fuzzer] interrupted by user")

    # 通知状态线程退出并换行
    if printer_thr is not None:
        stop_ev.set()
        try:
            printer_thr.join(timeout=1.0)
        except Exception:
            pass
    sys.stdout.write("\n")

    # 最终导出记录与覆盖曲线
    os.makedirs(out_dir, exist_ok=True)
    rec_path = monitor.export_records(path=os.path.join(out_dir, "monitor_records.json"))
    curve = coverage_curve(monitor)
    csvp = os.path.join(out_dir, "coverage_curve.csv")
    export_curve_csv(curve, csvp)
    # 统计信息
    total_execs = iter_count[0]
    new_paths = len(monitor.cumulative_cov.points)
    cov_pct = _cov_percent()
    crashes = sum(1 for r in monitor.records if r.status == "crash")

    print(f"=====[fuzzer] finished.=====")
    print(f"  total executions: {total_execs}")
    print(f"  new paths: {new_paths}")
    print(f"  coverage: {cov_pct:.2f}%")
    print(f"  crashes: {crashes}")
    print(f"  records saved to: {rec_path}")


def main():
    p = argparse.ArgumentParser(description="MiniAFL fuzzer wrapper (afl-cc + mini_afl_py)")
    p.add_argument("--compile", help="C/C++ source to compile with afl-cc", default=None)
    p.add_argument("--out", help="output binary path when using --compile", default=None)
    p.add_argument("--afl-cc", help="path to afl-cc", default=DEFAULTS.get("afl_cc_path", "afl-cc"))
    p.add_argument("--cmd", help="command to run (if provided, used instead of --out)", default=None)
    p.add_argument("--target", help="(T01) path to target binary (alias for --out/--cmd)", default=None)
    p.add_argument("--seeds", help="seeds directory", required=True)
    p.add_argument("--status-interval", help="status print interval seconds (0 to disable)", type=float, default=5.0)
    p.add_argument("--time", help="fuzz time seconds", type=float, default=DEFAULTS.get("fuzz_time", 60))
    p.add_argument("--mode", help="input mode: stdin|file", choices=["stdin", "file"], default="stdin")
    p.add_argument("--timeout", help="per-run timeout seconds", type=float, default=1.0)
    p.add_argument("--outdir", help="output artifacts dir", default="fuzz_artifacts")

    args = p.parse_args()

    # 可选编译步骤
    if args.compile:
        if args.out is None:
            raise SystemExit("--out is required when --compile is used")
        run_afl_cc(args.compile, args.out, afl_cc_cmd=args.afl_cc)

    # 确定最终要执行的命令
    final_cmd = None
    if args.cmd:
        final_cmd = args.cmd.split()
    elif args.target:
        final_cmd = [str(args.target)]
    elif args.out:
        final_cmd = [str(args.out)]
    else:
        raise SystemExit("either --cmd, --target or --out must be provided")

    # 加载种子并运行
    seeds = load_seeds(args.seeds)
    os.makedirs(args.outdir, exist_ok=True)
    simple_fuzz_loop(final_cmd, seeds, out_dir=args.outdir, time_limit=args.time, mode=args.mode, timeout=args.timeout,
                     status_interval=args.status_interval)


if __name__ == "__main__":
    main()
