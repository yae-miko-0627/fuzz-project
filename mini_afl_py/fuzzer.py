"""
MiniFuzzer: 将 `Scheduler`、变异器、`CommandTarget` 与 `Monitor` 串联起来的最小 fuzz 引擎。

该实现为教学/快速验证用途，特点：
- 支持添加种子 (`add_seed`)；
- 先运行确定性变异器（bitflip/arith/interest），再运行非确定性变异（havoc/splice）；
- 默认关闭 AFL 插装（`DEFAULTS['instrumentation_mode']='none'`），除非通过 `use_afl=True` 覆盖。
"""
from __future__ import annotations

import time
import random
from typing import List, Optional

from .core.scheduler import Scheduler
from .core.monitor import Monitor
from .targets.command_target import CommandTarget, CommandTargetResult
from .mutators.bitflip_mutator import BitflipMutator
from .mutators.arith_mutator import ArithMutator
from .mutators.interest_mutator import InterestMutator
from .mutators.havoc_mutator import HavocMutator
from .mutators.splice_mutator import SpliceMutator
from .utils.config import DEFAULTS


class MiniFuzzer:
    """最小端到端 fuzzer。

        参数:
            target_cmd: 被测程序命令列表
            timeout: 每次执行超时（秒）
            use_shm: 是否使用 Python SHM 管理（默认 True，用于与 `afl-cc` 插装配合）
    """

    def __init__(self, target_cmd: List[str], timeout: float = 1.0, workdir: Optional[str] = None,
                                 use_shm: bool = True):
        # 默认使用 Python SHM 管理（shm_py）以配合 afl-cc 插装
        if use_shm:
            DEFAULTS["instrumentation_mode"] = "shm_py"
        else:
            DEFAULTS["instrumentation_mode"] = "none"

        self.scheduler = Scheduler()
        self.monitor = Monitor()
        self.target = CommandTarget(cmd=target_cmd, workdir=workdir, timeout_default=timeout)

        # 变异器集合（确定性 -> 非确定性）
        self.det_mutators = [BitflipMutator(), ArithMutator(), InterestMutator()]
        self.havoc = HavocMutator()
        self.splice = SpliceMutator()

        # 用于控制运行
        self.timeout = timeout

    def add_seed(self, data: bytes) -> int:
        sid = self.scheduler.add_seed(data)
        print(f"[MiniFuzzer] add_seed id={sid} len={len(data)}")
        return sid

    def _execute_sample(self, sample: bytes, parent_id: Optional[int]) -> Optional[int]:
        """执行一次样本并把结果上报到 scheduler 和 monitor。返回新加入的 sample id（若有）。"""
        print(f"[MiniFuzzer] exec_sample parent={parent_id} len={len(sample)}")
        res: CommandTargetResult = self.target.run(sample, mode="stdin", timeout=self.timeout)

        # 报告给 scheduler（可能返回新加入的 id）
        new_id = self.scheduler.report_result(sample, res)

        # 记录到 monitor（尽量把 sample_id 填为 parent_id 或新_id）
        sample_id = new_id if new_id is not None else parent_id
        cov = getattr(res, "coverage", None)
        self.monitor.record_run(sample_id, sample, res.status, res.wall_time, cov=cov,
                               artifact_path=res.artifact_path)
        print(f"[MiniFuzzer] result sample_id={sample_id} status={res.status} wall_time={res.wall_time:.4f}")
        return new_id

    def run(self, run_time: float = 10.0) -> None:
        """主循环：在指定时间内反复选取候选并对其应用变异与执行。"""
        start = time.time()
        print(f"[MiniFuzzer] start run_time={run_time}")
        # 保证 splice 的语料来源与 scheduler 的语料同步
        while time.time() - start < run_time:
            cand = self.scheduler.next_candidate()
            if cand is None:
                # 暂无语料，短暂等待后重试
                time.sleep(0.01)
                continue

            # 更新 splice 的 corpus
            try:
                self.splice.set_corpus(self.scheduler.corpus)
            except Exception:
                pass

            # 确定性阶段：对候选执行一系列确定性变异
            for m in self.det_mutators:
                for s in m.mutate(cand.data):
                    self._execute_sample(s, cand.id)
                    # 限制时间窗口
                    if time.time() - start >= run_time:
                        return

            # 非确定性阶段：基于 energy 做若干尝试
            attempts = max(1, int(cand.energy))
            # 一部分为 havoc，一部分为 splice
            for _ in range(attempts):
                # 随机选择使用 havoc 或 splice
                if random.random() < 0.7:
                    for s in self.havoc.mutate(cand.data):
                        self._execute_sample(s, cand.id)
                        break  # 每次只使用一条 havoc 变体
                else:
                    for s in self.splice.mutate(cand.data):
                        self._execute_sample(s, cand.id)
                        break
                if time.time() - start >= run_time:
                    print("[MiniFuzzer] run timeout, exiting")
                    print(f"[MiniFuzzer] end elapsed={time.time()-start:.4f}")
                    return

        print(f"[MiniFuzzer] end elapsed={time.time()-start:.4f}")


__all__ = ["MiniFuzzer"]
