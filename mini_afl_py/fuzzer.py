"""Minimal fuzzer loop that integrates mutators, scheduler and CommandTarget.

此文件提供一个可运行的最小 fuzz 主循环，用于把已实现的变异器接入到调度器与
`CommandTarget`。目的是在不依赖复杂覆盖信息的前提下搭建端到端执行路径，方便
后续逐步替换/扩展为带覆盖感知的调度器。
"""
import time
import random
from typing import List, Optional

from .core.scheduler import Scheduler
from .targets.command_target import CommandTarget, CommandTargetResult
from .core.monitor import Monitor
from .instrumentation.coverage import parse_trace_count_file, CoverageData
from .mutators.bitflip_mutator import BitflipMutator
from .mutators.arith_mutator import ArithMutator
from .mutators.interest_mutator import InterestMutator
from .mutators.havoc_mutator import HavocMutator
from .mutators.splice_mutator import SpliceMutator
from .utils.config import DEFAULTS


class MiniFuzzer:
    """一个极简的模糊循环实现：

    - 从 `Scheduler` 获取候选种子
    - 按确定性阶段（bitflip/arith/interest）变异并执行
    - 执行非确定性阶段（havoc/splice）并执行
    - 根据最简单的策略将有趣样本加入内部 corpus（用于 splice）

    注意：此处未集成覆盖信息（instrumentation），仅用结果状态做简单示例策略。
    """

    def __init__(self, target_cmd: List[str], workdir: Optional[str] = None, timeout: float = 1.0):
        self.scheduler = Scheduler()
        # 若未提供工作目录，创建一个持久目录用于保存运行产物/coverage/artifacts，便于监控解析
        import os
        if workdir is None:
            workdir = os.path.abspath(os.path.join(os.getcwd(), "miniafl_runs"))
            os.makedirs(workdir, exist_ok=True)
        self.target = CommandTarget(cmd=target_cmd, workdir=workdir, timeout_default=timeout)

        # 监控器：记录执行统计、累计覆盖，并保存特殊样本
        self.monitor = Monitor(out_dir=os.path.join(workdir, "monitor_artifacts"), novelty_threshold=1)

        # mutators
        self.bitflip = BitflipMutator()
        self.arith = ArithMutator()
        self.interest = InterestMutator()
        self.havoc = HavocMutator()

    def add_seed(self, seed: bytes) -> None:
        """向调度器添加初始种子（会自动加入语料池）。"""
        self.scheduler.add_seed(seed)

    def _maybe_add_to_corpus(self, sample: bytes, result: CommandTargetResult) -> None:
        """委托给 `Scheduler.report_result` 来决定是否把样本加入语料池。"""
        nid = self.scheduler.report_result(sample, result)
        if nid is not None:
            print(f"[fuzzer] Scheduler added sample id={nid} to corpus")

    def run(self, run_time: Optional[float] = None) -> None:
        """运行 fuzz 循环，若 run_time 为 None 则使用 DEFAULTS['fuzz_time']。"""
        duration = run_time if run_time is not None else DEFAULTS.get("fuzz_time", 3600)
        end_time = time.time() + duration
        print(f"[fuzzer] Starting fuzz loop for {duration} seconds")

        # 简单循环：从 scheduler 拉取候选并按阶段变异执行
        while time.time() < end_time:
            candidate = self.scheduler.next_candidate()
            if candidate is None:
                # 若无候选，可休眠并继续等待或直接结束（此处退出）
                print("[fuzzer] No more candidates in scheduler, exiting")
                break

            # 确定性阶段：bitflip / arith / interest
            for mutator, limit in ((self.bitflip, 16), (self.arith, 64), (self.interest, 64)):
                count = 0
                for mutated in mutator.mutate(candidate.data):
                    if count >= limit:
                        break
                    res = self.target.run(mutated)
                    # 尝试解析覆盖并记录运行到 Monitor
                    try:
                        cov = parse_trace_count_file(self.target.workdir)
                    except Exception:
                        cov = None
                    try:
                        rec = self.monitor.record_run(sample_id=candidate.id, sample=mutated,
                                                     status=res.status, wall_time=res.wall_time,
                                                     cov=cov, artifact_path=res.artifact_path)
                        # 将 novelty 传给 scheduler（通过在 result 上设置属性，供 report_result 使用）
                        setattr(res, "novelty", rec.novelty)
                    except Exception:
                        setattr(res, "novelty", 0)
                    print(f"[det] mutator={mutator.__class__.__name__} status={res.status} time={res.wall_time:.3f}")
                    self._maybe_add_to_corpus(mutated, res)
                    count += 1

            # 非确定性阶段：havoc
            hcount = 0
            for mutated in self.havoc.mutate(candidate.data):
                if hcount >= 8:
                    break
                res = self.target.run(mutated)
                try:
                    cov = parse_trace_count_file(self.target.workdir)
                except Exception:
                    cov = None
                try:
                    rec = self.monitor.record_run(sample_id=candidate.id, sample=mutated,
                                                 status=res.status, wall_time=res.wall_time,
                                                 cov=cov, artifact_path=res.artifact_path)
                    setattr(res, "novelty", rec.novelty)
                except Exception:
                    setattr(res, "novelty", 0)
                print(f"[havoc] status={res.status} time={res.wall_time:.3f}")
                self._maybe_add_to_corpus(mutated, res)
                hcount += 1

            # splice（需要语料池）
            corpus_for_splice = self.scheduler.corpus
            if corpus_for_splice:
                sp = SpliceMutator(corpus=corpus_for_splice, attempts=6)
                scount = 0
                for mutated in sp.mutate(candidate.data):
                    if scount >= 6:
                        break
                    res = self.target.run(mutated)
                    try:
                        cov = parse_trace_count_file(self.target.workdir)
                    except Exception:
                        cov = None
                    try:
                        rec = self.monitor.record_run(sample_id=candidate.id, sample=mutated,
                                                     status=res.status, wall_time=res.wall_time,
                                                     cov=cov, artifact_path=res.artifact_path)
                        setattr(res, "novelty", rec.novelty)
                    except Exception:
                        setattr(res, "novelty", 0)
                    print(f"[splice] status={res.status} time={res.wall_time:.3f}")
                    self._maybe_add_to_corpus(mutated, res)
                    scount += 1

        print("[fuzzer] Loop finished")


def quick_demo():
    """快速示例：用内置示例启动 fuzzer（仅在有可执行目标时有效）。"""
    # 这里以占位命令为例，实际使用时传入真实目标路径
    f = MiniFuzzer(target_cmd=["/bin/true"], timeout=1.0)
    # 示例种子
    f.add_seed(b"AAAA")
    f.add_seed(b"BBBB")
    # 运行 5 秒以示范循环
    f.run(run_time=5)


if __name__ == '__main__':
    quick_demo()
