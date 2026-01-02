"""
运行结果监控组件

功能：
- 记录每次执行的元数据（时间戳、耗时、状态、覆盖新点数等）
- 保存特殊测试用例（crash/hang/高新颖度）到 artifacts 目录
- 提供导出/序列化接口供评估模块使用

该模块不直接负责产生覆盖，而是接受来自上层的覆盖数据（`CoverageData` 或整数新点数）。
"""
from __future__ import annotations

import os
import time
import json
from dataclasses import dataclass, asdict
from typing import Optional, List

from ..instrumentation.coverage import CoverageData


@dataclass
class RunRecord:
    timestamp: float
    sample_id: Optional[int]
    status: str
    wall_time: float
    novelty: int
    cum_coverage: int
    artifact_path: Optional[str]


class Monitor:
    """监控器：维护运行历史、累计覆盖，并保存特殊样本。"""

    def __init__(self, out_dir: str = "monitor_artifacts", novelty_threshold: int = 10):
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)
        self.records: List[RunRecord] = []
        self.cumulative_cov = CoverageData()
        # 缓存累计覆盖大小，避免每次访问遍历位图（昂贵）
        self._cum_cov_size = 0
        self.novelty_threshold = novelty_threshold
        # 保留覆盖量随时间的采样，用于计算增长速率
        # 存储为 (timestamp, cum_cov_size)
        self._cov_history: List[tuple[float, int]] = []

    def record_run(self, sample_id: Optional[int], sample: bytes, status: str,
                   wall_time: float, cov: Optional[CoverageData] = None,
                   artifact_path: Optional[str] = None) -> RunRecord:
        """记录一次运行。

        - `cov`：可选的 CoverageData（若有，则用于计算 novelty 与更新累计覆盖）。
        - `artifact_path`：若产生崩溃，该路径可指向已保存的触发输入文件。
        返回创建的 RunRecord。
        """
        ts = time.time()
        novelty = 0
        if cov is not None:
            # 使用 CoverageData.merge_and_count_new 做按位合并并直接获取新增命中数，
            # 避免把位图转换为大集合（每次 65536 次迭代）的开销。
            try:
                novelty = self.cumulative_cov.merge_and_count_new(cov)
            except Exception:
                # 退回兼容实现（不应常发生）
                new_points = set(cov.points) - set(self.cumulative_cov.points)
                novelty = len(new_points)
                self.cumulative_cov.merge(cov)
            # 更新缓存的累计覆盖大小
            self._cum_cov_size += novelty

        cum_cov_size = self._cum_cov_size

        # 记录覆盖历史采样点（采样粒度由调用端控制，但这里保证每次 record_run 都有采样）
        try:
            self._cov_history.append((ts, cum_cov_size))
            # 为避免无限增长，保留最近 1024 个点
            if len(self._cov_history) > 1024:
                self._cov_history.pop(0)
        except Exception:
            pass

        rec = RunRecord(timestamp=ts, sample_id=sample_id, status=status,
                        wall_time=wall_time, novelty=novelty,
                        cum_coverage=cum_cov_size,
                        artifact_path=artifact_path)
        self.records.append(rec)

        # 仅保存高新颖度样本以避免输出目录被大量 crash/hang 填满
        if novelty >= self.novelty_threshold:
            fname = f"sample_{int(ts*1000)}_novel.bin"
            p = os.path.join(self.out_dir, fname)
            try:
                with open(p, "wb") as f:
                    f.write(sample)
                if artifact_path is None:
                    artifact_path = p
                rec.artifact_path = artifact_path
            except Exception:
                pass

        return rec

    def growth_rate(self, window_seconds: int = 60) -> float:
        """计算过去 window_seconds 窗口内的平均新增覆盖速率（edges/sec）。

        若历史数据不足，返回 0.0。
        """
        now = time.time()
        cutoff = now - float(window_seconds)
        # 找到最近窗口的第一个样本
        prev = None
        for ts, cov in reversed(self._cov_history):
            if ts <= cutoff:
                prev = (ts, cov)
                break
        if prev is None:
            # 若没有早期样本，则尝试使用最早的可用样本
            if not self._cov_history:
                return 0.0
            prev = self._cov_history[0]

        # 以最新样本为终点
        last_ts, last_cov = self._cov_history[-1]
        delta_cov = last_cov - prev[1]
        delta_t = max(1e-6, last_ts - prev[0])
        return float(delta_cov) / float(delta_t)

    def is_growth_slow(self, window_seconds: int = 60, min_rate: float = 0.02, min_delta: int = 2) -> bool:
        """判断在过去 window_seconds 内覆盖增长是否低于阈值。

        - `min_rate`：每秒新增 edge 的阈值。
        - `min_delta`：窗口总新增 edge 的最小阈值。
        """
        if not self._cov_history:
            return False
        now = time.time()
        cutoff = now - float(window_seconds)
        # 计算窗口内最早与最新的覆盖值
        first = None
        for ts, cov in self._cov_history:
            if ts >= cutoff:
                first = (ts, cov)
                break
        if first is None:
            # 窗口内没有采样，使用最早可用
            first = self._cov_history[0]
        last_ts, last_cov = self._cov_history[-1]
        delta_cov = last_cov - first[1]
        delta_t = max(1e-6, last_ts - first[0])
        rate = float(delta_cov) / float(delta_t)
        if rate < float(min_rate) and delta_cov < int(min_delta):
            return True
        return False

    def export_records(self, path: Optional[str] = None) -> str:
        """把记录导出为 JSON 文件，返回文件路径。"""
        path = path or os.path.join(self.out_dir, "monitor_records.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump([asdict(r) for r in self.records], f, ensure_ascii=False, indent=2)
        except Exception:
            raise
        return path


__all__ = ["Monitor", "RunRecord"]
