"""
评估组件：覆盖率曲线分析

提供函数将 `Monitor` 中的运行记录转换为覆盖率随时间变化（coverage curve），并导出为 CSV 以便绘图或进一步分析。
"""
from __future__ import annotations

import csv
from typing import List, Tuple, Optional

from .monitor import Monitor


def coverage_curve(monitor: Monitor) -> List[Tuple[float, int]]:
    """基于 Monitor.records 生成覆盖率随时间的曲线。

    返回列表：(elapsed_seconds_from_start, cumulative_coverage_count)
    """
    if not monitor.records:
        return []
    start = monitor.records[0].timestamp
    curve: List[Tuple[float, int]] = []
    for r in monitor.records:
        elapsed = r.timestamp - start
        curve.append((elapsed, r.cum_coverage))
    return curve


def export_curve_csv(curve: List[Tuple[float, int]], path: str) -> None:
    """把覆盖曲线导出为 CSV，列为 `time_sec,cumulative_coverage`。"""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["time_sec", "cumulative_coverage"])
        for t, c in curve:
            writer.writerow([f"{t:.6f}", c])


__all__ = ["coverage_curve", "export_curve_csv"]
