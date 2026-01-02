"""Aggression manager: 控制何时进入/退出激进变异模式。

策略：
- 外部通过 `update(slow_growth: bool)` 告诉 manager 当前是否处于覆盖增长缓慢状态。
- manager 在满足条件时进入激进模式（增加 scale），并在 cooldown 后按指数/线性回退到正常。
- 提供 `is_aggressive` 和 `scale` 属性供 fuzzer 查询并让变异器据此调整参数。

"""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class AggressionConfig:
    scale: float = 2.0  # 激进模式将参数放大的因子
    min_duration: float = 15.0  # 激进模式至少保持的秒数
    cooldown: float = 60.0  # 触发后在 cooldown 内不会再次触发
    decay: float = 0.9  # 每次周期性检查时的退坡比例（用于平滑返回）


class AggressionManager:
    def __init__(self, cfg: AggressionConfig | None = None):
        self.cfg = cfg or AggressionConfig()
        self._aggressive = False
        self._scale = 1.0
        self._last_enter = 0.0
        self._last_exit = 0.0

    def update(self, slow_growth: bool) -> None:
        """根据是否增长缓慢更新内部状态。

        - 当检测到 slow_growth 且不在 cooldown 且当前不是激进时，进入激进模式。
        - 激进模式至少保持 min_duration 后才允许退出；退出后记录退出时间用于 cooldown 判断。
        """
        now = time.time()
        if slow_growth and not self._aggressive:
            # 检查 cooldown
            if now - self._last_exit >= self.cfg.cooldown:
                self._aggressive = True
                self._scale = float(self.cfg.scale)
                self._last_enter = now
        elif not slow_growth and self._aggressive:
            # 若满足最小持续时间，开始退坡并退出
            if now - self._last_enter >= self.cfg.min_duration:
                # 立即退出到正常尺度
                self._aggressive = False
                self._scale = 1.0
                self._last_exit = now
        # 若当前激进且仍在激进期，可以选择缓慢衰减 scale（可选）
        if self._aggressive:
            # 保持固定 scale while aggressive; decay applied after exit
            pass

    @property
    def is_aggressive(self) -> bool:
        return self._aggressive

    @property
    def scale(self) -> float:
        return float(self._scale)
 