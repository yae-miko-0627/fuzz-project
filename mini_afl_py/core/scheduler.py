"""
调度器占位模块

调度器负责：
- 管理种子/输入队列
- 选择待变异样本
- 调用变异器生成候选输入
- 调用执行模块运行目标并收集覆盖信息
- 基于能量调度策略调整变异次数/优先级

"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import random


@dataclass
class Candidate:
    """表示一个语料条目/候选样本的元数据。

    字段：
      id: 唯一 id
      data: bytes 数据本身
      energy: int 分配给该样本的能量/优先级（可作为后续调度依据）
      cycles: int 被选中次数计数
    """

    id: int
    data: bytes
    energy: int = 1
    cycles: int = 0
    avg_exec_time: float = 0.0
    hits: int = 0


class Scheduler:
    """简单调度器实现（轮询 + 简单能量策略）。

    特性：
    - 管理语料池（`corpus`）和候选队列（按 id 存储）；
    - `add_seed` 将种子加入语料与队列；
    - `next_candidate` 返回下一个 Candidate（并把它轮询回队列末尾）；
    - `report_result` 根据执行结果调整语料（例如把 crash/hang 样本加入语料、增加能量）。

    该实现为最小可用策略，便于后续替换为更复杂的基于覆盖或频率的能量调度。
    """

    def __init__(self) -> None:
        self._next_id = 1
        self._corpus: Dict[int, Candidate] = {}
        self._queue: List[int] = []

    def add_seed(self, seed: bytes, energy: int = 1) -> int:
        """将种子加入语料池并返回分配的 id。"""
        cid = self._next_id
        self._next_id += 1
        cand = Candidate(id=cid, data=seed, energy=energy, cycles=0)
        self._corpus[cid] = cand
        self._queue.append(cid)
        return cid

    def next_candidate(self) -> Optional[Candidate]:
        """返回下一个候选 `Candidate`（轮询）或 None（队列空）。

        返回的 Candidate 是当前语料池中的视图；调用者应该只读取 `data`。
        """
        if not self._queue:
            return None
        # 若语料池较小或未收集到足够统计，使用简单轮询
        if len(self._corpus) <= 2:
            cid = self._queue.pop(0)
            cand = self._corpus.get(cid)
            if cand is None:
                return self.next_candidate()
            cand.cycles += 1
            self._queue.append(cid)
            return cand

        # 否则基于能量/得分做加权选择（启发式调度，参考 AFL 的 calculate_score）
        ids = list(self._corpus.keys())
        scores = [self.calculate_score(self._corpus[i]) for i in ids]
        # 防止全部为 0
        total = sum(scores)
        if total <= 0:
            # 回退到轮询
            cid = self._queue.pop(0)
            cand = self._corpus.get(cid)
            if cand is None:
                return self.next_candidate()
            cand.cycles += 1
            self._queue.append(cid)
            return cand

        # 加权随机选择一个 id
        # 使用累积权重方式以避免依赖 Python 3.6+ random.choices
        import random
        r = random.uniform(0, total)
        upto = 0.0
        chosen = ids[0]
        for i, s in zip(ids, scores):
            upto += s
            if upto >= r:
                chosen = i
                break

        cand = self._corpus.get(chosen)
        # 更新 cycles 并将选中 id 放到队尾以保持基本轮询语义
        if cand:
            cand.cycles += 1
            # 保证队列包含该 id
            if chosen in self._queue:
                try:
                    self._queue.remove(chosen)
                except ValueError:
                    pass
            self._queue.append(chosen)
        return cand

    def report_result(self, sample: bytes, result: object) -> Optional[int]:
        """接收执行结果并根据简化策略更新语料池。

        简单策略：
        - 若 `result` 表示 crash 或 hang（包含属性 `status`），则把该样本加入语料并提升能量；
        - 否则以小概率把样本加入语料以增加多样性。

        返回新加入样本的 id（若未加入返回 None）。
        """
        status = getattr(result, "status", None)
        # 若样本已在语料池中，则更新其统计（exec time、hits、energy）
        for cid, cand in list(self._corpus.items()):
            if cand.data == sample:
                # 更新平均执行时间（简单指数移动平均）
                try:
                    t = float(getattr(result, "wall_time", 0.0) or 0.0)
                except Exception:
                    t = 0.0
                if cand.avg_exec_time <= 0.0:
                    cand.avg_exec_time = t
                else:
                    alpha = 0.3
                    cand.avg_exec_time = alpha * t + (1 - alpha) * cand.avg_exec_time
                cand.hits += 1
                # 若为 crash/hang，提升能量
                if status in ("crash", "hang"):
                    cand.energy = max(cand.energy, 8)
                else:
                    # 依据新的统计重新计算能量
                    cand.energy = self.calculate_score(cand)
                return cid

        # 若不在语料中，则根据结果决定是否把该样本加入语料
        if status in ("crash", "hang"):
            cid = self.add_seed(sample, energy=8)
            return cid
        if random.random() < 0.01:
            cid = self.add_seed(sample, energy=1)
            return cid
        return None

    def calculate_score(self, cand: Candidate) -> float:
        """基于启发式计算候选的能量/得分，参考 AFL 的 calculate_score。

        因为缺少覆盖信息，此函数使用可用的属性：
        - cand.avg_exec_time: 越小越好（单位时间内能尝试更多变体）
        - len(cand.data): 输入长度，较小的输入通常更快
        - cand.cycles: 被选中次数，越多则得分略减以避免过度偏好

        返回一个正数分数；`next_candidate` 会把分数作为权重进行选择。
        """
        # 基础分数
        score = 100.0
        size = len(cand.data) if cand.data is not None else 0
        # 小输入加分（经验值）
        if size <= 16:
            score += 40
        elif size <= 64:
            score += 20
        elif size <= 256:
            score += 5

        # 执行速度：avg_exec_time 越小越好，采用反比例缩放
        if cand.avg_exec_time and cand.avg_exec_time > 0:
            speed_bonus = max(0.0, min(50.0, 100.0 / (cand.avg_exec_time * 1000.0 + 1.0)))
            score += speed_bonus

        # cycles 惩罚，避免对已多次选中的样本过度偏好
        score -= min(cand.cycles * 1.5, 60)

        # hits 代表被采纳/命中的次数，适当微调
        score += min(cand.hits * 2.0, 40)

        # 保证下限
        if score < 1.0:
            score = 1.0
        return score

    @property
    def corpus(self) -> List[bytes]:
        """返回当前语料池的 bytes 列表（按 id 顺序）。"""
        return [c.data for _id, c in sorted(self._corpus.items())]
