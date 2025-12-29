"""

调度器负责：
- 管理种子/输入队列
- 选择待变异样本
- 调用变异器生成候选输入
- 调用执行模块运行目标并收集覆盖信息
- 基于能量调度策略调整变异次数/优先级

"""

from dataclasses import dataclass
import sys
from typing import Dict, List, Optional
import random
import hashlib
import time
from ..instrumentation.coverage import CoverageData


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
    # 最近一次被 report_result 标记为有新颖覆盖的数量（用于评分提升）
    last_novelty: int = 0
    # 覆盖特征签名（字符串），用于基于覆盖的唯一性判定
    cov_sig: Optional[str] = None


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
        # favored 映射：候选 id -> 最近一次被标记/选中的时间戳
        # 用于短期优先（带 TTL 与容量限制）
        self._favored: Dict[int, float] = {}
        # 调度统计与策略参数
        self._select_count = 0
        self._shuffle_interval = 200  # 每多少次选择对队列做一次洗牌以打破长期霸占
        self._decay_rate = 0.90       # 兼容保留（默认，不再直接使用）
        # 差异化能量衰减：无新颖样本时更快衰减，有新颖样本保留更多
        self._decay_no_novelty = 0.8
        self._decay_with_novelty = 0.95
        self._max_energy_cap = 20     # 能量上限，避免单个样本长期垄断
        # 强制探索比例：以一定概率优先抽取低 cycles（新的）种子
        self._explore_fraction = 0.15
        # 动态探索参数
        self._explore_default = 0.15
        self._explore_min = 0.05
        self._explore_max = 0.30
        self._explore_stagnant = 0.30  # 覆盖停滞时提升到 30%
        # 探索池大小：默认较小，停滞时扩大
        self._explore_pool_size = 8
        self._explore_pool_size_stagnant = 32
        self._explore_pool_size_max = 64
        # 覆盖增长检测
        self._cov_check_interval = 10.0  # seconds
        self._last_cov_check = time.time()
        self._last_cov_points = 0
        # 累计覆盖（edge id 集合），用于计算 novelty
        self.cumulative_cov = CoverageData()
        # favored 策略参数
        self._favored_ttl = 30.0   # seconds: 若 30s 未被选中则移除
        self._favored_capacity = 20 # 最多保留多少 favored 条目

    def add_seed(self, seed: bytes, energy: int = 1) -> int:
        """将种子加入语料池并返回分配的 id。"""
        # 保证 seed 为 bytes-like，避免将错误的类型写入语料池
        if not isinstance(seed, (bytes, bytearray)):
            try:
                seed = bytes(seed)
            except Exception:
                # 退回到字符串化表示，避免插入不受支持的对象
                seed = str(seed).encode('utf-8', errors='ignore')
        cid = self._next_id
        self._next_id += 1
        cand = Candidate(id=cid, data=seed, energy=energy, cycles=0, cov_sig=None)
        self._corpus[cid] = cand
        self._queue.append(cid)
        return cid

    def next_candidate(self) -> Optional[Candidate]:
        """返回下一个候选 `Candidate`（轮询）或 None（队列空）。

        返回的 Candidate 是当前语料池中的视图；调用者应该只读取 `data`。
        """
        if not self._queue:
            return None
        # 维护选择计数，每隔若干次做能量衰减与队列洗牌，防止长期垄断
        self._select_count += 1
        if self._select_count % self._shuffle_interval == 0:
            try:
                # 对整个队列进行洗牌以逼近随机性
                random.shuffle(self._queue)
                # 周期性地对所有候选应用能量衰减与能量上限
                now = time.time()
                # 清理过期的 favored（未在 TTL 内被选中）
                try:
                    to_del = [fid for fid, ts in list(self._favored.items()) if now - ts > self._favored_ttl]
                    for fid in to_del:
                        try:
                            del self._favored[fid]
                        except Exception:
                            pass
                except Exception:
                    pass
                # 若 favored 超出容量，删除最旧的条目
                try:
                    if len(self._favored) > self._favored_capacity:
                        # 按时间戳排序并保留最新的 N
                        items = sorted(self._favored.items(), key=lambda kv: kv[1], reverse=True)
                        keep = dict(items[:self._favored_capacity])
                        self._favored = keep
                except Exception:
                    pass
                # 对所有候选应用差异化能量衰减与能量上限
                for cid in list(self._corpus.keys()):
                    try:
                        c = self._corpus[cid]
                        # 依据最近新颖度选择衰减因子
                        if getattr(c, 'last_novelty', 0):
                            factor = self._decay_with_novelty
                        else:
                            factor = self._decay_no_novelty
                        c.energy = max(1, int(c.energy * factor))
                        if c.energy > self._max_energy_cap:
                            c.energy = self._max_energy_cap
                    except Exception:
                        pass
            except Exception:
                pass
        # 若语料池较小或未收集到足够统计，使用简单轮询
        if len(self._corpus) <= 2:
            cid = self._queue.pop(0)
            cand = self._corpus.get(cid)
            if cand is None:
                return self.next_candidate()
            cand.cycles += 1
            self._queue.append(cid)
            # 若该候选在 favored 中，刷新其时间戳
            try:
                if cid in self._favored:
                    self._favored[cid] = time.time()
            except Exception:
                pass
            return cand

        # 动态覆盖增长检测：按时间间隔检查累计覆盖的增长速率，若停滞则增大探索比例与池大小
        try:
            now = time.time()
            if now - self._last_cov_check >= self._cov_check_interval:
                try:
                    cur_points = len(self.cumulative_cov.points)
                    prev_points = max(1, self._last_cov_points)
                    growth = 0.0
                    if prev_points > 0:
                        growth = (cur_points - self._last_cov_points) / float(prev_points)
                    # 若增长非常小或为 0，视为停滞
                    if growth <= 0.01:
                        self._explore_fraction = self._explore_stagnant
                        self._explore_pool_size = min(self._explore_pool_size_stagnant, self._explore_pool_size_max)
                    else:
                        # 恢复为默认值并缩小池
                        self._explore_fraction = self._explore_default
                        self._explore_pool_size = max(8, int(self._explore_pool_size / 2))
                    self._last_cov_points = cur_points
                except Exception:
                    pass
                self._last_cov_check = now
        except Exception:
            pass

        # 强制探索：有一定概率优先从低 cycles（新种子）中抽样，池大小根据当前状态调整
        try:
            if random.random() < self._explore_fraction:
                ids_sorted = sorted(self._corpus.keys(), key=lambda x: self._corpus[x].cycles)
                pool_n = max(1, min(self._explore_pool_size, len(ids_sorted)))
                sample_pool = ids_sorted[:pool_n]
                chosen = random.choice(sample_pool)
                cand = self._corpus.get(chosen)
                if cand:
                    cand.cycles += 1
                    if chosen in self._queue:
                        try:
                            self._queue.remove(chosen)
                        except Exception:
                            pass
                    self._queue.append(chosen)
                    # 刷新 favored 时间戳（若存在）
                    try:
                        if chosen in self._favored:
                            self._favored[chosen] = time.time()
                    except Exception:
                        pass
                    return cand
        except Exception:
            pass

        # 否则基于能量/得分做加权选择（优先选取 favored 集合，但保留随机性）
        ids = list(self._corpus.keys())
        # 若存在 favored，按概率优先从 favored 池抽样
        favored_ids = [i for i in ids if i in self._favored]
        if favored_ids:
            try:
                if random.random() < 0.65:
                    ids = favored_ids
            except Exception:
                pass
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
            # 刷新 favored 时间戳（若存在）
            try:
                if chosen in self._favored:
                    self._favored[chosen] = time.time()
            except Exception:
                pass
            # 若该候选属于 favored，则在多次被选中后逐步从 favored 中移出以避免长期垄断
            try:
                if chosen in self._favored and cand.cycles > 8:
                    try:
                        del self._favored[chosen]
                    except Exception:
                        pass
            except Exception:
                pass
        return cand

    def report_result(self, sample: bytes, result: object) -> Optional[int]:
        """接收执行结果并根据简化策略更新语料池。

        简单策略扩展：
        - 若 `result` 包含 `coverage_new`（novelty）则优先提升该样本的能量并尽可能保留；
        - crash/hang 始终给予较高能量；
        - 否则以小概率把样本加入语料以增加多样性。

        返回新加入样本的 id（若未加入返回 None）。
        """
        status = getattr(result, "status", None)
        # 优先从 result.coverage 获取 AFL 风格的 CoverageData
        novelty = 0
        cov = getattr(result, "coverage", None)
        cov_sig = None
        if cov and isinstance(cov, CoverageData):
            # 计算新颖点：cov.points - cumulative_cov.points
            try:
                new_points = set(cov.points) - set(self.cumulative_cov.points)
                novelty = len(new_points)
                # 合并到累计覆盖
                self.cumulative_cov.merge(cov)
                # 计算覆盖位图签名以用于唯一性判断（sha1）
                try:
                    bm = cov.to_bitmap()
                    cov_sig = hashlib.sha1(bytes(bm)).hexdigest()
                except Exception:
                    cov_sig = None
            except Exception:
                novelty = 0

        # 使用覆盖签名判断样本是否已在语料池中（仅当两者都有覆盖签名且相同则视为重复）
        # 注意：不再使用字节级回退匹配，以避免把覆盖不同但字节相同的样本误判为重复。
        for cid, cand in list(self._corpus.items()):
            is_same = False
            try:
                if cov_sig and cand.cov_sig and cov_sig == cand.cov_sig:
                    is_same = True
                else:
                    is_same = False
            except Exception:
                is_same = False
            if is_same:
                # 更新平均执行时间（简单指数移动平均）
                try:
                    t = float(getattr(result, "wall_time", 0.0) or getattr(result, 'exec_time', 0.0) or 0.0)
                except Exception:
                    t = 0.0
                if cand.avg_exec_time <= 0.0:
                    cand.avg_exec_time = t
                else:
                    alpha = 0.3
                    cand.avg_exec_time = alpha * t + (1 - alpha) * cand.avg_exec_time
                cand.hits += 1
                # 若观察到新覆盖位点（novelty），适度提升能量（有上限）
                if novelty and novelty > 0:
                    boost = int(2 + novelty)
                    # 以线性增加能量，但不超过全局上限
                    try:
                        cand.energy = min(self._max_energy_cap, int(cand.energy + boost))
                    except Exception:
                        cand.energy = min(self._max_energy_cap, 1 + boost)
                    try:
                        cand.last_novelty = int(novelty)
                    except Exception:
                        cand.last_novelty = 0
                    # 标记为 favored（记录时间戳），便于后续优先探索（短期）
                    try:
                        self._favored[cid] = time.time()
                    except Exception:
                        pass
                # 对于 crash/hang，不给予过高能量奖励以避免资源倾斜
                if status in ("crash", "hang"):
                    # 将能量限制在一个较低区间，允许继续探索但不放大优先级
                    try:
                        cand.energy = max(1, min(cand.energy, 3))
                    except Exception:
                        cand.energy = 1
                else:
                    # 依据新的统计重新计算能量
                    # 使用 calculate_score 的结果但施加能量上限
                    try:
                        cand_energy = max(1, int(self.calculate_score(cand)))
                        cand.energy = min(self._max_energy_cap, cand_energy)
                    except Exception:
                        cand.energy = 1
                return cid

        # 不在语料中，根据结果决定是否把该样本加入语料
        # 不把 crash/hang 新样本直接加入语料池，以免语料被低质量/不稳定样本占满
        if status in ("crash", "hang"):
            return None
        if novelty and novelty > 0:
            # 新颖样本加入语料并分配基于 novelty 的能量，使用全局上限
            energy = min(self._max_energy_cap, max(6, int(1 + novelty * 3)))
            cid = self.add_seed(sample, energy=energy)
            # 若有覆盖签名，则将其记录到新加入的候选中
            try:
                if cov_sig:
                    self._corpus[cid].cov_sig = cov_sig
            except Exception:
                pass
            # 新加入条目也标记其最近新颖度
            try:
                self._corpus[cid].last_novelty = int(novelty)
            except Exception:
                pass
            # 新加入的高新颖样本也应被短期优先探索（记录时间戳）
            try:
                self._favored[cid] = time.time()
            except Exception:
                pass
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
        # 兼容性防护：若传入的 cand 或 cand.data 非预期类型，返回保守分数
        try:
            data = getattr(cand, 'data', None)
        except Exception:
            return 1.0
        if data is None:
            size = 0
        else:
            # 若 data 不是 bytes/bytearray，尝试安全获取长度；否则设为 0
            if isinstance(data, (bytes, bytearray)):
                size = len(data)
            else:
                try:
                    size = len(data)
                except Exception:
                    # 记录一次简单警告到 stderr，以便后续调查
                    print(f"[scheduler] warning: candidate.data has unexpected type {type(data)}, treating size=0", file=sys.stderr)
                    size = 0
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

        # 新颖度加成（短期强推）
        try:
            novelty_boost = min(getattr(cand, 'last_novelty', 0) * 5.0, 200.0)
        except Exception:
            novelty_boost = 0.0
        score += novelty_boost

        # 将 energy 作为乘数因子引入评分（采用对数缩放以获得更平滑的收益，减少能量垄断）
        try:
            import math
            energy = max(1, int(getattr(cand, 'energy', 1) or 1))
        except Exception:
            energy = 1
        # 对数缩放：log1p 能量，再乘以小系数
        try:
            score *= (1.0 + math.log1p(min(energy, 100)) * 0.05)
        except Exception:
            score *= (1.0 + min(energy, 50) * 0.04)

        # 加入少量随机抖动，防止评分完全确定导致长期卡住（AFL++ 的非确定性选择行为）
        try:
            import random as _r
            jit = _r.random() * 0.01 * score
            score += jit
        except Exception:
            pass

        # 保证下限
        if score < 1.0:
            score = 1.0
        return score

    @property
    def corpus(self) -> List[bytes]:
        """返回当前语料池的 bytes 列表（按 id 顺序）。"""
        return [c.data for _id, c in sorted(self._corpus.items())]
