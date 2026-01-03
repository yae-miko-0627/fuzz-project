"""miniAFL - fuzzer 入口模块。
"""
from __future__ import annotations

import sys
import os
import argparse
import time
from typing import Optional
from pathlib import Path
import threading
import shlex

# 兼容性：允许直接用 `python fuzzer.py` 运行而不报相对导入错误。
# 当脚本作为顶级模块执行（__package__ is None）时，把包的父目录加入 sys.path
# 并设置 __package__ 为包名，这样后续的相对导入会正常工作。
if __name__ == "__main__" and __package__ is None:
	import sys as _sys, os as _os
	_this_dir = _os.path.dirname(_os.path.abspath(__file__))
	_pkg_parent = _os.path.dirname(_this_dir)
	if _pkg_parent not in _sys.path:
		_sys.path.insert(0, _pkg_parent)
	__package__ = "mini_afl_py"


from .core.scheduler import Scheduler
from .core.monitor import Monitor
from .core.aggression import AggressionManager
from .targets.command_target import CommandTarget
from .mutators.havoc_mutator import HavocMutator
from .mutators.bitflip_mutator import BitflipMutator
from .mutators.arith_mutator import ArithMutator
from .mutators.interest_mutator import InterestMutator
from .mutators.splice_mutator import SpliceMutator
from .mutators.lua_mutator import LuaMutator
from .mutators.mjs_mutator import MjsMutator
from .mutators.png_mutator import PngMutator
from .mutators.jpeg_mutator import JpegMutator
from .mutators.pcap_mutator import PcapMutator
from .mutators.xml_mutator import XmlMutator
from .mutators.elf_mutator import ElfMutator
from .instrumentation.coverage import CoverageData
from .core.eval import coverage_curve, export_curve_csv
from .utils import format_detector


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="miniAFL - minimal fuzzer runner")
	parser.add_argument("--target", required=True, help="full target command (e.g. '/path/to/readelf -a @@ @@')")
	parser.add_argument("--seeds", required=True, help="path to seeds directory")
	parser.add_argument("--outdir", required=True, help="output directory for results")
	parser.add_argument("--time", type=int, default=3600, help="fuzzing time in seconds")
	parser.add_argument("--mode", choices=["stdin", "file"], default="stdin", help="input mode: stdin or file")
	parser.add_argument("--timeout", type=float, default=1.0, help="per-run timeout in seconds")
	parser.add_argument("--status-interval", type=int, default=5, help="status print interval in seconds (0 to disable)")
	return parser.parse_args(argv)


def fuzz_loop(scheduler: Scheduler, target: CommandTarget, monitor: Monitor,
			 runtime_seconds: int, args: argparse.Namespace, out_dir: Path,
			 basic_mutators=None) -> None:
	"""核心 fuzz 循环入口。

	实现：
	- 从 `scheduler.next_candidate()` 获取 `Candidate`；
	- 根据 `target_format` 选择特化 `mutator`（若存在），否则在基础变异器中随机选择；
	- 对每个变体执行 `target.run()` 并把结果传入 `monitor.record_run()` 与 `scheduler.report_result()`；
	- reporter 线程负责周期性打印状态，主线程负责执行与调度。
	"""
	start_ts = time.time()
	end_ts = start_ts + float(runtime_seconds)
	print(f"fuzz loop starting, runtime={runtime_seconds}s")

	# 状态打印间隔（秒），若为 0 则不打印
	status_interval = getattr(args, 'status_interval', 0) or 0
	stop_event = threading.Event()

	def _reporter() -> None:
		if status_interval <= 0:
			return
		while not stop_event.is_set():
			now = time.time()
			if now >= end_ts:
				break
			elapsed = now - start_ts
			records = len(monitor.records)
			corpus_size = len(scheduler.corpus)
			exec_rate = records / elapsed if elapsed > 0 else 0.0
			remaining_s = int(max(0, end_ts - now))
			try:
				cum_cov = len(getattr(monitor, 'cumulative_cov', []))
			except Exception:
				cum_cov = 0
			print(f"status: elapsed={int(elapsed)}s, remaining={remaining_s}s, corpus={corpus_size}, records={records}, rate={exec_rate:.2f} r/s, cum_cov={cum_cov}", flush=True)
			stop_event.wait(status_interval)

	reporter_thread = threading.Thread(target=_reporter, name="status-reporter", daemon=True)
	reporter_thread.start()

	# 预备变异器集合
	import random as _rnd
	if basic_mutators is None:
		basic_mutators = [BitflipMutator(), ArithMutator(), InterestMutator(), HavocMutator(), SpliceMutator()]

	# 复合变异器：对候选执行若干次随机变异，每次从 pool 随机挑选变异器并消费其部分输出
	class CompositeMutator:
		def __init__(self, pool, calls=3, per_call_limit=8, rnd=None):
			self.pool = pool
			self.calls = calls
			self.per_call_limit = per_call_limit
			self._rnd = rnd or _rnd

		def mutate(self, data):
			# 对每次调用，随机选取一个变异器并从其生成器中取若干变体
			for _ in range(self.calls):
				m = self._rnd.choice(self.pool)
				try:
					gen = m.mutate(data)
				except Exception:
					continue
				count = 0
				for v in gen:
					if v is None:
						continue
					yield v
					count += 1
					if count >= self.per_call_limit:
						break

	# 覆盖增长检测（用于决定是否优先使用基础变异器以探索新种）
	cov_last = 0
	cov_check_interval = 10.0  # seconds
	last_cov_check = start_ts
	prefer_basic = False

	# Aggression manager: 在增长缓慢时触发更激进的变异参数
	agg_manager = AggressionManager()
	_prev_aggressive = False

	# 内置激进默认（基于测试脚本的观察）
	# - 每次 mutate() 处理更多变体以提高触发率
	# - 对单个候选应用更多 attempts 以做局部深入搜索
	max_variants = 100
	max_attempts = 16

    
	
	try:
		# 主循环：选择候选 -> 生成变体 -> 执行 -> 记录
		while True:
			now = time.time()
			if now >= end_ts:
				print("time limit reached, exiting fuzz loop")
				break
			cand = scheduler.next_candidate()
			if cand is None:
				time.sleep(0.2)
				continue

			# 周期性评估覆盖增长，若增长缓慢则提高基础变异器优先级
			now = time.time()
			if (now - last_cov_check) >= cov_check_interval:
				# 使用 Monitor 的窗口速率判断替代原先的简易判断
				try:
					cov_now = len(getattr(monitor, 'cumulative_cov', []))
				except Exception:
					cov_now = 0
				# 更新 cov history via record_run has already occurred; 使用 Monitor.is_growth_slow
				slow = False
				try:
					slow = monitor.is_growth_slow(window_seconds=int(cov_check_interval * 3), min_rate=0.02, min_delta=2)
				except Exception:
					slow = False

				prefer_basic = bool(slow)
				# 更新 aggression manager
				agg_manager.update(slow)
				# 若激进模式发生变更，则对基础变异器应用/恢复缩放
				if agg_manager.is_aggressive != _prev_aggressive:
					_prev_aggressive = agg_manager.is_aggressive
					if agg_manager.is_aggressive:
						# 启用激进模式
						for m in basic_mutators:
							try:
								if hasattr(m, 'apply_aggression'):
									m.apply_aggression(agg_manager.scale)
							except Exception:
								pass
					else:
						# 恢复为常规模式
						for m in basic_mutators:
							try:
								if hasattr(m, 'clear_aggression'):
									m.clear_aggression()
							except Exception:
								pass

				cov_last = cov_now
				last_cov_check = now

			# 根据种子内容检测格式并准备专用变异器（若存在）
			spec_mutator = None
			seed_fmt = format_detector.detect_from_bytes(cand.data)
			if seed_fmt == 'elf':
				spec_mutator = ElfMutator()
			elif seed_fmt in ('jpeg', 'jpg'):
				spec_mutator = JpegMutator()
			elif seed_fmt == 'lua':
				spec_mutator = LuaMutator()
			elif seed_fmt == 'mjs':
				spec_mutator = MjsMutator()
			elif seed_fmt == 'pcap':
				spec_mutator = PcapMutator()
			elif seed_fmt == 'png':
				spec_mutator = PngMutator()
			elif seed_fmt == 'xml':
				spec_mutator = XmlMutator()

			import random as _rnd
			# attempts 由候选 energy 决定，但受内置上限约束以避免过度爆炸
			attempts = int(getattr(cand, 'energy', 1) or 1)
			attempts = max(1, min(max_attempts, attempts))

			for _attempt in range(attempts):
				try:
					# 选择变异器策略：若存在专用变异器，则有三种使用模式：
					#  - 普通：优先使用专用变异器（保持高命中率）
					#  - 瓶颈/增长慢：较高概率使用复合策略或基础变异器以探索新种
					#  - 复合策略：在一次候选上执行若干次随机变异，每次随机挑选变异器并采样若干变体
					if spec_mutator is not None:
						# respect user override to disable auto prefer-basic switching
						_effective_prefer_basic = False if getattr(args, 'no_auto_prefer_basic', False) else bool(prefer_basic)
						# composite probability configurable via env; higher when in slow-growth
						if _effective_prefer_basic:
							comp_p = float(os.getenv('MINIAFL_COMPOSITE_PROB_SLOW', '0.6'))
						else:
							comp_p = float(os.getenv('MINIAFL_COMPOSITE_PROB_NORMAL', '0.1'))
						# decide to use composite strategy
						if _rnd.random() < comp_p:
							pool = [spec_mutator] + list(basic_mutators)
							calls = _rnd.randint(1, int(os.getenv('MINIAFL_COMPOSITE_MAX_CALLS', '4')))
							per_call = int(os.getenv('MINIAFL_COMPOSITE_PER_CALL', '8'))
							chosen = CompositeMutator(pool, calls=calls, per_call_limit=per_call, rnd=_rnd)
							gen = chosen.mutate(cand.data)
						else:
							# fallback to legacy weighting: 若处于瓶颈，倾向基础变异器；否则偏好专用变异器
							if _effective_prefer_basic:
								if _rnd.random() < 0.7:
									chosen = _rnd.choice(basic_mutators)
								else:
									chosen = spec_mutator
							else:
								if _rnd.random() < 0.7:
									chosen = spec_mutator
								else:
									chosen = _rnd.choice(basic_mutators)
							gen = chosen.mutate(cand.data)
					else:
						# 仅基础变异器可用时随机选择一个
						chosen = _rnd.choice(basic_mutators)
						gen = chosen.mutate(cand.data)

					# 规范化 mutator 输出：若 mutator 返回单个 bytes/bytearray，
					# 把它包装为可迭代集合；避免把 bytes 当作可迭代字节序列导致每次
					# 迭代产出 int（单字节），从而错误传入 target.run。
					if isinstance(gen, (bytes, bytearray)):
						gen = (gen,)
					count_v = 0
					# 使用内置的 max_variants（激进值）
					# max_variants 已在外部定义
					for variant in gen:
						if variant is None:
							continue
						if time.time() >= end_ts:
							break
						try:
							res = target.run(variant, mode=args.mode, timeout=args.timeout)
						except Exception:
							res = type('R', (), {'status': 'error', 'wall_time': 0.0, 'coverage': None, 'artifact_path': None})()

                        

						try:
							monitor.record_run(sample_id=cand.id if hasattr(cand, 'id') else None,
									 sample=variant,
									 status=res.status,
									 wall_time=getattr(res, 'wall_time', 0.0),
									 cov=getattr(res, 'coverage', None),
									 artifact_path=getattr(res, 'artifact_path', None),
									 stderr=getattr(res, 'stderr', None))
						except Exception:
							pass

						try:
							scheduler.report_result(variant, res)
						except Exception:
							pass

						count_v += 1
						if count_v >= max_variants:
							break

					if time.time() >= end_ts:
						break
				except Exception:
					continue

			time.sleep(0.001)

	except KeyboardInterrupt:
		print("interrupted by user, shutting down fuzz loop")
	finally:
		stop_event.set()
		reporter_thread.join(timeout=2.0)

	# 结束时导出监控记录并打印汇总
	try:
		outpath = monitor.export_records(str(out_dir / "monitor_records.json"))
		print(f"monitor records exported to: {outpath}")
		# 生成覆盖曲线并导出为 CSV（即使记录为空也会写入带表头的文件）
		try:
			curve = coverage_curve(monitor)
			csv_path = str(out_dir / "coverage_curve.csv")
			export_curve_csv(curve, csv_path)
			print(f"coverage curve exported to: {csv_path}")
		except Exception:
			print("failed to export coverage curve CSV")
	except Exception:
		print("failed to export monitor records")

	# 打印简要汇总信息
	total_runs = len(monitor.records)
	crashes = sum(1 for r in monitor.records if getattr(r, 'status', '') == 'crash')
	hangs = sum(1 for r in monitor.records if getattr(r, 'status', '') == 'hang')
	novelty_hits = sum(1 for r in monitor.records if getattr(r, 'novelty', 0) >= monitor.novelty_threshold)
	cum_cov = len(getattr(monitor.cumulative_cov, 'points', []))
	print("======== fuzz summary ========")
	print(f"  total runs: {total_runs}")
	print(f"  crashes: {crashes}, hangs: {hangs}, novelty_hits: {novelty_hits}")
	print(f"  cumulative_coverage: {cum_cov} edges")
	print("===== fuzz loop finished =====")
	return


def main(argv: Optional[list] = None) -> int:
	"""解析命令行参数并做最基本的校验与准备。

	目前只负责解析参数并创建输出目录，后续会把调度与执行逻辑填入此处。
	"""
	args = parse_args(argv)

	# 基本路径校验：--target 现在应为完整命令字符串，提取可执行文件并校验其存在
	seeds_path = Path(args.seeds)
	out_dir = Path(args.outdir)

	try:
		target_tokens = shlex.split(args.target)
	except Exception:
		print(f"error: failed to parse --target command: {args.target}", file=sys.stderr)
		return 2

	if len(target_tokens) == 0:
		print("error: empty --target", file=sys.stderr)
		return 2

	target_exec = Path(target_tokens[0])
	if not target_exec.exists():
		print(f"error: target executable not found: {target_exec}", file=sys.stderr)
		return 2
	# seeds 检查
	if not seeds_path.exists() or not seeds_path.is_dir():
		print(f"error: seeds directory not found: {seeds_path}", file=sys.stderr)
		return 3

	try:
		out_dir.mkdir(parents=True, exist_ok=True)
	except Exception as e:
		print(f"error: cannot create outdir {out_dir}: {e}", file=sys.stderr)
		return 4

	# 把解析结果打印以便调试（后续可切换到日志）
	print(f"target: {args.target}")
	print(f"seeds: {seeds_path}")
	print(f"outdir: {out_dir}")
	print(f"time: {args.time}s, mode: {args.mode}, timeout: {args.timeout}s, status-interval: {args.status_interval}s")

	# 初始化调度器与监控器
	scheduler = Scheduler()
	monitor = Monitor(out_dir=str(out_dir / "monitor_artifacts"))

	# 从 seeds 目录加载种子到调度器
	seed_files = list(seeds_path.iterdir())
	added = 0
	for sf in seed_files:
		if sf.is_file():
			try:
				data = sf.read_bytes()
				scheduler.add_seed(data)
				added += 1
			except Exception:
				continue

	print(f"Scheduler initialized: corpus_size={len(scheduler.corpus)} (added {added} seeds)")
	print(f"Monitor initialized, artifacts dir: {monitor.out_dir}")

	# 初始化 CommandTarget：--target 为完整命令字符串（例如 '/full/path/readelf -a @@ @@'）
	target_cmd = target_tokens
	target = CommandTarget(cmd=target_cmd, timeout_default=args.timeout)

	# 启动核心 fuzz 循环（当前为占位实现，会在达到时间限制后退出）
	fuzz_loop(scheduler=scheduler, target=target, monitor=monitor,
			 runtime_seconds=args.time, args=args, out_dir=out_dir)

	return 0


if __name__ == "__main__":
	sys.exit(main())

