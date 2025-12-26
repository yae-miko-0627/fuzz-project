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
	parser.add_argument("--target", required=True, help="path to target binary")
	parser.add_argument("--target-cmd", help="explicit target command template (e.g. \"readelf -a @@ @@\") - when provided, this string will be split and used as the command; '@@' is replaced with input file path in file mode")
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

			# 根据种子内容检测格式并选择专用变异器（若存在）；否则回退到基础变异器
			mutator_obj = None
			seed_fmt = format_detector.detect_from_bytes(cand.data)
			if seed_fmt == 'elf':
				mutator_obj = ElfMutator()
			elif seed_fmt in ('jpeg', 'jpg'):
				mutator_obj = JpegMutator()
			elif seed_fmt == 'lua':
				mutator_obj = LuaMutator()
			elif seed_fmt == 'mjs':
				mutator_obj = MjsMutator()
			elif seed_fmt == 'pcap':
				mutator_obj = PcapMutator()
			elif seed_fmt == 'png':
				mutator_obj = PngMutator()
			elif seed_fmt == 'xml':
				mutator_obj = XmlMutator()

			import random as _rnd
			attempts = int(getattr(cand, 'energy', 1) or 1)
			attempts = max(1, min(8, attempts))

			for _attempt in range(attempts):
				try:
					if mutator_obj is not None:
						gen = mutator_obj.mutate(cand.data)
					else:
						mut = _rnd.choice(basic_mutators)
						gen = mut.mutate(cand.data)

					count_v = 0
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
									 artifact_path=getattr(res, 'artifact_path', None))
						except Exception:
							pass

						try:
							scheduler.report_result(variant, res)
						except Exception:
							pass

						count_v += 1
						if count_v >= 4:
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

	# 基本路径校验
	target_path = Path(args.target)
	seeds_path = Path(args.seeds)
	out_dir = Path(args.outdir)

	if not target_path.exists():
		print(f"error: target not found: {target_path}", file=sys.stderr)
		return 2
	if not seeds_path.exists() or not seeds_path.is_dir():
		print(f"error: seeds directory not found: {seeds_path}", file=sys.stderr)
		return 3

	try:
		out_dir.mkdir(parents=True, exist_ok=True)
	except Exception as e:
		print(f"error: cannot create outdir {out_dir}: {e}", file=sys.stderr)
		return 4

	# 把解析结果打印以便调试（后续可切换到日志）
	print(f"target: {target_path}")
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

	# 初始化 CommandTarget：优先使用 --target-cmd 字符串（会被 shlex.split），否则使用 --target 路径
	if getattr(args, 'target_cmd', None):
		try:
			target_cmd = shlex.split(args.target_cmd)
		except Exception:
			# 解析失败时回退为把字符串整体作为命令
			target_cmd = [args.target_cmd]
	else:
		target_cmd = [str(target_path)]

	target = CommandTarget(cmd=target_cmd, timeout_default=args.timeout)

	# 启动核心 fuzz 循环（当前为占位实现，会在达到时间限制后退出）
	fuzz_loop(scheduler=scheduler, target=target, monitor=monitor,
			 runtime_seconds=args.time, args=args, out_dir=out_dir)

	return 0


if __name__ == "__main__":
	sys.exit(main())

