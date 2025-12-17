# fuzz-project

## 开发框架初始化日志

2025-12-15：初始化 Python 开发骨架，添加以下占位目录与文件（中文说明）：

- `mini_afl_py/` - Python 包入口（包含 `__init__.py`，包级说明与 `__version__` 占位）。
- `mini_afl_py/core/` - 核心模块占位：`__init__.py`, `scheduler.py`, `coverage.py`（调度器与覆盖数据结构占位）。
- `mini_afl_py/instrumentation/` - 插装适配占位：`__init__.py`, `assembler.py`（用于编译期/运行期插装的占位接口）。
- `mini_afl_py/mutators/` - 变异器占位：`__init__.py`, `basic_mutator.py`（基础变异器接口占位）。
- `mini_afl_py/targets/` - 模糊目标适配占位：`__init__.py`, `command_target.py`（命令行目标封装占位）。
- `mini_afl_py/utils/` - 通用工具占位：`__init__.py`, `config.py`（默认配置与载入占位）。
- `tests/test_placeholder.py` - 简单占位测试，用于验证包导入。
- `examples/README.md` - 示例目录说明（占位）。
- `docs/architecture.md` - 架构概览（占位文档）。

## 实现日志：CommandTarget

2025-12-16：实现 `CommandTarget` 的最小可用原型，目的是为上层调度器与变异器提供一个稳定、简单的执行器。

- 文件位置：`mini_afl_py/targets/command_target.py`。
- 主要功能：
	- 支持 `stdin` 与 `file` 两种输入传递方式；
	- 在 Unix 平台给子进程创建新进程组（`setsid`），便于在超时或 hang 时统一终止；
	- 使用 `subprocess.Popen` + `communicate(timeout=...)` 实现超时检测；
	- 捕获 `stdout` / `stderr` / `exit_code` 与 `wall_time` 并返回最小化的 `CommandTargetResult` 结构；
	- 在检测到 crash（简化：非零退出码或异常）时，将触发输入保存到 `artifacts/` 目录以便复现与最小化。

后续计划：将 `CommandTarget` 与 `Scheduler`、`Mutator`、`Instrumentation` 集成，构建最小可运行的 fuzz 循环，并增加更多测试以覆盖 `file`、`stdin`、超时与崩溃分类场景。

## 实现日志：变异器与 fuzz 循环集成（2025-12-17）

2025-12-17：完成初始变异算子实现并把变异器接入到一个最小 fuzz 主循环，方便快速验证和迭代。

- 新增/完善变异器实现（位置：`mini_afl_py/mutators/`）：
	- `bitflip_mutator.py`：逐位翻转变异（逐比特取反，默认限制为前 64 位）。
	- `arith_mutator.py`：对 1/2/4 字节字段进行小幅算术加减（实现中针对 2/4 字节使用 `int.from_bytes`/`to_bytes` 保持小端且可读性更好）。
	- `interest_mutator.py`：用“有趣值”（边界/特殊值）替换 1/2/4 字节字段以触发边界条件。
	- `havoc_mutator.py`：随机多次编辑（翻转/异或/插入/删除/设置）以生成较大扰动的样本。
	- `splice_mutator.py`：从语料池选择另一样本并在随机断点拼接，形成组合输入。

- 集成：
	- 新增最小 fuzz 循环实现：`mini_afl_py/fuzzer.py`，将 `Scheduler`、变异器与 `CommandTarget` 串联，按阶段执行变异（确定性阶段：`bitflip`/`arith`/`interest`，非确定性阶段：`havoc`/`splice`），并用简单启发式把有趣样本加入内部语料池。

## 实现日志：调度器改进、修复与验证（2025-12-17）

2025-12-17：对调度器、fuzzer 与若干实现错误进行了修复与增强，完成端到端的快速验证。

- `mini_afl_py/core/scheduler.py`：实现 `Candidate` 数据结构并改进调度逻辑
	- 新增 `Candidate`（包括 `id`, `data`, `energy`, `cycles`, `avg_exec_time`, `hits` 等元信息），用于在语料池中跟踪样本状态。
	- 实现 `calculate_score()` 启发式评分（基于样本大小、执行时间、被调度次数与命中计数），并用于加权抽样选择下一候选（近似 AFL 的评分思路以分配能量）。
	- `report_result()` 会在收到执行结果后更新 `avg_exec_time` / `hits` / `energy` 并决定是否将新样本加入语料池。

- Bug 修复与互操作性：
	- 修正 fuzzer -> mutator 的调用边界：之前误把 `Candidate` 对象直接传入变异器（导致 `TypeError: object of type 'Candidate' has no len()'`），现在统一传入 `candidate.data: bytes`。
	- 改进 `arith_mutator.py` 中对 2/4 字节的操作，实现 `int.from_bytes` / `to_bytes` 小端转换以提高可读性且保持原有环绕行为。

- 验证运行：
	- 在本地对 `MiniAFL` 运行快速验证：

```bash
python -c "from mini_afl_py.fuzzer import MiniFuzzer; import sys; f=MiniFuzzer(target_cmd=[sys.executable,'-c','import sys; sys.exit(0)'], timeout=1.0); f.add_seed(b'AAAA'); f.add_seed(b'BBBB'); f.run(run_time=4)"
```

	- 结果：确定性变异（`Bitflip`/`Arith`/`Interest`）与非确定性变异（`Havoc`/`Splice`）均执行正常，日志显示 `Scheduler` 成功将若干样本加入语料池（示例：`Scheduler added sample id=1/2`）。
