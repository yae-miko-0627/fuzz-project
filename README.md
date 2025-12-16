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