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