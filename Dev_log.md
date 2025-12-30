````markdown
# fuzz-project — 构建与实现日志

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

## 实现日志：监控与评估（2025-12-17）

2025-12-17：实现运行结果监控与覆盖评估的基础组件，便于在无完整插装时也能记录执行统计并分析覆盖随时间变化。

- 新增监控模块：mini_afl_py/core/monitor.py
  - 实现 Monitor 与 RunRecord，记录每次运行的时间戳、sample_id、status、wall_time、
ovelty（新增覆盖点数）和累计覆盖。
  - 在 crash/hang 或达到新颖度阈值时自动保存触发样本到 monitor_artifacts/（可配置）。

- 新增评估模块：mini_afl_py/core/eval.py
  - 提供 coverage_curve() 将 Monitor.records 转为覆盖率随时间变化的曲线，及 export_curve_csv() 导出为 CSV 以便绘图或分析。

- 简单验证：已添加示例测试脚本 mini_afl_py/tests/run_monitor_test.py，演示 Monitor 与 CoverageData 的交互，并导出覆盖曲线为 	est_monitor/curve.csv。

## 实现日志：将 `novelty`（覆盖新增点）纳入调度器（2025-12-17）

2025-12-17：在 `mini_afl_py/core/scheduler.py` 中增强 `report_result()`，把运行时产生的覆盖新增点（在运行路径中称为 `coverage_new` 或 `novelty`）作为能量分配的参考信号。

- 主要改动：
	- `report_result()` 现在会在收到 `result` 时读取 `coverage_new` / `novelty` 字段；
	- 对已存在的语料条目：如果观测到 `novelty>0`，则对该候选样本按 `novelty` 做能量提升（简单映射：`novelty 1 -> +3 energy`，可进一步调优）；
	- 对新发现样本：若 `novelty>0` 或 `status` 为 `crash`/`hang`，则以较高初始能量将其加入语料池，保证后续有更多机会被变异和调查；
	- 仍保持 `calculate_score()` 的启发式评分回路，用于对长期统计（avg_exec_time、size、cycles、hits）作背景性能量调整。

- 动机与效果：
	- 使调度器能更直接地把“发现新覆盖位点”的反馈转化为更多尝试资源，从而在没有完整 AFL 位图接入前也能提高探索效率；
	- 在本地快速验证（`quick_sched_test.py`）中已确认：当 `coverage_new` 为正时，样本会被提升能量并保留在语料中，语料池条目统计（`hits`/`avg_exec_time`）正确更新。

## AFL++ 适配变更日志（摘要）

2025-12-17 至 2025-12-18：为更好复用 AFL++ 的插装与种子能力，对 MiniAFL 做了下列适配与精简：

- 移除 Python 原生的 trace/text 覆盖解析与源码级覆盖结构，统一采用 AFL edge-id/bitmap 表示，避免重复实现带来的差异。
- 新增 AFL map 解析器：`mini_afl_py/instrumentation/coverage.py` 提供 `parse_afl_map()`，可解析 `afl-showmap` 的文本或二进制输出为 `CoverageData`（edge id 集合）。
- 精简编译辅助：`mini_afl_py/instrumentation/assembler.py` 仅保留 `afl_cc_command(...)` 用于构造 `afl-cc` 编译命令，上层负责在容器/主机上执行该命令（不在库内执行编译）。
- 目标运行器适配：`mini_afl_py/targets/command_target.py` 在 `DEFAULTS['instrumentation_mode']=='afl'` 时，优先通过 `afl-showmap` 执行目标并把 map 解析结果附加到 `CommandTargetResult.coverage`。
- 调度器改造：`mini_afl_py/core/scheduler.py` 增加累计覆盖集合并在 `report_result()` 中基于 `result.coverage` 计算 novelty（新增 edge 数）以调整能量分配与语料加入策略。

## 实现日志：Python SHM 管理器（`shm_manager.py`，2025-12-18）

2025-12-18：实现基于 System V 共享内存的 Python 管理器 `mini_afl_py/instrumentation/shm_manager.py` ，并把项目默认插装改为 `shm_py`（Python 创建 SHM，AFL++ 插装向 SHM 写位图，Python 读取位图并解析为 `CoverageData`）。

- 目的：摆脱对 `afl-showmap` 的依赖，直接使用与 AFL 插装 runtime 相同的共享内存位图机制，以降低开销并更好地与自定义调度器集成。

- 主要实现内容：
	- `shm_manager.py`：通过 ctypes 调用 libc 的 `shmget`/`shmat`/`shmdt`/`shmctl` 创建并读取 System V SHM（默认 65536 字节），将 `__AFL_SHM_ID` 注入子进程环境，运行目标，结束后把位图写入 `map_out` 文件。
	- `CommandTarget`：新增 `instrumentation_mode == 'shm_py'` 的执行路径，使用 `run_target_with_shm()` 启动目标并在返回后用 `parse_afl_map()` 解析位图为 `CoverageData`。
	- `utils/config.py`：默认 `instrumentation_mode` 改为 `shm_py`。
	- `MiniFuzzer`：新增 `use_shm` 参数，默认启用，确保 fuzz 循环默认走 SHM 流程.

## AFL-cc 整合测试准备（2025-12-21）

2025-12-21：为配合 AFL++ 的 `afl-cc` 插装能力并在 Ubuntu 22.04 容器中运行测试，完成如下准备工作：

- 新增 `mini_afl_py/fuzzer.py`：
	- 位置：`MiniAFL/mini_afl_py/fuzzer.py`。
	- 功能：可选调用 `afl-cc` 编译源文件（或直接使用已插装二进制），加载种子目录并在简单循环中调用 `CommandTarget` 执行样本；使用 `Monitor` 收集执行记录并周期性导出 `coverage_curve.csv` 与 `monitor_records.json`。

- 在 `MiniAFL/` 目录下新增 `Dockerfile`：
	- 位置：`MiniAFL/Dockerfile`（确保镜像构建上下文为 `MiniAFL`，以便相对路径与示例文件可用）。
	- 功能：基于 `ubuntu:22.04`，安装构建与运行依赖、克隆并编译 AFL++，把仓库内容复制到容器 `/fuzz`，并提供交互 shell 作为默认入口。可在运行命令中编译目标并调用 `fuzzer.py` 进行 smoke 测试。

## 使用 `AFLplusplus-stable/test-instr.c` 的 Smoke 测试（2025-12-22）

	2025-12-22：在构建完成的 `miniafl:latest` 容器内，使用仓库中的 `AFLplusplus-stable/test-instr.c` 作为被测程序执行了一次短时（~12s）smoke 测试，记录如下：

	- 操作步骤：
		- 在宿主 `fuzz` 目录将整个仓库挂载到容器 `/workspace`；
		- 使用 `afl-cc -g -O0 -o /workspace/MiniAFL/target_testinstr /workspace/AFLplusplus-stable/test-instr.c` 编译插装二进制；
		- 运行 `python3 /workspace/MiniAFL/mini_afl_py/fuzzer.py --out /workspace/MiniAFL/target_testinstr --seeds /workspace/MiniAFL/seeds --time 12 --outdir /workspace/MiniAFL/fuzz_out_testinstr`。

	- 关键结果摘要：
		- 测试时长：约 12 秒（实际 11.99s）；
		- 执行次数：1181 次（`sample_id` 最高为 1180）；
		- 吞吐率：约 95–100 exec/s（平均 wall_time ~0.0065s）；
		- 覆盖：首次执行产生 `novelty=6`，累计覆盖稳定为 6（`coverage_curve.csv` 全程为 6）；
		- 异常：无 `crash` 或 `hang`；首个带来新覆盖的样本已保存到 artifact（路径位于 `MiniAFL/fuzz_out_testinstr`）。

## 整合afl-cc的T01测试（2025-12-23）

2025-12-23：对 `T01`（`cxxfilt`）的整合测试与工作流记录。

- 环境准备与目录：
	- 在宿主与容器共享工作区下创建独立测试目录 `T01`：`/fuzz/T01`，并在其中建立 `source/ build/ seeds/ output/` 四个子目录，用于源码、构建产物、初始种子和 fuzz 输出。
	- 源码包位于 `/fuzz/MiniAFL/examples/binutils-2.28.tar.gz`，将其解压到 `/fuzz/T01/source`（宿主路径 `C:\Users\11053\Desktop\fuzz\T01\source`）。

- 构建被测程序（只编译目标工具以节省时间）：
	- 进入 `/fuzz/T01/source/binutils-2.28` 后，使用 `afl-cc` 插桩编译 `cxxfilt`：
		- 先运行 `./configure`（使用 `CC=afl-cc CXX=afl-c++`），以生成配置文件与构建环境；
		- 仅编译 `binutils` 子目录下的 `cxxfilt`：`make -C binutils cxxfilt`；
		- 将生成的二进制拷贝到 `/fuzz/T01/build/cxxfilt` 并设置可执行权限。
	- 验证：执行 `/fuzz/T01/build/cxxfilt --version`，确认输出 `GNU c++filt (GNU Binutils) 2.28`（表明构建成功且可运行）。

- 种子准备：
	- 在 `/fuzz/T01/seeds` 中创建初始种子文件 `seed1`，内容为字符串 `""Z1fv""`（用于 T01 的最小输入样例）。

- MiniAFL 脚本改进（实时显示功能）：
	- 为了方便短时交互式观察，把 `MiniAFL/mini_afl_py/fuzzer.py` 增强：
		- 新增 `--target` 参数（T01 便捷别名），并保留原有 `--out/--cmd` 支持；
		- 新增 `--status-interval` 参数（默认 5s），在 fuzz 运行期间以后台守护线程每隔该间隔打印一行覆盖式状态信息（使用 ANSI 清行并覆盖同一行，不持续刷屏）；
		- 在运行结束时导出 `monitor_records.json` 和 `coverage_curve.csv`，并打印汇总：总执行次数、新路径数、崩溃数与结果路径。
	- 状态行包含：已运行时间、总执行次数、执行速率、种子数、累计新路径数和崩溃数，便于在终端中实时观察探索进度。

- 运行与结果：
	- 所有准备操作（解压、构建 `cxxfilt`、创建种子与脚本增强）已完成，并在容器镜像 `miniafl:latest` 环境中通过语法检查；
	- 当前已准备好可执行的短时 fuzz 命令（样例）：
		```bash
		cd /fuzz
		python3 MiniAFL/mini_afl_py/fuzzer.py \
			--target /fuzz/T01/build/cxxfilt \
			--seeds /fuzz/T01/seeds \
			--outdir /fuzz/T01/output \
			--time 20 \
			--status-interval 5
		```
	- 说明：上面命令在容器内运行时会每 5 秒覆盖性打印当前状态行；程序结束后会生成 `monitor_records.json` 与 `coverage_curve.csv`，并在终端打印最终统计信息。 

## 重构记录：`fuzzer.py` 重构（2025-12-25）

2025-12-25：对 `mini_afl_py/fuzzer.py` 进行了重构，目标是把原有的占位主循环扩展为一个可运行的最小 fuzz 引擎骨架，变更要点如下：

- **并发状态汇报**：将周期性状态打印抽取到独立的后台线程（`status-reporter`），避免主执行线程在执行外部目标或阻塞操作时无法输出实时状态。
- **变异器选择逻辑**：按 `--target-format`（或自动检测结果）在循环内以 if/elif 直接选择特化变异器（支持 `elf`, `jpeg`/`jpg`, `lua`, `mjs`, `pcap`, `png`, `xml`）；非特化格式时从基础变异器集合中随机选择（`BitflipMutator`, `ArithMutator`, `InterestMutator`, `HavocMutator`, `SpliceMutator`）。
- **主循环实现**：实现了从 `Scheduler.next_candidate()` 获取 `Candidate`、对样本应用变异器生成若干变体、调用 `CommandTarget.run()` 执行、将结果传递给 `Monitor.record_run()` 并调用 `Scheduler.report_result()` 的完整流程。对变体数量、每次 mutate() 的迭代数及每个样本的尝试次数均设置上限以避免爆炸性产出。

## 本次调试与变异器增强（2025-12-26）

2025-12-26：针对 `mini_afl_py/fuzzer.py` 的调试工作与对若干变异器的增强已完成并验证，摘要如下：

- 问题背景与修复
	- 发现 `--target-cmd` 与 `--target` 的语义及 wrapper/超时交互导致在短超时时间内未能稳定产出 AFL 位图（coverage 0）的情况；另外在多次编辑 CLI 参数时引入了一个打印时的 `NameError`。
	- 采取措施：移除/停止使用 `--target-cmd` 的不确定路径（改为强制传入完整 `--target` 命令字符串并用 `shlex.split` 解析），修复 `fuzzer.py` 中的打印错误；优先使用 `shm_py` 模式（System V SHM）收集覆盖位图以避开 `afl-showmap` wrapper 的每次调用开销与超时问题。

- 关键文件变更（本次）
	- `mini_afl_py/fuzzer.py`：要求 `--target` 必填（完整命令），修正打印错误并明确使用 `CommandTarget(cmd=shlex.split(args.target))`；增强状态打印与监控导出保持不变。
	- `mini_afl_py/instrumentation/shm_manager.py`：验证并使用现有 `run_target_with_shm()` 接口用于目标执行并把位图写出（无代码变更，仅验证/使用）。
	- 变异器增强（已实现并提交）：
		- `mini_afl_py/mutators/bitflip_mutator.py`：增加多模式翻转（单比特、双比特、整字节、窗口翻转），提高变异多样性。
		- `mini_afl_py/mutators/havoc_mutator.py`：加入操作权重、可选语料`corpus`支持以及块异或（`block_xor`）和复制块（`copy_block`）操作，提升大扰动策略的表现力。
		- `mini_afl_py/mutators/splice_mutator.py`：避免自我拼接无效样本，增加多种拼接策略（前缀/后缀/保持前缀/保持后缀/交叉），并添加输出长度约束过滤。

- 验证摘要
	- 使用 `mini_afl_py/instrumentation/shm_manager.py` 在容器中对目标进行了单次运行测试：`run_target_with_shm()` 生成的 map 文件长度为 256 字节，解析后 `parse_afl_map()` 返回覆盖点数 252（作为基线验证）。
	- 在修复 `fuzzer.py` 的 `--target` 处理后，短跑 fuzz（shm 模式）显示监控导出文件 `monitor_records.json` 与 `coverage_curve.csv`，并能正确报告累计覆盖（cum_cov = 252）。
	- 变异器功能通过静态检查与小规模本地 mutate 调用验证，不引入语法错误或运行时异常（已通过 Python 语法检查）。

## 特化变异器实现记录（2025-12-26）

本次开发中为若干目标格式添加了轻量且实用的特化变异器，目的在于在保持变异速度的同时提升触发有效路径或崩溃的概率。以下为已加入的变异器清单、文件位置与要点说明：

- `ELF`：`MiniAFL/mini_afl_py/mutators/elf_mutator.py`
	- 要点：轻量解析 ELF header 与 section table，优先对 ELF 头关键字段（entry、phoff、shoff、e_type 等）做小幅扰动；对字符串表（.strtab/.shstrtab）进行替换/交换/截断；对可执行节使用字节级 `bitflip`/`havoc`，对符号/字符串节使用字符串级变异。
	- 设计目标：尽量保持 ELF 可解析性，变动有边界检查与 per-section 限制以避免爆炸性输出。

- `JPEG`：`MiniAFL/mini_afl_py/mutators/jpeg_mutator.py`
	- 要点：轻量解析 JPEG 段（marker/length），提供段级变异（截断到段边界、复制段、交换相邻段、破坏段长度字段）和段内字节翻转；解析失败时回退到字节级变异。
	- 适用性：对 libjpeg 解码器与文件解析逻辑能触发格式相关崩溃或异常处理代码。

- `Lua`：`MiniAFL/mini_afl_py/mutators/lua_mutator.py`
	- 要点：针对脚本文本，提供标识符改名、数字微调、字符串破坏、行删除/注释切换、插入字面量与行交换等轻量策略；对非 UTF-8 输入回退到字节变异。
	- 设计目标：在保持语法大致正确的前提下触发运行时逻辑错误或解析异常。

- `MJS / ES module`：`MiniAFL/mini_afl_py/mutators/mjs_mutator.py`
	- 要点：类似 JS 专用变异器，支持标识符扰动、数字/字符串微变、操作符替换（===/==、!==/!=）、行注释切换、插入字面量、相邻行交换。
	- 目标：触发 JS 引擎或运行时在类型/相等/控制流上的不同路径。

- `PCAP`：`MiniAFL/mini_afl_py/mutators/pcap_mutator.py`
	- 要点：轻量解析 pcap global header 与 packet records，提供包级变异（截断到包、复制包、交换相邻包）、包内字节翻转与破坏 incl_len 字段，解析失败回退字节级变异。
	- 适用场景：网络解析/回放工具、libpcap 解析器等。

- `PNG`：`MiniAFL/mini_afl_py/mutators/png_mutator.py`
	- 要点：解析 PNG chunk（长度/type/payload/crc），允许删除/复制/交换 chunk（保留 IHDR/IEND 保护）、在 payload 中翻转字节、破坏 chunk 长度或微调 IHDR 的宽高字段。
	- 设计目标：在尽量保持文件可解析性的同时诱发解码器对异常长度/CRC/metadata 的不同处理路径。

- `XML`：`MiniAFL/mini_afl_py/mutators/xml_mutator.py`
	- 要点：使用 stdlib `xml.etree.ElementTree` 做轻量解析，提供标签插入/删除、属性扰动、文本微变、实体替换及解析回退（字节级变异）。
	- 适用性：触发 XML 解析器在节点/属性/实体处理上的边界或异常路径。

共同设计原则：

- 轻量：尽量使用 Python 标准库进行快速解析（避免增加依赖），在变异循环中尽量保持低开销。
- 可复现：变异器支持可选随机种子参数以便复现结果。
- 回退安全：当针对性解析失败时，回退到简单的字节级变异以保证总能产出变体。
- 示例/自测：每个变异器文件包含 `__main__` 示例用于本地快速验证（打印变异样例、长度/头尾摘要等）。

## 本阶段调度与运行策略优化（2025-12-28）

2025-12-28：针对在长跑中出现的“语料快速膨胀但覆盖陷入瓶颈，且大量种子触发 crash 导致资源倾斜”的问题，进行了三方面的最小、可回退优化：

- 1) `fuzzer.py`：内置激进的运行默认值以靠近测试脚本行为（便于快速发现新路径）
	- 每次 mutate() 默认允许更多变体输出（`max_variants` 由原硬编码 4 提升到 100，内置于循环），每候选的最大尝试上限设置为 16

- 2) `Monitor`（`mini_afl_py/core/monitor.py`）行为调整：
	- 停止把 `crash` / `hang` 样本自动导出为 artifact 文件（原先会把所有崩溃样本写入 output，导致输出目录噪音过多）；
	- 仅在样本的 `novelty`（新增覆盖点）达到阈值时才保存为 artifact，以便后续手动/自动复用高价值样本。

- 3) `Scheduler`（`mini_afl_py/core/scheduler.py`）策略改造（参考 AFL++ 思路）：
	- 不再把新的 `crash`/`hang` 样本自动加入语料池；对已在语料池内的发生崩溃的样本不再赋予高能量（把其能量上限限制到 3），避免调度器把大部分尝试耗费在“重复崩溃”上；
	- 引入 `favored` 集合：当样本带来新颖覆盖时（novelty>0），把该样本短期标为 `favored`，scheduler 会以 ~65% 概率优先从 `favored` 集合抽样以加速“放大”该发现；被多次选中的 `favored` 会被逐步降级以避免长期垄断；
	- 能量影响评分时改为对数缩放（log1p）并降低增益系数，同时对评分加入少量随机抖动（jitter），以减少高能量样本的线性放大效应并提升探索多样性；
	- 对新加入的高新颖样本仍给予较高初始能量（有上限，如 12），以平衡短期深入与长期稳定探索。

预期效果与验证路径：
- 通过抑制 crash/hang 自动入池与降低其能量，减少崩溃噪音对调度资源的抢占；
- 通过 favored + 优先抽样 + 对数能量缩放与抖动，在短期内更快扩大新颖发现，同时避免长期垄断造成的 plateau；
- 已在 `T02` 上运行一次 300s 的激进试验，验证了变更后语料增长仍然迅速且覆盖能从基线（示例：252）上升；下一步建议把 `monitor` 中的高 `novelty` 样本周期性注入 `seeds/novel/` 以进一步突破覆盖瓶颈（无源码改动可立即生效）。

## 新增特化 + 基础变异器优先策略与容器运行改进（2025-12-28）

2025-12-28：为了解决在长跑中专用变异器过早耗尽预算、导致其它策略（如 PHDR/语义变异）难以命中的问题，以及希望在覆盖增长停滞时优先做广度探索，做了以下可回退改动：

- `mini_afl_py/fuzzer.py`：
	- 新增覆盖增长检测（10s 窗口，阈值可调）：周期性计算 `cumulative_cov` 的增长速率（edges/s）并设定布尔标志 `prefer_basic` 表示当前是否应优先使用基础变异器探索。
	- 当种子被识别为某些特化格式（如 `elf`, `jpeg`, `png` 等）时，除了使用对应的特化变异器外，还把基础变异器集合（`Bitflip`, `Arith`, `Interest`, `Havoc`, `Splice`）纳入候选池：
	- 该逻辑通过小改动实现（决定变异器的 `chosen` 对象），并保留原有的 `max_variants` / `max_attempts` 控制以避免输出爆炸。

## 测试日志：T01与T02 24h测试（2025-12-30）
完成了T01与T02的24h测试，但是因为忘记关电脑的自动休眠了，所以凌晨后台测试被强行暂停了

## 实现日志：覆盖与调度器性能优化（2025-12-30）

2025-12-30：为了解决在长时间 fuzz 运行中出现的速率衰减（随累计覆盖和语料池增长导致的 CPU/内存与调度开销上升），对覆盖表示与调度器做了以下优化：

- 目的：把随着时间线性增加的集合运算和遍历开销改为固定/可控的成本，从而在长跑中维持较稳定的执行速率。

- 修改文件：
	- `mini_afl_py/instrumentation/coverage.py`
	- `mini_afl_py/core/scheduler.py`

- 关键实现要点：
	1) 覆盖数据改为位图为主（`CoverageData`）：
		 - 用固定长度 `bytearray` 存储覆盖位点，新增 `merge_and_count_new()` 方法用于按位合并并返回新增命中数；
		 - 延迟构建 `points` 集合视图，仅在需要时生成，避免频繁的大集合差集计算。
	2) 覆盖签名索引（`cov_sig` -> candidate id）：
		 - 在 `Scheduler` 中维护覆盖位图的 SHA1 签名索引，优先用索引做 O(1) 匹配，避免每次遍历语料池查找重复覆盖样本。
	3) 控制活跃语料池大小（prune）：
		 - 新增 `Scheduler._prune_corpus()`：当活跃 `corpus` 超过 `_max_corpus_size`（默认 2000）时触发裁剪；保留 top-K（按 score）、所有 `favored`、少量随机样本作为探索缓冲；其余样本移至 `_archived`（可恢复/检查）；
		 - 在 `next_candidate()` 入口处周期性调用裁剪，保证调度、评分与遍历等操作的复杂度被限制在可控范围内。
	4) Score 缓存与批量计算：
		 - 为 `Candidate` 添加局部 score 缓存与时间戳；裁剪时批量刷新缓存（例如 30s 一次）以减少重复计算开销。

- 预期效果与验证要点：
	- 将 `novelty` 计算从集合差集 (O(n_points)) 降低为位图按位操作 (O(bitmap_size))，并把重复样本匹配从 O(n_corpus) 降到 O(1)（大多数情况下）；
	- 限制活跃 `corpus` 大小可显著降低 `next_candidate()` 中的排序、评分与遍历成本，从而缓解长期运行中执行速率逐渐下降的问题；
	- 被裁剪样本保留在 `_archived`，可按需写盘或延迟恢复，避免数据丢失。

## 实现日志：CSV 到 X/Y 绘图工具（2025-12-30）

2025-12-30：在 `mini_afl_py/utils` 下添加 `csv_to_xy_plot.py`，用于将 CSV 数据导出为 x-y 图（支持 `line` 与 `scatter`）。

- 文件位置：`MiniAFL/mini_afl_py/utils/csv_to_xy_plot.py`
- 主要功能：
	- 支持通过列名或列索引（从0开始）指定 `--x` 与 `--y`；`--y` 支持逗号分隔多列
	- 支持自定义分隔符 `-d`、输出文件 `-o`、图类型 `--kind`（line/scatter）、matplotlib 风格 `--style`
	- 支持对数坐标 `--xlog/--ylog`、输出分辨率 `--dpi` 及点标记 `--marker`
	- 若安装 `pandas` 会使用其读取 CSV，未安装则回退到标准库 `csv` 解析