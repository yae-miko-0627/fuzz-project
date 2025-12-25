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

## 专用变异器扩展（2025-12-25）

2025-12-25：为提高对目标样本格式的语义感知和变异效率，新增一组格式专用变异器（位于 `mini_afl_py/mutators/`）：

- `elf_mutator.py`：只变异 ELF 文件的节区（section）内容，保护 ELF 头与节表不被修改。实现要点：轻量解析 ELF32/ELF64 小端节表，跳过 SHT_NOBITS（.bss），对每个节调用已有基础变异器（`BitflipMutator`/`ArithMutator`/`InterestMutator`/`HavocMutator`），若变体长度与节大小不符则截断或以 0 填充以保持节大小一致。限制：为轻量实现，遇到复杂或非标准 ELF 时会静默跳过。

- `lua_mutator.py`：针对 Lua 源码的文本级变异器。实现要点：保护前 N 行（如 shebang）、内置增强字典（Lua 关键字与常用 API）用于插入/替换、对数字与字符串进行有针对性的变异、变异后尝试修复括号与引号闭合以减少语法错误，并复用基础变异器生成更多变体。限制：采用简单文本策略，复杂语法验证/执行需后续扩展（可接入 Lua 解释器做语法检查）。

- `xml_mutator.py`：针对 XML 的保守变异器。实现要点：保护 `<?xml ... ?>`、`<!DOCTYPE ...>`、注释与 CDATA 区域；检测并跳过常见十六进制校验和字段（32/40/64 长度）；仅对属性值与文本节点应用变异，变异结果在输出前通过 `xml.etree.ElementTree.fromstring()` 做 well-formedness 校验；变异同时对输出进行 XML 转义，保证结构完整。限制：不会主动修复或重写复杂校验和字段。

- `mjs_mutator.py`：针对 ECMAScript 模块（`.mjs`）的变异器。实现要点：保护 shebang 与 `import`/`export` 行以及 `require(...)` 内的路径字符串，内置 JS 关键字/API 词典用于插入/替换，对字符串字面量与数值字面量以及非保护代码块调用基础变异器，变异后执行括号/引号闭合修复并进行简单平衡检查，只有通过简单平衡检查的候选才输出。限制：当前仅做文本级保护与平衡检查，语法级别的精确校验（如 AST 验证）为后续改进项。

- `pcap_mutator.py`：针对 pcap 二进制抓包文件的变异器。实现要点：识别并保护全局头（24 字节）与每个 packet header（16 字节：ts_sec/ts_usec/incl_len/orig_len），仅对每个 packet 的 payload（incl_len 指定）调用基础变异器；变体保持原始 incl_len（通过截断或 0 填充），并提供 per-packet 与全局产出上限。限制：当前实现不重写或修正包内校验和（如 IP/TCP 校验和），且替换逻辑基于 payload 匹配，遇到多个相同 payload 的包时替换可能不按偏移精确定位（后续可改为记录偏移并精确替换）。

- `png_mutator.py`：针对 PNG 图片文件的变异器。实现要点：以 PNG chunk（长度/类型/数据/CRC）为单位解析文件，保护关键头（PNG signature）与非数据元的 chunk 类型（如 IHDR、IEND）；对 `IDAT`、`tEXt` 和 `zTXt` 等数据或文本类 chunk 进行变异，变异后对被修改 chunk 重新计算 CRC 并替换，确保整体文件结构与 chunk 长度字段一致；当需要对 IDAT 内部像素数据做语义变异时，当前策略为直接在压缩数据上做字节级变更（保守策略），并记录为后续改进点（建议：解压/变异/再压缩以保持更合法的图像）。限制：直接修改压缩数据可能导致图像损坏或读取失败，但可触发解析器/解码器漏洞；更高质量变异需实现 IDAT 解压-变异-重压缩流程并正确更新相关长度与 CRC。

- `jpeg_mutator.py`：针对 JPEG/JFIF/Exif 格式图像的变异器。实现要点：解析 JPEG marker 流（以 0xFFD8 SOI 开始，0xFFD9 EOI 结束），识别并保护 SOI、APPn（如 Exif）段与 SOS（Start Of Scan）之前的段元数据；对 SOS 到 EOI 之间的扫描数据（压缩熵编码部分）进行字节级变异以触发解码器在熵解码/去量化/逆变换阶段的潜在问题；变异时保留必要的段长度字段（当变更影响段长度时通过截断或填充保持一致性）并避免破坏 SOI/EOI 标记。限制：直接修改扫描数据常常产生不可解码的输出；更安全的高级策略包括解析 JPEG 到 MCU/系数层级并在系数级别进行变异（后续改进）。

## 重构记录：`fuzzer.py` 重构（2025-12-25）

2025-12-25：对 `mini_afl_py/fuzzer.py` 进行了重构，目标是把原有的占位主循环扩展为一个可运行的最小 fuzz 引擎骨架，变更要点如下：

- **并发状态汇报**：将周期性状态打印抽取到独立的后台线程（`status-reporter`），避免主执行线程在执行外部目标或阻塞操作时无法输出实时状态。
- **变异器选择逻辑**：按 `--target-format`（或自动检测结果）在循环内以 if/elif 直接选择特化变异器（支持 `elf`, `jpeg`/`jpg`, `lua`, `mjs`, `pcap`, `png`, `xml`）；非特化格式时从基础变异器集合中随机选择（`BitflipMutator`, `ArithMutator`, `InterestMutator`, `HavocMutator`, `SpliceMutator`）。
- **主循环实现**：实现了从 `Scheduler.next_candidate()` 获取 `Candidate`、对样本应用变异器生成若干变体、调用 `CommandTarget.run()` 执行、将结果传递给 `Monitor.record_run()` 并调用 `Scheduler.report_result()` 的完整流程。对变体数量、每次 mutate() 的迭代数及每个样本的尝试次数均设置上限以避免爆炸性产出。
