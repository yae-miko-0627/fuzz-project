MiniAFL是根据AFL++进行的简化，主要功能是针对被测文件进行模糊测试，样例测试结果放在result目录中

# MiniAFL 项目说明
总体上，MiniAFL可以通过fuzzer.py完成fuzz循环，关键的工具实现在其他相关目录中。MiniAFL需要借助AFL++的插桩，接收插桩好的二进制文件进行测试，下面将对各个工具进行以及主程序进行说明。

## 项目结构
core/:调度器Scheduuler,监控Monitor，评估汇总eval
mutators/:各类变异器以及针对专用格式变异器
targets/:目标运行封装(CommandTarget)，负责把变体送入被测程序并收集运行结果
instrumentions/:Coverage覆盖收集，Shm_Manager共享内存管理
utils/:辅助工具，Config参数默认设置，Format_detector种子形式分析

## 关键组件说明
Scheduler(调度器)：
角色：管理语料库（corpus）、候选（Candidate）选择与接收执行结果的反馈（report_result）。
行为：从 seeds 初始化语料，基于调度策略（能量值/启发式）选择下一个候选用于变异

Monitor（监控器）:
角色：记录每次执行的结果（状态、壁钟时间、覆盖、产生的 artifact），并能导出 monitor_records.json 与覆盖曲线 CSV。
用途：用于后处理、统计与绘制覆盖增长曲线（coverage_curve / export_curve_csv）

CommandTarget（目标运行器）:
角色：把变体写入 stdin 或临时文件并以子进程（或命令模板）运行目标，收集退出状态、超时、覆盖信息与可能的崩溃产物路径。
特点：--target 以完整命令字符串传入（shlex.split 解析）

变异器集合（mutators）:
基础变异器：Bitflip, Arith, Interest, Havoc, Splice —— 用于通用变异策略。
专用变异器：面向格式的变异器（PNG/JPEG/ELF/PCAP/Lua/MJS/XML 等），在检测到种子格式时优先使用

## fuzzer.py工作流程
入口与参数:
入口位于 fuzzer.py:1。通过 parse_args 解析 --target, --seeds, --outdir, --time, --mode, --timeout, --status-interval 等参数（见代码行 17–35）。
--target 要求传入完整命令字符串（如 "/full/path/readelf -a @@ @@"），脚本使用 shlex.split 解析并验证可执行文件存在（见 代码段 fuzzer.py:104）。

初始化:
创建 Scheduler() 与 Monitor(out_dir=...)（见 fuzzer.py:126）。
从 --seeds 目录读取种子文件，调用 scheduler.add_seed(data) 将初始语料加载到调度器（见 fuzzer.py:134）。
初始化 CommandTarget(cmd=target_tokens, timeout_default=...) 作为运行器。

核心 fuzz 循环（fuzz_loop）:
启动状态 reporter 线程以周期性打印进度（elapsed、corpus、exec_rate、累计覆盖）（见 fuzzer.py:19）。
主循环步骤（见 fuzzer.py:31-40）：
调用 scheduler.next_candidate() 获取待变异的候选（若无则短睡等待）。
使用 format_detector.detect_from_bytes(cand.data) 判断格式，优先选用相应的专用变异器（比如 ELF -> ElfMutator）；若无专用变异器，从基础变异器集合随机选择（见 fuzzer.py:62）。
根据候选的 energy 字段决定尝试次数（最多 8 次），对每次尝试生成若干变体（每次最多处理 4 个变体），对每个变体调用 target.run(variant, mode, timeout) 运行目标。
将运行结果通过 monitor.record_run(...) 记录，并调用 scheduler.report_result(variant, res) 将结果反馈给调度器（用于更新语料/种子优先级或收录有趣样本）。
周期性检查时间上限，超时则退出循环（并在 finally 中导出监控记录和覆盖曲线 CSV）。

结束与导出:
fuzzer 在结束时调用 monitor.export_records() 导出 monitor_records.json，并用 coverage_curve / export_curve_csv 导出 coverage_curve.csv（见 fuzzer.py:179）。
打印汇总：总运行次数、崩溃数、hangs、novelty hits、累计覆盖等（见末尾汇总打印）。

# MiniAFL 使用教程（手动版，Windows PowerShell）

## 第一步：构建镜像
借助给出的 Dockerfile 进行构建（请先熟悉 Docker）。
```powershell
  docker build -f Dockerfile -t miniafl:latest .
```

## 第二步：进入容器
挂载宿主工作区，开启 ptrace 权限。
```powershell
  docker run -d --name fuzz_T01 `
  -v "C:\Users\11053\Desktop\fuzz:/fuzz" `
  -w /fuzz `
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined `
  --restart unless-stopped `
  miniafl:latest tail -f /dev/null
```

若已存在容器，则直接进入。
```powershell
  docker exec -it fuzz_T01 /bin/bash
```

## 第三步：创建独立目录
以 T01 为例，准备 source / build / seeds / output 四个子目录。
```bash
mkdir -p /fuzz/T01/{source,build,seeds,output}
```

## 第四步：解压目标到 source
```bash
cd /fuzz/T01/source
tar -xzf /fuzz/<target>
```

## 第五步：AFL 插桩编译目标（通用示例）
```bash
# 进入源码根目录（如 binutils-2.28）
cd /fuzz/T01/source/<project-root>

# 使用 afl-cc/afl-c++ 进行插桩配置
CC=afl-cc CXX=afl-c++ ./configure --prefix=/fuzz/T01/build --disable-werror

# 编译目标（示例：只编译某个工具或子目录目标）
make -j$(nproc) <make-target>

# 拷贝产物到 build 并加执行权限
cp <path-to-built-binary>/<target-binary> /fuzz/T01/build/
chmod +x /fuzz/T01/build/<target-binary>

# 可选：验证可执行文件
/fuzz/T01/build/<target-binary> --version
```
占位说明：
- `<project-root>`：解压后的源码目录名（如 binutils-2.28）
- `<make-target>`：对应的 make 目标（如 binutils/cxxfilt）
- `<path-to-built-binary>`：产物所在目录（如 binutils）
- `<target-binary>`：可执行名（如 cxxfilt）

## 第六步：放入初始种子
```bash
# 从 AFL++ 自带用例拷贝
cp /AFLplusplus/testcases/others/elf/* /fuzz/T01/seeds/ 2>/dev/null || true

# 或自定义单个种子
echo '"_Z1fv"' > /fuzz/T01/seeds/seed1
```

## 第七步：运行测试
```bash
cd /fuzz
python3 MiniAFL/mini_afl_py/fuzzer.py \
  --target /fuzz/T01/build/<target-binary> \
  --seeds /fuzz/T01/seeds \
  --outdir /fuzz/T01/output \
  --time 60 \          # 运行时长（秒），可改 86400 做 24h
  --mode stdin \       # 若需文件模式改为 file
  --timeout 1 \        # 单次执行超时（秒）
  --status-interval 5  # 状态刷新间隔（秒，0 关闭）
```

### 后台运行示例（把日志写入 output）
以下示例在容器或宿主上均可运行，演示如何把 fuzzer 放到后台并把运行日志重定向到 `output/fuzzer.log`：

T01（示例）：
```bash
# 清空并确保 output 目录存在
rm -rf /fuzz/T01/output/*; mkdir -p /fuzz/T01/output

# 后台运行 24 小时（86400 秒），状态间隔设为 300 秒（5 分钟）
nohup python3 -m mini_afl_py.fuzzer \
  --target '/fuzz/T01/build/cxxfilt' \
  --seeds /fuzz/T01/seeds \
  --outdir /fuzz/T01/output \
  --time 86400 \
  --mode stdin \
  --timeout 5 \
  --status-interval 300 \
  > /fuzz/T01/output/fuzzer.log 2>&1 &

# 查看实时日志（可在宿主或容器运行）
tail -n 200 -f /fuzz/T01/output/fuzzer.log
```

T02（示例，带 `readelf -a @@ @@` 完整参数）：
```bash
# 容器内直接运行（前台，30s，file 模式，使用已有 seeds 目录）
rm -rf /fuzz/T02/output/*; mkdir -p /fuzz/T02/output /fuzz/T02/output/monitor_artifacts
cd /fuzz && python3 -u MiniAFL/mini_afl_py/fuzzer.py \
  --target "/fuzz/T02/build/readelf -a @@ @@" \
  --seeds /fuzz/T02/seeds \
  --outdir /fuzz/T02/output \
  --time 30 \
  --mode file \
  --timeout 5 \
  --status-interval 5
```

```powershell
# PowerShell（宿主）: 前台运行 30s（file 模式），不要覆盖已有种子目录
docker exec -i fuzz_T02 bash -lc "rm -rf /fuzz/T02/output/*; mkdir -p /fuzz/T02/output /fuzz/T02/output/monitor_artifacts; cd /fuzz && python3 -u MiniAFL/mini_afl_py/fuzzer.py --target '/fuzz/T02/build/readelf -a @@ @@' --seeds /fuzz/T02/seeds --outdir /fuzz/T02/output --mode file --time 30 --status-interval 5"
```

```powershell
# PowerShell（宿主）: 后台运行 24 小时，日志写入 output/fuzzer.log（保留现有 seeds，不要用 printf 覆盖）
docker exec -d fuzz_T02 bash -lc "rm -rf /fuzz/T02/output/*; mkdir -p /fuzz/T02/output /fuzz/T02/output/monitor_artifacts; cd /fuzz && nohup python3 -u MiniAFL/mini_afl_py/fuzzer.py --target '/fuzz/T02/build/readelf -a @@ @@' --seeds /fuzz/T02/seeds --outdir /fuzz/T02/output --mode file --time 86400 --status-interval 60 > /fuzz/T02/output/fuzzer.log 2>&1 &"
```

注意：上面命令为示例，若在容器外用 `docker exec` 启动，请在命令前加入 `docker exec -d <container> bash -lc "cd /fuzz && ..."` 将命令放到容器内部执行。

## 第八步：确认结果
输出位于 `/fuzz/T01/output`，包括记录、覆盖曲线等。

提示：
- `--target` 替换为实际产物路径（如 `/fuzz/T01/build/cxxfilt`）。
- 长时间运行建议在 tmux/screen 中执行，避免会话中断。

# 工具：CSV → X/Y 绘图（mini_afl_py/utils/csv_to_xy_plot.py）

项目内已新增一个小工具用于把 CSV 导出为 x-y 图像：`MiniAFL/mini_afl_py/utils/csv_to_xy_plot.py`。

主要说明：

- 依赖：`matplotlib`（必须），`pandas`（可选，推荐用于复杂 CSV）
- 功能：支持通过列名或列索引指定 `--x` 与 `--y`，`--y` 支持多列（逗号分隔）；支持 `line` / `scatter`，自定义分隔符 `-d`，输出文件 `-o`，matplotlib 风格 `--style`，以及对数坐标 `--xlog/--ylog`。

示例：
```bash
python MiniAFL/mini_afl_py/utils/csv_to_xy_plot.py data.csv --x time --y value -o out.png --kind line \
  --title "Time vs Value" --xlabel Time --ylabel Value
```

# 项目工作说明

## 项目成员
郑智文  241880567
张苏楠  241880199
马宇航  241880054