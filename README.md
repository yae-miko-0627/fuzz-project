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
  --mode file \
  --timeout 5 \
  --status-interval 300 \
  > /fuzz/T01/output/fuzzer.log 2>&1 &

# 查看实时日志（可在宿主或容器运行）
tail -n 200 -f /fuzz/T01/output/fuzzer.log
```

T02（示例，带 `readelf -a @@ @@` 完整参数）：
```bash
rm -rf /fuzz/T02/output/*; mkdir -p /fuzz/T02/output

nohup python3 -m mini_afl_py.fuzzer \
  --target "/fuzz/T02/build/readelf -a @@ @@" \
  --seeds /fuzz/T02/seeds \
  --outdir /fuzz/T02/output \
  --time 86400 \
  --mode file \
  --timeout 5 \
  --status-interval 300 \
  > /fuzz/T02/output/fuzzer.log 2>&1 &

tail -n 200 -f /fuzz/T02/output/fuzzer.log
```

注意：上面命令为示例，若在容器外用 `docker exec` 启动，请在命令前加入 `docker exec -d <container> bash -lc "cd /fuzz && ..."` 将命令放到容器内部执行。

## 第八步：确认结果
输出位于 `/fuzz/T01/output`，包括记录、覆盖曲线等。

提示：
- `--target` 替换为实际产物路径（如 `/fuzz/T01/build/cxxfilt`）。
- 长时间运行建议在 tmux/screen 中执行，避免会话中断。