
# MiniAFL使用教程（手动版，Windows PowerShell）

第一步：构建容器
    借助给出的Dockerfile进行构建(请事先自行学习Docker)
    
    指令示例：
        docker build -f Dockerfile -t miniafl:latest .
    
第二步：进入容器
    指令示例：
        docker run -it --rm --name miniafl `
        -v "{你的宿主机fuzz目录绝对路径}:/fuzz" `
        -w /fuzz `
        --cap-add=SYS_PTRACE --security-opt seccomp=unconfined `
        miniafl:latest /bin/bash

第三步：创建独立目录
    为被测目标准备专门的文件目录，根目录自己决定，在下面准备source（源文件），build（AFL编译后文件），seeds（种子），output（输出文件）

    **注**:后用T01代指文件根目录

    指令示例：
        mkdir -p /fuzz/T01/{source,build,seeds,output}

第四步：解压目标到sorce
    指令示例：
        cd /fuzz/T01/source
        tar -xzf {容器内压缩包的绝对路径}

第五步：AFL插桩编译目标
    指令示例：

    # 进入源码根目录（解压后的项目根，如 binutils-2.28）
    cd /fuzz/T01/source/<project-root>

    # 使用 afl-cc/afl-c++ 进行插桩配置（按需调整选项）
    CC=afl-cc CXX=afl-c++ ./configure --prefix=/fuzz/T01/build --disable-werror

    # 编译目标（示例：只编译某个工具或子目录目标）
    make -j$(nproc) <make-target>

    # 拷贝产物到 build 并加执行权限（请替换 <target-binary>）
    cp <path-to-built-binary>/<target-binary> /fuzz/T01/build/
    chmod +x /fuzz/T01/build/<target-binary>

    #可选：验证可执行文件
    /fuzz/T01/build/<target-binary> --version

第六步：放入初始种子
    将目标指定的初始种子放入seeds目录中

    指令示例：
    # 若已有 seed 文件：从 AFL++ 自带测试用例拷贝
    # 示例：AFL++ 仓库位于 /AFLplusplus，选择一个用例拷贝到 seeds
    cp /AFLplusplus/testcases/others/elf/* /fuzz/T01/seeds/ 2>/dev/null || true

    # 若需要自定义单个种子（示例内容替换为你的初始输入）
    echo '"_Z1fv"' > /fuzz/T01/seeds/seed1

第七步：运行测试
    指令示例：
    cd /fuzz
    python3 MiniAFL/mini_afl_py/fuzzer.py \
        --target /fuzz/T01/build/<target-binary> \
        --seeds /fuzz/T01/seeds \
        --outdir /fuzz/T01/output \
        --time 60 \          # 运行时长（秒），可改 86400 做 24h 正式测试
        --mode stdin \       # 目标从 stdin 读取输入时使用；若需文件模式，改为 file
        --timeout 1 \        # 单次执行超时（秒），按需调整
        --status-interval 5  # 状态刷新间隔（秒，设 0 关闭）

第八步：确认结果
    最后可以在output目录中获取导出的测试结果信息

提示：
--target 替换为实际产物路径（如 /fuzz/T01/build/cxxfilt）。
长时间运行建议在 tmux/screen 中执行，避免会话断开。