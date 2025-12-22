FROM ubuntu:22.04

# 非交互模式
ENV DEBIAN_FRONTEND=noninteractive

# 基本工具与 Python
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    make \
    gcc \
    g++ \
    clang \
    libclang-dev \
    libtool \
    automake \
    cmake \
    libc6-dev \
    libssl-dev \
    pkg-config \
    ca-certificates \
    wget \
    unzip \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# 克隆并构建 AFL++（安装到 /usr/local/bin）
RUN git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git /AFLplusplus \
    && cd /AFLplusplus \
    && make distrib -j"$(nproc)" \
    && make install -j"$(nproc)" \
    && cd / \
    && rm -rf /AFLplusplus

# 设置环境变量，确保 afl-* 可执行文件在 PATH
ENV AFL_PATH=/usr/local/bin
ENV PATH=$AFL_PATH:$PATH

# 工作目录：将构建上下文（MiniAFL 文件）复制到 /fuzz
WORKDIR /fuzz
COPY . /fuzz

# 创建默认输出目录
RUN mkdir -p /fuzz/fuzz_artifacts

# 入口：默认进入交互 shell。用户可覆盖为运行特定脚本（例如 python3 mini_afl_py/fuzzer.py ...）
CMD ["/bin/bash"]
