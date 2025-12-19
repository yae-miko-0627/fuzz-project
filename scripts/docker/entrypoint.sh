#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] Starting MiniAFL container entrypoint"

# 清理残留的 System V 共享内存 (ipcs/ipcrm)
if command -v ipcs >/dev/null 2>&1 && command -v ipcrm >/dev/null 2>&1; then
    echo "[entrypoint] Cleaning up stale System V shared memory segments"
    # 列出所有 shmid 并逐个删除（忽略 header 行）
    ipcs -m | awk 'NR>3 {print $2}' | while read -r shmid; do
        if [ -n "$shmid" ]; then
            echo "[entrypoint] removing shm id=$shmid" || true
            ipcrm -m "$shmid" || true
        fi
    done || true
else
    echo "[entrypoint] ipcs/ipcrm not available; skipping shm cleanup"
fi

# 如果 afl-cc 不存在，则通过 Python 的 ensure_afl_built() 尝试构建 AFL++
build_afl() {
    echo "[entrypoint] Building AFL++ from /workspace/AFLplusplus-stable"
    if [ -d /workspace/AFLplusplus-stable ]; then
        cd /workspace/AFLplusplus-stable || return 1
        # try a normal make; if not present, attempt distrib
        if [ -f Makefile ] || [ -f GNUmakefile ]; then
            make -j"$(nproc)" || make || true
        else
            if [ -f ./build.sh ]; then
                ./build.sh || true
            fi
        fi
        # copy built binaries into /opt/afl (overwrite if any)
        mkdir -p /opt/afl && cp -a bin/* /opt/afl/ 2>/dev/null || true
        export PATH="/opt/afl:$PATH"
        echo "[entrypoint] AFL++ build step finished (check logs above)"
        return 0
    else
        echo "[entrypoint] /workspace/AFLplusplus-stable not found; skipping build"
        return 1
    fi
}

if ! command -v afl-cc >/dev/null 2>&1; then
    echo "[entrypoint] afl-cc not found; attempting build in-entrypoint"
    # try Python helper first if available
    if python3 -c "import sys; sys.path.insert(0,'/workspace/MiniAFL'); import mini_afl_py.utils.afl_tools as a; print('ok')" >/dev/null 2>&1; then
        echo "[entrypoint] Calling Python ensure_afl_built()"
        if python3 - <<'PY'
import sys
sys.path.insert(0, '/workspace/MiniAFL')
from mini_afl_py.utils import afl_tools
try:
    afl_tools.ensure_afl_built()
    print('[entrypoint] ensure_afl_built completed')
except Exception as e:
    print('[entrypoint][error] ensure_afl_built failed:', e, file=sys.stderr)
    raise
PY
        then
            export PATH="/opt/afl:$PATH"
        else
            echo "[entrypoint] Python helper failed; falling back to shell build"
            build_afl || true
        fi
    else
        build_afl || true
    fi
fi

# 编译 demo 目标（若存在）
if [ -f /workspace/testcases/target.c ]; then
    echo "[entrypoint] Compiling demo target /workspace/testcases/target.c"
    if command -v afl-cc >/dev/null 2>&1; then
        afl-cc -o /workspace/testcases/target_bin /workspace/testcases/target.c || gcc -o /workspace/testcases/target_bin /workspace/testcases/target.c || true
    else
        echo "[entrypoint] afl-cc not found; using gcc as fallback"
        gcc -o /workspace/testcases/target_bin /workspace/testcases/target.c || true
    fi
else
    echo "[entrypoint] No demo target found at /workspace/testcases/target.c"
fi

echo "[entrypoint] Running MiniFuzzer demo (short run)"
python3 - <<'PY'
import sys
sys.path.insert(0, '/workspace/MiniAFL')
from mini_afl_py.fuzzer import MiniFuzzer
f = MiniFuzzer(target_cmd=['/workspace/testcases/target_bin'], timeout=1.0)
f.add_seed(b'AAAA')
f.run(run_time=10)
print('MiniFuzzer demo finished')
PY

echo "[entrypoint] Demo finished; dropping to shell"
exec /bin/bash
