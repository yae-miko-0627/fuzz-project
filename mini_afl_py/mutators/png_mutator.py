"""
PNG 专用变异器

实现要点：
- 解析 PNG chunk（length(4)|type(4)|data|crc(4)），保护签名和关键头（IHDR、IEND），
- 对可变 chunk（默认 IDAT、tEXt/zTXt/iTXt）进行变异，变异后重新计算 CRC 并更新长度字段，
- 变体长度与原 chunk 长度不一致时通过截断或 0 填充以保持与 chunk 长度一致（保持结构稳定），
- 复用已有基础变异器（Bitflip/Arith/Interest/Havoc），并支持 per_chunk_limit 与 max_variants 控制产出。

注意：修改 IDAT 会破坏 zlib 压缩流，但这是 fuzzing 的常见做法；若需更高成功率，可实现 IDAT 解压、修改后重压缩并更新 CRC（后续改进）。
"""
from __future__ import annotations

import struct
import binascii
from typing import Iterable, List, Optional

from .bitflip_mutator import BitflipMutator
from .arith_mutator import ArithMutator
from .interest_mutator import InterestMutator
from .havoc_mutator import HavocMutator


PNG_SIG = b"\x89PNG\r\n\x1a\n"


class PngMutator:
    def __init__(self, mutators: Optional[List] = None, per_chunk_limit: int = 20, max_variants: int = 200):
        if mutators is None:
            mutators = [BitflipMutator(max_bits=256), ArithMutator(max_positions=64), InterestMutator(max_positions=64), HavocMutator(rounds=4, max_changes=6)]
        self.mutators = mutators
        self.per_chunk_limit = int(per_chunk_limit)
        self.max_variants = int(max_variants)

    def mutate(self, data: bytes) -> Iterable[bytes]:
        # 基本签名检查
        if not data.startswith(PNG_SIG):
            return

        L = len(data)
        offset = len(PNG_SIG)
        # 将 chunk 解析为 (offset_len, length, type, data, crc, header_offset) 列表
        chunks = []
        try:
            while offset + 8 <= L:
                length = struct.unpack('>I', data[offset:offset+4])[0]
                ctype = data[offset+4:offset+8]
                dstart = offset + 8
                dend = dstart + length
                if dend + 4 > L:
                    break
                cdata = data[dstart:dend]
                crc = struct.unpack('>I', data[dend:dend+4])[0]
                chunks.append((offset, length, ctype, cdata, crc, offset))
                offset = dend + 4
        except Exception:
            return

        variants = 0

        # 定义可变的 chunk 类型
        mutable_types = {b'IDAT', b'tEXt', b'zTXt', b'iTXt'}

        for idx, (off, length, ctype, cdata, crc, hdr_off) in enumerate(chunks):
            if variants >= self.max_variants:
                break
            if ctype not in mutable_types:
                continue

            per_chunk = 0
            for mut in self.mutators:
                if variants >= self.max_variants or per_chunk >= self.per_chunk_limit:
                    break
                try:
                    for v in mut.mutate(cdata):
                        if variants >= self.max_variants or per_chunk >= self.per_chunk_limit:
                            break
                        if v is None:
                            continue
                        # 调整为原始长度
                        if len(v) != length:
                            if len(v) > length:
                                v_use = v[:length]
                            else:
                                v_use = v + b'\x00' * (length - len(v))
                        else:
                            v_use = v

                        # 重新计算 type+data 的 CRC
                        new_crc = binascii.crc32(ctype + v_use) & 0xffffffff

                        # 构造新的 PNG 数据
                        out = bytearray()
                        out.extend(data[:off])
                        out.extend(struct.pack('>I', len(v_use)))
                        out.extend(ctype)
                        out.extend(v_use)
                        out.extend(struct.pack('>I', new_crc))
                        # 追加剩余部分
                        # 计算原始 chunk 结束偏移
                        # 找到原始 chunk 的结束偏移
                        # 原始 chunk 占用 4(len)+4(type)+length+4(crc) 字节
                        orig_chunk_end = off + 4 + 4 + length + 4
                        out.extend(data[orig_chunk_end:])

                        yield bytes(out)
                        variants += 1
                        per_chunk += 1
                except Exception:
                    continue

        return


__all__ = ["PngMutator"]
