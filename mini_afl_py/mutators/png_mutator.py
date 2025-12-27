"""轻量级 PNG 变异器。

解析 PNG chunk 并提供若干 chunk 级与字节级变异：
- 删除/复制 chunk（避免删除 IHDR/IEND）
- 在 chunk payload 中翻转/替换字节
- 破坏 chunk 长度字段
- 交换相邻 chunk

仅依赖标准库，目标是快速生成有效变体。
"""
from __future__ import annotations

import struct
import binascii
import random
from typing import List, Tuple, Optional


PNG_SIG = b"\x89PNG\r\n\x1a\n"


class PngMutator:
    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)

    def mutate(self, data: bytes, num_mutations: int = 1) -> bytes:
        try:
            chunks = self._parse_chunks(data)
        except Exception:
            return self._fallback_byte_mutation(data)

        out = bytearray(data)
        for _ in range(num_mutations):
            ops = [self._delete_chunk, self._duplicate_chunk, self._flip_bytes_in_chunk,
                   self._corrupt_chunk_length, self._swap_adjacent_chunks, self._tweak_ihdr]
            op = self.rng.choice(ops)
            try:
                out = op(out, chunks)
                chunks = self._parse_chunks(bytes(out))
            except Exception:
                continue

        return bytes(out)

    def _parse_chunks(self, data: bytes) -> List[Tuple[int,int,str]]:
        if not data.startswith(PNG_SIG):
            raise ValueError('not png')
        off = len(PNG_SIG)
        n = len(data)
        chunks: List[Tuple[int,int,str]] = []
        while off + 8 <= n:
            length = struct.unpack_from('>I', data, off)[0]
            type_bytes = data[off+4:off+8]
            ctype = type_bytes.decode('ascii', errors='ignore')
            data_start = off + 8
            data_end = data_start + length
            if data_end + 4 > n:
                break
            chunks.append((off, data_end + 4, ctype))
            off = data_end + 4
        return chunks

    def _fallback_byte_mutation(self, data: bytes) -> bytes:
        b = bytearray(data)
        if not b:
            return data
        i = self.rng.randrange(len(b))
        b[i] = (b[i] + self.rng.randrange(1,255)) & 0xFF
        return bytes(b)

    def _delete_chunk(self, out: bytearray, chunks) -> bytearray:
        # 不删除 IHDR 或 IEND
        choices = [c for c in chunks if c[2] not in ('IHDR','IEND')]
        if not choices:
            return out
        c = self.rng.choice(choices)
        start, end, _ = c
        return out[:start] + out[end:]

    def _duplicate_chunk(self, out: bytearray, chunks) -> bytearray:
        choices = [c for c in chunks if c[2] not in ('IHDR','IEND')]
        if not choices:
            return out
        c = self.rng.choice(choices)
        start, end, _ = c
        seg = out[start:end]
        return out[:end] + seg + out[end:]

    def _flip_bytes_in_chunk(self, out: bytearray, chunks) -> bytearray:
        choices = [c for c in chunks if c[2] not in ('IHDR','IEND')]
        if not choices:
            return out
        start, end, _ = self.rng.choice(choices)
        # payload area: start+8 .. end-4
        payload_start = start + 8
        payload_end = end - 4
        if payload_end <= payload_start:
            return out
        for _ in range(max(1, (payload_end-payload_start)//50)):
            i = self.rng.randrange(payload_start, payload_end)
            out[i] = (out[i] ^ self.rng.randrange(1,256)) & 0xFF
        return out

    def _corrupt_chunk_length(self, out: bytearray, chunks) -> bytearray:
        choices = [c for c in chunks if c[2] not in ('IHDR','IEND')]
        if not choices:
            return out
        start, end, _ = self.rng.choice(choices)
        # length field at start..start+4 big endian
        new_len = self.rng.randrange(0, max(1, end - start + 100))
        struct.pack_into('>I', out, start, new_len)
        return out

    def _swap_adjacent_chunks(self, out: bytearray, chunks) -> bytearray:
        if len(chunks) < 3:
            return out
        idx = self.rng.randrange(1, len(chunks)-1)
        a = chunks[idx]
        b = chunks[idx+1]
        a_bytes = out[a[0]:a[1]]
        b_bytes = out[b[0]:b[1]]
        return out[:a[0]] + b_bytes + a_bytes + out[b[1]:]

    def _tweak_ihdr(self, out: bytearray, chunks) -> bytearray:
        # 在 IHDR 中修改宽高字段（偏移 IHDR payload 内前 8 字节为 width/height）
        ihdr = None
        for c in chunks:
            if c[2] == 'IHDR':
                ihdr = c
                break
        if not ihdr:
            return out
        payload_start = ihdr[0] + 8
        if payload_start + 8 > len(out):
            return out
        # width and height big-endian 4 bytes each
        width = struct.unpack_from('>I', out, payload_start)[0]
        height = struct.unpack_from('>I', out, payload_start+4)[0]
        new_w = max(1, (width + self.rng.randint(-100,100)) & 0xFFFFFFFF)
        new_h = max(1, (height + self.rng.randint(-100,100)) & 0xFFFFFFFF)
        struct.pack_into('>I', out, payload_start, new_w)
        struct.pack_into('>I', out, payload_start+4, new_h)
        return out


if __name__ == '__main__':
    # 构造最小 PNG：PNG sig + IHDR chunk(minimal) + IEND
    ihdr_data = struct.pack('>IIBBBBB', 1,1,8,2,0,0,0)[:13]
    ihdr = struct.pack('>I4s', len(ihdr_data), b'IHDR') + ihdr_data
    ihdr += struct.pack('>I', binascii.crc32(b'IHDR'+ihdr_data) & 0xffffffff)
    iend = struct.pack('>I4sI', 0, b'IEND', binascii.crc32(b'IEND') & 0xffffffff)
    example = PNG_SIG + ihdr + iend
    m = PngMutator(seed=7)
    print('原始长度:', len(example))
    for i in range(6):
        out = m.mutate(example, num_mutations=2)
        print(f'变异 {i+1}: 长度={len(out)}')
