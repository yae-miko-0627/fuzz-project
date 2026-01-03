import struct
import binascii
import random
import zlib
from typing import List, Tuple, Optional, Dict, Set, Callable
from enum import Enum
from collections import OrderedDict
import os


PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_HEADER_SIZE = 8


class MutationStage(Enum):
    DETERMINISTIC = 1
    RANDOM = 2
    SPLICE = 3
    PNG_AWARE = 4


class PNGMutatorAFL:
    """AFL++ 风格的 PNG 变异器（分层：确定性、随机、拼接、PNG 感知）

    本文件提供一个紧凑且自包含的 PNG 变异器，适用于 MiniAFL 类的模糊测试
    运行环境。目标是在尽可能保持 PNG 结构的同时生成有助于触达覆盖的
    变体；但在需要时也允许破坏性操作以触发潜在缺陷。
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)
        # 短期修复/安全模式：减少破坏性变异以降低 parse_error 比例
        # 可通过环境变量 MINIAFL_PNG_SAFE=0 关闭
        self.safe_mode = os.getenv('MINIAFL_PNG_SAFE', '1') not in ('0', 'false', 'False')
        self.stage = MutationStage.DETERMINISTIC
        self.cycle = 0

        # 确定性和随机操作（针对 PNG 调整的子集）
        self.deterministic_ops = [
            self._bit_flip_1,
            self._bit_flip_2,
            self._bit_flip_4,
            self._byte_flip_1,
            self._byte_flip_2,
            self._byte_flip_4,
            self._arith_8,
            self._arith_16,
            self._arith_32,
            self._interest_8,
            self._interest_16,
            self._interest_32,
        ]

        self.random_ops = [
            self._havoc_byte,
            self._havoc_bit,
            self._havoc_arith,
            self._havoc_interest,
            # 删除/插入等高破坏性操作对解析错误贡献较大，safe_mode 下禁用
            (self._havoc_delete if not getattr(self, 'safe_mode', False) else None),
            self._havoc_clone,
            self._havoc_overwrite,
            self._png_aware_mutate,
        ]

        # PNG 感知级别的操作（针对 PNG chunk 级别的变异）
        self.png_ops = [
            self._mutate_ihdr,
            self._mutate_idat,
            self._mutate_plte,
            self._mutate_time_chunk,
            # 长度破坏会导致解析失败；在 safe_mode 下尽量避免极端长度修改
            self._corrupt_chunk_length_afl,
            self._swap_png_chunks,
            self._duplicate_chunk_afl,
            self._inject_invalid_chunk,
            self._mutate_filter_type,
            self._corrupt_zlib_stream,
        ]

        # 关键 chunk 类型（尽量避免删除或破坏这些）
        self.critical_chunks = {'IHDR', 'PLTE', 'IDAT', 'IEND'}

        # 常用极值/兴趣值（AFL 风格）
        self.interest_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
        self.interest_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
        self.interest_32 = [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647]

        self.stats = {
            'deterministic_mutations': 0,
            'random_mutations': 0,
            'splice_mutations': 0,
            'png_mutations': 0,
            'total_executions': 0,
        }

        self.unique_edges: Set[int] = set()

        self.fitness_callback: Optional[Callable[[bytes], int]] = None

        # 对解析后 chunk 的有界缓存，避免重复解析开销并防止内存无限增长
        # 使用 OrderedDict 做成简单的 LRU（最近最少使用）缓存，容量可调。
        self._chunk_cache_max = 512
        self._chunk_cache: "OrderedDict[bytes, List[Tuple[int, int, str, bytes]]]" = OrderedDict()

    def set_fitness_callback(self, cb: Callable[[bytes], int]) -> None:
        self.fitness_callback = cb

    def mutate(self, data: bytes, num_mutations: int = 1, stage: Optional[MutationStage] = None) -> bytes:
        if not data or len(data) < PNG_HEADER_SIZE:
            return self._havoc_byte(bytearray(data))

        if not data.startswith(PNG_SIG):
            return self._havoc_byte(bytearray(data))

        if stage is None:
            if self.cycle % 100 < 70:
                stage = MutationStage.RANDOM
            elif self.cycle % 100 < 85:
                stage = MutationStage.DETERMINISTIC
            elif self.cycle % 100 < 95:
                stage = MutationStage.SPLICE
            else:
                stage = MutationStage.PNG_AWARE

        self.stage = stage
        self.cycle += 1

        out = bytearray(data)

        if stage == MutationStage.DETERMINISTIC:
            out = self._deterministic_mutation(out, num_mutations)
            self.stats['deterministic_mutations'] += 1
        elif stage == MutationStage.RANDOM:
            out = self._random_mutation(out, num_mutations)
            self.stats['random_mutations'] += 1
        elif stage == MutationStage.SPLICE:
            if hasattr(self, '_splice_candidate'):
                out = self._splice_mutation(out, self._splice_candidate)
                self.stats['splice_mutations'] += 1
        else:
            out = self._png_custom_mutation(out, num_mutations)
            self.stats['png_mutations'] += 1

        return bytes(out)

    def add_splice_candidate(self, data: bytes) -> None:
        self._splice_candidate = data

    # ---------------- 确定性 / 随机 / 拼接 阶段 ----------------
    def _deterministic_mutation(self, data: bytearray, num_mutations: int) -> bytearray:
        out = data.copy()
        size = len(out)
        for op in self.deterministic_ops[:min(num_mutations, len(self.deterministic_ops))]:
            step = 1
            for i in range(0, size, max(1, step)):
                original = out[:]
                mutated = op(out, i, step) if op.__code__.co_argcount >= 3 else op(out)
                if mutated != original:
                    out = mutated
                    break
        return out

    def _random_mutation(self, data: bytearray, num_mutations: int) -> bytearray:
        out = data.copy()
        intensity = min(max(num_mutations, 1), 256)
        for _ in range(intensity):
            if not out:
                break
            # 从可用操作中选择，过滤 None（safe_mode 下禁用的一些 ops 会为 None）
            ops = [o for o in self.random_ops if o is not None]
            op = self.rng.choice(ops) if ops else None
            try:
                if op is not None:
                    out = op(out)
            except Exception:
                continue
        return out

    def _splice_mutation(self, data1: bytearray, data2: bytes) -> bytearray:
        if not data2 or len(data2) < PNG_HEADER_SIZE:
            return data1
        size1 = len(data1)
        size2 = len(data2)
        start1 = PNG_HEADER_SIZE
        start2 = PNG_HEADER_SIZE
        if start1 >= size1 or start2 >= size2:
            return data1
        split1 = self.rng.randint(start1, size1 - 1)
        split2 = self.rng.randint(start2, size2 - 1)
        max_len = min(size1 - split1, size2 - split2)
        if max_len < 4:
            return data1
        splice_len = self.rng.randint(4, max_len)
        result = bytearray()
        result.extend(data1[:split1])
        result.extend(data2[split2:split2 + splice_len])
        result.extend(data1[split1 + splice_len:])
        return result

    # ---------------- PNG 感知变异 阶段 ----------------
    def _png_custom_mutation(self, data: bytearray, num_mutations: int) -> bytearray:
        out = data.copy()
        try:
            chunks = self._parse_chunks_with_cache(out)
            if len(chunks) >= 2:
                for _ in range(num_mutations):
                    op = self.rng.choice(self.png_ops)
                    try:
                        out = op(out, chunks)
                        chunks = self._parse_chunks_with_cache(out)
                    except Exception:
                        continue
                return out
        except Exception:
            pass
        return self._random_mutation(out, 1)

    # ---------------- 基础的 AFL 风格字节/位操作 ----------------
    def _bit_flip_1(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos >= len(data):
            return data
        data[pos] ^= 1 << self.rng.randint(0, 7)
        return data

    def _bit_flip_2(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos >= len(data):
            return data
        for _ in range(2):
            data[pos] ^= 1 << self.rng.randint(0, 7)
        return data

    def _bit_flip_4(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos >= len(data):
            return data
        for _ in range(4):
            data[pos] ^= 1 << self.rng.randint(0, 7)
        return data

    def _byte_flip_1(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos >= len(data):
            return data
        data[pos] ^= 0xFF
        return data

    def _byte_flip_2(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos + 1 >= len(data):
            return data
        for i in range(2):
            data[pos + i] ^= 0xFF
        return data

    def _byte_flip_4(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos + 3 >= len(data):
            return data
        for i in range(4):
            data[pos + i] ^= 0xFF
        return data

    def _arith_8(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos >= len(data):
            return data
        value = int(self.rng.choice([-35, -1, 1, 35]))
        new_val = (data[pos] + value) & 0xFF
        if new_val != data[pos]:
            data[pos] = new_val
        return data

    def _arith_16(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos + 1 >= len(data):
            return data
        value = int(self.rng.choice([-1, 1, 2, 4, 8, 16, 32, 64, 128, 255, -255]))
        current = (data[pos] << 8) | data[pos + 1]
        new_val = (current + value) & 0xFFFF
        if new_val != current:
            data[pos] = (new_val >> 8) & 0xFF
            data[pos + 1] = new_val & 0xFF
        return data

    def _arith_32(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos + 3 >= len(data):
            return data
        value = int(self.rng.choice([-1, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]))
        current = struct.unpack('>I', bytes(data[pos:pos+4]))[0]
        new_val = (current + value) & 0xFFFFFFFF
        if new_val != current:
            data[pos:pos+4] = struct.pack('>I', new_val)
        return data

    def _interest_8(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos >= len(data):
            return data
        new_val = self.rng.choice(self.interest_8) & 0xFF
        if new_val != data[pos]:
            data[pos] = new_val
        return data

    def _interest_16(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos + 1 >= len(data):
            return data
        new_val = self.rng.choice(self.interest_16) & 0xFFFF
        current = (data[pos] << 8) | data[pos + 1]
        if new_val != current:
            data[pos] = (new_val >> 8) & 0xFF
            data[pos + 1] = new_val & 0xFF
        return data

    def _interest_32(self, data: bytearray, pos: int, step: int) -> bytearray:
        if pos + 3 >= len(data):
            return data
        new_val = self.rng.choice(self.interest_32) & 0xFFFFFFFF
        current = struct.unpack('>I', bytes(data[pos:pos+4]))[0]
        if new_val != current:
            data[pos:pos+4] = struct.pack('>I', new_val)
        return data

    # ---------------- Havoc（高度随机破坏）操作 ----------------
    def _havoc_byte(self, data: bytearray) -> bytearray:
        if not data:
            return data
        pos = self.rng.randint(0, len(data) - 1)
        data[pos] = self.rng.randint(0, 255)
        return data

    def _havoc_bit(self, data: bytearray) -> bytearray:
        if not data:
            return data
        pos = self.rng.randint(0, len(data) - 1)
        bit = 1 << self.rng.randint(0, 7)
        data[pos] ^= bit
        return data

    def _havoc_arith(self, data: bytearray) -> bytearray:
        if len(data) < 2:
            return data
        pos = self.rng.randint(0, len(data) - 2)
        size = self.rng.choice([1, 2, 4])
        if size == 1:
            return self._arith_8(data, pos, 1)
        elif size == 2:
            return self._arith_16(data, pos, 2)
        else:
            if pos + 3 < len(data):
                return self._arith_32(data, pos, 4)
        return data

    def _havoc_interest(self, data: bytearray) -> bytearray:
        if len(data) < 2:
            return data
        pos = self.rng.randint(0, len(data) - 2)
        size = self.rng.choice([1, 2, 4])
        if size == 1:
            return self._interest_8(data, pos, 1)
        elif size == 2:
            return self._interest_16(data, pos, 2)
        else:
            if pos + 3 < len(data):
                return self._interest_32(data, pos, 4)
        return data

    def _havoc_delete(self, data: bytearray) -> bytearray:
        if len(data) <= 1:
            return data
        delete_len = self.rng.randint(1, min(256, len(data) // 2))
        delete_pos = self.rng.randint(0, len(data) - delete_len)
        result = bytearray()
        result.extend(data[:delete_pos])
        result.extend(data[delete_pos + delete_len:])
        return result

    def _havoc_clone(self, data: bytearray) -> bytearray:
        if len(data) < 2:
            return data
        clone_len = self.rng.randint(1, min(256, len(data) // 2))
        clone_pos = self.rng.randint(0, len(data) - clone_len)
        insert_pos = self.rng.randint(0, len(data))
        result = bytearray()
        result.extend(data[:insert_pos])
        result.extend(data[clone_pos:clone_pos + clone_len])
        result.extend(data[insert_pos:])
        return result

    def _havoc_overwrite(self, data: bytearray) -> bytearray:
        if len(data) < 2:
            return data
        src_pos = self.rng.randint(0, len(data) - 1)
        dst_pos = self.rng.randint(0, len(data) - 1)
        if src_pos != dst_pos:
            data[dst_pos] = data[src_pos]
        return data

    def _png_aware_mutate(self, data: bytearray) -> bytearray:
        try:
            chunks = self._parse_chunks_with_cache(data)
            if chunks:
                return self._png_custom_mutation(data, 1)
        except Exception:
            pass
        return self._havoc_byte(data)

    # ---------------- PNG chunk 解析 ----------------
    def _parse_chunks_with_cache(self, data: bytearray) -> List[Tuple[int, int, str, bytes]]:
        data_bytes = bytes(data)
        if data_bytes in self._chunk_cache:
            # 标记为最近使用（LRU）并返回副本
            val = self._chunk_cache.pop(data_bytes)
            self._chunk_cache[data_bytes] = val
            return val.copy()
        if not data_bytes.startswith(PNG_SIG):
            raise ValueError('not png')
        off = PNG_HEADER_SIZE
        n = len(data_bytes)
        chunks: List[Tuple[int, int, str, bytes]] = []
        while off + 8 <= n:
            length_bytes = data_bytes[off:off+4]
            length = struct.unpack('>I', length_bytes)[0]
            type_bytes = data_bytes[off+4:off+8]
            try:
                ctype = type_bytes.decode('ascii')
            except Exception:
                ctype = '????'
            data_start = off + 8
            data_end = data_start + length
            if data_end + 4 > n:
                break
            chunk_data = data_bytes[off:data_end+4]
            chunks.append((off, data_end + 4, ctype, chunk_data))
            off = data_end + 4
        # 在插入前确保缓存大小上限
        if len(self._chunk_cache) >= self._chunk_cache_max:
            try:
                self._chunk_cache.popitem(last=False)
            except Exception:
                # 保底：若 pop 失败则清空
                self._chunk_cache.clear()
        self._chunk_cache[data_bytes] = chunks.copy()
        return chunks

    # ---------------- 针对 PNG 的 chunk 级变异 ----------------
    def _mutate_ihdr(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        out = data.copy()
        for start, end, ctype, chunk_data in chunks:
            if ctype == 'IHDR':
                payload_start = start + 8
                if payload_start + 13 > end:
                    continue
                field = self.rng.choice(['width', 'height', 'bit_depth', 'color_type', 'compression', 'filter', 'interlace'])
                if field == 'width':
                    new_width = self.rng.randint(1, 10000)
                    struct.pack_into('>I', out, payload_start, new_width)
                elif field == 'height':
                    new_height = self.rng.randint(1, 10000)
                    struct.pack_into('>I', out, payload_start + 4, new_height)
                elif field == 'bit_depth':
                    valid_depths = [1, 2, 4, 8, 16]
                    new_depth = self.rng.choice(valid_depths + [0, 32, 64, 255])
                    out[payload_start + 8] = new_depth
                elif field == 'color_type':
                    valid_types = [0, 2, 3, 4, 6]
                    new_type = self.rng.choice(valid_types + [1, 5, 7, 255])
                    out[payload_start + 9] = new_type
                self._update_chunk_crc(out, start)
                break
        return out

    def _mutate_idat(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        out = data.copy()
        idat_chunks = [(i, start, end, ctype, chunk_data)
                       for i, (start, end, ctype, chunk_data) in enumerate(chunks)
                       if ctype == 'IDAT']
        if not idat_chunks:
            return out
        idx, start, end, ctype, chunk_data = self.rng.choice(idat_chunks)
        payload_start = start + 8
        payload_end = end - 4
        if payload_end - payload_start < 4:
            return out
        mutation_type = self.rng.choice(['bit_flip', 'byte_flip', 'insert', 'delete'])
        if mutation_type == 'bit_flip':
            for _ in range(self.rng.randint(1, 10)):
                pos = self.rng.randint(payload_start, payload_end - 1)
                bit = 1 << self.rng.randint(0, 7)
                out[pos] ^= bit
        elif mutation_type == 'byte_flip':
            for _ in range(self.rng.randint(1, 5)):
                pos = self.rng.randint(payload_start, payload_end - 1)
                out[pos] = self.rng.randint(0, 255)
        elif mutation_type == 'insert':
            insert_pos = self.rng.randint(payload_start, payload_end)
            insert_data = bytes([self.rng.randint(0, 255) for _ in range(self.rng.randint(1, 10))])
            out[insert_pos:insert_pos] = insert_data
        elif mutation_type == 'delete':
            if payload_end - payload_start > 10:
                delete_pos = self.rng.randint(payload_start, payload_end - 5)
                delete_len = self.rng.randint(1, min(10, payload_end - delete_pos))
                del out[delete_pos:delete_pos + delete_len]
        self._update_chunk_crc(out, start)
        return out

    def _mutate_plte(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        out = data.copy()
        for start, end, ctype, chunk_data in chunks:
            if ctype == 'PLTE':
                payload_start = start + 8
                payload_end = end - 4
                if payload_end - payload_start < 3:
                    continue
                num_entries = (payload_end - payload_start) // 3
                if num_entries == 0:
                    continue
                for _ in range(self.rng.randint(1, min(10, num_entries))):
                    entry_idx = self.rng.randint(0, num_entries - 1)
                    offset = payload_start + entry_idx * 3
                    for i in range(3):
                        if self.rng.random() < 0.5:
                            out[offset + i] = self.rng.randint(0, 255)
                self._update_chunk_crc(out, start)
                break
        return out

    def _mutate_time_chunk(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        out = data.copy()
        for start, end, ctype, chunk_data in chunks:
            if ctype == 'tIME':
                payload_start = start + 8
                if payload_start + 7 > end:
                    continue
                field_idx = self.rng.randint(0, 5)
                if field_idx == 0:
                    new_year = self.rng.randint(0, 65535)
                    struct.pack_into('>H', out, payload_start, new_year)
                else:
                    new_val = self.rng.randint(0, 255)
                    out[payload_start + 1 + field_idx] = new_val
                self._update_chunk_crc(out, start)
                break
        return out

    def _corrupt_chunk_length_afl(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        out = data.copy()
        candidates = [(i, start, end, ctype, chunk_data)
                      for i, (start, end, ctype, chunk_data) in enumerate(chunks)
                      if ctype not in self.critical_chunks]
        if not candidates:
            candidates = [(i, start, end, ctype, chunk_data)
                          for i, (start, end, ctype, chunk_data) in enumerate(chunks)
                          if ctype != 'IEND']
        if candidates:
            idx, start, end, ctype, chunk_data = self.rng.choice(candidates)
            # 在安全模式下，执行保守的长度修改以避免破坏性解析错误
            if getattr(self, 'safe_mode', False):
                # 仅进行微小增减，不设极端值或负数
                current_len = end - start - 12
                delta = self.rng.randint(- min(4, current_len), min(16, max(0, current_len)))
                new_len = max(0, current_len + delta) & 0xFFFFFFFF
            else:
                strategy = self.rng.choice(['overflow', 'underflow', 'zero', 'max', 'negative'])
                if strategy == 'overflow':
                    new_len = min(0xFFFFFFFF, (end - start - 12) + self.rng.randint(1, 1000))
                elif strategy == 'underflow':
                    current_len = end - start - 12
                    new_len = max(0, current_len - self.rng.randint(1, max(1, current_len)))
                elif strategy == 'zero':
                    new_len = 0
                elif strategy == 'max':
                    new_len = 0xFFFFFFFF
                else:
                    new_len = self.rng.randint(-1000, -1) & 0xFFFFFFFF
            struct.pack_into('>I', out, start, new_len)
        return out

    def _swap_png_chunks(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        if len(chunks) < 4:
            return data.copy()
        swappable = [i for i, (_, _, ctype, _) in enumerate(chunks) if ctype not in self.critical_chunks and ctype != 'IEND']
        if len(swappable) >= 2:
            idx1, idx2 = self.rng.sample(swappable, 2)
            chunk1 = chunks[idx1]
            chunk2 = chunks[idx2]
            result = bytearray()
            result.extend(data[:chunk1[0]])
            result.extend(chunk2[3])
            result.extend(data[chunk1[1]:chunk2[0]])
            result.extend(chunk1[3])
            result.extend(data[chunk2[1]:])
            return result
        return data.copy()

    def _duplicate_chunk_afl(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        candidates = [(start, end, ctype, chunk_data)
                      for start, end, ctype, chunk_data in chunks
                      if ctype not in self.critical_chunks]
        if candidates:
            start, end, ctype, chunk_data = self.rng.choice(candidates)
            insert_before_iend = -1
            for i, (s, e, ct, _) in enumerate(chunks):
                if ct == 'IEND':
                    insert_before_iend = s
                    break
            if insert_before_iend > 0:
                result = bytearray()
                result.extend(data[:insert_before_iend])
                result.extend(chunk_data)
                result.extend(data[insert_before_iend:])
                return result
        return data.copy()

    def _inject_invalid_chunk(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        chunk_types = ['INVL', 'CRSH', 'BUGG', 'TEST', 'AAAA', 'BBBB']
        chunk_type = self.rng.choice(chunk_types).encode('ascii')
        length = self.rng.randint(0, 100)
        chunk_data = bytes([self.rng.randint(0, 255) for _ in range(length)])
        crc = binascii.crc32(chunk_type + chunk_data) & 0xffffffff
        invalid_chunk = struct.pack('>I', length) + chunk_type + chunk_data + struct.pack('>I', crc)
        iend_pos = -1
        for start, end, ctype, _ in chunks:
            if ctype == 'IEND':
                iend_pos = start
                break
        if iend_pos > 0:
            result = bytearray()
            result.extend(data[:iend_pos])
            result.extend(invalid_chunk)
            result.extend(data[iend_pos:])
            return result
        return data.copy()

    def _mutate_filter_type(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        out = data.copy()
        idat_chunks = [(start, end, chunk_data) for start, end, ctype, chunk_data in chunks if ctype == 'IDAT']
        if not idat_chunks:
            return out
        start, end, chunk_data = self.rng.choice(idat_chunks)
        payload_start = start + 8
        payload_end = end - 4
        compressed_data = bytes(out[payload_start:payload_end])
        try:
            decompressed = zlib.decompress(compressed_data)
        except Exception:
            return out
        decompressed_ba = bytearray(decompressed)

        for i in range(0, len(decompressed_ba), max(1, self.rng.randint(1, 100))):
            if i < len(decompressed_ba):
                if self.rng.random() < 0.3:
                    if self.rng.random() < 0.5:
                        decompressed_ba[i] = self.rng.randint(0, 4)
                    else:
                        decompressed_ba[i] = self.rng.randint(5, 255)
        try:
            new_compressed = zlib.compress(bytes(decompressed_ba))
        except Exception:
            return out
        new_len = len(new_compressed)
        struct.pack_into('>I', out, start, new_len)
        out[payload_start:payload_end] = new_compressed
        crc = binascii.crc32(bytes(out[start+4:start+8]) + bytes(out[payload_start:payload_start+new_len])) & 0xffffffff
        end_pos = payload_start + new_len
        out[end_pos:end_pos] = struct.pack('>I', crc)
        self._chunk_cache.clear()
        return out

    def _corrupt_zlib_stream(self, data: bytearray, chunks: List[Tuple[int, int, str, bytes]]) -> bytearray:
        out = data.copy()
        idat_chunks = [(start, end, chunk_data) for start, end, ctype, chunk_data in chunks if ctype == 'IDAT']
        if not idat_chunks:
            return out
        start, end, chunk_data = self.rng.choice(idat_chunks)
        payload_start = start + 8
        payload_end = end - 4
        if payload_end - payload_start < 4:
            return out
        # 在安全模式下优先进行位/字节翻转而非删除插入，减少解压失败导致的 parse_error
        for _ in range(self.rng.randint(1, 5)):
            pos = self.rng.randint(payload_start, payload_end - 1)
            if getattr(self, 'safe_mode', False):
                # 仅字节替换或位翻转
                if self.rng.random() < 0.7:
                    out[pos] ^= 1 << self.rng.randint(0, 7)
                else:
                    out[pos] = self.rng.randint(0, 255)
            else:
                if self.rng.random() < 0.5:
                    out[pos] = self.rng.randint(0, 255)
                else:
                    if self.rng.random() < 0.5 and payload_end - payload_start > 2:
                        del out[pos:pos+1]
                    else:
                        out[pos:pos] = bytes([self.rng.randint(0, 255)])
                    payload_end = len(out) - 4 if len(out) >= 4 else payload_start
        new_len = payload_end - payload_start
        struct.pack_into('>I', out, start, new_len)
        self._update_chunk_crc(out, start)
        return out

    def _update_chunk_crc(self, out: bytearray, start: int) -> None:
        if start + 8 > len(out):
            return
        length = struct.unpack('>I', bytes(out[start:start+4]))[0]
        type_bytes = bytes(out[start+4:start+8])
        payload_start = start + 8
        payload_end = payload_start + length
        if payload_end + 4 > len(out):
            return
        crc_val = binascii.crc32(type_bytes + bytes(out[payload_start:payload_end])) & 0xffffffff
        struct.pack_into('>I', out, payload_end, crc_val)
        self._chunk_cache.clear()


__all__ = ['PNGMutatorAFL', 'MutationStage']

# 兼容旧的导入名字：一些工具/脚本期望 `PngMutator` 可用
PngMutator = PNGMutatorAFL
