"""
AFL++风格的JPEG变异器，采用分层变异策略：确定性变异 + 随机变异 + 自定义JPEG感知变异。
优化目标：最大化覆盖率，平衡速度和有效性。
"""
from __future__ import annotations

import random
import struct
import time
from typing import List, Tuple, Optional, Dict, Set, Callable
from enum import Enum
import copy


class MutationStage(Enum):
    """变异阶段，模仿AFL++的层次结构"""
    DETERMINISTIC = 1      # 确定性变异：按顺序应用所有变异操作
    RANDOM = 2            # 随机阶段：随机选择变异操作
    SPLICE = 3            # 拼接阶段：合并两个输入
    CUSTOM = 4            # JPEG感知变异


class JPEGMutatorAFL:
    """AFL++风格的JPEG变异器"""
    
    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)
        self.stage = MutationStage.DETERMINISTIC
        self.cycle = 0  # 变异周期计数
        
        # AFL++风格的变异操作配置
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
            self._havoc_delete,
            self._havoc_clone,
            self._havoc_overwrite,
            self._jpeg_aware_mutate,
        ]
        
        # JPEG特殊变异操作
        self.jpeg_ops = [
            self._mutate_jpeg_header,
            self._mutate_quantization_table,
            self._mutate_huffman_table,
            self._mutate_scan_data,
            self._corrupt_segment_length_afl,
            self._swap_jpeg_segments,
            self._duplicate_app_segment,
            self._inject_jpeg_restart,
        ]
        
        # 兴趣值表（AFL++风格）
        self.interest_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
        self.interest_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
        self.interest_32 = [
            -2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647
        ]
        
        # 性能统计
        self.stats = {
            'deterministic_mutations': 0,
            'random_mutations': 0,
            'splice_mutations': 0,
            'custom_mutations': 0,
            'unique_crashes': 0,
            'total_executions': 0,
        }
        
        # 已发现的独特边（覆盖率跟踪）
        self.unique_edges: Set[int] = set()
        
        # 适应度反馈（如果提供）
        self.fitness_callback: Optional[Callable[[bytes], int]] = None
    
    def set_fitness_callback(self, callback: Callable[[bytes], int]) -> None:
        """设置适应度回调函数，用于指导变异"""
        self.fitness_callback = callback
    
    def mutate(self, data: bytes, num_mutations: int = 1, 
               stage: Optional[MutationStage] = None) -> bytes:
        """主变异函数，支持不同阶段的变异"""
        if not data:
            return data
        
        if stage is None:
            # 自动选择阶段（模仿AFL++调度）
            if self.cycle % 100 < 70:  # 70%时间用随机阶段
                stage = MutationStage.RANDOM
            elif self.cycle % 100 < 85:  # 15%时间用确定性阶段
                stage = MutationStage.DETERMINISTIC
            elif self.cycle % 100 < 95:  # 10%时间用拼接阶段
                stage = MutationStage.SPLICE
            else:  # 5%时间用JPEG感知变异
                stage = MutationStage.CUSTOM
        
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
            # 需要另一个输入进行拼接
            if hasattr(self, '_splice_candidate'):
                out = self._splice_mutation(out, self._splice_candidate)
                self.stats['splice_mutations'] += 1
        
        elif stage == MutationStage.CUSTOM:
            out = self._jpeg_custom_mutation(out, num_mutations)
            self.stats['custom_mutations'] += 1
        
        return bytes(out)
    
    def add_splice_candidate(self, data: bytes) -> None:
        """添加拼接候选（另一个有趣的输入）"""
        self._splice_candidate = data
    
    def _deterministic_mutation(self, data: bytearray, num_mutations: int) -> bytearray:
        """确定性变异阶段 - 系统性地探索变异空间"""
        out = data.copy()
        size = len(out)
        
        # 按AFL++顺序应用确定性变异
        for op in self.deterministic_ops[:min(num_mutations, len(self.deterministic_ops))]:
            # 根据操作类型决定步长
            if op.__name__ in ['_bit_flip_1', '_bit_flip_2', '_bit_flip_4']:
                step = 1
            elif op.__name__ in ['_byte_flip_1', '_arith_8', '_interest_8']:
                step = 1
            elif op.__name__ in ['_byte_flip_2', '_arith_16', '_interest_16']:
                step = 2
            else:
                step = 4
            
            for i in range(0, size - (step - 1), max(1, step)):
                original = out[i:i+step]
                mutated = op(out, i, step)
                if mutated != original:
                    # 如果提供了适应度回调，检查变异是否改善适应度
                    if self.fitness_callback:
                        old_fitness = self.fitness_callback(bytes(out))
                        new_fitness = self.fitness_callback(bytes(mutated))
                        if new_fitness > old_fitness:
                            out = mutated
                            break
                    else:
                        out = mutated
                        break
        
        return out
    
    def _random_mutation(self, data: bytearray, num_mutations: int) -> bytearray:
        """随机（havoc）变异阶段 - 高强度的随机变异"""
        out = data.copy()
        
        # 确定变异次数（类似AFL++的havoc阶段）
        # num_mutations决定变异强度，范围1-256
        intensity = min(max(num_mutations, 1), 256)
        
        for _ in range(intensity):
            if not out:
                break
            
            # 随机选择变异操作
            op = self.rng.choice(self.random_ops)
            try:
                out = op(out)
            except (IndexError, ValueError):
                continue
        
        return out
    
    def _splice_mutation(self, data1: bytearray, data2: bytes) -> bytearray:
        """拼接两个输入（类似AFL++的splice阶段）"""
        if not data2 or len(data2) < 4:
            return data1
        
        size1 = len(data1)
        size2 = len(data2)
        
        # 选择拼接点
        split1 = self.rng.randint(0, size1 - 1)
        split2 = self.rng.randint(0, size2 - 1)
        
        # 选择拼接长度
        max_len = min(size1 - split1, size2 - split2)
        if max_len < 4:
            return data1
        
        splice_len = self.rng.randint(4, max_len)
        
        # 执行拼接
        result = bytearray()
        result.extend(data1[:split1])
        result.extend(data2[split2:split2 + splice_len])
        result.extend(data1[split1 + splice_len:])
        
        return result
    
    def _jpeg_custom_mutation(self, data: bytearray, num_mutations: int) -> bytearray:
        """JPEG感知的定制变异"""
        out = data.copy()
        
        # 尝试解析JPEG段结构
        try:
            segments = self._parse_jpeg_segments(out)
            if len(segments) >= 2:  # 至少有SOI和EOI
                for _ in range(num_mutations):
                    op = self.rng.choice(self.jpeg_ops)
                    try:
                        out = op(out, segments)
                        # 更新段信息
                        segments = self._parse_jpeg_segments(out)
                    except Exception:
                        continue
                return out
        except Exception:
            pass
        
        # 如果JPEG解析失败，回退到随机变异
        return self._random_mutation(out, 1)
    
    # ========== AFL++核心变异操作 ==========
    
    def _bit_flip_1(self, data: bytearray, pos: int, step: int) -> bytearray:
        """翻转1个bit"""
        if pos >= len(data):
            return data
        data[pos] ^= 1 << self.rng.randint(0, 7)
        return data
    
    def _bit_flip_2(self, data: bytearray, pos: int, step: int) -> bytearray:
        """翻转2个bits"""
        if pos >= len(data):
            return data
        for _ in range(2):
            data[pos] ^= 1 << self.rng.randint(0, 7)
        return data
    
    def _bit_flip_4(self, data: bytearray, pos: int, step: int) -> bytearray:
        """翻转4个bits"""
        if pos >= len(data):
            return data
        for _ in range(4):
            data[pos] ^= 1 << self.rng.randint(0, 7)
        return data
    
    def _byte_flip_1(self, data: bytearray, pos: int, step: int) -> bytearray:
        """翻转整个字节"""
        if pos >= len(data):
            return data
        data[pos] ^= 0xFF
        return data
    
    def _byte_flip_2(self, data: bytearray, pos: int, step: int) -> bytearray:
        """翻转2个字节"""
        if pos + 1 >= len(data):
            return data
        for i in range(2):
            data[pos + i] ^= 0xFF
        return data
    
    def _byte_flip_4(self, data: bytearray, pos: int, step: int) -> bytearray:
        """翻转4个字节"""
        if pos + 3 >= len(data):
            return data
        for i in range(4):
            data[pos + i] ^= 0xFF
        return data
    
    def _arith_8(self, data: bytearray, pos: int, step: int) -> bytearray:
        """8位算术变异"""
        if pos >= len(data):
            return data
        
        value = int(self.rng.choice([-35, -1, 1, 35]))
        new_val = (data[pos] + value) & 0xFF
        
        # 避免无变化
        if new_val != data[pos]:
            data[pos] = new_val
        
        return data
    
    def _arith_16(self, data: bytearray, pos: int, step: int) -> bytearray:
        """16位算术变异（大端序）"""
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
        """32位算术变异（大端序）"""
        if pos + 3 >= len(data):
            return data
        
        value = int(self.rng.choice([
            -1, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096,
            8192, 16384, 32768, 65536, 131072, 262144, 524288
        ]))
        
        current = struct.unpack('>I', bytes(data[pos:pos+4]))[0]
        new_val = (current + value) & 0xFFFFFFFF
        
        if new_val != current:
            data[pos:pos+4] = struct.pack('>I', new_val)
        
        return data
    
    def _interest_8(self, data: bytearray, pos: int, step: int) -> bytearray:
        """用兴趣值替换8位值"""
        if pos >= len(data):
            return data
        
        new_val = self.rng.choice(self.interest_8) & 0xFF
        if new_val != data[pos]:
            data[pos] = new_val
        
        return data
    
    def _interest_16(self, data: bytearray, pos: int, step: int) -> bytearray:
        """用兴趣值替换16位值（大端序）"""
        if pos + 1 >= len(data):
            return data
        
        new_val = self.rng.choice(self.interest_16) & 0xFFFF
        current = (data[pos] << 8) | data[pos + 1]
        
        if new_val != current:
            data[pos] = (new_val >> 8) & 0xFF
            data[pos + 1] = new_val & 0xFF
        
        return data
    
    def _interest_32(self, data: bytearray, pos: int, step: int) -> bytearray:
        """用兴趣值替换32位值（大端序）"""
        if pos + 3 >= len(data):
            return data
        
        new_val = self.rng.choice(self.interest_32) & 0xFFFFFFFF
        current = struct.unpack('>I', bytes(data[pos:pos+4]))[0]
        
        if new_val != current:
            data[pos:pos+4] = struct.pack('>I', new_val)
        
        return data
    
    # ========== 随机阶段操作 ==========
    
    def _havoc_byte(self, data: bytearray) -> bytearray:
        """随机字节变异"""
        if not data:
            return data
        
        pos = self.rng.randint(0, len(data) - 1)
        data[pos] = self.rng.randint(0, 255)
        return data
    
    def _havoc_bit(self, data: bytearray) -> bytearray:
        """随机位翻转"""
        if not data:
            return data
        
        pos = self.rng.randint(0, len(data) - 1)
        bit = 1 << self.rng.randint(0, 7)
        data[pos] ^= bit
        return data
    
    def _havoc_arith(self, data: bytearray) -> bytearray:
        """随机算术变异"""
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
        """随机兴趣值替换"""
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
        """随机删除字节"""
        if len(data) <= 1:
            return data
        
        # 删除1-256字节
        delete_len = self.rng.randint(1, min(256, len(data) // 2))
        delete_pos = self.rng.randint(0, len(data) - delete_len)
        
        result = bytearray()
        result.extend(data[:delete_pos])
        result.extend(data[delete_pos + delete_len:])
        return result
    
    def _havoc_clone(self, data: bytearray) -> bytearray:
        """随机克隆字节块"""
        if len(data) < 2:
            return data
        
        # 克隆1-256字节
        clone_len = self.rng.randint(1, min(256, len(data) // 2))
        clone_pos = self.rng.randint(0, len(data) - clone_len)
        insert_pos = self.rng.randint(0, len(data))
        
        result = bytearray()
        result.extend(data[:insert_pos])
        result.extend(data[clone_pos:clone_pos + clone_len])
        result.extend(data[insert_pos:])
        return result
    
    def _havoc_overwrite(self, data: bytearray) -> bytearray:
        """随机覆盖字节"""
        if len(data) < 2:
            return data
        
        # 用另一位置的字节覆盖
        src_pos = self.rng.randint(0, len(data) - 1)
        dst_pos = self.rng.randint(0, len(data) - 1)
        
        if src_pos != dst_pos:
            data[dst_pos] = data[src_pos]
        
        return data
    
    def _jpeg_aware_mutate(self, data: bytearray) -> bytearray:
        """JPEG感知的随机变异"""
        try:
            segments = self._parse_jpeg_segments(data)
            if segments:
                return self._jpeg_custom_mutation(data, 1)
        except Exception:
            pass
        return self._havoc_byte(data)
    
    # ========== JPEG专用变异操作 ==========
    
    def _parse_jpeg_segments(self, data: bytearray) -> List[Tuple[int, int, int]]:
        """解析JPEG段结构"""
        i = 0
        n = len(data)
        segs: List[Tuple[int, int, int]] = []
        
        while i + 1 < n:
            if data[i] != 0xFF:
                i += 1
                continue
            
            j = i + 1
            if j >= n:
                break
                
            marker = data[j]
            code = 0xFF00 | marker
            
            # 特殊标记：SOI, EOI, RST
            if marker == 0xD8 or marker == 0xD9 or (0xD0 <= marker <= 0xD7):
                segs.append((code, i, j + 1))
                i = j + 1
                continue
            
            # 其他标记：读取长度字段
            if j + 2 >= n:
                break
                
            length = (data[j + 1] << 8) | data[j + 2]
            seg_end = j + 1 + length
            
            if seg_end > n:
                seg_end = n
                
            segs.append((code, i, seg_end))
            i = seg_end
        
        return segs
    
    def _mutate_jpeg_header(self, data: bytearray, 
                           segments: List[Tuple[int, int, int]]) -> bytearray:
        """变异JPEG头部信息"""
        out = data.copy()
        
        # 找到第一个APP段（通常是JFIF或EXIF）
        app_segments = [s for s in segments if 0xFFE0 <= s[0] <= 0xFFEF]
        if app_segments:
            _, start, end = app_segments[0]
            if end - start > 20:  # 确保有足够空间
                # 随机修改APP段中的某些字节
                for _ in range(self.rng.randint(1, 5)):
                    pos = self.rng.randint(start + 4, end - 1)
                    out[pos] = self.rng.randint(0, 255)
        
        return out
    
    def _mutate_quantization_table(self, data: bytearray,
                                  segments: List[Tuple[int, int, int]]) -> bytearray:
        """变异量化表（DQT段）"""
        out = data.copy()
        
        dqt_segments = [s for s in segments if s[0] == 0xFFDB]
        for _, start, end in dqt_segments:
            if end - start > 4:
                # 在量化表数据中引入随机扰动
                for i in range(start + 4, min(end, start + 68)):
                    if self.rng.random() < 0.3:
                        out[i] = (out[i] + self.rng.randint(-10, 10)) & 0xFF
        
        return out
    
    def _mutate_huffman_table(self, data: bytearray,
                             segments: List[Tuple[int, int, int]]) -> bytearray:
        """变异哈夫曼表（DHT段）"""
        out = data.copy()
        
        dht_segments = [s for s in segments if s[0] == 0xFFC4]
        for _, start, end in dht_segments:
            if end - start > 20:
                # 修改哈夫曼表数据
                for i in range(start + 4, min(end, start + 50)):
                    if self.rng.random() < 0.2:
                        out[i] = self.rng.randint(0, 255)
        
        return out
    
    def _mutate_scan_data(self, data: bytearray,
                         segments: List[Tuple[int, int, int]]) -> bytearray:
        """变异扫描数据（SOS段之后的数据）"""
        out = data.copy()
        
        # 找到SOS段
        sos_segments = [s for s in segments if s[0] == 0xFFDA]
        if sos_segments:
            _, _, sos_end = sos_segments[-1]
            # 变异扫描数据（直到EOI或文件结束）
            scan_end = len(out)
            for i in range(len(segments)):
                if segments[i][0] == 0xFFD9:  # EOI
                    scan_end = segments[i][1]
                    break
            
            if scan_end - sos_end > 10:
                # 随机修改扫描数据
                for _ in range(self.rng.randint(10, 50)):
                    pos = self.rng.randint(sos_end, scan_end - 1)
                    out[pos] = (out[pos] + self.rng.randint(-5, 5)) & 0xFF
        
        return out
    
    def _corrupt_segment_length_afl(self, data: bytearray,
                                   segments: List[Tuple[int, int, int]]) -> bytearray:
        """AFL风格的段长度损坏"""
        out = data.copy()
        
        # 选择有长度字段的段
        candidates = [s for s in segments 
                     if s[0] not in (0xFFD8, 0xFFD9) and s[2] - s[1] >= 4]
        
        if candidates:
            _, start, end = self.rng.choice(candidates)
            
            # 随机选择变异策略
            strategy = self.rng.choice(['overflow', 'underflow', 'zero', 'max'])
            
            if strategy == 'overflow':
                new_len = min(65535, (end - start) + self.rng.randint(1, 1000))
            elif strategy == 'underflow':
                new_len = max(2, (end - start) - self.rng.randint(1, (end - start) - 2))
            elif strategy == 'zero':
                new_len = 0
            else:  # max
                new_len = 65535
            
            out[start + 2] = (new_len >> 8) & 0xFF
            out[start + 3] = new_len & 0xFF
        
        return out
    
    def _swap_jpeg_segments(self, data: bytearray,
                           segments: List[Tuple[int, int, int]]) -> bytearray:
        """交换JPEG段顺序"""
        if len(segments) < 4:
            return data.copy()
        
        # 选择两个非关键段交换
        swappable = [i for i, s in enumerate(segments) 
                    if s[0] not in (0xFFD8, 0xFFD9, 0xFFDA, 0xFFD0, 0xFFD1, 
                                   0xFFD2, 0xFFD3, 0xFFD4, 0xFFD5, 0xFFD6, 0xFFD7)]
        
        if len(swappable) >= 2:
            idx1, idx2 = self.rng.sample(swappable, 2)
            s1 = segments[idx1]
            s2 = segments[idx2]
            
            # 构建新数据
            result = bytearray()
            result.extend(data[:s1[1]])
            result.extend(data[s2[1]:s2[2]])
            result.extend(data[s1[2]:s2[1]])
            result.extend(data[s1[1]:s1[2]])
            result.extend(data[s2[2]:])
            
            return result
        
        return data.copy()
    
    def _duplicate_app_segment(self, data: bytearray,
                              segments: List[Tuple[int, int, int]]) -> bytearray:
        """重复APP段"""
        app_segments = [s for s in segments if 0xFFE0 <= s[0] <= 0xFFEF]
        
        if app_segments:
            _, start, end = self.rng.choice(app_segments)
            segment_data = data[start:end]
            
            # 选择插入位置
            insert_pos = self.rng.choice([s[2] for s in segments[:-1]])
            
            result = bytearray()
            result.extend(data[:insert_pos])
            result.extend(segment_data)
            result.extend(data[insert_pos:])
            
            return result
        
        return data.copy()
    
    def _inject_jpeg_restart(self, data: bytearray,
                            segments: List[Tuple[int, int, int]]) -> bytearray:
        """注入RST标记（用于错误恢复测试）"""
        out = data.copy()
        
        # 在扫描数据中注入RST标记
        sos_segments = [s for s in segments if s[0] == 0xFFDA]
        if sos_segments:
            _, _, sos_end = sos_segments[-1]
            scan_end = len(out)
            
            for i in range(len(segments)):
                if segments[i][0] == 0xFFD9:  # EOI
                    scan_end = segments[i][1]
                    break
            
            if scan_end - sos_end > 100:
                # 在随机位置注入RST标记
                inject_pos = self.rng.randint(sos_end, scan_end - 10)
                rst_marker = 0xFFD0 + self.rng.randint(0, 7)
                
                result = bytearray()
                result.extend(out[:inject_pos])
                result.extend([0xFF, rst_marker])
                result.extend(out[inject_pos:])
                
                return result
        
        return out
    
    def get_stats(self) -> Dict[str, int]:
        """获取变异统计信息"""
        return self.stats.copy()
    
    def reset_stats(self) -> None:
        """重置统计信息"""
        for key in self.stats:
            self.stats[key] = 0
        self.unique_edges.clear()


# 兼容性别名
JpegMutatorAFL = JPEGMutatorAFL


if __name__ == "__main__":
    # 测试代码
    example_jpeg = (
        b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xFF\xDB\x00\x43\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\x09\x09"
        b"\x08\x0A\x0C\x14\x0D\x0C\x0B\x0B\x0C\x19\x12\x13\x0F\x14\x1D\x1A\x1F"
        b"\x1E\x1D\x1A\x1C\x1C\x20\x24\x2E\x27\x20\x22\x2C\x23\x1C\x1C\x28\x37"
        b"\x29\x2C\x30\x31\x34\x34\x34\x1F\x27\x39\x3D\x38\x32\x3C\x2E\x33\x34"
        b"\x32\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00\xFF\xC4\x00"
        b"\x1F\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\xFF\xC4\x00\xB5"
        b"\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01\x7D"
        b"\x01\x02\x03\x00\x04\x11\x05\x12\x21\x31\x41\x06\x13\x51\x61\x07\x22"
        b"\x71\x14\x32\x81\x91\xA1\x08\x23\x42\xB1\xC1\x15\x52\xD1\xF0\x24\x33"
        b"\x62\x72\x82\x09\x0A\x16\x17\x18\x19\x1A\x25\x26\x27\x28\x29\x2A\x34"
        b"\x35\x36\x37\x38\x39\x3A\x43\x44\x45\x46\x47\x48\x49\x4A\x53\x54\x55"
        b"\x56\x57\x58\x59\x5A\x63\x64\x65\x66\x67\x68\x69\x6A\x73\x74\x75\x76"
        b"\x77\x78\x79\x7A\x83\x84\x85\x86\x87\x88\x89\x8A\x92\x93\x94\x95\x96"
        b"\x97\x98\x99\x9A\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xB2\xB3\xB4\xB5"
        b"\xFF\xD9"
    )
    
    print("=== AFL++风格JPEG变异器测试 ===")
    print(f"原始JPEG大小: {len(example_jpeg)} 字节")
    
    mutator = JPEGMutatorAFL(seed=42)
    
    # 测试不同阶段的变异
    stages = [
        (MutationStage.DETERMINISTIC, "确定性变异"),
        (MutationStage.RANDOM, "随机变异"),
        (MutationStage.CUSTOM, "JPEG感知变异"),
    ]
    
    for stage, name in stages:
        print(f"\n--- {name} ---")
        for i in range(3):
            mutated = mutator.mutate(example_jpeg, num_mutations=2, stage=stage)
            print(f"  变异{i+1}: 大小={len(mutated)} 头部={mutated[:4].hex()}...")
    
    print(f"\n统计信息: {mutator.get_stats()}")
# 兼容旧接口：保留 `JpegMutator` 名称用于旧代码导入
JpegMutator = JPEGMutatorAFL
