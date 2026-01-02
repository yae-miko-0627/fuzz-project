"""轻量且高效的 ELF 专用变异器。

特性：
- 结构化常量管理，消除硬编码；
- 完善的边界检查与精细化异常处理；
- 支持符号表（SHT_SYMTAB）、动态段（SHT_DYNAMIC）、PHDR 结构化变异；
- 增强字符串表/语义变异策略，提升路径覆盖；
- 解析结果缓存，提升吞吐；
- 可配置策略开关，支持固定强度（便于复现）；
- 完善的日志输出，便于调试。

设计目标：在保持轻量和高吞吐的同时，大幅提升触发格式相关代码路径的概率。
"""

from __future__ import annotations

import struct
import random
import logging
from typing import Iterable, Optional, List, Tuple, Dict, Any


# ======================== ELF 常量定义（归一化）========================
class ElfConst:
    """ELF 相关常量归类，消除硬编码"""
    # ELF 魔数
    ELF_MAGIC = b"\x7fELF"
    
    # 节类型
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    
    # ELF 类（32/64 位）
    ELFCLASS32 = 1
    ELFCLASS64 = 2
    
    # 字节序
    ELFDATA2LSB = 1  # 小端
    ELFDATA2MSB = 2  # 大端
    
    # ELF 头偏移（32/64 通用）
    E_ENTRY_32_OFF = 24
    E_ENTRY_64_OFF = 24
    E_TYPE_OFF = 16
    E_PHOFF_32_OFF = 28
    E_PHOFF_64_OFF = 32
    E_SHOFF_32_OFF = 32
    E_SHOFF_64_OFF = 40
    E_SHENTSIZE_OFF_32 = 46
    E_SHENTSIZE_OFF_64 = 58
    E_SHNUM_OFF_32 = 48
    E_SHNUM_OFF_64 = 60
    E_SHSTRNDX_OFF_32 = 50
    E_SHSTRNDX_OFF_64 = 62
    
    # 数值掩码
    MASK_32 = 0xFFFFFFFF
    MASK_64 = 0xFFFFFFFFFFFFFFFF
    
    # 变异阈值
    MIN_SECTION_SIZE = 4
    MIN_STRING_LEN = 3
    BLOCK_SIZE_BASE = 4
    BLOCK_SIZE_MAX = 64
    MAX_CACHE_SIZE = 1000  # 解析缓存最大条目数
    
    # PHDR 相关
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PHENT_SIZE_32 = 32
    PHENT_SIZE_64 = 56
    
    # 常见符号名（用于语义变异）
    COMMON_SYMBOLS = [b'main', b'_start', b'init', b'malloc', b'free',
                      b'_init', b'_fini', b'printf', b'strcpy', b'memcpy']


# ======================== 通用工具函数 ========================
def _is_elf(data: bytes) -> bool:
    """检查数据是否为 ELF 格式"""
    return len(data) >= len(ElfConst.ELF_MAGIC) and data[:len(ElfConst.ELF_MAGIC)] == ElfConst.ELF_MAGIC


def _check_bounds(data: bytes, off: int, size: int) -> bool:
    """通用边界检查：确保 [off, off+size) 完全在 data 范围内"""
    return 0 <= off < len(data) and 0 <= size and (off + size) <= len(data)


# ======================== ELF 变异器核心类 ========================
class ElfMutator:
    """ELF 专用变异器（优化版）
    
    保持原接口兼容，新增精细化配置项，增强变异策略与鲁棒性。
    """
    def __init__(
        self, 
        seed: Optional[int] = None, 
        max_outputs: int = 120, 
        strength: int = 8,
        # 基础策略开关（默认全开）
        mutate_header: bool = True,
        mutate_strtab: bool = True,
        mutate_symtab: bool = True,
        mutate_dynamic: bool = True,
        mutate_phdr: bool = True,
        mutate_rodata: bool = True,
        # 高级配置
        aggressive_ops: bool = True,
        fixed_strength: bool = False,  # 固定强度（便于复现）
        log_level: int = logging.WARNING  # 日志级别
    ) -> None:
        """初始化变异器
        
        参数:
            seed: 随机种子（用于复现）
            max_outputs: 每次 mutate 的基准输出上限（会乘以 strength）
            strength: 变异强度因子（>=1），越大变体越激进/越多
            mutate_header: 是否变异 ELF 头字段
            mutate_strtab: 是否变异字符串表
            mutate_symtab: 是否变异符号表
            mutate_dynamic: 是否变异动态段
            mutate_phdr: 是否变异程序头
            mutate_rodata: 是否变异只读数据段
            aggressive_ops: 是否启用激进的节操作
            fixed_strength: 是否固定强度（False 则随机 1~strength）
            log_level: 日志级别（logging.DEBUG/INFO/WARNING/ERROR）
        """
        # 随机数生成器
        self.rng = random.Random(seed)
        
        # 变异配置
        self.max_outputs = max(1, int(max_outputs))
        self.strength = max(1, int(strength)) if fixed_strength else self.rng.randint(1, max(1, int(strength)))
        self.aggressive_ops = aggressive_ops
        
        # 策略开关
        self.mutate_header = mutate_header
        self.mutate_strtab = mutate_strtab
        self.mutate_symtab = mutate_symtab
        self.mutate_dynamic = mutate_dynamic
        self.mutate_phdr = mutate_phdr
        self.mutate_rodata = mutate_rodata
        
        # 缓存：解析结果（避免重复解析）
        self._parse_cache: Dict[int, Tuple[Optional[dict], List[dict]]] = {}
        
        # 日志配置
        self._init_logger(log_level)

    def _init_logger(self, log_level: int) -> None:
        """初始化日志器"""
        self.logger = logging.getLogger(f"ElfMutator-{id(self)}")
        self.logger.setLevel(log_level)
        
        # 避免重复添加处理器
        if self.logger.handlers:
            return
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    # ----------------- 核心变异入口 -----------------
    def mutate(self, data: bytes) -> Iterable[bytes]:
        """对 ELF 数据产生若干变体（generator）
        
        若无法解析 ELF，则回退为字节级简单变异以保证产出。
        """
        if not data:
            self.logger.warning("空数据，直接返回")
            return
        
        # 步骤1：解析 ELF（带缓存）
        hdr, sections = self._parse_elf(data)
        
        # 步骤2：构建变异策略列表
        strategies = self._build_mutate_strategies(data, hdr, sections)
        
        # 步骤3：调度策略生成变体
        variant_count = 0
        for variant in self._schedule_strategies(strategies):
            yield variant
            variant_count += 1
        
        # 步骤4：无有效变体时回退到基础字节变异
        if variant_count == 0:
            self.logger.debug("无有效变异策略，触发回退变异")
            yield from self._fallback_mutations(data)

    # ----------------- 解析相关方法（带缓存+结构化） -----------------
    def _parse_elf(self, data: bytes) -> Tuple[Optional[dict], List[dict]]:
        """带缓存的 ELF 解析：返回 (ELF头信息, 节表列表)"""
        # 缓存键：数据的哈希值（快速判断重复）
        data_hash = hash(data)
        if data_hash in self._parse_cache:
            return self._parse_cache[data_hash]
        
        # 解析 ELF 头和节表
        try:
            hdr = self._parse_elf_header(data)
            sections = self._parse_section_table(data, hdr) if hdr else []
        except Exception as e:
            self.logger.debug(f"ELF 解析失败: {e}")
            hdr, sections = None, []
        
        # 缓存结果（限制缓存大小，避免内存泄漏）
        if len(self._parse_cache) >= ElfConst.MAX_CACHE_SIZE:
            self._parse_cache.pop(next(iter(self._parse_cache)))
        self._parse_cache[data_hash] = (hdr, sections)
        
        return hdr, sections

    def _parse_elf_header(self, data: bytes) -> Optional[dict]:
        """结构化解析 ELF 头，返回标准化字典"""
        if not _is_elf(data) or len(data) < 16:
            self.logger.debug("非 ELF 格式或数据过短，解析失败")
            return None
        
        # 解析基础标识
        ei_class = data[4]
        ei_data = data[5]
        endian = '<' if ei_data == ElfConst.ELFDATA2LSB else '>' if ei_data == ElfConst.ELFDATA2MSB else None
        if endian is None:
            self.logger.debug("无效的字节序标识")
            return None
        
        # 解析 32 位 ELF 头
        try:
            if ei_class == ElfConst.ELFCLASS32 and len(data) >= 52:
                return {
                    'class': 32,
                    'endian': endian,
                    'e_entry': struct.unpack_from(endian + 'I', data, ElfConst.E_ENTRY_32_OFF)[0],
                    'e_phoff': struct.unpack_from(endian + 'I', data, ElfConst.E_PHOFF_32_OFF)[0],
                    'e_shoff': struct.unpack_from(endian + 'I', data, ElfConst.E_SHOFF_32_OFF)[0],
                    'e_shentsize': struct.unpack_from(endian + 'H', data, ElfConst.E_SHENTSIZE_OFF_32)[0],
                    'e_shnum': struct.unpack_from(endian + 'H', data, ElfConst.E_SHNUM_OFF_32)[0],
                    'e_shstrndx': struct.unpack_from(endian + 'H', data, ElfConst.E_SHSTRNDX_OFF_32)[0]
                }
            # 解析 64 位 ELF 头
            elif ei_class == ElfConst.ELFCLASS64 and len(data) >= 64:
                return {
                    'class': 64,
                    'endian': endian,
                    'e_entry': struct.unpack_from(endian + 'Q', data, ElfConst.E_ENTRY_64_OFF)[0],
                    'e_phoff': struct.unpack_from(endian + 'Q', data, ElfConst.E_PHOFF_64_OFF)[0],
                    'e_shoff': struct.unpack_from(endian + 'Q', data, ElfConst.E_SHOFF_64_OFF)[0],
                    'e_shentsize': struct.unpack_from(endian + 'H', data, ElfConst.E_SHENTSIZE_OFF_64)[0],
                    'e_shnum': struct.unpack_from(endian + 'H', data, ElfConst.E_SHNUM_OFF_64)[0],
                    'e_shstrndx': struct.unpack_from(endian + 'H', data, ElfConst.E_SHSTRNDX_OFF_64)[0]
                }
        except struct.error as e:
            self.logger.debug(f"ELF 头解析失败（struct 错误）: {e}")
        except IndexError as e:
            self.logger.debug(f"ELF 头解析失败（索引越界）: {e}")
        
        return None

    def _parse_section_table(self, data: bytes, hdr: dict) -> List[dict]:
        """结构化解析节表，返回标准化节信息列表"""
        sections = []
        if not hdr:
            return sections
        
        endian = hdr['endian']
        cls = hdr['class']
        shoff = hdr.get('e_shoff', 0)
        shentsize = hdr.get('e_shentsize', 0)
        shnum = hdr.get('e_shnum', 0)
        
        if shoff == 0 or shnum == 0 or shentsize == 0:
            self.logger.debug("节表偏移/数量/大小为 0，跳过解析")
            return sections
        
        # 限制解析节数量（避免性能问题）
        max_sections = min(shnum, 200)
        for i in range(max_sections):
            off = shoff + i * shentsize
            if not _check_bounds(data, off, shentsize):
                break
            
            try:
                if cls == ElfConst.ELFCLASS32:
                    sh_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
                    sh_offset = struct.unpack_from(endian + 'I', data, off + 16)[0]
                    sh_size = struct.unpack_from(endian + 'I', data, off + 20)[0]
                else:  # ELF64
                    sh_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
                    sh_offset = struct.unpack_from(endian + 'Q', data, off + 24)[0]
                    sh_size = struct.unpack_from(endian + 'Q', data, off + 32)[0]
                
                sections.append({
                    'index': i,
                    'offset': sh_offset,
                    'size': sh_size,
                    'type': sh_type
                })
            except Exception as e:
                self.logger.debug(f"解析节 {i} 失败: {e}")
                continue
        
        return sections

    def _parse_phdr_table(self, data: bytes, hdr: dict) -> List[dict]:
        """结构化解析程序头（PHDR）表，返回标准化 PHDR 列表"""
        phdrs = []
        if not hdr or hdr.get('e_phoff', 0) == 0:
            return phdrs
        
        endian = hdr['endian']
        cls = hdr['class']
        phoff = hdr['e_phoff']
        phentsize = ElfConst.PHENT_SIZE_32 if cls == ElfConst.ELFCLASS32 else ElfConst.PHENT_SIZE_64
        
        # 限制解析数量（避免性能问题）
        max_phdrs = 10
        for i in range(max_phdrs):
            ph_off = phoff + i * phentsize
            if not _check_bounds(data, ph_off, phentsize):
                break
            
            try:
                if cls == ElfConst.ELFCLASS32:
                    p_type = struct.unpack_from(endian + 'I', data, ph_off)[0]
                    p_flags = struct.unpack_from(endian + 'I', data, ph_off + 24)[0]
                else:  # ELF64
                    p_type = struct.unpack_from(endian + 'I', data, ph_off)[0]
                    p_flags = struct.unpack_from(endian + 'Q', data, ph_off + 40)[0]
                
                phdrs.append({
                    'index': i,
                    'offset': ph_off,
                    'type': p_type,
                    'flags': p_flags
                })
            except Exception as e:
                self.logger.debug(f"解析 PHDR {i} 失败: {e}")
                continue
        
        return phdrs

    # ----------------- 策略构建与调度 -----------------
    def _build_mutate_strategies(self, data: bytes, hdr: dict, sections: List[dict]) -> List[Tuple[str, Iterable[bytes]]]:
        """构建所有启用的变异策略列表"""
        strategies = []
        
        # 1. ELF 头变异
        if self.mutate_header and hdr:
            strategies.append(('header', self._mutate_header_fields(data, hdr)))
        
        # 2. 字符串表变异
        if self.mutate_strtab:
            strtabs = self._filter_sections_by_type(sections, ElfConst.SHT_STRTAB)
            for s in strtabs:
                if _check_bounds(data, s['offset'], s['size']):
                    strategies.append((f'strtab_{s["index"]}', self._mutate_string_table(data, s['offset'], s['size'])))
        
        # 3. 符号表变异
        if self.mutate_symtab:
            symtabs = self._filter_sections_by_type(sections, ElfConst.SHT_SYMTAB)
            for s in symtabs:
                if _check_bounds(data, s['offset'], s['size']):
                    strategies.append((f'symtab_{s["index"]}', self._mutate_symbol_table(data, s['offset'], s['size'], hdr)))
        
        # 4. 动态段变异
        if self.mutate_dynamic:
            dynsecs = self._filter_sections_by_type(sections, ElfConst.SHT_DYNAMIC)
            for s in dynsecs:
                if _check_bounds(data, s['offset'], s['size']):
                    strategies.append((f'dynamic_{s["index"]}', self._mutate_dynamic_section(data, s['offset'], s['size'], hdr)))
        
        # 5. 节字节级变异
        for s in sections:
            if s.get('type') == ElfConst.SHT_NOBITS:
                continue
            if not _check_bounds(data, s['offset'], s['size']) or s['size'] < ElfConst.MIN_SECTION_SIZE:
                continue
            strategies.append((f'section_{s["index"]}', self._mutate_section_bytes(data, s['offset'], s['size'])))
        
        # 6. 激进的节操作
        if self.aggressive_ops and self.strength >= 3:
            for s in sections:
                if s.get('type') == ElfConst.SHT_NOBITS:
                    continue
                if not _check_bounds(data, s['offset'], s['size']) or s['size'] < ElfConst.MIN_SECTION_SIZE:
                    continue
                strategies.append((f'aggr_{s["index"]}', self._aggressive_section_ops(data, s['offset'], s['size'])))
        
        # 7. 语义级变异
        if self.strength >= 2 and (self.mutate_rodata or self.mutate_symtab):
            strategies.append(('semantic', self._mutate_semantic_fields(data, sections)))
        
        # 8. PHDR 变异
        if self.mutate_phdr and hdr:
            strategies.append(('phdr', self._mutate_phdr_fields(data, hdr)))
        
        return strategies

    def _schedule_strategies(self, strategies: List[Tuple[str, Iterable[bytes]]]) -> Iterable[bytes]:
        """随机交错调度变异策略，避免单一策略耗尽配额"""
        if not strategies:
            return
        
        effective_max = max(1, self.max_outputs * self.strength)
        count = 0
        
        # 转换为可操作的生成器字典
        generators = {name: gen for name, gen in strategies}
        names = list(generators.keys())
        
        while count < effective_max and names:
            # 随机选择一个策略
            name = self.rng.choice(names)
            gen = generators.get(name)
            
            try:
                variant = next(gen)
                yield variant
                count += 1
            except StopIteration:
                # 策略生成器耗尽，移除
                self.logger.debug(f"策略 {name} 变体耗尽，移除")
                names.remove(name)
                generators.pop(name, None)
            except Exception as e:
                # 策略执行出错，移除并记录
                self.logger.warning(f"策略 {name} 执行失败: {e}")
                names.remove(name)
                generators.pop(name, None)

    def _filter_sections_by_type(self, sections: List[dict], sectype: int) -> List[dict]:
        """按节类型过滤节表"""
        return [s for s in sections if s.get('type') == sectype]

    # ----------------- 具体变异策略（增强版） -----------------
    def _mutate_header_fields(self, data: bytes, hdr: dict) -> Iterable[bytes]:
        """ELF 头字段变异（拆分 32/64 位逻辑）"""
        if hdr['class'] == ElfConst.ELFCLASS32:
            yield from self._mutate_header_32(data, hdr)
        elif hdr['class'] == ElfConst.ELFCLASS64:
            yield from self._mutate_header_64(data, hdr)

    def _mutate_header_32(self, data: bytes, hdr: dict) -> Iterable[bytes]:
        """32 位 ELF 头变异"""
        endian = hdr['endian']
        e_entry = hdr['e_entry']
        e_entry_off = ElfConst.E_ENTRY_32_OFF
        e_type_off = ElfConst.E_TYPE_OFF
        
        # 小幅偏移 e_entry
        deltas = [1, -1, 16, -16, 256]
        if self.strength >= 2:
            deltas += [1024, -1024]
        
        for d in deltas:
            nd = bytearray(data)
            struct.pack_into(endian + 'I', nd, e_entry_off, (e_entry + d) & ElfConst.MASK_32)
            yield bytes(nd)
        
        # 随机化 e_entry（高强度）
        if self.strength >= 2:
            for _ in range(self.strength):
                nd = bytearray(data)
                randv = self.rng.randrange(0, ElfConst.MASK_32)
                struct.pack_into(endian + 'I', nd, e_entry_off, randv)
                yield bytes(nd)
        
        # 变异 e_type
        for t in (2, 3):
            nd = bytearray(data)
            struct.pack_into(endian + 'H', nd, e_type_off, t)
            yield bytes(nd)
        
        # 变异 e_ident 字段
        yield from self._mutate_e_ident(data)

    def _mutate_header_64(self, data: bytes, hdr: dict) -> Iterable[bytes]:
        """64 位 ELF 头变异"""
        endian = hdr['endian']
        e_entry = hdr['e_entry']
        e_entry_off = ElfConst.E_ENTRY_64_OFF
        e_type_off = ElfConst.E_TYPE_OFF
        
        # 小幅偏移 e_entry
        deltas = [1, -1, 16, -16, 256]
        if self.strength >= 2:
            deltas += [1024, -1024]
        
        for d in deltas:
            nd = bytearray(data)
            struct.pack_into(endian + 'Q', nd, e_entry_off, (e_entry + d) & ElfConst.MASK_64)
            yield bytes(nd)
        
        # 随机化 e_entry（高强度）
        if self.strength >= 2:
            for _ in range(self.strength):
                nd = bytearray(data)
                randv = self.rng.randrange(0, ElfConst.MASK_64)
                struct.pack_into(endian + 'Q', nd, e_entry_off, randv)
                yield bytes(nd)
        
        # 变异 e_type
        for t in (2, 3):
            nd = bytearray(data)
            struct.pack_into(endian + 'H', nd, e_type_off, t)
            yield bytes(nd)
        
        # 变异 e_ident 字段
        yield from self._mutate_e_ident(data)

    def _mutate_e_ident(self, data: bytes) -> Iterable[bytes]:
        """变异 ELF 标识字段（e_ident）"""
        if len(data) < 16:
            return
        
        # 切换 class 字段（offset 4）
        nd = bytearray(data)
        nd[4] = ElfConst.ELFCLASS64 if nd[4] == ElfConst.ELFCLASS32 else ElfConst.ELFCLASS32
        yield bytes(nd)
        
        # 切换字节序字段（offset 5）
        nd2 = bytearray(data)
        if nd2[5] in (ElfConst.ELFDATA2LSB, ElfConst.ELFDATA2MSB):
            nd2[5] = ElfConst.ELFDATA2MSB if nd2[5] == ElfConst.ELFDATA2LSB else ElfConst.ELFDATA2LSB
            yield bytes(nd2)
        
        # 高强度时随机扰动 e_ident 其他字段
        if self.strength >= 2:
            for _ in range(self.strength):
                nd3 = bytearray(data)
                i = self.rng.randrange(1, min(15, len(nd3)-1))
                nd3[i] = (nd3[i] ^ self.rng.randrange(1, 256)) & 0xFF
                yield bytes(nd3)

    def _mutate_string_table(self, data: bytes, off: int, size: int) -> Iterable[bytes]:
        """增强版字符串表变异：替换/截断/交换/插入/重复"""
        tbl = data[off:off+size]
        strs = self._extract_null_terminated_strings(tbl)
        if not strs:
            return
        
        # 基础变异：替换/截断/交换
        yield from self._mutate_strtab_basic(strs, data, off, size)
        
        # 增强变异：插入常见符号
        yield from self._mutate_strtab_insert(strs, data, off, size)
        
        # 增强变异：重复字符串（模拟符号重复定义）
        yield from self._mutate_strtab_duplicate(strs, data, off, size)

    def _extract_null_terminated_strings(self, tbl: bytes) -> List[Tuple[int, bytes]]:
        """提取以 NULL 结尾的字符串列表"""
        strs = []
        cur = 0
        while cur < len(tbl):
            end = tbl.find(b'\x00', cur)
            if end == -1:
                break
            s = tbl[cur:end]
            if len(s) >= ElfConst.MIN_STRING_LEN:
                strs.append((cur, s))
            cur = end + 1
        return strs

    def _mutate_strtab_basic(self, strs: List[Tuple[int, bytes]], data: bytes, off: int, size: int) -> Iterable[bytes]:
        """字符串表基础变异：替换/截断/交换"""
        max_out = max(6, 6 * self.strength)
        out_count = 0
        
        for idx, s in strs:
            if out_count >= max_out:
                break
            if len(s) == 0:
                continue
            
            nd = bytearray(data)
            r = self.rng.random()
            
            # 替换为常见符号
            if r < 0.25:
                new_s = self.rng.choice(ElfConst.COMMON_SYMBOLS)
            # 反转字符串
            elif r < 0.55:
                new_s = s[::-1]
            # 截断
            elif r < 0.75:
                new_s = s[:max(1, len(s)//2)]
            # 部分替换
            else:
                new_s = s[:max(1, len(s)//2)]
            
            # 写入（保证不越界）
            write = new_s + b'\x00' * max(0, len(s) - len(new_s))
            write_len = min(len(write), len(nd) - (off + idx))
            if write_len > 0:
                nd[off + idx: off + idx + write_len] = write[:write_len]
                yield bytes(nd)
                out_count += 1
        
        # 交换两个字符串
        if len(strs) >= 2:
            a, b = self.rng.sample(strs, 2)
            nd = bytearray(data)
            sa = a[1]; sb = b[1]
            la = len(sa); lb = len(sb)
            
            # 交换并保证长度
            va = (sb[:la] + b'\x00'*max(0, la-lb))[:la]
            vb = (sa[:lb] + b'\x00'*max(0, lb-la))[:lb]
            
            nd[off + a[0]: off + a[0] + la] = va
            nd[off + b[0]: off + b[0] + lb] = vb
            yield bytes(nd)

    def _mutate_strtab_insert(self, strs: List[Tuple[int, bytes]], data: bytes, off: int, size: int) -> Iterable[bytes]:
        """插入常见符号到字符串表（保持长度）"""
        if not strs or self.strength < 2:
            return
        
        for idx, s in strs[:self.strength]:
            nd = bytearray(data)
            insert_str = self.rng.choice(ElfConst.COMMON_SYMBOLS)
            # 插入后截断，保持原长度
            new_s = insert_str[:len(s)] + b'\x00' * max(0, len(s) - len(insert_str))
            write_len = min(len(new_s), len(nd) - (off + idx))
            if write_len > 0:
                nd[off + idx: off + idx + write_len] = new_s[:write_len]
                yield bytes(nd)

    def _mutate_strtab_duplicate(self, strs: List[Tuple[int, bytes]], data: bytes, off: int, size: int) -> Iterable[bytes]:
        """重复字符串（模拟符号重复定义）"""
        if len(strs) < 2:
            return
        
        a, b = self.rng.sample(strs, 2)
        nd = bytearray(data)
        a_off = off + a[0]
        # 将 b 的字符串复制到 a 的位置（保持长度）
        b_str = b[1][:len(a[1])] + b'\x00' * max(0, len(a[1]) - len(b[1]))
        write_len = min(len(b_str), len(nd) - a_off)
        if write_len > 0:
            nd[a_off: a_off + write_len] = b_str[:write_len]
            yield bytes(nd)

    def _mutate_symbol_table(self, data: bytes, off: int, size: int, hdr: dict) -> Iterable[bytes]:
        """符号表变异：扰动 st_name/st_value/st_size 等字段"""
        endian = hdr['endian']
        cls = hdr['class']
        sym_ent_size = 16 if cls == ElfConst.ELFCLASS32 else 24
        sym_count = size // sym_ent_size
        
        if sym_count == 0:
            return
        
        # 限制变异数量（保证吞吐）
        max_sym = min(sym_count, 10 * self.strength)
        for sym_idx in range(max_sym):
            sym_off = off + sym_idx * sym_ent_size
            if not _check_bounds(data, sym_off, sym_ent_size):
                continue
            
            nd = bytearray(data)
            # 扰动 st_name（符号名索引）: st_name 在 ELF32/ELF64 中均为 uint32
            st_name_off = sym_off
            # 先做边界检查，确保能安全读写 4 字节
            if not _check_bounds(data, st_name_off, 4):
                continue
            st_name = struct.unpack_from(endian + 'I', nd, st_name_off)[0]
            delta = self.rng.choice([1, -1, 8, -8])
            struct.pack_into(endian + 'I', nd, st_name_off, (st_name + delta) & ElfConst.MASK_32)
            
            yield bytes(nd)

    def _mutate_dynamic_section(self, data: bytes, off: int, size: int, hdr: dict) -> Iterable[bytes]:
        """动态段变异：扰动 DT_TAG/DT_VAL 等字段"""
        endian = hdr['endian']
        cls = hdr['class']
        dyn_ent_size = 8 if cls == ElfConst.ELFCLASS32 else 16
        dyn_count = size // dyn_ent_size
        
        if dyn_count == 0:
            return
        
        # 常见 DT_TAG 值
        common_tags = [1, 2, 3, 5, 7, 10, 12]
        max_dyn = min(dyn_count, 5 * self.strength)
        
        for dyn_idx in range(max_dyn):
            dyn_off = off + dyn_idx * dyn_ent_size
            if not _check_bounds(data, dyn_off, dyn_ent_size):
                continue
            
            nd = bytearray(data)
            # 扰动 DT_TAG
            tag_off = dyn_off
            if cls == ElfConst.ELFCLASS32:
                tag = struct.unpack_from(endian + 'I', nd, tag_off)[0]
                new_tag = self.rng.choice(common_tags) if self.rng.random() < 0.7 else tag ^ self.rng.randint(1, 0xFF)
                struct.pack_into(endian + 'I', nd, tag_off, new_tag)
            else:
                tag = struct.unpack_from(endian + 'Q', nd, tag_off)[0]
                new_tag = self.rng.choice(common_tags) if self.rng.random() < 0.7 else tag ^ self.rng.randint(1, 0xFF)
                struct.pack_into(endian + 'Q', nd, tag_off, new_tag)
            
            yield bytes(nd)

    def _mutate_section_bytes(self, data: bytes, off: int, size: int) -> Iterable[bytes]:
        """节字节级变异：少量字节翻转/异或"""
        max_changes = max(1, min(max(8, size // 16), size))
        rounds = 1 + self.strength
        
        for _ in range(rounds):
            nd = bytearray(data)
            changes = self.rng.randrange(1, min(max_changes, size) + 1)
            
            for _ in range(changes):
                i = self.rng.randrange(off, off + size)
                if i >= len(nd):
                    continue
                nd[i] = (nd[i] ^ self.rng.randrange(1, 256)) & 0xFF
            
            yield bytes(nd)

    def _aggressive_section_ops(self, data: bytes, off: int, size: int) -> Iterable[bytes]:
        """激进的节操作：块异或/块互换/填零"""
        if size <= 8 or not _check_bounds(data, off, size):
            return
        
        block = max(ElfConst.BLOCK_SIZE_BASE, min(ElfConst.BLOCK_SIZE_MAX, size // 8))

        # 块异或 — 计算有效起始位置并避免 randrange 抛错
        max_start = off + size - block
        if max_start >= off:
            for _ in range(self.strength):
                nd = bytearray(data)
                start = self.rng.randrange(off, max_start + 1)
                end = min(start + block, len(nd))
                for i in range(start, end):
                    nd[i] = (nd[i] ^ self.rng.randrange(1, 256)) & 0xFF
                yield bytes(nd)
        
        # 块互换
        if size > 2 * block:
            max_a_start = off + size - block * 2
            if max_a_start >= off:
                nd = bytearray(data)
                a = self.rng.randrange(off, max_a_start + 1)
                b = a + block
                if a + block <= len(nd) and b + block <= len(nd):
                    tmp = nd[a:a+block]
                    nd[a:a+block] = nd[b:b+block]
                    nd[b:b+block] = tmp
                    yield bytes(nd)
        
        # 块填零
        nd = bytearray(data)
        zmax = off + max(0, size - block)
        if zmax >= off:
            zstart = self.rng.randrange(off, zmax + 1)
        else:
            zstart = off
        for i in range(zstart, min(zstart + block // 2, off + size, len(nd))):
            nd[i] = 0
        yield bytes(nd)

    def _mutate_semantic_fields(self, data: bytes, sections: List[dict]) -> Iterable[bytes]:
        """语义级变异：替换可见 ASCII 符号、注入版本后缀等"""
        if not data:
            return
        
        buf = bytearray(data)
        seen = set()
        candidates = self._extract_ascii_candidates(buf)
        max_out = max(6, 6 * self.strength)
        out_count = 0
        
        for (off, ln) in candidates:
            if out_count >= max_out or off in seen:
                continue
            seen.add(off)
            orig = bytes(buf[off:off+ln])
            nd = bytearray(buf)
            r = self.rng.random()
            
            # 替换为常见符号
            if r < 0.25:
                rep = self.rng.choice(ElfConst.COMMON_SYMBOLS)
                rep = rep[:ln] + b'\x00' * max(0, ln - len(rep))
            # 反转字符串
            elif r < 0.6 and ln >= 4:
                rep = orig[::-1]
            # 注入版本后缀
            elif r < 0.85:
                suf = b'_v' + bytes(str(self.rng.randrange(1, 10)), 'ascii')
                rep = (orig[:max(1, ln - len(suf))] + suf)[:ln]
            # 随机字节替换
            else:
                rep = bytearray(orig)
                for i in range(max(1, min(3, ln // 4))):
                    pos = self.rng.randrange(0, ln)
                    rep[pos] = (rep[pos] ^ self.rng.randrange(1, 256)) & 0xFF
                rep = bytes(rep)
            
            # 写入（保证不越界）
            write_len = min(len(rep), len(nd) - off)
            if write_len > 0:
                nd[off:off+write_len] = rep[:write_len]
                yield bytes(nd)
                out_count += 1

    def _extract_ascii_candidates(self, buf: bytearray) -> List[Tuple[int, int]]:
        """提取长度 >= MIN_STRING_LEN 的可见 ASCII 字符串"""
        candidates = []
        cur = 0
        while cur < len(buf):
            b = buf[cur]
            if 32 <= b <= 126:
                start = cur
                while cur < len(buf) and 32 <= buf[cur] <= 126:
                    cur += 1
                if cur - start >= ElfConst.MIN_STRING_LEN:
                    candidates.append((start, cur - start))
            else:
                cur += 1
        return candidates

    def _mutate_phdr_fields(self, data: bytes, hdr: dict) -> Iterable[bytes]:
        """结构化 PHDR 变异：扰动 p_type/p_flags 等字段"""
        phdrs = self._parse_phdr_table(data, hdr)
        if not phdrs:
            return
        
        # 常见 PT_TYPE 值
        common_pt_types = [ElfConst.PT_LOAD, ElfConst.PT_DYNAMIC, ElfConst.PT_INTERP, ElfConst.PT_NOTE]
        
        for phdr in phdrs[:self.strength * 2]:  # 限制变异数量
            nd = bytearray(data)
            endian = hdr['endian']
            cls = hdr['class']
            
            # 扰动 p_type
            p_type_off = phdr['offset']
            new_type = self.rng.choice(common_pt_types)
            if cls == ElfConst.ELFCLASS32:
                struct.pack_into(endian + 'I', nd, p_type_off, new_type)
            else:
                struct.pack_into(endian + 'I', nd, p_type_off, new_type)
            
            # 扰动 p_flags（权限位）
            p_flags_off = phdr['offset'] + (24 if cls == ElfConst.ELFCLASS32 else 40)
            old_flags = phdr['flags']
            new_flags = old_flags ^ self.rng.choice([1, 2, 4])  # 翻转 R/W/X 位
            if cls == ElfConst.ELFCLASS32:
                struct.pack_into(endian + 'I', nd, p_flags_off, new_flags)
            else:
                struct.pack_into(endian + 'Q', nd, p_flags_off, new_flags)
            
            yield bytes(nd)

    def _fallback_mutations(self, data: bytes) -> Iterable[bytes]:
        """回退变异：基础字节级扰动（保证产出）"""
        for _ in range(max(1, self.strength)):
            b = bytearray(data)
            i = self.rng.randrange(len(b))
            b[i] = (b[i] ^ self.rng.randrange(1, 256)) & 0xFF
            yield bytes(b)


# ======================== 测试入口 ========================
if __name__ == "__main__":
    # 生成测试用 ELF 数据（简化版）
    sample_elf = (
        ElfConst.ELF_MAGIC +
        b"\x01\x01\x01\x00" +  # ELFCLASS32 + ELFDATA2LSB + ELFVERSION
        bytes(12) +            # 预留 e_type/e_machine/e_version
        b"\x00\x00\x00\x00" +  # e_entry
        b"\x00\x00\x00\x00" +  # e_phoff
        b"\x30\x00\x00\x00" +  # e_shoff
        bytes(12) +            # 预留 e_flags/e_ehsize/e_phentsize/e_phnum
        b"\x28\x00" +          # e_shentsize
        b"\x02\x00" +          # e_shnum
        b"\x01\x00" +          # e_shstrndx
        # 节表（2 个节）
        b"\x00\x00\x00\x00" * 8 +  # 节 0（SHT_NULL）
        b"\x03\x00\x00\x00" +  # 节 1 类型（SHT_STRTAB）
        b"\x00\x00\x00\x00" +  # 节 1 标志
        b"\x40\x00\x00\x00" +  # 节 1 偏移
        b"\x20\x00\x00\x00" +  # 节 1 大小
        bytes(12)              # 预留其他字段
    )
    
    # 初始化变异器（开启 DEBUG 日志，固定强度）
    mutator = ElfMutator(
        seed=42,
        max_outputs=10,
        strength=3,
        fixed_strength=True,
        log_level=logging.DEBUG
    )
    
    # 生成变体并打印
    print(f"原始 ELF 长度: {len(sample_elf)}")
    print(f"原始 ELF 头（前 64 字节）: {sample_elf[:64].hex()}")
    print("-" * 80)
    
    variant_count = 0
    for variant in mutator.mutate(sample_elf):
        variant_count += 1
        print(f"变体 {variant_count}: 长度={len(variant)} 头（前 64 字节）={variant[:64].hex()}")
        if variant_count >= 8:
            break