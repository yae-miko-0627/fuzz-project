"""轻量且高效的 ELF 专用变异器。

特性（轻量实现）：
- 使用 stdlib `struct` 做最小 ELF 头 / 节表解析（支持 ELF32/ELF64 小端/大端）。
- 变异策略：头字段微扰（e_entry/e_phoff/e_shoff/e_type 等小幅偏移）、字符串表（SHT_STRTAB）内字符串替换/截断/交换、节内字节级小幅翻转。
- 安全性：输出数量受 `max_outputs` 限制；对边界和解析失败做回退处理。解析失败时回退到简单字节级变异。

设计目标：在保持轻量和高吞吐的同时提高触发格式相关代码路径的概率。
"""

from __future__ import annotations

import struct
import random
from typing import Iterable, Optional, List, Tuple


SHT_STRTAB = 3
SHT_NOBITS = 8


def _is_elf(data: bytes) -> bool:
	return len(data) >= 4 and data[0:4] == b"\x7fELF"


class ElfMutator:
	"""ELF 专用变异器（轻量实现）。

	参数:
	  seed: 可选随机种子，用于复现。
	  max_outputs: 每次 `mutate` 产出变体的上限（防止爆发）。
	"""

	def __init__(self, seed: Optional[int] = None, max_outputs: int = 120, strength: int = 8,
			 mutate_symbols: bool = True, mutate_phdr: bool = True, mutate_rodata: bool = True) -> None:
			"""初始化变异器。

			参数:
				seed: 可选随机种子。
				max_outputs: 基准每次 `mutate` 的输出上限（会乘以 `strength`）。
				strength: 强度因子（>=1），越大产生越激进/越多变体。
			"""
			self.rng = random.Random(seed)
			self.max_outputs = max(1, int(max_outputs))
			self.strength = random.randint(1, max(1, int(strength)))
			# 语义变异控制项：允许在 ELF 内部做更高层次的语义变换
			self.mutate_symbols = bool(mutate_symbols)
			self.mutate_phdr = bool(mutate_phdr)
			self.mutate_rodata = bool(mutate_rodata)

	def mutate(self, data: bytes) -> Iterable[bytes]:
		"""对 ELF 数据产生若干变体（generator）。

		若无法解析 ELF，则回退为字节级简单变异以保证产出。
		"""
		# 尝试解析 ELF header 和节表
		try:
			hdr = self._parse_elf_header(data)
			sections = self._parse_section_table(data, hdr) if hdr else []
		except Exception:
			hdr = None
			sections = []

		count = 0
		effective_max = max(1, self.max_outputs * self.strength)
		# 汇总可用策略并交错/随机抽取，以避免某一策略耗尽全部配额
		strategies = []
		# header
		if hdr:
			strategies.append(('header', self._mutate_header_fields(data, hdr)))

		# string tables
		if sections:
			strtabs = [s for s in sections if s.get('type') == SHT_STRTAB and s.get('size', 0) > 4]
			for s in strtabs:
				off = s['offset']; size = s['size']
				strategies.append((f'strtab_{s["index"]}', self._mutate_string_table(data, off, size)))

		# section-level byte mutations
		for s in sections:
			if s.get('type') == SHT_NOBITS:
				continue
			off = s.get('offset', 0)
			size = s.get('size', 0)
			if size <= 0 or off + size > len(data):
				continue
			strategies.append((f'section_{s.get("index")}', self._mutate_section_bytes(data, off, size)))

		# aggressive section ops when strength high
		if self.strength >= 3:
			for s2 in sections:
				if s2.get('type') == SHT_NOBITS:
					continue
				off2 = s2.get('offset', 0)
				size2 = s2.get('size', 0)
				if size2 <= 0 or off2 + size2 > len(data):
					continue
				strategies.append((f'aggr_{s2.get("index")}', self._aggressive_section_ops(data, off2, size2)))

		# semantic and phdr
		if hdr and self.strength >= 2:
			if self.mutate_rodata or self.mutate_symbols:
				strategies.append(('semantic', self._mutate_semantic_fields(data, sections)))
			if self.mutate_phdr:
				strategies.append(('phdr', self._mutate_phdr_fields(data, hdr)))

		# 若没有策略，回退到后备
		if not strategies:
			yield from self._fallback_mutations(data)
			return

		# 把策略列表转换为可变列表并维护对应的 generators
		generators = {name: gen for name, gen in strategies}
		names = list(generators.keys())

		# 随机交错抽取生成变体
		while count < effective_max and names:
			name = self.rng.choice(names)
			gen = generators.get(name)
			try:
				out = next(gen)
			except StopIteration:
				# 该生成器耗尽，移除
				names.remove(name)
				generators.pop(name, None)
				continue
			except Exception:
				# 生成器出错则移除并继续
				names.remove(name)
				generators.pop(name, None)
				continue
			# 成功产生变体
			yield out
			count += 1


		# 若什么都没生成，则返回一个简单的字节扰动
		if count == 0:
			yield from self._fallback_mutations(data)

	# ----------------- 解析与变异助手 -----------------
	def _parse_elf_header(self, data: bytes) -> Optional[dict]:
		if not _is_elf(data) or len(data) < 16:
			return None
		ei_class = data[4]
		ei_data = data[5]
		if ei_data == 1:
			endian = '<'
		elif ei_data == 2:
			endian = '>'
		else:
			return None

		try:
			if ei_class == 1 and len(data) >= 52:  # ELF32
				e_entry = struct.unpack_from(endian + 'I', data, 24)[0]
				e_phoff = struct.unpack_from(endian + 'I', data, 28)[0]
				e_shoff = struct.unpack_from(endian + 'I', data, 32)[0]
				e_shentsize = struct.unpack_from(endian + 'H', data, 46)[0]
				e_shnum = struct.unpack_from(endian + 'H', data, 48)[0]
				e_shstrndx = struct.unpack_from(endian + 'H', data, 50)[0]
				return {'class': 32, 'endian': endian, 'e_entry': e_entry, 'e_phoff': e_phoff, 'e_shoff': e_shoff, 'e_shentsize': e_shentsize, 'e_shnum': e_shnum, 'e_shstrndx': e_shstrndx}
			elif ei_class == 2 and len(data) >= 64:  # ELF64
				e_entry = struct.unpack_from(endian + 'Q', data, 24)[0]
				e_phoff = struct.unpack_from(endian + 'Q', data, 32)[0]
				e_shoff = struct.unpack_from(endian + 'Q', data, 40)[0]
				e_shentsize = struct.unpack_from(endian + 'H', data, 58)[0]
				e_shnum = struct.unpack_from(endian + 'H', data, 60)[0]
				e_shstrndx = struct.unpack_from(endian + 'H', data, 62)[0]
				return {'class': 64, 'endian': endian, 'e_entry': e_entry, 'e_phoff': e_phoff, 'e_shoff': e_shoff, 'e_shentsize': e_shentsize, 'e_shnum': e_shnum, 'e_shstrndx': e_shstrndx}
		except Exception:
			return None
		return None

	def _parse_section_table(self, data: bytes, hdr: dict) -> List[dict]:
		"""返回节表列表：每项包含 offset,size,type,index。"""
		out = []
		if not hdr:
			return out
		endian = hdr['endian']
		ei_class = hdr['class']
		shoff = hdr.get('e_shoff', 0)
		shentsize = hdr.get('e_shentsize', 0)
		shnum = hdr.get('e_shnum', 0)
		if shoff == 0 or shnum == 0:
			return out
		for i in range(min(shnum, 200)):
			off = shoff + i * shentsize
			if off + shentsize > len(data):
				break
			if ei_class == 32:
				sh_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
				sh_offset = struct.unpack_from(endian + 'I', data, off + 16)[0]
				sh_size = struct.unpack_from(endian + 'I', data, off + 20)[0]
			else:
				sh_type = struct.unpack_from(endian + 'I', data, off + 4)[0]
				sh_offset = struct.unpack_from(endian + 'Q', data, off + 24)[0]
				sh_size = struct.unpack_from(endian + 'Q', data, off + 32)[0]
			out.append({'index': i, 'offset': sh_offset, 'size': sh_size, 'type': sh_type})
		return out

	# ----------------- 具体变异策略 -----------------
	def _mutate_header_fields(self, data: bytes, hdr: dict) -> Iterable[bytes]:
		"""对 e_entry/e_phoff/e_shoff/e_type 等做小幅扰动并产生变体。"""
		endian = hdr['endian']
		cls = hdr['class']
		try:
			if cls == 32 and len(data) >= 52:
				e_entry_off = 24
				e_type_off = 16
				e_entry = struct.unpack_from(endian + 'I', data, e_entry_off)[0]
				# 基础小幅偏移；strength越高允许更大偏移与更多随机扰动
				deltas = [1, -1, 16, -16, 256]
				if self.strength >= 2:
					deltas += [1024, -1024]
				for d in deltas:
					nd = bytearray(data)
					struct.pack_into(endian + 'I', nd, e_entry_off, (e_entry + d) & 0xFFFFFFFF)
					yield bytes(nd)
				# 随机化写入（增加触发机会）
				if self.strength >= 2:
					for _ in range(self.strength):
						nd = bytearray(data)
						randv = self.rng.randrange(0, 0xFFFFFFFF)
						struct.pack_into(endian + 'I', nd, e_entry_off, randv)
						yield bytes(nd)
				for t in (2, 3):
					nd = bytearray(data)
					struct.pack_into(endian + 'H', nd, e_type_off, t)
					yield bytes(nd)
			elif cls == 64 and len(data) >= 64:
				e_entry_off = 24
				e_type_off = 16
				e_entry = struct.unpack_from(endian + 'Q', data, e_entry_off)[0]
				deltas = [1, -1, 16, -16, 256]
				if self.strength >= 2:
					deltas += [1024, -1024]
				for d in deltas:
					nd = bytearray(data)
					struct.pack_into(endian + 'Q', nd, e_entry_off, (e_entry + d) & 0xFFFFFFFFFFFFFFFF)
					yield bytes(nd)
				# 随机化写入（64-bit）
				if self.strength >= 2:
					for _ in range(self.strength):
						nd = bytearray(data)
						randv = self.rng.randrange(0, 0xFFFFFFFFFFFFFFFF)
						struct.pack_into(endian + 'Q', nd, e_entry_off, randv)
						yield bytes(nd)
				for t in (2, 3):
					nd = bytearray(data)
					struct.pack_into(endian + 'H', nd, e_type_off, t)
					yield bytes(nd)
			# 也对 e_ident 的部分字节做少量可见变异，便于 demo 观察
			try:
				nd = bytearray(data)
				# 切换 class 字段（offset 4）在 1/2 之间
				if len(nd) > 5:
					nd[4] = 2 if nd[4] == 1 else 1
					yield bytes(nd)
				nd2 = bytearray(data)
				# 切换 data 字段（offset 5）在 little/big 端表示之间
				if len(nd2) > 6:
					nd2[5] = 2 if nd2[5] == 1 else 1
					yield bytes(nd2)
				# strength 较高时尝试更多 e_ident 的扰动
				if self.strength >= 2:
					for _ in range(self.strength):
						nd3 = bytearray(data)
						i = self.rng.randrange(1, min(15, len(nd3)-1))
						nd3[i] = (nd3[i] ^ self.rng.randrange(1, 256)) & 0xFF
						yield bytes(nd3)
			except Exception:
				pass
		except Exception:
			return

	def _mutate_string_table(self, data: bytes, off: int, size: int) -> Iterable[bytes]:
		"""对字符串表做轻量替换/截断/交换变异，保持总体长度不大幅变化。"""
		if off + size > len(data) or size < 4:
			return
		tbl = data[off:off+size]
		strs: List[Tuple[int, bytes]] = []
		cur = 0
		while cur < len(tbl):
			end = tbl.find(b'\x00', cur)
			if end == -1:
				break
			s = tbl[cur:end]
			strs.append((cur, s))
			cur = end + 1

		common = [b'main', b'_start', b'init', b'malloc', b'free']
		out_count = 0
		max_out = max(6, 6 * self.strength)
		for idx, s in strs:
			if out_count >= max_out:
				break
			if len(s) == 0:
				continue
			nd = bytearray(data)
			new_s = s
			r = self.rng.random()
			if r < 0.25:
				new_s = self.rng.choice(common)
			elif r < 0.55:
				new_s = s[::-1]
			elif r < 0.75:
				# 更激进的截断或随机字节替换
				if self.strength >= 2:
					new_s = bytes([self.rng.randrange(97, 123) for _ in range(max(1, len(s)//2))])
				else:
					new_s = s[:max(1, len(s)//2)]
			else:
				new_s = s[:max(1, len(s)//2)]
			write = new_s + b'\x00' * max(0, len(s) - len(new_s))
			nd[off + idx: off + idx + len(write)] = write
			out_count += 1
			yield bytes(nd)

		if len(strs) >= 2:
			a,b = self.rng.sample(strs, 2)
			nd = bytearray(data)
			sa = a[1]; sb = b[1]
			la = len(sa); lb = len(sb)
			va = (sb[:la] + b'\x00'*max(0, la-lb))[:la]
			vb = (sa[:lb] + b'\x00'*max(0, lb-la))[:lb]
			nd[off + a[0]: off + a[0] + la] = va
			nd[off + b[0]: off + b[0] + lb] = vb
			yield bytes(nd)

		# strength >=2 时再做一次更激进的替换尝试
		if self.strength >= 2 and len(strs) >= 1:
			idx, s = self.rng.choice(strs)
			nd = bytearray(data)
			new_s = b''.join(self.rng.choice([b'init', b'main', b'func', b'run', b'cfg']) for _ in range(1 + self.strength//2))
			write = new_s + b'\x00' * max(0, len(s) - len(new_s))
			nd[off + idx: off + idx + len(write)] = write
			yield bytes(nd)

	def _mutate_section_bytes(self, data: bytes, off: int, size: int) -> Iterable[bytes]:
		"""在节的 payload 中进行少量字节翻转或随机异或。"""
		if size <= 0 or off + size > len(data):
			return
		# 根据 strength 增加每个节变异的强度与次数
		max_changes = max(1, min(max(8, size // 16), size))
		rounds = 1 + self.strength
		for _ in range(rounds):
			nd = bytearray(data)
			changes = self.rng.randrange(1, min(max_changes, size) + 1)
			for _c in range(changes):
				i = self.rng.randrange(off, off + size)
				nd[i] = (nd[i] ^ self.rng.randrange(1, 256)) & 0xFF
			yield bytes(nd)

	def _fallback_mutations(self, data: bytes) -> Iterable[bytes]:
		if not data:
			return
		# 产生多种后备变体，数量由 strength 决定
		for _ in range(max(1, self.strength)):
			b = bytearray(data)
			i = self.rng.randrange(len(b))
			b[i] = (b[i] ^ self.rng.randrange(1, 256)) & 0xFF
			yield bytes(b)

	def _aggressive_section_ops(self, data: bytes, off: int, size: int) -> Iterable[bytes]:
		"""更激进的节内操作：块异或、块互换、整块填零等，不改变文件长度以保持解析稳定性。"""
		if size <= 8 or off + size > len(data):
			return
		nd = bytearray(data)
		block = max(4, min(64, size // 8))
		for _ in range(self.strength):
			nd = bytearray(data)
			start = self.rng.randrange(off, off + size - block)
			for i in range(start, start + block):
				nd[i] = (nd[i] ^ self.rng.randrange(1, 256)) & 0xFF
			yield bytes(nd)
		if size >= 2*block:
			nd = bytearray(data)
			a = self.rng.randrange(off, off + size - block*2)
			b = a + block
			tmp = nd[a:a+block]
			dn = nd
			dn[a:a+block] = dn[b:b+block]
			dn[b:b+block] = tmp
			yield bytes(dn)
		nd = bytearray(data)
		zstart = self.rng.randrange(off, off + max(1, size - block))
		for i in range(zstart, min(zstart + block//2, off + size)):
			nd[i] = 0
		yield bytes(nd)



# ----------------- 语义级与 PHDR 级别的轻量变异 -----------------

	def _mutate_semantic_fields(self, data: bytes, sections: List[dict]) -> Iterable[bytes]:
		"""在 ELF 数据内部进行轻量语义级变换：
		- 在 rodata / 字符串表中识别可见 ASCII 符号并替换为常见符号/版本化名称
		- 在整个文件中寻找短 ascii 标识符并进行替换以扩大触发空间
		此方法故意保持简单和安全：不修改文件长度，只替换字节序列。"""
		if not data:
			return
		buf = bytearray(data)
		seen = set()
		# 扫描整个文件，寻找长度 >=3 的可见 ASCII 字符串
		min_len = 3
		candidates = []
		cur = 0
		while cur < len(buf):
			b = buf[cur]
			if 32 <= b <= 126:
				start = cur
				while cur < len(buf) and 32 <= buf[cur] <= 126:
					cur += 1
				if cur - start >= min_len:
					candidates.append((start, cur - start))
			else:
				cur += 1

		common_names = [b'main', b'_start', b'init', b'run', b'cfg', b'init_module', b'do_action', b'parse', b'handle']
		out_count = 0
		max_out = max(6, 6 * self.strength)
		for (off, ln) in candidates:
			if out_count >= max_out:
				break
			# 避免重复处理同一偏移
			if off in seen:
				continue
			seen.add(off)
			orig = bytes(buf[off:off+ln])
			r = self.rng.random()
			nd = bytearray(buf)
			if r < 0.25:
				# 替换为常见函数名
				rep = self.rng.choice(common_names)
				nd[off:off+len(rep)] = rep + b'\x00' * max(0, ln - len(rep))
				yield bytes(nd)
				out_count += 1
			elif r < 0.6 and ln >= 4:
				# 部分截断或反转
				rep = orig[::-1]
				nd[off:off+ln] = rep
				yield bytes(nd)
				out_count += 1
			elif r < 0.85:
				# 注入版本后缀或者随机数字以模拟不同符号
				suf = b'_v' + bytes(str(self.rng.randrange(1, 10)), 'ascii')
				rep = (orig[:max(1, ln - len(suf))] + suf)[:ln]
				nd[off:off+ln] = rep
				yield bytes(nd)
				out_count += 1
			else:
				# 小范围随机字节替换以模拟拼写错误/别名
				for i in range(max(1, min(3, ln // 4))):
					i = off + self.rng.randrange(0, ln)
					nd[i] = (nd[i] ^ self.rng.randrange(1, 256)) & 0xFF
				yield bytes(nd)
				out_count += 1

		# 额外：对字符串表中的 symbol-like 名称做更有针对性的替换
		# 已有的 _mutate_string_table 会处理 SHT_STRTAB 一部分，这里作为补充覆盖全文件可见字符串
		return

	def _mutate_phdr_fields(self, data: bytes, hdr: dict) -> Iterable[bytes]:
		"""对 program header 区域做轻量的字节级扰动（不改变文件长度），以尝试影响加载/布局相关的行为。"""
		if not hdr:
			return
		phoff = hdr.get('e_phoff', 0)
		if not phoff or phoff <= 0 or phoff >= len(data):
			return
		# 以少量随机扰动尝试生成几个变体
		variants = max(1, min(4, self.strength))
		for _ in range(variants):
			nd = bytearray(data)
			# 在 phoff 附近做一些随机小幅翻转/异或
			off = phoff + self.rng.randrange(0, min(64, max(1, len(data) - phoff)))
			nd[off] = (nd[off] ^ self.rng.randrange(1, 256)) & 0xFF
			# 额外在 phoff+8/16 做小扰动以尝试影响 flags/offset 字段
			for a in (8, 16):
				p = phoff + a
				if 0 <= p < len(nd):
					nd[p] = (nd[p] ^ self.rng.randrange(1, 256)) & 0xFF
			yield bytes(nd)
		return


if __name__ == "__main__":
	sample = b"\x7fELF" + b"\x01\x01\x01\x00" + bytes(60)
	m = ElfMutator(seed=42, max_outputs=10)
	print("原始长度:", len(sample))
	k = 0
	for v in m.mutate(sample):
		k += 1
		# 打印前 40 字节，便于观察 header 相关字段的变更
		print(f"变体 {k}: 长度={len(v)} head={v[:40].hex()}")
		if k >= 8:
			break

