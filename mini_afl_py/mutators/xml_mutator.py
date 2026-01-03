"""改进版 XML 变异器（向 AFL++ 的专用结构变异借鉴）。

新增内容：
- 多种结构化变异操作：重命名标签、复制/移动子树、交换兄弟节点、增删属性与元素、数值文本变异、注释插入等。
- 操作权重支持：可更容易调优变异分布。
- 保留 XML 声明（若存在）并更鲁棒的回退机制：若结构化变异导致不可解析的结果，则回退到上一次有效状态或使用字节级回退。

设计原则：依然以标准库为主（`xml.etree.ElementTree`），保持 API 兼容 `mutate(data: bytes, num_mutations: int) -> bytes`。
"""

from __future__ import annotations

import random
import re
import xml.etree.ElementTree as ET
from typing import Optional, List, Tuple


class XMLMutator:
	"""更完整的 XML 变异器实现。

	参数:
	- seed: 随机种子，便于可复现测试
	- op_weights: 可选的操作权重列表，按顺序对应内部操作集合
	"""

	def __init__(
		self,
		seed: Optional[int] = None,
		op_weights: Optional[List[float]] = None,
		safe_mode: bool = True,
		max_size_factor: float = 4.0,
		max_extra_depth: int = 3,
	) -> None:
		self._rng = random.Random(seed)
		self.safe_mode = bool(safe_mode)
		# 限制：变异后最大大小相对于原始大小的倍数
		self.max_size_factor = float(max_size_factor)
		# 限制：允许增加的最大深度
		self.max_extra_depth = int(max_extra_depth)
		# 定义可用操作（按优先级或重要性排序）
		self._ops = [
			self._rename_tag,
			self._insert_element,
			self._delete_element,
			self._duplicate_element,
			self._move_subtree,
			self._swap_siblings,
			self._tweak_attribute,
			self._delete_attribute,
			self._mutate_numeric_text,
			self._tweak_text,
			self._insert_comment,
			self._replace_entity,
		]
		# 默认权重（可调），长度与 self._ops 保持一致
		if op_weights is None:
			self._weights = [1.0] * len(self._ops)
		else:
			w = list(op_weights)
			if len(w) < len(self._ops):
				w.extend([1.0] * (len(self._ops) - len(w)))
			self._weights = w[: len(self._ops)]

		# 当 safe_mode 启用时，降低破坏性操作（删除/移动/重复等）的权重，增加温和变异的概率
		if self.safe_mode:
			# 索引对应 self._ops 列表
			# 破坏性 ops: _delete_element (index 2), _duplicate_element (3), _move_subtree (4), _swap_siblings (5)
			for i in (2, 3, 4, 5):
				if i < len(self._weights):
					self._weights[i] = max(0.05, self._weights[i] * 0.15)
			# 提升温和操作的权重
			for name_idx in (6, 9, 11):
				if name_idx < len(self._weights):
					self._weights[name_idx] = self._weights[name_idx] * 2.0


	# ---------- 公共 API ----------
	def mutate(self, data: bytes, num_mutations: int = 1) -> bytes:
		# 尝试保留 XML 声明（例如 <?xml version='1.0' encoding='utf-8'?>）
		prolog, body = self._split_prolog(data)

		try:
			# 若 body 为空或仅空白，初始化最小根节点以避免返回空输出
			if not body or body.strip() == b"":
				root = ET.Element('root')
			else:
				root = ET.fromstring(body)
		except Exception:
			return self._fallback_mutation(data)

		# 做多次结构化变异；在每次变异后尝试序列化以保证仍然有效
		original_size = len(prolog) + len(body)
		original_depth = self._max_depth(root)

		for _ in range(num_mutations):
			op = self._choose_op()
			prev_tree_bytes = ET.tostring(root, encoding="utf-8")
			prev_root = ET.fromstring(prev_tree_bytes)
			try:
				op(root)
				# 验证能否序列化并再次解析
				cand = self._serialize_with_prolog(prolog, root)
				# 检查大小和深度限制以减少对目标触发崩溃的高风险输入
				if len(cand) > max(1, int(original_size * self.max_size_factor)):
					# 回退
					root = prev_root
					continue
				try:
					cand_body = self._strip_prolog(cand)
					tmp_root = ET.fromstring(cand_body)
					# 检查深度限值
					new_depth = self._max_depth(tmp_root)
					if new_depth > original_depth + self.max_extra_depth:
						root = prev_root
						continue
				except Exception:
					# 回退到上次有效状态
					root = prev_root
			except Exception:
				# 单次操作失败则回退
				root = prev_root

		return self._serialize_with_prolog(prolog, root)

	# ---------- 辅助与回退 ----------
	def _split_prolog(self, data: bytes) -> Tuple[bytes, bytes]:
		s = data.decode("utf-8", errors="replace")
		m = re.match(r"^(\s*<\?xml[^>]*>\s*)(.*)$", s, flags=re.S)
		if m:
			return m.group(1).encode("utf-8"), m.group(2).encode("utf-8")
		return b"", data

	def _strip_prolog(self, data: bytes) -> bytes:
		s = data.decode("utf-8", errors="replace")
		return re.sub(r"^\s*<\?xml[^>]*>\s*", "", s, flags=re.S).encode("utf-8")

	def _serialize_with_prolog(self, prolog: bytes, root: ET.Element) -> bytes:
		body = ET.tostring(root, encoding="utf-8")
		if prolog:
			return prolog + b"\n" + body
		return body

	def _fallback_mutation(self, data: bytes) -> bytes:
		# 更强的字节级回退：随机替换/删除/插入
		b = bytearray(data)
		if not b:
			return data
		r = self._rng.random()
		if r < 0.5:
			i = self._rng.randrange(len(b))
			b[i] = (b[i] + self._rng.randrange(1, 255)) & 0xFF
		elif r < 0.8:
			# 删除一个字节
			i = self._rng.randrange(len(b))
			del b[i]
		else:
			# 插入
			i = self._rng.randrange(len(b) + 1)
			b.insert(i, self._rng.randrange(1, 255))
		return bytes(b)

	def _choose_op(self):
		# 按权重随机选择操作
		total = sum(self._weights)
		if total <= 0:
			return self._rng.choice(self._ops)
		r = self._rng.random() * total
		acc = 0.0
		for op, w in zip(self._ops, self._weights):
			acc += w
			if r <= acc:
				return op
		return self._ops[-1]

	def _max_depth(self, root: ET.Element) -> int:
		# 计算树的最大深度
		def depth(node: ET.Element) -> int:
			if not list(node):
				return 1
			return 1 + max(depth(c) for c in list(node))

		try:
			return depth(root)
		except Exception:
			return 0

	# ---------- 基本工具 ----------
	def _random_element(self, root: ET.Element) -> ET.Element:
		elems = list(root.iter())
		return self._rng.choice(elems) if elems else root

	def _find_parent(self, root: ET.Element, child: ET.Element) -> Optional[ET.Element]:
		stack: List[ET.Element] = [root]
		while stack:
			node = stack.pop()
			for c in list(node):
				if c is child:
					return node
				stack.append(c)
		return None

	def _all_elements(self, root: ET.Element) -> List[ET.Element]:
		return list(root.iter())

	# ---------- 结构化变异操作 ----------
	def _insert_element(self, root: ET.Element) -> None:
		parent = self._random_element(root)
		tag = "x" + str(self._rng.randrange(10000))
		new = ET.Element(tag)
		if self._rng.random() < 0.7:
			new.text = self._small_random_text(12)
		children = list(parent)
		idx = self._rng.randrange(len(children) + 1) if children else 0
		if children:
			parent.insert(idx, new)
		else:
			parent.append(new)

	def _delete_element(self, root: ET.Element) -> None:
		elems = [e for e in self._all_elements(root) if e is not root]
		if not elems:
			return
		target = self._rng.choice(elems)
		parent = self._find_parent(root, target)
		if parent is not None:
			parent.remove(target)

	def _duplicate_element(self, root: ET.Element) -> None:
		elems = self._all_elements(root)
		if not elems:
			return
		src = self._rng.choice(elems)
		clone = ET.fromstring(ET.tostring(src, encoding="utf-8"))
		parent = self._find_parent(root, src)
		if parent is None:
			# 作为子节点追加到根
			root.append(clone)
		else:
			idx = list(parent).index(src)
			parent.insert(idx + 1, clone)

	def _move_subtree(self, root: ET.Element) -> None:
		elems = [e for e in self._all_elements(root) if e is not root]
		if len(elems) < 2:
			return
		src = self._rng.choice(elems)
		dst = self._rng.choice(elems)
		if src is dst:
			return
		# 移除 src
		src_parent = self._find_parent(root, src)
		if src_parent is None:
			return
		# 插入到 dst 的子节点
		try:
			src_parent.remove(src)
			dst.append(src)
		except Exception:
			return

	def _swap_siblings(self, root: ET.Element) -> None:
		elems = [e for e in self._all_elements(root) if list(self._find_parent(root, e) or [])]
		if len(elems) < 2:
			return
		a = self._rng.choice(elems)
		pa = self._find_parent(root, a)
		if pa is None:
			return
		siblings = list(pa)
		if len(siblings) < 2:
			return
		i = siblings.index(a)
		j = self._rng.randrange(len(siblings))
		if i == j:
			return
		siblings[i], siblings[j] = siblings[j], siblings[i]
		# 重新排列
		for k, c in enumerate(siblings):
			pa.remove(c)
		for c in siblings:
			pa.append(c)

	def _rename_tag(self, root: ET.Element) -> None:
		el = self._random_element(root)
		if el is root and len(list(root)) == 0:
			# 若是单节点且无子节点，跳过
			return
		new_tag = el.tag + self._small_random_text(3)
		# 保留 namespace 前缀（若存在）
		el.tag = new_tag

	# ---------- 属性 / 文本变异 ----------
	def _tweak_attribute(self, root: ET.Element) -> None:
		el = self._random_element(root)
		if el.attrib:
			key = self._rng.choice(list(el.attrib.keys()))
			val = el.attrib.get(key, "")
			el.attrib[key] = self._small_mutation_string(val)
		else:
			name = "a" + str(self._rng.randrange(1000))
			el.attrib[name] = self._small_random_text(6)

	def _delete_attribute(self, root: ET.Element) -> None:
		el = self._random_element(root)
		if not el.attrib:
			return
		key = self._rng.choice(list(el.attrib.keys()))
		del el.attrib[key]

	def _mutate_numeric_text(self, root: ET.Element) -> None:
		# 在文本中寻找数字并进行小幅算术变化
		els = [e for e in self._all_elements(root) if e.text and re.search(r"\d+", e.text)]
		if not els:
			return
		el = self._rng.choice(els)
		def repl(m):
			v = int(m.group(0))
			delta = self._rng.randint(-10, 10)
			return str(max(0, v + delta))
		el.text = re.sub(r"\d+", repl, el.text, count=1)

	def _tweak_text(self, root: ET.Element) -> None:
		el = self._random_element(root)
		base = el.text or ""
		el.text = self._small_mutation_string(base)

	def _insert_comment(self, root: ET.Element) -> None:
		# ElementTree 没有直接的 Comment 插入 API 的便捷方法，使用 ET.Comment
		parent = self._random_element(root)
		comment = ET.Comment(self._small_random_text(12))
		parent.append(comment)

	def _replace_entity(self, root: ET.Element) -> None:
		replacements = [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"')]
		old, new = self._rng.choice(replacements)
		for el in root.iter():
			if el.text and old in el.text:
				el.text = el.text.replace(old, new, 1)

	# ---------- 随机文本与字符串变异 ----------
	def _small_random_text(self, max_len: int = 8) -> str:
		length = self._rng.randrange(1, max_len + 1)
		alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
		return ''.join(self._rng.choice(alphabet) for _ in range(length))

	def _small_mutation_string(self, s: str) -> str:
		if not s:
			return self._small_random_text()
		r = self._rng.random()
		if r < 0.35:
			i = self._rng.randrange(len(s))
			c = self._rng.choice('abcdxyz0123')
			return s[:i] + c + s[i+1:]
		elif r < 0.65:
			i = self._rng.randrange(len(s) + 1)
			return s[:i] + self._small_random_text(3) + s[i:]
		else:
			if self._rng.random() < 0.5:
				return s[: max(1, len(s) // 2)]
			else:
				return s + self._small_random_text(3)


if __name__ == "__main__":
	example = b"""<?xml version='1.0'?>\n<root><item id="1">hello &amp; world</item><group><sub>text</sub></group></root>"""
	m = XMLMutator(seed=42)
	print("Original:\n", example.decode('utf-8'))
	for i in range(6):
		out = m.mutate(example, num_mutations=3)
		print(f"\nMutation {i+1}:\n", out.decode('utf-8'))

# 兼容导入别名（有的代码期望 XmlMutator）
XmlMutator = XMLMutator

