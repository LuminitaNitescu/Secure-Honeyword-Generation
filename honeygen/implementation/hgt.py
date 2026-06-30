from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional
import random

from utils.embedding import EmbeddingBackend


@dataclass(frozen=True)
class TweakParams:
	p: float = 0.3
	f: float = 0.03
	q: float = 0.05
	symbols: tuple[str, ...] = (
		"!",
		"#",
		"$",
		"%",
		"&",
		"\"",
		"(",
		")",
		"*",
		"+",
		",",
		"-",
		".",
		"/",
		":",
		";",
		"<",
		"=",
		">",
		"?",
		"@",
		"[",
		"\\",
		"]",
		"^",
		"_",
		"`",
		"{",
		"|",
		"}",
		"~",
		"'",
	)


@dataclass(frozen=True)
class _PasswordRef:
    """Minimal stand-in for UserData when calling PCFGModel.generate()."""
    password: str


def _chaff_by_model(
	password: str,
	l: int,
	backend: EmbeddingBackend,
	structures: Optional[Dict[str, Any]] = None,
) -> List[str]:
	needed = l - 1
	if needed <= 0:
		return [password]

	if structures is None:
		return [password] + backend.nearest_neighbors(password, needed)

	# PCFG-aware: expand the KNN batch until we have `needed` neighbors that
	# all have known PCFG structures.  Each doubling is a strict superset since
	# FastText returns results in similarity order.
	batch = needed
	max_batch = needed * 32

	while batch <= max_batch:
		candidates = backend.nearest_neighbors(password, batch)
		valid = [c for c in candidates if c != password and c in structures]
		if len(valid) >= needed:
			return [password] + valid[:needed]
		batch *= 2

	# Best effort: return however many valid neighbors were found.
	candidates = backend.nearest_neighbors(password, max_batch)
	valid = [c for c in candidates if c != password and c in structures]
	return [password] + valid[:needed]


def _tweak_password(
	password: str,
	rng: random.Random,
	p: float,
	f: float,
	q: float,
	symbols: tuple[str, ...],
) -> str:
	replace_map: dict[str, str] = {}
	chars: List[str] = []

	for ch in password:
		if "a" <= ch <= "z":
			chars.append(ch.upper() if rng.random() <= f else ch)
			continue
		if "A" <= ch <= "Z":
			chars.append(ch.lower() if rng.random() <= p else ch)
			continue
		if "0" <= ch <= "9":
			chars.append(str(int(rng.random() * 10)) if rng.random() <= q else ch)
			continue
		if ch in symbols:
			if ch in replace_map:
				chars.append(replace_map[ch])
				continue
			if rng.random() <= p:
				replacement = symbols[int(len(symbols) * rng.random())]
				replace_map[ch] = replacement
			else:
				replace_map[ch] = ch
			chars.append(replace_map[ch])
			continue
		chars.append(ch)

	return "".join(chars)


def _tweak_variants(
	password: str,
	target_count: int,
	rng: random.Random,
	params: TweakParams,
) -> List[str]:
	if target_count <= 0:
		return []

	variants = [password]
	seen = {password}
	duplicates = 0
	p, f, q = params.p, params.f, params.q
	max_attempts = target_count * 20
	attempts = 0

	while len(variants) < target_count and attempts < max_attempts:
		attempts += 1
		candidate = _tweak_password(password, rng, p, f, q, params.symbols)
		if candidate in seen:
			duplicates += 1
			if duplicates % 4 == 0:
				p = min(1.0, p + 0.1)
				f = min(1.0, f + 0.1)
				q = min(1.0, q + 0.1)
			continue
		seen.add(candidate)
		variants.append(candidate)

	return variants


def _chaff_by_tweaking(
	honeywords: Iterable[str],
	k: int,
	l: int,
	rng: random.Random,
	params: TweakParams,
) -> List[str]:
	r = k // l
	results: List[str] = []
	seen = set()

	for base in honeywords:
		variants = _tweak_variants(base, r, rng, params)
		for variant in variants:
			if variant in seen:
				continue
			seen.add(variant)
			results.append(variant)
			if len(results) >= k:
				return results

	# Fill any gaps with extra tweaks if duplicates were heavy.
	honeywords_list = list(honeywords)
	max_attempts = k * 20
	attempts = 0
	while len(results) < k and attempts < max_attempts:
		attempts += 1
		base = honeywords_list[int(rng.random() * len(honeywords_list))]
		candidate = _tweak_password(base, rng, params.p, params.f, params.q, params.symbols)
		if candidate in seen:
			continue
		seen.add(candidate)
		results.append(candidate)

	return results


def chaffing_with_a_hybrid_model(
	password: str,
	k: int,
	l: int,
	backend: EmbeddingBackend,
	rng: random.Random,
	params: TweakParams,
) -> List[str]:
	if k <= 0 or l <= 0:
		raise ValueError("k and l must be positive.")
	if l > k:
		raise ValueError("l must be less than or equal to k.")
	if k % l != 0:
		raise ValueError("k must be divisible by l.")

	honeywords = _chaff_by_model(password, l, backend)
	return _chaff_by_tweaking(honeywords, k, l, rng, params)


def _chaff_by_pcfg(
	honeywords: Iterable[str],
	k: int,
	l: int,
	pcfg_model: Any,
	structures: Dict[str, Any],
	seed: int,
) -> List[str]:
	honeywords_list = list(honeywords)
	r = k // l
	seen: set = set()
	results: List[str] = []

	for i, base in enumerate(honeywords_list):
		if base not in structures:
			continue
		generated, _ = pcfg_model.generate(
			k=r,
			mode="honeywords",
			queries=[_PasswordRef(password=base)],
			seed=seed + i,
			structures=structures,
		)
		if not generated:
			continue
		_, hw_list = generated[0]   # [[hw, prob], ...]
		for hw, _ in hw_list:
			if hw not in seen:
				seen.add(hw)
				results.append(hw)
				if len(results) >= k:
					return results

	# Fill any shortfall by re-sampling from whichever bases still have structures.
	valid_bases = [b for b in honeywords_list if b in structures]
	attempts = 0
	max_attempts = (k - len(results)) * 20
	while len(results) < k and valid_bases and attempts < max_attempts:
		attempts += 1
		base = valid_bases[attempts % len(valid_bases)]
		generated, _ = pcfg_model.generate(
			k=1,
			mode="honeywords",
			queries=[_PasswordRef(password=base)],
			seed=seed + attempts,
			structures=structures,
		)
		if not generated:
			continue
		_, hw_list = generated[0]
		for hw, _ in hw_list:
			if hw not in seen:
				seen.add(hw)
				results.append(hw)
				break

	return results


class HoneywordGenerator:
	def __init__(
		self,
		backend: EmbeddingBackend,
		k: int,
		l: int,
		seed: int,
		tweak_params: TweakParams | None = None,
		pcfg_model: Any = None,
		pcfg_structures: Optional[Dict[str, Any]] = None,
	) -> None:
		self.backend = backend
		self.k = k
		self.l = l
		self.seed = seed
		self.rng = random.Random(seed)
		self.params = tweak_params or TweakParams()
		self.pcfg_model = pcfg_model
		self.pcfg_structures = pcfg_structures

	def generate(self, password: str) -> List[str]:
		if self.pcfg_model is not None and self.pcfg_structures is not None:
			base_words = _chaff_by_model(
				password, self.l, self.backend, structures=self.pcfg_structures
			)
			return _chaff_by_pcfg(
				base_words,
				self.k,
				self.l,
				self.pcfg_model,
				self.pcfg_structures,
				self.seed,
			)

		return chaffing_with_a_hybrid_model(
			password,
			self.k,
			self.l,
			self.backend,
			self.rng,
			self.params,
		)

	def generate_batch(self, passwords: List[str]) -> List[List[str]]:
		if self.pcfg_model is None or self.pcfg_structures is None:
			return [self.generate(pw) for pw in passwords]

		r = self.k // self.l

		all_bases: List[List[str]] = [
			_chaff_by_model(pw, self.l, self.backend, structures=self.pcfg_structures)
			for pw in passwords
		]

		flat_queries: List[_PasswordRef] = []
		provenance: List[int] = []  
		for pw_idx, bases in enumerate(all_bases):
			for base in bases:
				if base in self.pcfg_structures:
					flat_queries.append(_PasswordRef(password=base))
					provenance.append(pw_idx)

		if not flat_queries:
			return [[] for _ in passwords]

		results, _ = self.pcfg_model.generate(
			k=r,
			mode="honeywords",
			queries=flat_queries,
			seed=self.seed,
			structures=self.pcfg_structures,
		)

		pw_seen: List[set] = [set() for _ in passwords]
		pw_sweetwords: List[List[str]] = [[] for _ in passwords]

		for result, pw_idx in zip(results, provenance):
			_, hw_list = result
			seen = pw_seen[pw_idx]
			sweetwords = pw_sweetwords[pw_idx]
			if len(sweetwords) >= self.k:
				continue
			for hw, _ in hw_list:
				if hw not in seen:
					seen.add(hw)
					sweetwords.append(hw)
					if len(sweetwords) >= self.k:
						break

		return pw_sweetwords
