from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List
import random

from embedding import EmbeddingBackend


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


def _chaff_by_model(password: str, l: int, backend: EmbeddingBackend) -> List[str]:
	honeywords = [password]
	if l <= 1:
		return honeywords
	neighbors = backend.nearest_neighbors(password, l - 1)
	honeywords.extend(neighbors)
	return honeywords


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


class HoneywordGenerator:
	def __init__(
		self,
		backend: EmbeddingBackend,
		k: int,
		l: int,
		seed: int,
		tweak_params: TweakParams | None = None,
	) -> None:
		self.backend = backend
		self.k = k
		self.l = l
		self.rng = random.Random(seed)
		self.params = tweak_params or TweakParams()

	def generate(self, password: str) -> List[str]:
		return chaffing_with_a_hybrid_model(
			password,
			self.k,
			self.l,
			self.backend,
			self.rng,
			self.params,
		)
