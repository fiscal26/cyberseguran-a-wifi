"""Geradores determinísticos e limitados em memória para o laboratório."""

from itertools import islice
from typing import Iterable, Iterator

DEFAULT_SUFFIXES = ("", "123", "123!", "!", "2026", "2026!")
LEET = bytes.maketrans(b"aeiostAEIOST", b"431057431057")


def variations(words: Iterable[bytes], suffixes=DEFAULT_SUFFIXES) -> Iterator[bytes]:
    for word in words:
        # Deduplicação por palavra mantém a memória limitada em listas grandes.
        seen = set()
        for base in (word, word.lower(), word.capitalize(), word.upper(), word.translate(LEET)):
            for suffix in suffixes:
                candidate = base + suffix.encode("ascii")
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def mask_space(charset: str, minimum: int, maximum: int, prefix="", suffix="") -> int:
    values = charset + prefix + suffix
    if any(ord(c) < 32 or ord(c) > 126 for c in values):
        raise ValueError("alfabeto, prefixo e sufixo devem usar ASCII imprimível")
    if not charset or len(set(charset)) != len(charset):
        raise ValueError("o alfabeto deve ser não vazio e não conter caracteres repetidos")
    if not 1 <= minimum <= maximum <= 63:
        raise ValueError("a parte variável deve ter de 1 a 63 caracteres, com mínimo <= máximo")
    fixed = len(prefix) + len(suffix)
    if fixed + minimum < 8 or fixed + maximum > 63:
        raise ValueError("o comprimento total de todas as combinações deve ficar entre 8 e 63")
    return sum(len(charset) ** length for length in range(minimum, maximum + 1))


def combinations(charset: str, minimum: int, maximum: int, prefix="", suffix="", start=0):
    total = mask_space(charset, minimum, maximum, prefix, suffix)
    if not 0 <= start <= total:
        raise ValueError("posição de retomada fora do espaço de busca")
    alphabet = charset.encode("ascii")
    for length in range(minimum, maximum + 1):
        size = len(alphabet) ** length
        if start >= size:
            start -= size
            continue
        for number in range(start, size):
            digits = bytearray(length)
            for index in range(length - 1, -1, -1):
                number, digit = divmod(number, len(alphabet))
                digits[index] = alphabet[digit]
            yield prefix.encode("ascii") + digits + suffix.encode("ascii")
        start = 0


def skip_candidates(candidates: Iterable[bytes], start: int):
    # Dicionários são relidos na retomada, sem repetir os cálculos PBKDF2.
    return islice(candidates, start, None)
