"""Extração de strings imprimíveis de binários e dumps de memória."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Caracteres imprimíveis ASCII: 0x20 (espaço) a 0x7E (~) inclusive.
_PRINTABLE = bytes(range(0x20, 0x7F))


@dataclass(frozen=True)
class ExtractedString:
    """Uma string imprimível extraída de um binário.

    Attributes:
        value: Texto da string.
        offset: Offset em bytes onde a string inicia no dado original.
    """

    value: str
    offset: int


def extract_strings(data: bytes, min_len: int = 4) -> list[ExtractedString]:
    """Extrai sequências de caracteres imprimíveis ASCII de ``data``.

    Percorre os bytes uma única vez, acumulando sequências de bytes
    imprimíveis. Ao encontrar um byte não-imprimível (ou ao final), a
    sequência acumulada é emitida se seu tamanho for >= ``min_len``.

    A função é determinística: mesma entrada produz mesma saída, na mesma
    ordem de aparição.

    Args:
        data: Conteúdo binário a analisar.
        min_len: Tamanho mínimo de caracteres para emitir uma string.

    Returns:
        Lista de :class:`ExtractedString` na ordem de aparição.

    Raises:
        ValueError: Se ``min_len`` for menor que 1.
    """
    if min_len < 1:
        raise ValueError("min_len deve ser >= 1")

    results: list[ExtractedString] = []
    current: bytearray = bytearray()
    start: int | None = None

    for index, byte in enumerate(data):
        if byte in _PRINTABLE:
            if start is None:
                start = index
            current.append(byte)
        else:
            if start is not None and len(current) >= min_len:
                results.append(ExtractedString(value=current.decode("ascii"), offset=start))
            current = bytearray()
            start = None

    # Fecha a última sequência, se o dado terminar com bytes imprimíveis.
    if start is not None and len(current) >= min_len:
        results.append(ExtractedString(value=current.decode("ascii"), offset=start))

    return results


def extract_strings_from_file(path: str | Path, min_len: int = 4) -> list[ExtractedString]:
    """Lê ``path`` como binário e extrai suas strings imprimíveis.

    Args:
        path: Caminho do arquivo binário/dump.
        min_len: Tamanho mínimo de caracteres para emitir uma string.

    Returns:
        Lista de :class:`ExtractedString` extraída do arquivo.
    """
    data = Path(path).read_bytes()
    return extract_strings(data, min_len=min_len)
