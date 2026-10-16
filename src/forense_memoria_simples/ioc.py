"""Regras de IOC (Indicadores de Comprometimento) sobre strings extraídas."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .strings import ExtractedString

# Endereço IPv4 válido: cada octeto entre 0 e 255.
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b"
)

# URL HTTP, HTTPS ou FTP.
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)

# Comandos suspeitos (match case-insensitive por substring na string).
_SUSPICIOUS_COMMANDS = frozenset(
    {
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "net user",
        "net localgroup",
        "reg add",
        "reg delete",
        "schtasks",
        "wget",
        "curl",
        "nc.exe",
        "ncat",
        "whoami",
        "ipconfig",
        "netstat",
        "tasklist",
        "format ",
        "del /",
        "bcdedit",
        "vssadmin delete shadows",
        "wevtutil cl",
    }
)


@dataclass(frozen=True)
class IOC:
    """Um indicador de comprometimento encontrado.

    Attributes:
        type: Tipo do IOC ("ipv4", "url" ou "suspicious_command").
        value: Valor do indicador (ex.: endereço IP, URL, comando).
        string_index: Posição da string na lista extraída.
        context: A string inteira onde o IOC apareceu.
    """

    type: str
    value: str
    string_index: int
    context: str


def _find_ipv4s(text: str) -> list[str]:
    return _IPV4_RE.findall(text)


def _find_urls(text: str) -> list[str]:
    return _URL_RE.findall(text)


def _find_suspicious_commands(text: str) -> list[str]:
    lowered = text.lower()
    found: list[str] = []
    for command in _SUSPICIOUS_COMMANDS:
        if command in lowered:
            found.append(command)
    return found


def scan_iocs(strings: list[ExtractedString]) -> list[IOC]:
    """Aplica as regras de IOC sobre a lista de strings extraídas.

    Para cada string, verifica endereços IPv4, URLs e comandos suspeitos.
    Retorna IOCs na ordem em que são encontrados (string por string, regra
    por regra). Determinístico: mesma entrada, mesma saída.

    Args:
        strings: Lista de :class:`ExtractedString` produzida por
            :func:`extract_strings` ou :func:`extract_strings_from_file`.

    Returns:
        Lista de :class:`IOC` encontrados.
    """
    iocs: list[IOC] = []
    for index, extracted in enumerate(strings):
        text = extracted.value
        for value in _find_ipv4s(text):
            iocs.append(IOC(type="ipv4", value=value, string_index=index, context=text))
        for value in _find_urls(text):
            iocs.append(IOC(type="url", value=value, string_index=index, context=text))
        for value in _find_suspicious_commands(text):
            iocs.append(
                IOC(
                    type="suspicious_command",
                    value=value,
                    string_index=index,
                    context=text,
                )
            )
    return iocs
