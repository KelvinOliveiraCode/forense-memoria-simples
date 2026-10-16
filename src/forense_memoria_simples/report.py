"""Geração de relatório de IOCs (texto e JSON)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .ioc import IOC
from .strings import ExtractedString


@dataclass
class Report:
    """Relatório consolidado de strings e IOCs.

    Attributes:
        file_path: Caminho do arquivo analisado.
        total_strings: Quantidade de strings extraídas.
        iocs: Lista de IOCs encontrados.
    """

    file_path: str
    total_strings: int
    iocs: list[IOC] = field(default_factory=list)

    @property
    def ipv4_count(self) -> int:
        return sum(1 for ioc in self.iocs if ioc.type == "ipv4")

    @property
    def url_count(self) -> int:
        return sum(1 for ioc in self.iocs if ioc.type == "url")

    @property
    def suspicious_command_count(self) -> int:
        return sum(1 for ioc in self.iocs if ioc.type == "suspicious_command")

    def to_text(self) -> str:
        """Renderiza o relatório em formato de texto legível."""
        lines: list[str] = []
        lines.append("=== Relatório de Forense Volátil ===")
        lines.append(f"Arquivo: {self.file_path}")
        lines.append(f"Strings extraídas: {self.total_strings}")
        lines.append(f"IOCs encontrados: {len(self.iocs)}")
        lines.append(f"  - IPv4: {self.ipv4_count}")
        lines.append(f"  - URLs: {self.url_count}")
        lines.append(f"  - Comandos suspeitos: {self.suspicious_command_count}")
        lines.append("")
        if self.iocs:
            lines.append("Detalhes dos IOCs:")
            for ioc in self.iocs:
                lines.append(
                    f"  [{ioc.type}] {ioc.value} "
                    f"(string #{ioc.string_index}: {ioc.context!r})"
                )
        else:
            lines.append("Nenhum IOC encontrado.")
        lines.append("")
        return "\n".join(lines)

    def to_json(self) -> str:
        """Renderiza o relatório em formato JSON."""
        payload = {
            "file_path": self.file_path,
            "total_strings": self.total_strings,
            "ioc_count": len(self.iocs),
            "iocs": [
                {
                    "type": ioc.type,
                    "value": ioc.value,
                    "string_index": ioc.string_index,
                    "context": ioc.context,
                }
                for ioc in self.iocs
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)


def build_report(
    file_path: str | Path,
    strings: Iterable[ExtractedString],
    iocs: Iterable[IOC],
) -> Report:
    """Constrói um :class:`Report` a partir de strings e IOCs.

    Args:
        file_path: Caminho do arquivo analisado.
        strings: Strings extraídas.
        iocs: IOCs encontrados.

    Returns:
        Instância de :class:`Report` populada.
    """
    string_list = list(strings)
    ioc_list = list(iocs)
    return Report(
        file_path=str(Path(file_path)),
        total_strings=len(string_list),
        iocs=ioc_list,
    )
