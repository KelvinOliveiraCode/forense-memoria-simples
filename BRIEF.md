# BRIEF — forense-memoria-simples

**Projeto:** forense-memoria-simples (área: Cibersegurança — forense volátil: strings + IOC)
**Dono da validação:** workflow manager (solicitante)
**Stack:** Python (stdlib apenas), strings + regras tipo yara, pytest

## Entregas

| Caminho | Conteúdo |
|---------|----------|
| `pyproject.toml` | Metadados do pacote, entry point `forense-memoria`, `pythonpath = ["src"]` para pytest |
| `src/forense_memoria_simples/__init__.py` | Export da API pública e versão |
| `src/forense_memoria_simples/strings.py` | `extract_strings(data, min_len)` e `extract_strings_from_file(path, min_len)` — extrai sequências ASCII imprimíveis (0x20-0x7E) com offset em bytes; determinístico |
| `src/forense_memoria_simples/ioc.py` | `scan_iocs(strings)` — regras de IOC: IPv4 válido (octeto 0-255), URLs http/https/ftp, comandos suspeitos (powershell, net user, reg add, schtasks, wget, curl, whoami, ipconfig, vssadmin delete shadows, etc.); retorna lista de `IOC` (type, value, string_index, context) |
| `src/forense_memoria_simples/report.py` | `Report` com to_text() e to_json(); contagens por tipo de IOC; `build_report()` |
| `src/forense_memoria_simples/cli.py` | CLI: `arquivo`, `--min-len`, `--format {text,json}`, `--output` |
| `src/forense_memoria_simples/__main__.py` | `python -m forense_memoria_simples` |
| `tests/test_strings.py` | Extração, min_len, vazio, offset, quebra em não-imprimíveis, ValueError |
| `tests/test_ioc.py` | IPv4 válido/inválido, URLs, comandos suspeitos, string_index, sem IOC, imutabilidade |
| `tests/test_report.py` | Contagens, resumo em texto, detalhes, JSON válido |
| `tests/test_cli.py` | Saída texto, saída JSON, código de saída 0 |
| `README.md` | Bilíngue PT-BR + EN: título, descrição, como usar, teste com arquivo sintético, testes, licença MIT, autor Kelvin Oliveira |
| `BRIEF.md` | Este arquivo |

## Critérios de aceitação (espec)

- [x] Relatório de IOCs (texto e JSON)
- [x] Suíte pytest que passa
- [x] README PT-BR + EN completo

## Como verificar

1. Entre na pasta do projeto:

```bash
cd "C:\Users\Kelvin\AppData\Local\Temp\opencode\github-staging\projects\forense-memoria-simples"
```

2. Rode a suíte de testes:

```bash
python -m pytest -q
```

Resultado esperado: `19 passed` (código de saída 0).

3. Teste com arquivo sintético:

```bash
python - <<'PY'
from pathlib import Path
Path("sintetico.bin").write_bytes(b"\x00cmd.exe /c whoami\x00192.168.1.10 https://evil.com/payload\x00")
PY
python -m forense_memoria_simples sintetico.bin --format json
```

Esperado: JSON com `ioc_count >= 3`, incluindo tipos `ipv4`, `url` e `suspicious_command`.

4. Instale e use o entry point (opcional):

```bash
pip install -e .
forense-memoria dump.bin --min-len 4 --format text
```

## Resultado da verificação (preencher pelo dono da validação)

- Comando de teste: `python -m pytest -q`
- Resultado: pass/fail
- Caminho do README: `...\forense-memoria-simples\README.md`
- Caminho do BRIEF: `...\forense-memoria-simples\BRIEF.md`
