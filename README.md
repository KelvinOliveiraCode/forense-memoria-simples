# forense-memoria-simples

Forense volátil simples: extrai strings imprimíveis de um binário ou dump de memória simulado, aplica regras de IOC (endereços IPv4, URLs e comandos suspeitos) e gera um relatório em texto ou JSON.

Escrito em Python (stdlib apenas, sem dependências externas), determinístico e testado com pytest.

## PT-BR

### O que faz

- Lê um arquivo binário/dump byte a byte.
- Extrai sequências de caracteres ASCII imprimíveis (0x20 a 0x7E) com tamanho mínimo configurável.
- Aplica regras de IOC sobre cada string extraída:
  - endereços IPv4 válidos (cada octeto de 0 a 255);
  - URLs http, https e ftp;
  - comandos suspeitos (por exemplo: powershell, net user, reg add, schtasks, wget, curl, whoami, ipconfig, vssadmin delete shadows).
- Emite relatório em formato de texto ou JSON, com contagem por tipo de IOC e detalhes de cada ocorrência (índice da string e contexto).

### Como usar

Instale o pacote no modo editável:

```bash
pip install -e .
```

Execute sobre um arquivo de dump:

```bash
python -m forense_memoria_simples dump.bin
```

Saída em JSON:

```bash
python -m forense_memoria_simples dump.bin --format json --output relatorio.json
```

Ou use o entry point instalado:

```bash
forense-memoria dump.bin --min-len 6
```

Opções:

| Opção | Significado |
|-------|-------------|
| `arquivo` | Caminho do binário/dump a analisar (obrigatório) |
| `--min-len` | Tamanho mínimo de cada string (padrão: 4) |
| `--format` | `text` ou `json` (padrão: text) |
| `--output` | Caminho do arquivo de relatório (padrão: stdout) |

### Teste com arquivo sintético

Crie um dump sintético e analise:

```bash
python - <<'PY'
from pathlib import Path
Path("sintetico.bin").write_bytes(b"\x00cmd.exe /c whoami\x00conexao em 192.168.1.10 via https://evil.com/payload\x00")
PY
python -m forense_memoria_simples sintetico.bin --format json
```

Esperado: IOCs do tipo `suspicious_command` (`cmd.exe`, `whoami`), `ipv4` (`192.168.1.10`) e `url` (`https://evil.com/payload`).

### Rodar os testes

```bash
python -m pytest -q
```

Resultado esperado: todos os testes passam (19 testes cobrindo extração de strings, regras de IOC, relatório e CLI).

### Licença

MIT.

### Autor

Kelvin Oliveira.

---

## EN

### What it does

- Reads a binary file / memory dump byte by byte.
- Extracts runs of printable ASCII characters (0x20 to 0x7E) with a configurable minimum length.
- Applies IOC rules over each extracted string:
  - valid IPv4 addresses (each octet from 0 to 255);
  - http, https and ftp URLs;
  - suspicious commands (for example: powershell, net user, reg add, schtasks, wget, curl, whoami, ipconfig, vssadmin delete shadows).
- Emits a report in plain text or JSON, with counts per IOC type and details of each occurrence (string index and context).

### How to use

Install the package in editable mode:

```bash
pip install -e .
```

Run against a dump file:

```bash
python -m forense_memoria_simples dump.bin
```

JSON output:

```bash
python -m forense_memoria_simples dump.bin --format json --output report.json
```

Or use the installed entry point:

```bash
forense-memoria dump.bin --min-len 6
```

Options:

| Option | Meaning |
|--------|---------|
| `file` | Path of the binary/dump to analyze (required) |
| `--min-len` | Minimum length of each extracted string (default: 4) |
| `--format` | `text` or `json` (default: text) |
| `--output` | Path of the report file (default: stdout) |

### Test with a synthetic file

Create a synthetic dump and analyze it:

```bash
python - <<'PY'
from pathlib import Path
Path("synthetic.bin").write_bytes(b"\x00cmd.exe /c whoami\x00connection to 192.168.1.10 via https://evil.com/payload\x00")
PY
python -m forense_memoria_simples synthetic.bin --format json
```

Expected: IOCs of type `suspicious_command` (`cmd.exe`, `whoami`), `ipv4` (`192.168.1.10`) and `url` (`https://evil.com/payload`).

### Run the tests

```bash
python -m pytest -q
```

Expected result: all tests pass (19 tests covering string extraction, IOC rules, report, and CLI).

### License

MIT.

### Author

Kelvin Oliveira.
