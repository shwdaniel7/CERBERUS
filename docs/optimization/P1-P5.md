# CERBERUS — Relatório de Otimizações (Rodada P1–P5)

Data: 2026-09-09
Escopo: otimização sem novas funcionalidades (desempenho, memória, corretude e limpeza).
Requires: `dev` (d668310). Nenhuma assinatura pública quebrada.

---

## 1. Contexto e objetivo

O CERBERUS analisa arquivos sem executá-los, encadeando motores (hash, blacklist,
VirusTotal, magic numbers, entropia, packers, strings, IOCs, PE) e gerando um score
de risco com relatórios JSON/CSV/HTML. Nosso objetivo foi tornar o software mais
rápido e mais correto — **sem introduzir features novas** — com foco especial no
gargalo relatado no **batch scan** (aplicação lenta/travada durante varreduras em
pastas).

---

## 2. Diagnóstico

### 2.1 I/O redundante — arquivo lido 4 vezes por análise
Em uma análise completa, o mesmo arquivo era lido **4 vezes por completo** do disco:

| Chamada | Arquivo | Antes |
|---|---|---|
| `collect_file_metrics` / `calc_sha256` | `.py` (analyzer) | leitura completa |
| `detect_packers` | `modules/packers.py` | `f.read()` completo |
| `strings` | `modules/strings.py` | `f.read()` completo |
| `extract_iocs` | `modules/ioc_extract.py` | `f.read()` completo + **decode UTF-8 de todo o binário** |

Para amostras de 10–500 MB isso era o custo dominante.

### 2.2 Matching de termos suspeitos — O(strings × termos) com regex recompilada
O loop de detecção em `strings.py` recompilava uma expressão regular **a cada
chamada** e varria cada string extraída contra cada termo da lista:

```python
def _term_matches(text, term):            # recompila a regex em toda chamada
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])"
    return re.search(pattern, text, re.IGNORECASE) is not None
```

Para ~77 mil strings × ~10 termos ≈ **770 mil compilações + buscas** por arquivo.
O filtro de termos benignos (`BENIGN_TERMS`) era reaplicado dentro do loop interno.

### 2.3 Cache nunca invalidava com a edição dos IOCs
A chave do cache incluía o config, o caminho, tamanho e mtime do arquivo — mas
**não o conteúdo de `iocs/blacklist.txt` e `iocs/suspect_strings.txt`**. Editar as
listas de indicadores não invalidava nada, devolvendo vereditos obsoletos.

### 2.4 Descobertas pontuais
- `engine_done("IOC extraction", ...)` estava **dentro** do bloco `if show_details:`
  (analyzer.py) — em modo quiet (GUI batch / `--quiet`) o engine nunca era
  finalizado: `engine_times` e o evento `engine_completed` dos IOCs ficavam perdidos.
- `calc_sha256` lia em blocos de **4 KB** (vs 1 MB usado por `collect_file_metrics`),
  aumentando syscalls.
- `AnalysisCache._key()` fazia `os.stat` **duas vezes** por arquivo (no `get` e no
  `put`), e `close()` só fechava a conexão SQLite da thread principal — as conexões
  criadas pelas threads workers do batch ficavam abertas, inflando o WAL.
- Código morto: `uploadFile`, `upload_folder`, `from modules.menu import optionsMenu`.

---

## 3. Otimizações executadas

### P1 — Leitura única do arquivo (I/O)
- **`modules/file_metrics.py`**: nova função `read_analysis_buffer()` que lê o
  arquivo **uma vez** (chunks de 1 MB), calcula SHA-256 + histograma de bytes e
  devolve `(content_bytes, metrics)`. O buffer completo só é retido quando o
  arquivo tem até **128 MB** (`MAX_BUFFERED_BYTES`); acima disso, `content=None`
  e cada motor volta à leitura própria — mantendo o pico de memória limitado em
  análises em lote.
- **`modules/strings.py`, `modules/ioc_extract.py`, `modules/packers.py`**:
  ganharam o parâmetro opcional `content=None` — quando recebem o buffer, **não
  reabrem o arquivo**. Assinaturas antigas preservadas (compatibilidade total com
  GUI, CLI e scripts de validação).
- **`analyzer.py`**: `analyze_file` decide, no bloco do SHA-256, se algum motor
  pesado está habilitado (`entropy`/`strings`/`ioc_extract`) e, em caso positivo,
  lê o arquivo uma única vez e compartilha `shared_content`/`shared_metrics` entre
  os motores. Em cache-hit o retorno acontece **antes de qualquer leitura**.

**Resultado medido:** uma análise completa passou de **4 leituras completas +
2 leituras de header** para **1 leitura completa + 2 leituras de header**
(6 → 3 `open`s, instrumentado com monkeypatching de `open`).

### P2 — Matching de termos suspeitos em uma única regex
- **`modules/strings.py`**: filtragem de `BENIGN_TERMS` feita **uma vez** (na
  compilação) e construção de **uma única regex de alternância** com lookarounds de
  word boundary:

```python
re.compile(rf"(?<![A-Za-z0-9_])T1|T2|T3…(?![A-Za-z0-9_])", re.IGNORECASE)
```

- Cada string é varrida **uma vez** com `finditer`; os termos detectados são
  reportados na ordem original da lista — mesma semântica de antes (um alerta por
  termo + string).

**Resultado medido (arquivo de 20 MB, 76.899 strings):**
| Método | Tempo |
|---|---|
| Antes (compição+busca por termo) | 0.4022 s |
| Depois (regex única) | 0.0301 s |
| Contagem de alertas | idêntica |

≈ **13× mais rápido**, e o ganho cresce com o número de termos/strings (o antigo
era multiplicativo).

### P3 — Correção: cache invalida com o conteúdo dos IOCs
- **`modules/analysis_cache.py`**: a chave do cache agora inclui um **fingerprint
  SHA-256** de `iocs/blacklist.txt` + `iocs/suspect_strings.txt`. O fingerprint é
  memoizado por `(mtime_ns, size)` das listas, então **não custa praticamente nada**
  em varreduras em lote, mas **qualquer edição nas listas invalida o cache**.
- Verificado por teste: analisar → cache hit → editar `suspect_strings.txt` →
  re-análise **não** vem do cache e o novo termo é detectado.

### P4 — Extração de IOCs sobre bytes (sem decode)
- **`modules/ioc_extract.py`**: todos os padrões recompilados com `re.BYTES` e
  executados **direto sobre o buffer binário**. O decode UTF-8 de todo o arquivo
  foi eliminado; apenas os grupos capturados são decodificados (helper
  `_decode_unique` mantém a deduplicação + remoção de pontuação final).
- Elimina uma cópia integral da memória (`str ~2× o binário em RAM`) e um passe
  extra de CPU. Resultados idênticos (testado contra a versão em leitura própria).

### P5 — Micro-otimizações e limpeza
- **`modules/hashes.py`**: `calc_sha256` passou de chunks de 4 KB para **1 MB**
  (mesmo `CHUNK_SIZE` usado por `read_analysis_buffer`).
- **`modules/analysis_cache.py`**:
  - `key_for()` — a chave e o `os.stat` são calculados **uma vez** por arquivo e
    reutilizados entre `get` e `put` (um `os.stat` a menos por arquivo);
  - `close()` — fecha **todas** as conexões thread-local registradas, inclusive as
    das threads workers do batch (o WAL é liberado/checkpointed ao final).
- **`analyzer.py`**:
  - `engine_done("IOC extraction", ...)` movido para **fora** do `if show_details:`
    (conserta `engine_times` e o evento no modo quiet/gui batch);
  - removidos `uploadFile`, `upload_folder` e `from modules.menu import optionsMenu`
    (código morto).

---

## 4. Bugs corrigidos no percurso
1. **`engine_done` dos IOCs sob `show_details`** — tempo/evento perdidos no modo quiet.
2. **Cache obsoleto após edição das listas IOC** — agravado pelo descarte do cache
   agora ser transparente (P3).

---

## 5. Validação (tudo executado nesta rodada)

| Teste | Resultado |
|---|---|
| `python validate_all.py` (scan full, cache hit, quick, clear history ± cache, acesso concorrente 3 threads) | **ALL TESTS PASSED** |
| `python test_cache_hit.py` | **PASS** (cache hit True) |
| Suíte dedicada (19 asserts): equivalência buffer×arquivo, fallback >128 MB, `engine_times` dos IOCs no modo quiet, invalidação do cache por IOCs, detecção de novos termos | **19 PASS, 0 FAIL** |
| Scan CLI completo com detalhes (`--full`) | OK (Moderate 33/100, relatório gerado) |
| `analyze_folder` com 2 workers (3 arquivos, cache compartilhado) | OK (resumo em lote gerado) |
| Benchmark 20 MB: leitura única (3 opens), matching ~13× (0.030 s) | OK |
| `python -m py_compile` + import de `modules.gui` | OK |

---

## 6. Notas pré-existentes (fora do escopo desta rodada)

- **CLI não despacha `analyze_folder`**: no `main()` da CLI, passar uma pasta executa
  `analyze_file` sobre ela (erro de Permission). Isso já acontecia no HEAD antes das
  mudanças. O batch funcionante hoje é o da GUI (`gui._run_batch`) e a função pública
  `analyzer.analyze_folder` (usada nos testes). Conectar o modo pasta à CLI é um
  ajuste recomendado futuro.
- **Travamento do batch — causa raiz estrutural**: mesmo com P1–P5, o batch roda como
  threads CPU-bound **no mesmo processo da Tk**, limitado pelo GIL. Para uma janela
  100% fluida em varreduras longas, o próximo passo recomendado é migrar o batch para
  **`multiprocessing`** (processos separados, sem interferência de GIL, escalável em
  multicore). O cache SQLite já é compatível com múltiplos processos; foi adiado por
  decisão do usuário.
- **`pefile`** continua opcional (não adicionado ao `requirements.txt`), como já era.

---

## 7. Arquivos alterados

```
analyzer.py               leitura única, fix engine_done IOC, remoção de código morto
modules/analysis_cache.py fingerprint dos IOCs na chave, key_for (1 stat), close() global
modules/file_metrics.py   read_analysis_buffer() + CHUNK_SIZE/MAX_BUFFERED_BYTES
modules/hashes.py         chunk de hashing 4 KB → 1 MB
modules/ioc_extract.py    padrões em bytes (re.BYTES), sem decode UTF-8
modules/packers.py        parâmetro content (buffer compartilhado)
modules/strings.py        regex única de suspeitos, filtro benigno uma vez
```