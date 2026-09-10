# CERBERUS — Relatório: Batch Scan com multiprocessing

Data: 2026-09-09
Escopo: eliminar o travamento/lentidão do batch-scan migrando os workers para
processos separados; corrigir o dispatch de pasta na CLI.
Branch: `fix/gui-window-constraints`. Base: rodada P1–P5 (opt. de I/O e matching).

---

## 1. Contexto e objetivo

Documento anterior (P1–P5) listou como caso estrutural pendente o fato de o batch
rodar como **threads CPU-bound no mesmo processo da Tk**, limitado pelo GIL. Nesta
rodada esse caso foi atacado: **cada análise do batch agora roda em um processo
separado**, de modo que os motores (regex, extração de strings, hashing) não
disputam mais o GIL com o mainloop da interface.

---

## 2. Diagnóstico

### 2.1 GIL monopolizado pelo worker de análise
`gui._run_batch` usava `ThreadPoolExecutor(min(4, cpu_count))` executando
`analyze_file` **na thread de análise do próprio processo da GUI**. Como os motores
são heavy-CPU em Python puro (regex combinada, `finditer`, loops), a janela ficava
congelada durante a varredura — o mainloop Tk só rodava nos gaps entre chunks.

### 2.2 Chunks de threads → pool efêmero por chunk
O antigo código dividia os arquivos em `chunk_size = worker_count * 4` e criava um
`ThreadPoolExecutor` **por chunk** (start/teardown repetidos e fila FIFO nunca
drenada — resultados executavam em ordem de submissão).

### 2.3 Cache não compartilhado com a profundidade esperada
`_run_batch` criava **um** `AnalysisCache` no processo pai e o injetava via
`config["_cache"]`, mas as conexões eram thread-local, o que já era
desajustado para o padrão multi-thread; com processos, seria inviável.

### 2.4 CLI não despachava pastas (bug pré-existente)
`analyzer.main()` chamava `analyze_file(args.file, ...)` em todo caminho — passar
uma **pasta** para a CLI levantava `PermissionError` (documentado no fim da rodada
P1–P5).

---

## 3. Solução implementada

### 3.1 Novo módulo `modules/batch.py`
Núcleo compartilhado por GUI e CLI:

- `collect_candidates(folder)` — walk com `BATCH_IGNORED_DIRECTORIES`, filtrando
  `BATCH_ASSET_EXTENSIONS` (lista ampliada, ex.: `.apng`, `.eot`, `.m4a`, `.ttf`);
  devolve `(candidates, skipped)`.
- `_clean_worker_config(config)` — cópia rasa sem chaves `_*` nem
  `event_callback`, deixando apenas valores escalares pickláveis.
- `_batch_analyze_file(filepath, config)` — entry point **de nível de módulo**
  (obrigatório para `spawn` no Windows): faz `from analyzer import analyze_file`
  **lazy** para evitar import circular e retorna o resultado da análise.
- `run_batch_analysis(folder, config, on_progress=None, on_error=None)` —
  cria **um único `ProcessPoolExecutor`** para todo o lote (nenhum custo de spawn
  por chunk), itera com `as_completed`, e entrega:
  - `on_progress(result, index, total)`
  - `on_error(filepath, message, index, total)`
  ambos executados **na thread chamadora** (nunca picklados).
  Retorna `(results, skipped, duration)`.
  **Fallback seguro:** se a criação do pool de processos falhar no ambiente
  (ex.: restrição de spawn), cai para `ThreadPoolExecutor` com os mesmos
  callbacks — o batch continua funcionando, apenas sem o ganho de processos.

### 3.2 `analyzer.analyze_folder` refatorado
Deixou de gerenciar threads/chunks localmente e passou a delegar em
`run_batch_analysis`, com `on_progress`/`on_error` que imprimem `[i/N]`,
risco, tempo e erros — mesma saída visual de antes. Somado ao `run_batch_analysis`,
a função agora **compartilha implementação com a GUI**.

### 3.3 `gui._run_batch` refatorado
- Removeu `ThreadPoolExecutor`, `as_completed`, `AnalysisCache` e o
  `config["_cache"]` do processo pai (cada worker cria seu cache).
- Removeu `batch_chunk_size`.
- Troca o filtro local de extensões por `collect_candidates`.
- Usa `run_batch_analysis` com `on_progress`/`on_error` → `self.events.put`.
- **Formatos de evento preservados**: `("batch_started", total)`,
  `("batch_result", index, total, result)`, `("batch_error", index, total, path,
  msg)`, `("batch_summary", path)`, `("batch_complete", total)` — os handlers
  existentes do `_drain_events` não mudaram.

### 3.4 CLI passa a despachar pastas
`analyzer.main()`: se `os.path.isdir(args.file)`, executa `analyze_folder(...)`
(com `--workers` respeitado). Corrigido o bug pré-existente da rodada P1–P5.

---

## 4. Detalhes técnicos (Windows/spawn)

- **Worker picklável**: `_batch_analyze_file` é função de módulo → o
  `ProcessPoolExecutor` bufferiza por referência (`modules.batch._batch_analyze_file`).
- **Filhos reimportam `__main__`** com nome `__mp_main__` — os guards
  `if __name__ == "__main__"` dos scripts (analyzer, drivers) impedem recursão.
- **Pool criado dentro de thread de background (GUI)**: testado — o
  `ProcessPoolExecutor` iniciado de uma `threading.Thread` daemon funciona
  normalmente no Windows.
- **Cache entre processos**: cada processo filho cria seu `AnalysisCache`
  (SQLite WAL compartilhado em `reports/`). Leituras/escritas concorrentes já são
  seguras (validado na rodada P1–P5); teste real de warm-cache entre processos OK.
- **Pickle mínimo**: só `(filepath, worker_config)` trafega entre processos.
  Resultados voltam como dicts JSON-serializáveis.

---

## 5. Validação (tudo executado nesta rodada)

| Teste | Resultado |
|---|---|
| `python validate_all.py` | **ALL TESTS PASSED** |
| `python test_cache_hit.py` | **PASS** |
| Driver de batch (`cb_batch_driver.py`), fixture única regenerada a cada execução: | |
| — batch a partir de **thread daemon** (igual GUI), 2 processos, 3/3 OK, 1 asset pulado, cache frio | PASS |
| — prova de **processos reais**: `ThreadPoolExecutor` substituído por classe que explode no construtor → fallback nunca disparou | PASS |
| — warm cache: 2ª execução 3/3 cache hits **através de processos** | PASS |
| — CLI com pasta: `analyzer.py <pasta> --workers 2 --no-virustotal --quiet` → resumo em lote gerado, exit 0 | PASS |
| — import de `modules.gui` (wiring batch) | PASS |
| `python -m py_compile` (analyzer, gui, batch) | OK |

Observação de medição: a fluidez da janela durante varredura longa não foi medida
interativamente; a justificativa é estrutural — os workers saíram do processo da Tk
(sem disputa de GIL com o mainloop). O tempo total de CPU do lote não muda por si
só; o ganho é em responsividade + aproveitamento real de multicore (2–4 núcleos).

---

## 6. Notas e limites

- **Fallback automático**: se processos não puderem ser criados no ambiente, o
  batch usa threads automaticamente (mesma saída, mesma carga na GUI de antes).
- O walk de `collect_candidates` é executado uma vez pela GUI/CLI para os totas e
  reexecutado dentro de `run_batch_analysis` (nosso único custo duplicado,
  desprezível frente à análise).
- `pefile` continua opcional (sem mudança).

---

## 7. Arquivos alterados

```
modules/batch.py           NOVO — collect_candidates, run_batch_analysis (ProcessPool + fallback)
analyzer.py                analyze_folder via run_batch_analysis; main() despacha diretórios
modules/gui.py             _run_batch via run_batch_analysis; imports limpos (sem ThreadPool/AnalysisCache)
```