# CERBERUS — GUI Responsiveness & Window Constraints (Issue #18)

Data: 2026-09-09
Escopo: correção da Issue #18 — população imediata da Identity após seleção de
arquivo, mínimo de janela definido e aplicado, e layout funcional sem clipping
em 980×650.
Branch: `dev`. Base: HEAD `1e40470` (batch via multiprocessing, PR #20).

---

## 1. Contexto e objetivo

A Issue #18 pede que a interface reaja melhor ao redimensionamento da janela,
especialmente em tamanhos pequenos, e que a Identity seja preenchida logo após a
escolha do arquivo (sem esperar o término do scan). Validação manual registrada
em `VALIDATION.md` apontava:

- A Identity **não aparece corretamente** quando a janela fica muito pequena (§1);
- O filename **só aparece na Identity quando o scan inicia/termina** (§3).

Critérios de aceite: metadata básica imediata, mínimo de janela definido e
impossível de reduzir, seções utilizáveis no mínimo, e nenhum elemento cortado.

---

## 2. Diagnóstico

### 2.1 Identity só era preenchida no fim do scan
`_choose_file` apenas registrava o caminho e atualizava `TARGET`/status. Todos os
seis campos + path só eram escritos por `_render_result` dentro do evento de
resultado final. Além disso, `_reset_view` (chamado ao iniciar um scan) **apagava**
a Identity — o dado recém-selecionado sumia até a conclusão da análise.

### 2.2 Grid sem folga — a Identity virava uma fresta
O conteúdo usa `grid` com colunas de peso 3/5/3. O grid do Tk só distribui espaço
extra proporcional aos pesos; sem folga, ele **encolhe todas as colunas pela mesma
quantia absoluta** (proporcional ao peso) a partir do tamanho solicitado. Como
`total_requested` (>1300px) superava a janela (1196px a 1240 / 932px a 980), **não
havia folga**:

| Coluna (a 980px) | Request | Resultado antes |
|---|---|---|
| Identity | 176px | **66px** (esmagada) |
| Evidence | 614px (tree 492px + notebook) | 431px |
| Verdict | 514px (**`tk.Text` com 80 chars de largura**) | 403px |

Os principais "vilões" de largura solicitada: `factors_text` (`tk.Text` padrão 80
colunas de largura) e as colunas fixas da Treeview de evidências.

### 2.3 Outros pontos
- **`wraplength=260` fixo** nos labels da Identity — mais largo que a coluna em
  janelas estreitas → texto cortado.
- **Hash SHA-256 (64 hex)** é um **token único sem quebras**: `wraplength` não o
  quebra (Tk só quebra em limites de palavra) → estourava a coluna.
- **Path completo** (sem espaços, cheio de `\`) também não quebrava.
- `_result_reveal_job = None` duplicado no `__init__`.

---

## 3. Mudanças implementadas

Todas em `modules/gui.py`.

### 3.1 Identity imediata após a seleção
`_choose_file` agora chama `_populate_identity(filepath)`:

- **Imediatos (síncronos, baratos):** Filename, declared extension (ou
  `"(none)"`), Size (com `os.path.getsize`, guardado contra `OSError`), Path.
- **Tipo/compatibilidade:** `analyze_file_type()` de `modules/magic_numbers.py`
  lê apenas os 32 primeiros bytes do header (custo desprezível) e já entrega
  `detected_type` + `compatibility` com a mesma coloração usada no resultado
  final (Compatible/verde, Mismatch/vermelho, Unknown/amarelo).
- **SHA-256:** em **thread daemon** (`calc_sha256`, stream 1MB) — não bloqueia a
  janela nem em arquivos grandes. Enquanto calcula, o label mostra
  `Calculating...`; o resultado chega pela fila de eventos como
  `("identity", caminho, "hash", valor)`.

### 3.2 Guarda contra resultados obsoletos
No evento `("identity", token, "hash", value)`, o hash só é aplicado se
`token == self.selected_file` (usuário trocou de arquivo no meio do cálculo →
evento antigo ignorado).

### 3.3 Hash e path legíveis em coluna estreita
- `_chunk_hex(value)` quebra o hash em 4 linhas de 16 caracteres; o valor **cru**
  fica em `self._selected_hash` para o botão `Copy SHA-256` copiar o hash inteiro.
- `_format_path(path)` quebra o caminho por componente (`\` ou `/`) em múltiplas
  linhas.
- `_copy_hash` não copia placeholders (`-`, `Calculating...`,
  `Hash not available`, `Not calculated`).

### 3.4 Wrap responsivo
`<Configure>` no painel Identity → `_fit_identity_wrap`:
`wraplength = min(520, max(140, largura_do_painel - 24))` nos seis valores + path.
Redimensionou → o texto re-flui e nunca excede a coluna.

### 3.5 Folga na grid (correção estrutural do layout)
- `factors_text` (verdict): `width=2` (antes o default de 80 colunas de texto
  inflava o request do painel em ~480px).
- Colunas da Treeview de evidências: `82/150/260` → `70/130/220`.

### 3.6 `_reset_view` preserva a Identity
Ao iniciar um scan, os seis campos + path **não são mais apagados** — o usuário
vê os dados da seleção durante toda a análise; o `_render_result` os sobrepõe com
os dados completos ao final.

### 3.7 Limpeza
Removido o `self._result_reveal_job = None` duplicado.

### 3.8 Mínimo de janela
`self.minsize(980, 650)` e geometria padrão `1240x780` **mantidos** — o
enforcement já existia; agora o layout funciona de fato nesse mínimo.

---

## 4. Resultados medidos

| Métrica | Antes | Depois |
|---|---|---|
| Identity a 980×650 | 66px (texto cortado) | **192px**, sem clipping |
| Identity a 1240×780 | 137px (path já encostava) | **262px** |
| Evidence a 1240×780 | 549px | **717px** |
| Verdict a 1240×780 | 474px (inflado pelo Text) | **181px** |

Todos os labels da Identity com `reqwidth ≤` largura do painel em 980 e 1240.

---

## 5. Validação (executada nesta rodada)

Teste funcional dedicado (`gui_issue18_test.py`, app real sem mainloop):

| Teste | Resultado |
|---|---|
| Identity preenchida na seleção (file/ext/size/path/type/compat + cor) | PASS |
| Hash em thread de fundo → 4 linhas de 16 hex, valor cru consistente (`_selected_hash`) | PASS |
| Token obsoleto (arquivo antigo) ignorado | PASS |
| `_copy_hash`: placeholder nunca copiado, hash real copiado | PASS |
| Sem clipping a 980×650 (reqwidth ≤ painel, `minsize` = 980×650) | PASS |
| `_reset_view` preserva Identity e reinicia o restante | PASS |

Regressão geral:

- `python -m py_compile modules/gui.py` — OK
- `import modules.gui` — OK
- `python validate_all.py` — **ALL TESTS PASSED**
- `python test_cache_hit.py` — PASS

---

## 6. Notas e limites

- A "detected type/compatibility" imediata vem da classificação por **header de 32
  bytes** (`analyze_file_type`), igual à usada pelo motor de magic numbers; o
  resultado final (`_render_result`) continua sendo a fonte canônica ao concluir a
  análise.
- O batch-scan via multiprocessing (PR #20) permanece **intocado**; esta rodada
  não altera `modules/batch.py`.
- O hash é exibido quebrado em 4 linhas por legibilidade; o valor copiado é o hash
  integral (64 hex).
- A checagem de layout foi automatizada via `winfo_reqwidth ≤ winfo_width`;
  recomenda-se um passe visual rápido em 980×650 antes do merge.

---

## 7. Arquivos alterados

```
modules/gui.py    _populate_identity, evento "identity" + guarda de token, _chunk_hex/_format_path,
                  _fit_identity_wrap (<Configure>), _reset_view sem apagar Identity,
                  factors_text width=2, colunas da tree 70/130/220, limpeza do init
docs/gui/ISSUE_18_GUI_RESPONSIVENESS.md   este relatório
```