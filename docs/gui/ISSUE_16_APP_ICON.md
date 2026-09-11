# CERBERUS — Application Icon & README Branding (Issue #16)

Data: 2026-09-10
Escopo: correção da Issue #16 — ícone de aplicação dedicado para a janela da GUI
e atualização das imagens de identidade visual no README, utilizando os ativos em
`assets/images/`.
Branch: `feat/gui-application-icon`.

---

## 1. Contexto e objetivo

A Issue #16 pede um ícone de aplicação dedicado ao CERBERUS, usado de forma
consistente como ícone da janela e alinhado à identidade visual do projeto.
Critérios de aceite:

- Criar um ícone dedicado de aplicação;
- Integrar o ícone à GUI;
- Verificar que o ícone é exibido corretamente na inicialização;
- Verificar que funciona nos ambientes suportados.

Os ativos necessários já estão em `assets/images/`:

| Arquivo | Dimensões | Uso |
|---|---|---|
| `assets/images/applogo.png` | 500×500 | Ícone da janela (PhotoImage/iconphoto) |
| `assets/images/logo.jpg` | 1024×1024 | Imagem principal do README |

A pasta `assets/` é criada/cuidada pelo usuário e não é ignorada pelo `.gitignore`.

---

## 2. Diagnóstico

### 2.1 Sem ícone configurado na GUI
`CerberusApp` (`modules/gui.py`) herda de `tk.Tk` e nenhum ícone era definido — a
janela usava o ícone padrão do Tk. A única outra janela do fluxo é o `Tooltip`
(widget `Toplevel` com `overrideredirect`), que não precisa de ícone.

### 2.2 Ativos não tinham `.ico`
O conjunto de imagens é PNG/JPG. Em vez de gerar um `.ico` (o que exigiria
`Pillow` ou um passo extra), o Tk suporta PNG nativamente via `tk.PhotoImage` +
`iconphoto()`, que define o ícone da janela e da barra de tarefas no Windows.

---

## 3. Mudanças implementadas

### 3.1 GUI — ícone de janela (`modules/gui.py`)
Adicionado o método `_set_application_icon()` chamado logo após
`super().__init__()` no `__init__` de `CerberusApp`:

- O caminho é resolvido a partir de `__file__`
  (`os.path.dirname(os.path.dirname(os.path.abspath(__file__)))` +
  `assets/images/applogo.png`), ficando **independente do diretório de trabalho**;
- `tk.PhotoImage` recebe o PNG e `self.iconphoto(True, photo)` aplica o ícone à
  janela e a janelas filhas;
- A referência é mantida em `self._icon_photo` para **evitar coleta de lixo**;
- Degradação graciosa: se o arquivo não existir ou o `PhotoImage` falhar
  (`tk.TclError`), imprime um aviso e segue sem ícone — não quebra o app.
- Nenhuma dependência nova (`requests`, `python-dotenv` continuam sendo as únicas).

### 3.2 README — imagens locais (`README.md`)
- Imagem superior (substituiu `https://i.imgur.com/VG9jzJy.png`) →
  `assets/images/logo.jpg` (width 420);
- Slot "demo/app" (substituiu `https://files.catbox.moe/c8nu8t.webp`) →
  `assets/images/applogo.png` (width 180);
- Estrutura do projeto: adicionado o bloco `assets/images/` (applogo.png,
  logo.jpg) à árvore e um bullet explicando seu propósito.

---

## 4. Verificação

`python validate_all.py` — 6/6 PASS; `python -m compileall -q analyzer.py modules`
OK; teste funcional (Tk em cabeça — `gui_issue16_test.py`):

| # | Verificação | Resultado |
|---|---|---|
| 1 | Toplevel handle existe | PASS |
| 2 | `tk.PhotoImage` carregado da `applogo.png` (500×500) | PASS |
| 3 | Referência mantida em `self._icon_photo` (previne GC) | PASS |
| 4 | `assets/images/applogo.png` presente (219916 bytes) | PASS |
| 5 | Degradação graciosa quando o arquivo é removido | PASS |

---

## 5. Observações

- O `Tooltip` usa `overrideredirect` e não exibe ícone próprio — nenhuma mudança
  necessária.
- Não foi gerado `.ico`; se houver futuramente packaging (exe/instalador), o
  `applogo.png` pode ser reutilizado para o ícone do atalho.
- A pasta `assets/` é gerenciada pelo usuário e permanece versionável.