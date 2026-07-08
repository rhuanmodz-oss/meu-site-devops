# FlowSpec SOC — Coletor automático

Coleta o feed de incidentes do painel **ASN Monitor** a cada 30 segundos, salva em
`data/soc-snapshot.json` (sobrescrevendo) e faz **commit + push** no Git. O
`index.html` lê esse arquivo e se atualiza sozinho.

## Como funciona

```
collector.py  →  data/soc-snapshot.json  →  git push  →  index.html (dashboard)
   (loop 30s)        (sobrescreve)                          (re-lê a cada 30s)
```

Autenticação é por **login no navegador**: na 1ª execução abre uma janela pra você
logar; a sessão fica salva em `.soc-profile/` (ignorada no Git) e é reutilizada.

## Instalação (uma vez)

```powershell
pip install playwright
playwright install chromium
```

## Rodar

```powershell
python collector.py                # loop de 30 em 30 segundos + git push
python collector.py --interval 60  # a cada 60s
python collector.py --once         # coleta 1 vez e sai
python collector.py --no-git       # só gera o JSON, sem commit/push
```

Na 1ª vez, **faça login** na janela que abrir. Quando o feed aparecer, a coleta
começa e não para até você apertar `Ctrl+C`.

## Ver o dashboard

Como o `index.html` faz `fetch` do JSON, abra via um servidor (não `file://`):

```powershell
python -m http.server 8000
# depois abra http://localhost:8000/index.html
```

Ou publique o repositório (ex.: GitHub Pages) — aí o push do coletor já atualiza
o painel online. Aberto direto como arquivo, ele cai no snapshot embutido de
fallback (não atualiza sozinho).

## Avisos honestos

- **Não é 24/7 automático de verdade.** Como depende da sessão logada, a coleta só
  roda enquanto `collector.py` estiver aberto. Pra rodar sem babá, deixe o processo
  ligado numa máquina que fica online (ou registre no Agendador de Tarefas do Windows).
- **30s é o intervalo do loop**, feito no próprio script. O agendador nativo do
  Cowork tem granularidade mínima de 1 minuto — por isso o loop fica no `collector.py`.
- **`.soc-profile/` contém os cookies de login** — já está no `.gitignore`. Nunca
  versione essa pasta.
- Se o `git push` pedir credencial toda vez, configure um credential helper ou uma
  chave SSH no seu Git.
