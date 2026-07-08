# FlowSpec SOC — Coletor automático

Coleta os módulos do painel **ASN Monitor**, grava em `data/soc-snapshot.json`
e faz **commit + push** no GitHub a cada ciclo. O Cloudflare Pages reconstrói o
site (`meu-site-devops-5i2.pages.dev`) e o `index.html` mostra os dados ao vivo.

```
collector.py → data/soc-snapshot.json → git push → GitHub → Cloudflare Pages → site
```

## O que é coletado

| Módulo               | Tipo             | Coleta |
|----------------------|------------------|--------|
| FlowSpec SOC (feed)  | HTML nativo      | completa |
| Reputação ASN        | HTML nativo      | completa (cards + Intel Feed) |
| Visão Global         | Grafana (iframe) | conteúdo de texto dos painéis |
| Ataques Inbound      | Grafana (iframe) | conteúdo de texto dos painéis |
| Infectados Outbound  | Grafana (iframe) | conteúdo de texto dos painéis |
| Análise Profunda     | Grafana (iframe) | tabelas Veredito/Perfil + texto |

Os painéis do Grafana renderizam **devagar** — por isso o coletor espera
`--grafana-wait` (padrão 12s) por módulo antes de ler. Gráficos SVG dão só
rótulos/legenda; tabelas saem completas.

## Instalação (uma vez)

```powershell
pip install playwright
playwright install chromium
```

## Uso manual

```powershell
python collector.py                          # loop 30s, grafana-wait 12s, push
python collector.py --grafana-wait 20000     # espera 20s no Grafana (mais lento/completo)
python collector.py --once                   # 1 coleta e sai
python collector.py --no-git                 # só gera o JSON
```

Na **1ª execução** abre uma janela do navegador: **faça login** (é a única
interação manual — eu não guardo/uso sua senha). A sessão fica salva em
`.soc-profile/` e é reutilizada; depois disso roda sozinho, sem login.

## Rodar 100% sozinho (auto-start no boot)

1. Dê um duplo-clique em **`run-collector.bat`** para testar (ele reinicia
   sozinho se cair).
2. Para ligar junto com o Windows, registre no **Agendador de Tarefas**:
   - Abra "Agendador de Tarefas" → **Criar Tarefa Básica**.
   - Nome: `FlowSpec SOC Collector`.
   - Disparador: **Ao fazer logon**.
   - Ação: **Iniciar um programa** → Programa/script: aponte para
     `run-collector.bat` (nesta pasta).
   - Concluir. Pronto: a cada logon ele sobe sozinho e publica no GitHub.

   Alternativa via PowerShell (uma linha):
   ```powershell
   schtasks /Create /TN "FlowSpec SOC Collector" /TR "\"%CD%\run-collector.bat\"" /SC ONLOGON /RL LIMITED /F
   ```

## Avisos

- Depende da **sessão logada** no navegador — mantenha o processo/PC ligado
  para coleta contínua.
- `.soc-profile/` guarda os cookies de login → já está no `.gitignore`, nunca
  versione.
- Se o `git push` pedir senha toda vez, configure um credential helper ou chave
  SSH no Git (o Windows normalmente já guarda após o 1º push).
- O traceback ao dar `Ctrl+C` é inofensivo (é o navegador fechando).
```
