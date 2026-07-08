#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FlowSpec SOC collector (v2 - multi-modulo)
==========================================
Coleta os modulos do ASN Monitor (SOC) a cada N segundos, salva em
data/soc-snapshot.json (SOBRESCREVENDO) e faz commit + push no Git.

O que e coletado de cada modulo:
  - FLOWSPEC SOC ...... feed de incidentes (HTML nativo)         -> completo
  - REPUTACAO ASN ..... cards + tabela Intel Feed (HTML nativo)  -> completo
  - VISAO GLOBAL ...... paineis Grafana (iframe/SVG)             -> inventario
  - ATAQUES INBOUND ... paineis Grafana                          -> inventario
  - INFECTADOS OUTBOUND paineis Grafana + radar 3D               -> inventario
  - ANALISE PROFUNDA .. paineis Grafana (tabelas Veredito/Perfil) -> inventario

  "inventario" = titulos dos paineis daquele modulo. Os graficos do Grafana
  sao SVG dentro de iframes aninhados: nao ha numero limpo para raspar pela
  tela. Para dados limpos desses paineis, use a API do Grafana (ver README).

Autenticacao: LOGIN NO NAVEGADOR (voce loga 1x; a sessao fica em ./.soc-profile).

Uso:
    pip install playwright
    playwright install chromium
    python collector.py                 # loop de 30s + git push
    python collector.py --interval 60
    python collector.py --once
    python collector.py --no-git
"""

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from playwright.sync_api import sync_playwright

# --------------------------------------------------------------------------- #
URL = "https://asn-monitor.linknetbandalarga.net/"
ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "data" / "soc-snapshot.json"
PROFILE_DIR = ROOT / ".soc-profile"
READY_MARKER = "FEED DE INCIDENTES"

# rotulos dos KPIs globais (topo do FLOWSPEC SOC)
_KPI_LABELS = {
    "iocs_mundiais": "IOCS MUNDIAIS", "critical": "CRITICAL", "high": "HIGH",
    "info": "INFO", "permanentes": "PERMANENTES", "inbound": "INBOUND",
    "outbound": "OUTBOUND",
}
_DT_RE = re.compile(r"\d{2}/\d{2}/\d{4},\s*\d{2}:\d{2}:\d{2}")

# titulos de painel esperados por modulo Grafana (inventario)
GRAFANA_MODULES = {
    "visao_global":       {"nav": "VISÃO GLOBAL",        "panels": ["ALVOS INTERNOS", "VOLUME", "VETORES", "IN/OUT", "MAPA", "ASN"]},
    "ataques_inbound":    {"nav": "ATAQUES INBOUND",     "panels": ["LOG ATAQUES", "TOP ASNS", "SERVIDORES"]},
    "infectados_outbound":{"nav": "INFECTADOS OUTBOUND", "panels": ["DISPERSÃO", "PROTOCOLOS", "MAPA3D", "MBPS", "CLIENTES", "PORTAS", "REDES"]},
    "analise_profunda":   {"nav": "ANÁLISE PROFUNDA",    "panels": ["CRONOLOGIA", "RANKING", "VEREDITO: CATEGORIA DO ATAQUE", "MATRIZ FORENSE", "PERFIL COMPORTAMENTAL"]},
}


# ---------------------- parsing: FLOWSPEC feed ----------------------------- #
def _to_int(s: str) -> int:
    return int(re.sub(r"[^\d]", "", s) or 0)


def parse_kpis(body: str) -> dict:
    lines = [ln.strip() for ln in body.splitlines()]
    kpis = {}
    for key, label in _KPI_LABELS.items():
        val = 0
        for i, ln in enumerate(lines):
            if ln.upper() == label:
                for nxt in lines[i + 1:i + 4]:
                    if re.fullmatch(r"[\d.\s]+", nxt) and any(c.isdigit() for c in nxt):
                        val = _to_int(nxt); break
                break
        kpis[key] = val
    return kpis


def parse_sync(body: str) -> str:
    m = re.search(r"Sync:\s*(\d{2}:\d{2}:\d{2})", body)
    return m.group(1) if m else ""


def _parse_incident(chunk: str):
    dt = re.search(r"(\d{2})/(\d{2})/(\d{4}),\s*(\d{2}:\d{2}:\d{2})", chunk)
    if not dt:
        return None
    ts = f"{dt.group(3)}-{dt.group(2)}-{dt.group(1)} {dt.group(4)}"
    m_hit = re.search(r"\d{2}:\d{2}:\d{2}\s+([\d.]+)\s+(CRITICAL|HIGH|INFO)", chunk)
    hits = _to_int(m_hit.group(1)) if m_hit else 0
    level = m_hit.group(2) if m_hit else "INFO"
    m_dir = re.search(r"\b(OUT|IN)([A-Z0-9][^\[\n]*)", chunk)
    direction = m_dir.group(1) if m_dir else ""
    category = m_dir.group(2).strip() if m_dir else ""
    m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", chunk)
    origin_ip = m_ip.group(1) if m_ip else ""
    m_dest = re.search(r"(\d+)\s+(Destinos Externos|Dispositivos Internos)", chunk)
    dest_count = int(m_dest.group(1)) if m_dest else 0
    dest_type = m_dest.group(2) if m_dest else ""
    risks = re.findall(r"(\d+)%", chunk)
    risk = int(risks[-1]) if risks else 0
    country, origin_net = "Interna", "REDE INTERNA"
    if origin_ip and m_dest:
        block = chunk[chunk.find(origin_ip) + len(origin_ip):m_dest.start()]
        parts = [p.strip() for p in block.splitlines() if p.strip()]
        if any("REDE INTERNA" in p.upper() for p in parts):
            country, origin_net = "Interna", "REDE INTERNA"
        elif parts:
            country = parts[0]
            origin_net = " ".join(parts[1:]) if len(parts) > 1 else parts[0]
    return {"ts": ts, "hits": hits, "level": level, "direction": direction,
            "category": category, "origin_ip": origin_ip, "origin_net": origin_net,
            "country": country, "dest_count": dest_count, "dest_type": dest_type, "risk": risk}


def parse_incidents(body: str) -> list:
    starts = [m.start() for m in _DT_RE.finditer(body)]
    out = []
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else len(body)
        inc = _parse_incident(body[s:e])
        if inc:
            out.append(inc)
    return out


# ---------------------- parsing: REPUTACAO ASN ----------------------------- #
def parse_reputacao(txt: str) -> dict:
    """Recebe o innerText do iframe da Reputacao ASN."""
    flat = re.sub(r"\s+", " ", txt)
    def num(rx):
        m = re.search(rx, flat, re.I)
        return _to_int(m.group(1)) if m else None
    asn = (re.search(r"(AS\d+)", flat) or [None, None])[1]
    prefix = (re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", flat) or [None, None])[1]
    saude = (re.search(r"([\d.]+)%\s*SA[UÚ]DE", flat, re.I) or [None, None])[1]
    # tabela Intel Feed: pares IP + status
    intel = []
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})\s+(CR[IÍ]TICO|SAUD[ÁA]VEL|LIMPO|OK)", flat, re.I):
        intel.append({"ip": m.group(1), "status": m.group(2).upper()})
    return {
        "asn": asn, "prefix": prefix,
        "saude_pct": float(saude) if saude else None,
        "total_ips": num(r"TOTAL IPs\s*([\d.]+)"),
        "saudaveis": num(r"SAUD[ÁA]VEIS\s*([\d.]+)"),
        "criticos": num(r"CR[IÍ]TICOS\s*([\d.]+)"),
        "intel_feed": intel[:50],
    }


# ---------------------- coleta por modulo ---------------------------------- #
def _click_nav(page, label: str) -> bool:
    try:
        page.get_by_role("button", name=label, exact=False).first.click(timeout=5000)
        return True
    except Exception:
        try:
            page.get_by_text(label, exact=False).first.click(timeout=5000)
            return True
        except Exception:
            return False


def collect_reputacao(page) -> dict:
    if not _click_nav(page, "Reputação ASN"):
        return {}
    page.wait_for_timeout(4000)
    # procura o frame que contem "SAUDE DA REDE"
    for fr in page.frames:
        try:
            t = fr.locator("body").inner_text(timeout=1500)
        except Exception:
            continue
        if "SAÚDE DA REDE" in t.upper() or "SAUDE DA REDE" in t.upper():
            return parse_reputacao(t)
    return {}


def collect_grafana(page, key: str, meta: dict, wait_ms: int) -> dict:
    """Grafana renderiza devagar: espera wait_ms e le TODOS os frames
    (inclusive iframes aninhados) capturando o texto que aparecer -
    tabelas como Veredito/Perfil saem; graficos SVG dao so rotulos."""
    _click_nav(page, meta["nav"])
    page.wait_for_timeout(wait_ms)
    conteudo = []
    for fr in page.frames:
        try:
            t = fr.locator("body").inner_text(timeout=2000).strip()
        except Exception:
            continue
        t = re.sub(r"[ \t]+", " ", t).strip()
        if len(t) < 15 or t.lower().startswith("powered by"):
            continue
        conteudo.append(t[:1500])
    try:
        body = page.locator("body").inner_text(timeout=3000).upper()
    except Exception:
        body = ""
    present = [p for p in meta["panels"] if p.upper() in body]
    return {"tipo": "grafana", "paineis": meta["panels"],
            "paineis_carregados": present, "conteudo": conteudo[:14]}


# JS executado NA PAGINA (usa a sessao logada): lista dashboards, busca o modelo
# de cada um e reproduz as queries Elasticsearch via /api/ds/query, devolvendo
# os valores reais de cada painel (campos + linhas).
_GRAFANA_API_JS = r"""
async () => {
  const HOURS = 6;
  const now = Date.now();
  const from = String(now - HOURS*3600*1000), to = String(now);
  const DS = 'P31C819B24CF3C3C7';
  const T = (field,size)=>[{id:'2',type:'terms',field:field,settings:{min_doc_count:'1',order:'desc',orderBy:'_count',size:String(size||12)}}];
  const H = [{id:'2',type:'date_histogram',field:'@timestamp',settings:{interval:'5m',min_doc_count:'0'}}];
  const BASE = 'tags:"threat_detected"';
  const IN = BASE + ' AND event.direction:"inbound"';
  const OUT = BASE + ' AND event.direction:"outbound"';
  const SPEC = [
    {dash:'Visão Geral', q:BASE, panels:[
      {title:'Volume de ameaças no tempo', viz:'line', agg:H},
      {title:'Direção do tráfego', viz:'pie', agg:T('event.direction',5)},
      {title:'Países de origem', viz:'rank', agg:T('source.geo.country_name',12)},
      {title:'Países de destino', viz:'rank', agg:T('destination.geo.country_name',12)},
      {title:'Portas mais visadas', viz:'rank', agg:T('destination.port',12)},
      {title:'Protocolos', viz:'pie', agg:T('network.transport',5)},
    ]},
    {dash:'Ataques Inbound', q:IN, panels:[
      {title:'Volume de ataques no tempo', viz:'line', agg:H},
      {title:'Países de origem dos ataques', viz:'rank', agg:T('source.geo.country_name',12)},
      {title:'Operadoras / Redes de origem', viz:'rank', agg:T('source.as.as.organization.name.keyword',12)},
      {title:'Portas alvo', viz:'rank', agg:T('destination.port',12)},
      {title:'IPs internos mais atacados', viz:'rank', agg:T('destination.ip',12)},
      {title:'Protocolos', viz:'pie', agg:T('network.transport',5)},
    ]},
    {dash:'Infectados Outbound', q:OUT, panels:[
      {title:'Volume de saída no tempo', viz:'line', agg:H},
      {title:'Países de destino', viz:'rank', agg:T('destination.geo.country_name',12)},
      {title:'Operadoras / Redes de destino', viz:'rank', agg:T('destination.as.as.organization.name.keyword',12)},
      {title:'IPs internos infectados', viz:'rank', agg:T('source.ip',12)},
      {title:'Portas de destino', viz:'rank', agg:T('destination.port',12)},
      {title:'Protocolos', viz:'pie', agg:T('network.transport',5)},
    ]},
    {dash:'Análise Profunda', q:BASE, panels:[
      {title:'Top IPs de origem', viz:'rank', agg:T('source.ip',15)},
      {title:'Top IPs de destino', viz:'rank', agg:T('destination.ip',15)},
      {title:'Portas mais usadas', viz:'rank', agg:T('destination.port',15)},
      {title:'Operadoras envolvidas (destino)', viz:'rank', agg:T('destination.as.as.organization.name.keyword',15)},
    ]},
  ];
  async function runPanel(q, agg){
    const body={queries:[{refId:'A',datasource:{type:'elasticsearch',uid:DS},query:q,timeField:'@timestamp',
      alias:'',bucketAggs:agg,metrics:[{id:'1',type:'count'}],intervalMs:300000,maxDataPoints:80}],from:from,to:to};
    const j=await (await fetch('/grafana/api/ds/query',{method:'POST',credentials:'include',
      headers:{'content-type':'application/json'},body:JSON.stringify(body)})).json();
    const res=j.results||{}; const k=Object.keys(res)[0]; const fr=(res[k]&&res[k].frames&&res[k].frames[0]);
    if(!fr) return null;
    const fields=((fr.schema&&fr.schema.fields)||[]).map(f=>f.name);
    const vals=(fr.data&&fr.data.values)||[]; const n=vals[0]?vals[0].length:0;
    const rows=[]; for(let i=0;i<Math.min(n,120);i++) rows.push(fields.map((nm,c)=>vals[c]?vals[c][i]:null));
    return {fields:fields, rows:rows};
  }
  const out=[];
  for(const mod of SPEC){
    const panels=[];
    for(const p of mod.panels){
      try{ const r=await runPanel(mod.q, p.agg); if(r) panels.push({title:p.title, viz:p.viz, fields:r.fields, rows:r.rows}); }
      catch(e){}
    }
    out.push({dash:mod.dash, panels:panels});
  }
  return out;
}
"""


def collect_grafana_api(page) -> object:
    """Coleta os dados reais dos paineis do Grafana via API (sessao logada)."""
    return page.evaluate(_GRAFANA_API_JS)


# ---------------------- montagem do snapshot ------------------------------- #
def build_snapshot(page, grafana_wait: int = 12000) -> dict:
    # 1) FLOWSPEC SOC (feed)
    _click_nav(page, "FlowSpec SOC")
    page.wait_for_selector(f"text={READY_MARKER}", timeout=30000)
    page.wait_for_timeout(1200)
    body = page.locator("body").inner_text()

    snap = {
        "collected_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "sync": parse_sync(body),
        "source": "FlowSpec Enterprise SOC (asn-monitor.linknetbandalarga.net)",
        "kpis": parse_kpis(body),
        "incidents": parse_incidents(body),
        "modules": {},
    }

    # 2) REPUTACAO ASN
    try:
        snap["modules"]["reputacao_asn"] = collect_reputacao(page)
    except Exception as e:
        snap["modules"]["reputacao_asn"] = {"erro": str(e)}

    # 3) Grafana via API — dado limpo do Elasticsearch (todos os dashboards)
    try:
        snap["grafana"] = collect_grafana_api(page)
    except Exception as e:
        snap["grafana"] = {"erro": str(e)}

    # volta ao feed pra proxima rodada
    _click_nav(page, "FlowSpec SOC")
    return snap


# ---------------------- git ------------------------------------------------ #
def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def commit_and_push() -> None:
    # stage o repo inteiro (respeitando .gitignore) para publicar tambem o
    # index.html/collector/README na 1a vez; depois so o JSON muda por ciclo.
    git("add", "-A")
    if not git("status", "--porcelain").stdout.strip():
        print("   (sem mudancas)"); return
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c = git("commit", "-m", f"chore(soc): snapshot {stamp}")
    if c.returncode != 0:
        print("   commit:", c.stderr.strip() or c.stdout.strip()); return
    p = git("push")
    print("   push OK" if p.returncode == 0 else "   push FALHOU: " + (p.stderr.strip() or p.stdout.strip()))


# ---------------------- main ----------------------------------------------- #
def ensure_logged_in(page):
    page.goto(URL, wait_until="domcontentloaded")
    try:
        page.wait_for_selector(f"text={READY_MARKER}", timeout=4000); return
    except Exception:
        pass
    print("\n>>> Faca LOGIN na janela do navegador. A coleta comeca quando o feed aparecer.\n")
    page.wait_for_selector(f"text={READY_MARKER}", timeout=0)


def collect_once(page, do_git: bool, grafana_wait: int = 12000):
    snap = build_snapshot(page, grafana_wait)
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    rep = snap["modules"].get("reputacao_asn", {})
    graf = snap.get("grafana")
    n_g = len(graf) if isinstance(graf, list) else 0
    n_pan = sum(len(d.get("panels", [])) for d in graf) if isinstance(graf, list) else 0
    print(f"[{snap['collected_at']}] sync={snap['sync']} "
          f"incidentes={len(snap['incidents'])} "
          f"asn_saude={rep.get('saude_pct')}% intel={len(rep.get('intel_feed', []))} "
          f"grafana={n_g}dash/{n_pan}paineis")
    if do_git:
        commit_and_push()


def _pick_page(ctx):
    """Reaproveita a aba do ASN Monitor; se nao existir, abre UMA aba nova
    (na sua janela, nao uma janela separada)."""
    for p in ctx.pages:
        if "asn-monitor" in (p.url or ""):
            return p
    return ctx.new_page()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=30, help="segundos entre coletas")
    ap.add_argument("--grafana-wait", type=int, default=12000,
                    help="ms de espera para o Grafana renderizar (default 12000)")
    ap.add_argument("--cdp", default="http://localhost:9222",
                    help="endereco do seu Chrome aberto com --remote-debugging-port")
    ap.add_argument("--own-window", action="store_true",
                    help="abre uma janela propria (perfil .soc-profile) em vez de anexar ao seu Chrome")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--no-git", action="store_true")
    args = ap.parse_args()
    do_git = not args.no_git

    with sync_playwright() as pw:
        browser = None
        attached = False

        # 1) tenta ANEXAR ao seu Chrome (aberto via start-chrome-debug.bat)
        if not args.own_window:
            try:
                browser = pw.chromium.connect_over_cdp(args.cdp, timeout=5000)
                attached = True
            except Exception:
                print(">>> Nao encontrei um Chrome com depuracao em", args.cdp)
                print(">>> Abra o seu Chrome pelo atalho 'start-chrome-debug.bat' (uma vez),")
                print(">>> faca login no ASN Monitor, e deixe rodando. Depois rode este coletor.")
                print(">>> (alternativa: rode 'python collector.py --own-window' para janela propria)")
                return 1

        if attached:
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = _pick_page(ctx)
            print(">>> Anexado ao seu Chrome em", args.cdp)
        else:
            for lock in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
                try:
                    (PROFILE_DIR / lock).unlink()
                except Exception:
                    pass
            ctx = pw.chromium.launch_persistent_context(
                user_data_dir=str(PROFILE_DIR), headless=False,
                viewport={"width": 1500, "height": 900})
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

        ensure_logged_in(page)

        try:
            if args.once:
                collect_once(page, do_git, args.grafana_wait)
                return 0
            print(f">>> Coletando a cada {args.interval}s. Ctrl+C para parar.\n")
            while True:
                t0 = time.time()
                try:
                    # se a janela do Chrome caiu/fechou, reanexa
                    if attached:
                        need = page is None
                        if not need:
                            try:
                                need = page.is_closed()
                            except Exception:
                                need = True
                        if need:
                            browser = pw.chromium.connect_over_cdp(args.cdp, timeout=5000)
                            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
                            page = _pick_page(ctx)
                            ensure_logged_in(page)
                            print(">>> Reanexado ao seu Chrome.")
                    collect_once(page, do_git, args.grafana_wait)
                except Exception as e:
                    print("   erro na coleta:", e)
                    if attached:
                        page = None  # forca reconexao no proximo ciclo
                dt = args.interval - (time.time() - t0)
                if dt > 0:
                    time.sleep(dt)
        except KeyboardInterrupt:
            print("\n>>> Encerrado.")
        finally:
            # quando anexado, NAO fecha o seu navegador — so desconecta
            if not attached:
                try:
                    ctx.close()
                except Exception:
                    pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
