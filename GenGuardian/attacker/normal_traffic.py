#!/usr/bin/env python3
"""
normal_traffic_sim.py (versão final)

- Simula tráfego legítimo realista contra TARGET_IP (páginas, imagens, vídeo).
- Tokens do RateController iniciam aleatoriamente (evita bursts sincronizados).
- Por padrão usa Range requests para vídeo (streaming); toggle via VIDEO_USE_RANGE.
- Não faz XHR/JS.
- Grava resultados em JSONL e envia actions ao detector (se presente).

Uso:
    pip3 install requests
    python3 normal_traffic_sim.py
"""

import os
import time
import json
import random
import math
from datetime import datetime, timedelta
from urllib.parse import urljoin

import requests

# ---------------- CONFIGURAÇÃO ----------------
WORKDIR = "/home/pedro"
TARGET_IP = "192.168.56.3"               # IP do servidor alvo
BASE_HOST = f"http://{TARGET_IP}"
SITE_PREFIX = "/mysite"
BASE_URL = f"{BASE_HOST}{SITE_PREFIX}/"
OUTPUT_JSONL = os.path.join(WORKDIR, "resultados_normal_only.jsonl")

REPETICOES = 10
CONCURRENT_SESSIONS = 2
MAX_REQUEST_TIMEOUT = 12
POST_WAIT = 1.5
MAX_BODY_SNIPPET = 1024

# Rate control
MAX_RPS = 1.0
BURST_CAPACITY = 4

# Tunáveis de naturalidade
MIN_THINK_MEDIAN = 0.8
THINK_SIGMA = 0.6
PROB_POST = 0.08
PROB_HEAD = 0.14
PROB_LONG_IDLE = 0.12
LONG_IDLE_RANGE = (12.0, 40.0)

RECENT_ROUTES_WINDOW = 8

# Vídeo: True = usa Range requests (streaming parcial). False = GET completo do ficheiro.
VIDEO_USE_RANGE = True

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "curl/8.2.1",
    "Wget/1.21.3 (linux-gnu)",
]

SITEMAP = [
    "/", "/about.html", "/gallery.html", "/video.html", "/contact.html"
] + [f"/product-{i}.html" for i in range(1, 13)]

DETECTOR_IA_URL = "http://192.168.56.1:3000/ia"
CHECK_ANALISE_URL = "http://192.168.56.1:3000/analise"

# ---------------- UTILITÁRIOS ----------------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def append_jsonl(record, path=OUTPUT_JSONL):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def sample_think_time(mu=MIN_THINK_MEDIAN, sigma=THINK_SIGMA):
    try:
        val = random.lognormvariate(math.log(mu), sigma)
    except Exception:
        val = mu
    return max(0.05, val)

def route_to_url(route):
    if route.startswith(SITE_PREFIX):
        return BASE_HOST + route
    if not route.startswith("/"):
        route = "/" + route
    return BASE_HOST + SITE_PREFIX + route if SITE_PREFIX and SITE_PREFIX != "/" else BASE_HOST + route

def safe_fetch(session, method, url, headers=None, stream=True, timeout=MAX_REQUEST_TIMEOUT):
    try:
        r = session.request(method, url, headers=headers or {}, timeout=timeout, stream=stream)
    except Exception as e:
        return {"ok": False, "method": method, "url": url, "error": str(e)}

    content_type = r.headers.get("Content-Type", "") or ""
    total = 0
    text_snippet = None

    if any(t in content_type.lower() for t in ("text/", "json", "javascript", "xml", "css")):
        parts = []
        read = 0
        try:
            for chunk in r.iter_content(4096):
                if not chunk:
                    break
                parts.append(chunk)
                read += len(chunk)
                total += len(chunk)
                if read >= (MAX_BODY_SNIPPET * 2):
                    break
            for chunk in r.iter_content(65536):
                if not chunk:
                    break
                total += len(chunk)
            try:
                joined = b"".join(parts)
                text_snippet = joined.decode(errors="replace")[:MAX_BODY_SNIPPET]
            except Exception:
                text_snippet = None
        except Exception:
            try:
                txt = r.text
                text_snippet = txt[:MAX_BODY_SNIPPET]
                total = len(txt.encode(errors="replace"))
            except Exception:
                text_snippet = None
    else:
        try:
            for chunk in r.iter_content(65536):
                if not chunk:
                    break
                total += len(chunk)
        except Exception:
            pass

    hdrs = dict(r.headers)
    status = r.status_code
    r.close()
    return {"ok": True, "method": method, "url": url, "status": status, "len": total, "content_type": content_type, "text_snippet": text_snippet, "headers": hdrs}

# ---------------- Rate Controller ----------------
class RateController:
    def __init__(self, max_rps=MAX_RPS, capacity=BURST_CAPACITY):
        self.rate = float(max_rps)
        self.capacity = float(capacity)
        # **inicialização aleatória de tokens** para evitar bursts sincronizados
        self.tokens = random.uniform(0.0, self.capacity)
        self.last = time.time()

    def wait_for_token(self):
        now = time.time()
        elapsed = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return
        need = 1.0 - self.tokens
        wait = need / self.rate
        # adicionar pequeno jitter
        wait *= random.uniform(0.9, 1.15)
        time.sleep(wait)
        self.tokens = 0.0
        return

# ---------------- Cenários ----------------
def make_session():
    s = requests.Session()
    s.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8",
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate",
    })
    return s

def pick_ua():
    return random.choice(USER_AGENTS)

def choose_route_avoid_recent(recent):
    choices = [r for r in SITEMAP if r not in recent]
    if not choices:
        choices = SITEMAP[:]
    return random.choice(choices)

def scenario_browse_realistic(session, recent_routes, rc: RateController):
    """
    Cenário de navegação realista:
      - GET das páginas do sitemap
      - GET de imagens e CSS
      - Vídeo: por padrão usa Range requests (se VIDEO_USE_RANGE True), senão GET completo
      - Mantém Referer / User-Agent variáveis
    """
    start = now_iso()
    actions = []
    steps = random.randint(2, 5)
    current_ref = None

    for _ in range(steps):
        route = choose_route_avoid_recent(recent_routes)
        url = route_to_url(route)
        method = "GET"
        headers = {"User-Agent": pick_ua()}
        if current_ref:
            headers["Referer"] = current_ref
        if random.random() < 0.12:
            ims = (datetime.utcnow() - timedelta(days=random.randint(1, 60))).strftime("%a, %d %b %Y %H:%M:%S GMT")
            headers["If-Modified-Since"] = ims

        rc.wait_for_token()
        res = safe_fetch(session, method, url, headers=headers)
        actions.append((method, url, res))

        # carregar imagens (1-4)
        img_count = random.randint(1, 4)
        for i in range(img_count):
            img_index = random.randint(1, 8)
            img_route = f"/assets/images/img{img_index}.jpg"
            img_url = route_to_url(img_route)
            img_headers = {"User-Agent": pick_ua(), "Referer": url}
            rc.wait_for_token()
            img_res = safe_fetch(session, "GET", img_url, headers=img_headers)
            actions.append(("GET", img_url, img_res))
            time.sleep(sample_think_time(mu=0.12, sigma=0.5))

        # carregar CSS ocasionalmente
        if random.random() < 0.6:
            css_route = "/assets/css/styles.css"
            css_url = route_to_url(css_route)
            css_headers = {"User-Agent": pick_ua(), "Referer": url}
            rc.wait_for_token()
            css_res = safe_fetch(session, "GET", css_url, headers=css_headers)
            actions.append(("GET", css_url, css_res))
            time.sleep(sample_think_time(mu=0.05, sigma=0.3))

        # vídeo: parcial (Range) ou GET completo dependendo da flag
        wants_video = ("video" in route) or (random.random() < 0.18)
        if wants_video:
            video_route = "/assets/video/sample.mp4"
            video_url = route_to_url(video_route)
            if VIDEO_USE_RANGE:
                # pedir um chunk inicial e possivelmente um segundo chunk
                start_byte = 0
                end_byte = random.randint(50000, 300000)
                vh = {"User-Agent": pick_ua(), "Referer": url, "Range": f"bytes={start_byte}-{end_byte}"}
                rc.wait_for_token()
                video_res = safe_fetch(session, "GET", video_url, headers=vh)
                actions.append(("GET", video_url, video_res))
                if random.random() < 0.35:
                    time.sleep(sample_think_time(mu=0.18, sigma=0.4))
                    start2 = end_byte + 1
                    end2 = start2 + random.randint(80000, 400000)
                    vh2 = {"User-Agent": pick_ua(), "Referer": url, "Range": f"bytes={start2}-{end2}"}
                    rc.wait_for_token()
                    video_res2 = safe_fetch(session, "GET", video_url, headers=vh2)
                    actions.append(("GET", video_url, video_res2))
            else:
                # GET completo (pode ser pesado)
                vh = {"User-Agent": pick_ua(), "Referer": url}
                rc.wait_for_token()
                video_res = safe_fetch(session, "GET", video_url, headers=vh)
                actions.append(("GET", video_url, video_res))
            time.sleep(sample_think_time(mu=0.4, sigma=0.7))

        recent_routes.append(route)
        if len(recent_routes) > RECENT_ROUTES_WINDOW:
            recent_routes.pop(0)
        current_ref = url

        time.sleep(sample_think_time())

    end = now_iso()
    return {"nome": "scenario_browse_realistic", "actions": actions, "start": start, "end": end, "label": "normal"}

SCENARIO_FUNCS = [
    scenario_browse_realistic
]

# ---------------- DETECTOR COM EXECID ----------------
def fetch_detector_by_exec(actions, timeout_total=60, poll_interval=3):
    payload = {"actions": actions}
    try:
        r = requests.post(DETECTOR_IA_URL, json=payload, timeout=35)
        r.raise_for_status()
        data = r.json()
        exec_id = data.get("execId")
        if not exec_id:
            return {"error": "no_execId", "raw": data}
    except Exception as e:
        return {"error": f"post_exception:{str(e)}"}

    elapsed = 0
    while elapsed < timeout_total:
        try:
            check_r = requests.get(f"{CHECK_ANALISE_URL}/{exec_id}", timeout=35)
            if check_r.status_code == 200:
                try:
                    return check_r.json()
                except Exception:
                    return {"error": "invalid_json_in_check", "text": check_r.text}
            elif check_r.status_code == 404:
                time.sleep(poll_interval)
                elapsed += poll_interval
            else:
                check_r.raise_for_status()
        except Exception as e:
            time.sleep(poll_interval)
            elapsed += poll_interval
    return {"error": "timeout_waiting_analysis", "execId": exec_id}

# ---------------- Runner ----------------
# ---------------- Runner ----------------
def run_simulation():
    print("=== Iniciando simulação natural (mesmo IP, múltiplas sessões) ===")
    sessions = [make_session() for _ in range(CONCURRENT_SESSIONS)]
    recent_routes_per_session = [[] for _ in range(CONCURRENT_SESSIONS)]
    rc = RateController()

    seq = []
    for _ in range(REPETICOES):
        funcs = SCENARIO_FUNCS.copy()
        random.shuffle(funcs)
        seq.extend(funcs)

    try:
        for scenario_fn in seq:
            idx = random.randrange(len(sessions))
            session = sessions[idx]
            recent = recent_routes_per_session[idx]

            pre = random.uniform(0.8, 4.5)
            time.sleep(pre)

            ts_start = now_iso()
            scenario_name = scenario_fn.__name__
            print(f"[{ts_start}] Sessão {idx} executando cenário: {scenario_name}")

            try:
                result = scenario_fn(session, recent, rc)
            except Exception as exc:
                result = {"nome": scenario_name, "error": str(exc), "start": ts_start, "end": now_iso(), "label": "normal"}

            time.sleep(POST_WAIT)
            det = fetch_detector_by_exec(result.get("actions", []), timeout_total=60, poll_interval=3)

            # Extrai summary e execId
            det_summary = det.get("dos_attack_probability") if isinstance(det, dict) else None
            det_summary_val = int(det_summary) if isinstance(det_summary, (int, float)) else det.get("error", "no_prob")
            exec_id = det.get("execId")

            # Imprime com execId ao lado
            print(f"[{now_iso()}] Cenário {scenario_name} (sessão {idx}) concluído. detector summary: {det_summary_val} ; execId: {exec_id}")

            # Registra no JSONL
            registro = {
                "timestamp_start": ts_start,
                "timestamp_end_scenario": now_iso(),
                "session_index": idx,
                "cenario": result.get("nome", scenario_name),
                "label_real": result.get("label", "normal"),
                "detector_execId": exec_id,
                "detector_summary": det_summary_val,
                "scenario_result": result,
                "detector_result": det,
            }
            append_jsonl(registro)

            if random.random() < PROB_LONG_IDLE:
                long_idle = random.uniform(*LONG_IDLE_RANGE)
                print(f"[{now_iso()}] Inserindo idle longo de {long_idle:.1f}s para naturalidade.")
                time.sleep(long_idle)

            time.sleep(1.0 + random.uniform(0, 2.5))

    except KeyboardInterrupt:
        print("Interrompido pelo usuário (Ctrl-C). Saindo.")
    finally:
        print("=== Simulação completa ===")
        print(f"Resultados gravados em: {OUTPUT_JSONL}")


if __name__ == "__main__":
    run_simulation()
