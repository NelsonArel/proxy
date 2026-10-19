#!/usr/bin/env python3
"""MakeItEarn - сбор и проверка прокси на GitHub Actions.
Всё тяжёлое здесь, а не в n8n: сбор из источников, память «что уже проверяли», проверка тысяч прокси.
В n8n уходит только итог - список рабочих (сотни строк), который заменяет таблицу целиком.

Память хранится в файле state.json между запусками (кэш GitHub Actions), поэтому:
  - новые адреса проверяются один раз, дальше - по расписанию ниже;
  - рабочие перепроверяются каждый запуск ОТДЕЛЬНО от новых (своя умеренная нагрузка), с повтором при неудаче;
    из рабочих прокси выбывает только после ALIVE_FAILS неудач подряд (бесплатные прокси «мигают»);
  - мёртвые перепроверяются по нарастающей (2 ч, 6 ч, 24 ч, 72 ч) - даже если источник их уже убрал:
    многие бесплатные прокси через время снова начинают работать;
  - мёртвые хранятся KEEP_DEAD_D дней с последней удачной проверки.
Поля результата: proxy, status, protocol, country, latency, last_checked, added."""
import asyncio, json, os, random, re, time
from datetime import datetime, timezone
import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType

RESULT_URL = os.environ["RESULT_URL"]                 # вебхук n8n, принимает итоговый список рабочих
AUTH = os.environ.get("WEBHOOK_TOKEN", "")
CONC = int(os.environ.get("CONCURRENCY", "2000"))
TIMEOUT = float(os.environ.get("TIMEOUT", "8"))
RECHECK_ALIVE_MIN = float(os.environ.get("RECHECK_ALIVE_MIN", "10"))   # в быстром режиме (каждые 15 мин) рабочие проверяются каждый раз
MODE = os.environ.get("MODE", "full")            # full - сбор новых + проверка; alive - только перепроверка рабочих
RECHECK_DEAD_H = float(os.environ.get("RECHECK_DEAD_H", "72"))   # мёртвые - повторно не чаще раза в 3 суток
NEW_TIMEOUT = float(os.environ.get("NEW_TIMEOUT", "6"))            # таймаут для ещё не проверенных адресов
MAX_NEW = int(os.environ.get("MAX_NEW", "150000"))                 # не больше стольких непроверенных за полный прогон - остальное в следующих
STATE = os.environ.get("STATE_FILE", "state/state.json")
ALIVE_FAILS = int(os.environ.get("ALIVE_FAILS", "3"))              # из рабочих - только после стольких неудач подряд
ALIVE_CONC = int(os.environ.get("ALIVE_CONCURRENCY", "400"))       # рабочие - отдельно и без перегрузки (иначе ложные «смерти»)
ALIVE_TIMEOUT = float(os.environ.get("ALIVE_TIMEOUT", "10"))
RETRY_TIMEOUT = float(os.environ.get("RETRY_TIMEOUT", "15"))       # повтор не ответившего рабочего - другой адрес проверки, дольше
DEAD_BACKOFF_H = [float(x) for x in os.environ.get("DEAD_BACKOFF_H", "2,6,24,72").split(",")]   # когда перепроверять мёртвые
MAX_DEAD = int(os.environ.get("MAX_DEAD", "60000"))                # мёртвых на перепроверку за полный прогон
KEEP_DEAD_D = float(os.environ.get("KEEP_DEAD_D", "21"))
RECHECK_ALL = os.environ.get("RECHECK_ALL", "1") == "1"            # полный прогон перепроверяет ВСЮ память, а не только тех, у кого подошёл срок
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "4"))    # мёртвые обычно не отвечают даже на подключение - не ждём их весь таймаут
CHUNK = int(os.environ.get("CHUNK", "40000"))                      # память сохраняется после каждой такой части (не теряется при обрыве)
TIME_BUDGET_MIN = float(os.environ.get("TIME_BUDGET_MIN", "95"))   # не начинать новые части позже этого (запуск должен успеть сохраниться)
PUBLISH_FAILS = int(os.environ.get("PUBLISH_FAILS", "1"))          # в n8n - рабочие, не ответившие не больше стольких раз подряд
T_START = time.time()
SEND_UNTIL_MIN = float(os.environ.get("SEND_UNTIL_MIN", "105"))     # до какой минуты запуска повторять отправку в n8n
GEO = os.environ.get("GEO_DB", "geo.mmdb")        # база стран DB-IP (dbip-country-lite, CC BY 4.0)
HEADERS = {"Authorization": "Bearer " + AUTH} if AUTH else {}

SOURCES = [
  ("http", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxytype=http"),
  ("socks5", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxytype=socks5"),
  ("socks4", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxytype=socks4"),
  ("http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
  ("socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
  ("socks4", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt"),
  ("http", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt"),
  ("socks5", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
  ("socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
  ("socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"),
  ("http", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"),
  ("socks5", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"),
  ("socks5", "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt"),
  ("socks5", "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"),
  # ── добавлено в v224: открытые списки на GitHub, проверенные на доступность ──
  ("socks4", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt"),
  ("socks5", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt"),
  ("socks4", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt"),
  ("socks5", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt"),
  ("socks4", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt"),
  ("http", "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt"),
  ("http", "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt"),
  ("socks4", "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt"),
  ("socks5", "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt"),
  ("socks4", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt"),
  ("http", "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt"),
  ("socks4", "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt"),
  ("socks5", "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt"),
  ("http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt"),
  ("socks4", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt"),
  ("socks5", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt"),
  ("http", "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt"),
  ("socks4", "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks4_proxies.txt"),
  ("socks5", "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt"),
  ("http", "https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt"),
  ("socks5", "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/http_proxies.txt"),
  ("socks4", "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/socks4_proxies.txt"),
  ("socks5", "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/socks5_proxies.txt"),
  ("http", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt"),
  ("socks5", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt"),
  ("http", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt"),
  ("socks4", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt"),
  ("socks5", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"),
  ("http", "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/http/global/http_checked.txt"),
  ("socks4", "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/socks4/global/socks4_checked.txt"),
  ("socks5", "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/socks5/global/socks5_checked.txt"),
  ("http", "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt"),
  ("http", "https://raw.githubusercontent.com/saisuiu/Lionkings-Http-Proxys-Proxies/main/free.txt"),
  ("http", "https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/http.txt"),
  ("socks4", "https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/socks4.txt"),
  ("socks5", "https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/socks5.txt"),
  ("http", "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/http.txt"),
  ("socks4", "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks4.txt"),
  ("socks5", "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks5.txt"),
  # ── сайты вне GitHub (доступность не проверена заранее: если не ответит - проверка его пропустит) ──
  ("http", "https://proxyspace.pro/http.txt"),
  ("http", "https://proxyspace.pro/https.txt"),
  ("socks4", "https://proxyspace.pro/socks4.txt"),
  ("socks5", "https://proxyspace.pro/socks5.txt"),
  ("http", "https://spys.me/proxy.txt"),
  ("socks5", "https://spys.me/socks.txt"),
  ("http", "https://www.proxy-list.download/api/v1/get?type=http"),
  ("http", "https://www.proxy-list.download/api/v1/get?type=https"),
  ("socks4", "https://www.proxy-list.download/api/v1/get?type=socks4"),
  ("socks5", "https://www.proxy-list.download/api/v1/get?type=socks5"),
  ("http", "https://api.openproxylist.xyz/http.txt"),
  ("socks4", "https://api.openproxylist.xyz/socks4.txt"),
  ("socks5", "https://api.openproxylist.xyz/socks5.txt"),
  ("geonode", "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc"),
  ("geonode", "https://proxylist.geonode.com/api/proxy-list?limit=500&page=2&sort_by=lastChecked&sort_type=desc"),
  ("geonode", "https://proxylist.geonode.com/api/proxy-list?limit=500&page=3&sort_by=lastChecked&sort_type=desc"),
]
CHECK_URLS = ["http://ip-api.com/json/?fields=query,countryCode", "http://ipinfo.io/json",
              "http://ifconfig.me/all.json", "http://api.ipify.org?format=json", "http://checkip.amazonaws.com"]
# «судьи» анонимности: показывают, какие заголовки дошли до сервера через прокси
JUDGES = ["http://httpbin.org/headers", "http://azenv.net/", "http://www.proxy-listen.de/azenv.php"]
# заголовки-«выдачи» прокси: и в виде X-Forwarded-For (httpbin), и в виде HTTP_X_FORWARDED_FOR (azenv)
LEAK = re.compile(r"(?i)(?:^|[^a-z0-9])(via|x[-_]forwarded[-_]for|x[-_]forwarded|forwarded|x[-_]real[-_]ip|x[-_]proxy[-_]id|proxy[-_]connection|client[-_]ip)(?:[^a-z0-9]|$)")
IP_PORT = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}$")
ANY_IP = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})(?!\d)")
RANK = {"socks5": 3, "socks4": 2, "http": 1}
now_iso = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")

def norm(line, default):
    line = line.strip()
    if not line or line.startswith("#"): return None
    proto = default
    m = re.match(r"^(https?|socks[45])://(.+)$", line, re.I)
    if m: proto = m.group(1).lower().replace("https", "http"); line = m.group(2)
    line = line.split("@")[-1].split(" ")[0].strip()
    if not IP_PORT.match(line): return None
    ip, port = line.split(":"); o = [int(x) for x in ip.split(".")]
    if max(o) > 255 or not (1 <= int(port) <= 65535): return None
    if o[0] in (0, 10, 127) or (o[0] == 192 and o[1] == 168) or (o[0] == 172 and 16 <= o[1] <= 31): return None
    return proto, line

_geo = None
def geo_country(ip):
    """Страна по своей базе DB-IP: без лимитов и сторонних сайтов. Пусто, если базы нет."""
    global _geo
    if _geo is None:
        try:
            import maxminddb; _geo = maxminddb.open_database(GEO)
        except Exception:
            _geo = False
    if not _geo or not ip: return ""
    try:
        rec = _geo.get(ip) or {}
        return ((rec.get("country") or {}).get("iso_code") or "").upper()
    except Exception:
        return ""

def parse_ip(text):
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", text or ""); ip = m.group(0) if m else None
    cm = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', text or "") or re.search(r'"country"\s*:\s*"([A-Z]{2})"', text or "")
    return ip, (cm.group(1) if cm else "")

def connector(proto, addr):
    ip, port = addr.split(":")
    t = {"http": ProxyType.HTTP, "socks4": ProxyType.SOCKS4, "socks5": ProxyType.SOCKS5}[proto]
    return ProxyConnector(proxy_type=t, host=ip, port=int(port), rdns=True)

async def anonymity(proto, addr, my):
    """SOCKS не добавляет заголовков - элитный. HTTP: если до сервера дошли Via / X-Forwarded-For и т.п.
    или наш адрес - анонимный (адрес скрыт, но видно, что это прокси); иначе - элитный."""
    if proto != "http": return "elite"
    for url in JUDGES:
        try:
            async with aiohttp.ClientSession(connector=connector(proto, addr)) as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
                    if r.status != 200: continue
                    text = await r.text()
        except Exception:
            continue
        if my and my in text: return "transparent"
        return "anonymous" if LEAK.search(text) else "elite"
    return ""

async def check(addr, protos, my, sem, timeout=None, shift=0):
    timeout = timeout or TIMEOUT
    async with sem:
        for proto in sorted(protos, key=lambda p: -RANK.get(p, 0)):
            t0 = time.monotonic()
            try:
                async with aiohttp.ClientSession(connector=connector(proto, addr)) as s:
                    async with s.get(CHECK_URLS[(hash(addr) + shift) % len(CHECK_URLS)], timeout=aiohttp.ClientTimeout(total=timeout, sock_connect=min(CONNECT_TIMEOUT, timeout))) as r:
                        if r.status != 200: continue
                        text = await r.text()
            except Exception:
                continue
            via, cc = parse_ip(text)
            if via and via != my:
                lat = int((time.monotonic() - t0) * 1000)
                anon = await anonymity(proto, addr, my)
                if anon == "transparent": return addr, {"status": "dead"}     # выдаёт наш адрес - не годится
                return addr, {"status": "alive", "protocol": proto, "country": geo_country(via) or cc, "exit_ip": via, "latency": lat, "anonymity": anon}
    return addr, {"status": "dead"}

def load_state():
    try:
        with open(STATE) as f: return json.load(f)
    except Exception:
        return {}

def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE, "w") as f: json.dump(st, f)

def now_plus_h(h):
    return datetime.fromtimestamp(time.time() + h * 3600, timezone.utc).isoformat(timespec="seconds")

def due(iso):   # срок наступил?
    try: return datetime.fromisoformat(iso) <= datetime.now(timezone.utc)
    except Exception: return True

def age_min(iso):
    try: return (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds() / 60
    except Exception: return 1e9

async def main():
    state = load_state()   # proxy -> {status, protocol, country, latency, last_checked, added}
    async with aiohttp.ClientSession(headers={"User-Agent": "MakeItEarn-ProxyCheck/2.0"}) as s:
        # свой адрес (чтобы отсеять прозрачные)
        my = None
        for u in ["http://ip-api.com/json/?fields=query", "http://api.ipify.org?format=json"]:
            try:
                async with s.get(u, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    j = await r.json(content_type=None); my = j.get("query") or j.get("ip"); break
            except Exception: continue
        # сбор
        found = {}
        stat = {}
        async def grab(default, url):
            try:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r: text = await r.text(errors="ignore")
            except Exception: stat[url] = -1; return
            n0 = len(found)
            if default == "geonode":                      # JSON: data[].ip, port, protocols[]
                try:
                    for it in json.loads(text).get("data", []):
                        for pr in (it.get("protocols") or ["http"]):
                            p = norm("%s:%s" % (it.get("ip", ""), it.get("port", "")), "http" if pr == "https" else pr)
                            if p and p[0] in RANK: found.setdefault(p[1], set()).add(p[0])
                except Exception: pass
            else:
                for ln in text.splitlines():
                    ln = ln.strip()
                    m = ANY_IP.search(ln)
                    if not m: continue
                    pref = re.match(r"^(https?|socks[45])://", ln, re.I)
                    p = norm((pref.group(0) if pref else "") + m.group(1), default)
                    if p: found.setdefault(p[1], set()).add(p[0])
            stat[url] = len(found) - n0
        if MODE == "full":
            await asyncio.gather(*[grab(d, u) for d, u in SOURCES])
    print(f"режим {MODE}: собрано {len(found)} уникальных из {len(SOURCES)} источников, в памяти {len(state)}, свой ip {my}", flush=True)
    if MODE == "full":
        dead_src = [u for u, n in stat.items() if n == -1]
        print(f"источников не ответило: {len(dead_src)}" + (" (" + ", ".join(u.split("/")[2] for u in dead_src[:8]) + ")" if dead_src else ""), flush=True)

    t = now_iso()
    stat = {"alive_ok": 0, "alive_flaky": 0, "alive_dropped": 0, "revived": 0, "new_alive": 0, "dead_checked": 0, "new_checked": 0}

    # ── 1. рабочие: каждый запуск, отдельно от новых (своя умеренная нагрузка), повтор при неудаче ──
    alive_set = [a for a, e in state.items() if e.get("status") == "alive"]
    if alive_set:
        sem_a = asyncio.Semaphore(ALIVE_CONC)
        protos_of = lambda a: {state[a].get("protocol", "http")} | set(found.get(a, set())) if state[a].get("protocol") else {"http", "socks5", "socks4"} | set(found.get(a, set()))
        res_a = dict(await asyncio.gather(*[check(a, protos_of(a), my, sem_a, ALIVE_TIMEOUT) for a in alive_set]))
        retry = [a for a, r in res_a.items() if r["status"] != "alive"]
        if retry:   # не ответил - ещё раз: другой адрес проверки и таймаут дольше (сеть и сайты проверки тоже иногда тормозят)
            res_a.update(dict(await asyncio.gather(*[check(a, protos_of(a), my, sem_a, RETRY_TIMEOUT, shift=1) for a in retry])))
        t1 = now_iso()   # время окончания проверки рабочих
        for a, r in res_a.items():
            e = state[a]
            if r["status"] == "alive":
                e.update(status="alive", fails=0, last_checked=t1, last_alive=t1, protocol=r["protocol"], country=r["country"], latency=r["latency"], exit_ip=r.get("exit_ip", ""), anonymity=r.get("anonymity", "")); stat["alive_ok"] += 1
            else:
                e["fails"] = e.get("fails", 0) + 1; e["last_checked"] = t1
                # в мёртвые переводит только полный прогон: быстрые проверки не убирают рабочих из памяти
                if MODE != "alive" and e["fails"] >= ALIVE_FAILS:   # несколько неудач подряд - в мёртвые, но перепроверим уже через 2 часа
                    e.update(status="dead", dead_n=1, next_check=now_plus_h(DEAD_BACKOFF_H[0])); stat["alive_dropped"] += 1
                else: stat["alive_flaky"] += 1
        print(f"рабочие ({'быстрая проверка' if MODE == 'alive' else 'полный прогон'}): ответили {stat['alive_ok']}, временно не ответили {stat['alive_flaky']}, выбыли после {ALIVE_FAILS} неудач подряд {stat['alive_dropped']}", flush=True)
        if MODE != "alive": save_state(state)

    # ── 2. полный прогон: новые из источников и мёртвые, у которых подошёл срок перепроверки (даже если источник их убрал) ──
    res = []
    if MODE != "alive":
        new = [a for a in found if a not in state]
        if len(new) > MAX_NEW:
            print(f"новых больше лимита: {len(new)}, сейчас берём {MAX_NEW}, остальные - в следующих полных прогонах", flush=True); new = new[:MAX_NEW]
        # старые записи без расписания (накопленные прежней версией): перепроверяем все в ближайшие сутки, вразброс -
        # среди них много прокси, которые уже снова работают
        for e in state.values():
            if e.get("status") == "dead" and "next_check" not in e:
                e["dead_n"] = 2; e["next_check"] = now_plus_h(random.random() * 24)
        dead = [a for a, e in state.items() if e.get("status") == "dead" and (RECHECK_ALL or due(e.get("next_check", "")))]
        dead.sort(key=lambda a: state[a].get("last_checked", ""))   # первыми - те, кого дольше всего не проверяли
        if not RECHECK_ALL and len(dead) > MAX_DEAD: dead = dead[:MAX_DEAD]
        queue = [(a, set(found[a]), NEW_TIMEOUT) for a in new] + [(a, set(found.get(a, set())) | ({state[a]["protocol"]} if state[a].get("protocol") else {"http", "socks5", "socks4"}), TIMEOUT) for a in dead]
        stat["new_checked"], stat["dead_checked"] = len(new), len(dead)
        print(f"проверяем: новых {len(new)}, из памяти {len(dead)} (всего в памяти {len(state)}), частями по {CHUNK}", flush=True)
        sem = asyncio.Semaphore(CONC)
        done_n = 0
        for i in range(0, len(queue), CHUNK):
            if (time.time() - T_START) / 60 > TIME_BUDGET_MIN:
                print(f"время прогона на исходе - остановились на {done_n} из {len(queue)}; остальные проверятся первыми в следующем полном прогоне", flush=True); break
            part = queue[i:i + CHUNK]
            res_p = await asyncio.gather(*[check(a, p_, my, sem, to) for a, p_, to in part])
            res += res_p; done_n += len(part)
            for addr, r in res_p:
                prev = state.get(addr)
                if r["status"] == "alive":
                    if prev and prev.get("status") == "dead": stat["revived"] += 1
                    elif not prev: stat["new_alive"] += 1
                    tn = now_iso()
                    state[addr] = {"status": "alive", "fails": 0, "last_checked": tn, "last_alive": tn, "added": (prev or {}).get("added", tn), "protocol": r["protocol"], "country": r["country"],
                                   "latency": r["latency"], "exit_ip": r.get("exit_ip", ""), "anonymity": r.get("anonymity", "")}
                else:
                    n = ((prev or {}).get("dead_n", 0) if prev and prev.get("status") == "dead" else 0) + 1
                    state[addr] = {"status": "dead", "dead_n": n, "last_checked": now_iso(), "next_check": now_plus_h(DEAD_BACKOFF_H[min(n - 1, len(DEAD_BACKOFF_H) - 1)]),
                                   "added": (prev or {}).get("added", t), "last_alive": (prev or {}).get("last_alive", ""), "protocol": (prev or {}).get("protocol", "")}
            save_state(state)   # сохраняем после каждой части - при обрыве запуска проверенное не потеряется
            print(f"  проверено {done_n} из {len(queue)} за {int((time.time() - T_START) / 60)} мин: новых рабочих {stat['new_alive']}, ожили {stat['revived']}", flush=True)
        print(f"итог полного прогона: новых рабочих {stat['new_alive']}, ожили {stat['revived']}", flush=True)

    # ── 3. уборка: мёртвые, которые долго не работали (KEEP_DEAD_D дней с последней удачи или с добавления) ──
    keep_min = KEEP_DEAD_D * 24 * 60
    before = len(state)
    state = {a: e for a, e in state.items() if not (e.get("status") == "dead" and e.get("dead_n", 0) >= len(DEAD_BACKOFF_H) and age_min(e.get("last_alive") or e.get("added", "")) > keep_min)}
    if before != len(state): print(f"удалено из памяти давно мёртвых: {before - len(state)}", flush=True)
    save_state(state)

    for a, e in state.items():
        if e["status"] == "alive" and not e.get("country"):
            e["country"] = geo_country(e.get("exit_ip") or a.split(":")[0])
    alive = [dict(proxy=a, status="alive", protocol=e.get("protocol", ""), country=e.get("country", ""),
                  latency=e.get("latency", 0), last_checked=e.get("last_checked", ""), added=e.get("added", ""),
                  anonymity=e.get("anonymity") or ("elite" if e.get("protocol") in ("socks4", "socks5") else ""))
             for a, e in state.items() if e["status"] == "alive" and e.get("fails", 0) <= PUBLISH_FAILS]   # одна случайная неудача не убирает из списка
    alive.sort(key=lambda x: x["latency"])
    no_cc = sum(1 for x in alive if not x["country"])
    print(f"рабочих сейчас: {len(alive)} (ещё {stat['alive_flaky']} временно не ответили и остаются в памяти рабочих), без страны: {no_cc}, база стран: {'есть' if _geo else 'НЕТ'}", flush=True)

    # в n8n - одним запросом весь актуальный список рабочих: n8n заменяет им таблицу.
    # Нет связи, n8n перезапускается или не отвечает - повторяем с нарастающей паузой (10 с, 20 с, 40 с, дальше раз в минуту),
    # пока n8n не примет. Предел - SEND_UNTIL_MIN минут от начала запуска (запуск на GitHub ограничен по времени);
    # память уже сохранена выше, а следующий запуск отправит более свежий список.
    payload = {"alive": alive, "count": len(alive), "updated": now_iso()}
    deadline = T_START + SEND_UNTIL_MIN * 60
    attempt, pause, last_err = 0, 10, ""
    while True:
        attempt += 1
        try:
            async with aiohttp.ClientSession(headers=HEADERS) as s:
                async with s.post(RESULT_URL, json=payload, timeout=aiohttp.ClientTimeout(total=120)) as r:
                    if r.status < 300:
                        print(f"отправлено в n8n: HTTP {r.status}" + (f" (с попытки {attempt})" if attempt > 1 else ""), flush=True); return
                    last_err = f"HTTP {r.status}"
        except Exception as e:
            last_err = type(e).__name__ + (": " + str(e)[:120] if str(e) else "")
        if time.time() + pause > deadline:
            # запуск станет красным - видно, что результат не дошёл (обычно: адрес RESULT_URL, выключен workflow или не совпадает WEBHOOK_TOKEN)
            raise SystemExit(f"n8n так и не принял результат за {attempt} попыток ({last_err}). Память сохранена, следующий запуск отправит свежий список")
        print(f"n8n недоступен ({last_err}), попытка {attempt}; следующая через {pause} с", flush=True)
        await asyncio.sleep(pause)
        pause = min(60, pause * 2)

if __name__ == "__main__":
    asyncio.run(main())
