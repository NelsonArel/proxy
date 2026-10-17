#!/usr/bin/env python3
"""MakeItEarn - сбор и проверка прокси на GitHub Actions.
Всё тяжёлое здесь, а не в n8n: сбор из источников, память «что уже проверяли», проверка тысяч прокси.
В n8n уходит только итог - список рабочих (сотни строк), который заменяет таблицу целиком.

Память хранится в файле state.json между запусками (кэш GitHub Actions), поэтому:
  - новые адреса проверяются один раз;
  - рабочие перепроверяются, если с последней проверки прошло RECHECK_ALIVE_MIN минут;
  - мёртвые не проверяются повторно RECHECK_DEAD_H часов (источники иногда «воскрешают» адреса).
Поля результата: proxy, status, protocol, country, latency, last_checked, added."""
import asyncio, json, os, re, time
from datetime import datetime, timezone
import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType

RESULT_URL = os.environ["RESULT_URL"]                 # вебхук n8n, принимает итоговый список рабочих
AUTH = os.environ.get("WEBHOOK_TOKEN", "")
CONC = int(os.environ.get("CONCURRENCY", "1000"))
TIMEOUT = float(os.environ.get("TIMEOUT", "8"))
RECHECK_ALIVE_MIN = float(os.environ.get("RECHECK_ALIVE_MIN", "10"))   # в быстром режиме (каждые 15 мин) рабочие проверяются каждый раз
MODE = os.environ.get("MODE", "full")            # full - сбор новых + проверка; alive - только перепроверка рабочих
RECHECK_DEAD_H = float(os.environ.get("RECHECK_DEAD_H", "24"))
STATE = os.environ.get("STATE_FILE", "state/state.json")
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
]
CHECK_URLS = ["http://ip-api.com/json/?fields=query,countryCode", "http://ipinfo.io/json",
              "http://ifconfig.me/all.json", "http://api.ipify.org?format=json", "http://checkip.amazonaws.com"]
# «судьи» анонимности: показывают, какие заголовки дошли до сервера через прокси
JUDGES = ["http://httpbin.org/headers", "http://azenv.net/", "http://www.proxy-listen.de/azenv.php"]
# заголовки-«выдачи» прокси: и в виде X-Forwarded-For (httpbin), и в виде HTTP_X_FORWARDED_FOR (azenv)
LEAK = re.compile(r"(?i)(?:^|[^a-z0-9])(via|x[-_]forwarded[-_]for|x[-_]forwarded|forwarded|x[-_]real[-_]ip|x[-_]proxy[-_]id|proxy[-_]connection|client[-_]ip)(?:[^a-z0-9]|$)")
IP_PORT = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}$")
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

async def check(addr, protos, my, sem):
    async with sem:
        for proto in sorted(protos, key=lambda p: -RANK.get(p, 0)):
            t0 = time.monotonic()
            try:
                async with aiohttp.ClientSession(connector=connector(proto, addr)) as s:
                    async with s.get(CHECK_URLS[hash(addr) % len(CHECK_URLS)], timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
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
        async def grab(default, url):
            try:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=25)) as r: text = await r.text()
            except Exception: return
            for ln in text.splitlines():
                p = norm(ln, default)
                if p: found.setdefault(p[1], set()).add(p[0])
        if MODE == "full":
            await asyncio.gather(*[grab(d, u) for d, u in SOURCES])
    print(f"режим {MODE}: собрано {len(found)} уникальных, в памяти {len(state)}, свой ip {my}", flush=True)

    # что проверять: новые; рабочие, давно не проверенные; мёртвые, у которых истёк срок
    todo = {}
    for addr, protos in found.items():
        e = state.get(addr)
        if not e:
            todo[addr] = protos | {"http", "socks5"}; continue
        if e["status"] == "alive" and age_min(e.get("last_checked", "")) >= RECHECK_ALIVE_MIN:
            todo[addr] = {e.get("protocol", "http")} | protos
        elif e["status"] == "dead" and age_min(e.get("last_checked", "")) >= RECHECK_DEAD_H * 60:
            todo[addr] = protos | {"http", "socks5"}
    # рабочие, которые пропали из источников, тоже перепроверяем (иначе протухнут в списке).
    # В быстром режиме (alive) рабочие проверяются ВСЕГДА: запуски идут каждые 10 минут, а с прошлой проверки
    # к этому моменту проходит чуть меньше 10 минут - с порогом по возрасту каждый второй запуск ничего не делал.
    for addr, e in state.items():
        if addr not in todo and e["status"] == "alive" and (MODE == "alive" or age_min(e.get("last_checked", "")) >= RECHECK_ALIVE_MIN):
            todo[addr] = {e.get("protocol", "http"), "http", "socks5"}
    print(f"проверяем сейчас: {len(todo)}", flush=True)

    sem = asyncio.Semaphore(CONC)
    res = await asyncio.gather(*[check(a, p, my, sem) for a, p in todo.items()])
    t = now_iso()
    for addr, r in res:
        prev = state.get(addr, {})
        rec = {"status": r["status"], "last_checked": t, "added": prev.get("added", t)}
        if r["status"] == "alive": rec.update(protocol=r["protocol"], country=r["country"], latency=r["latency"], exit_ip=r.get("exit_ip", ""), anonymity=r.get("anonymity", ""))
        state[addr] = rec
    # чистим память от мёртвых старше недели, чтобы файл не рос бесконечно
    state = {a: e for a, e in state.items() if not (e["status"] == "dead" and age_min(e.get("last_checked", "")) > 7 * 24 * 60)}
    save_state(state)

    for a, e in state.items():
        if e["status"] == "alive" and not e.get("country"):
            e["country"] = geo_country(e.get("exit_ip") or a.split(":")[0])
    alive = [dict(proxy=a, status="alive", protocol=e.get("protocol", ""), country=e.get("country", ""),
                  latency=e.get("latency", 0), last_checked=e.get("last_checked", ""), added=e.get("added", ""),
                  anonymity=e.get("anonymity") or ("elite" if e.get("protocol") in ("socks4", "socks5") else ""))
             for a, e in state.items() if e["status"] == "alive"]
    alive.sort(key=lambda x: x["latency"])
    no_cc = sum(1 for x in alive if not x["country"])
    print(f"рабочих сейчас: {len(alive)} (проверено в этом запуске {len(res)}), без страны: {no_cc}, база стран: {'есть' if _geo else 'НЕТ'}", flush=True)

    # в n8n - одним запросом весь актуальный список рабочих: n8n заменяет им таблицу
    async with aiohttp.ClientSession(headers=HEADERS) as s:
        async with s.post(RESULT_URL, json={"alive": alive, "count": len(alive), "updated": t}, timeout=aiohttp.ClientTimeout(total=120)) as r:
            print(f"отправлено в n8n: HTTP {r.status}", flush=True)
            if r.status >= 300:
                # запуск станет красным в Actions - сразу видно, что результат не дошёл до таблицы
                raise SystemExit(f"n8n не принял результат (HTTP {r.status}): проверьте адрес RESULT_URL, включён ли workflow и совпадает ли WEBHOOK_TOKEN")

if __name__ == "__main__":
    asyncio.run(main())
