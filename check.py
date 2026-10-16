#!/usr/bin/env python3
"""MakeItEarn - проверка прокси на GitHub Actions (не с домашнего интернета, бесплатно).
Берёт список «на проверку» из n8n (вебхук PENDING_URL), проверяет каждый ЧЕРЕЗ сам прокси
(HTTP/SOCKS4/SOCKS5), возвращает в n8n (RESULT_URL): кто жив (протокол, страна, скорость) и кто умер.
Поля результата совпадают с таблицей: proxy, status, protocol, country, latency, last_checked.
Секреты берутся из переменных окружения (GitHub Secrets), в коде их нет."""
import asyncio, json, os, re, time
from datetime import datetime, timezone
import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType

PENDING_URL = os.environ["PENDING_URL"]           # GET -> {"proxies":[{proxy,protocol},...]} или список строк
RESULT_URL = os.environ["RESULT_URL"]             # POST сюда результат
AUTH = os.environ.get("WEBHOOK_TOKEN", "")        # необязательный токен в заголовке Authorization
CONC = int(os.environ.get("CONCURRENCY", "1000"))
TIMEOUT = float(os.environ.get("TIMEOUT", "8"))
HEADERS = {"Authorization": "Bearer " + AUTH} if AUTH else {}

CHECK_URLS = [
  "http://ip-api.com/json/?fields=query,countryCode",
  "http://ipinfo.io/json", "http://ifconfig.me/all.json",
  "http://api.ipify.org?format=json", "http://checkip.amazonaws.com",
]
IP_PORT = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}$")
RANK = {"socks5": 3, "socks4": 2, "http": 1}

def parse_ip(text):
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", text or ""); ip = m.group(0) if m else None
    cm = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', text or "") or re.search(r'"country"\s*:\s*"([A-Z]{2})"', text or "")
    return ip, (cm.group(1) if cm else "")

def connector(proto, addr):
    ip, port = addr.split(":")
    t = {"http": ProxyType.HTTP, "socks4": ProxyType.SOCKS4, "socks5": ProxyType.SOCKS5}[proto]
    return ProxyConnector(proxy_type=t, host=ip, port=int(port), rdns=True)

async def check(addr, protos, my, sem):
    # пробуем протоколы по убыванию «силы»; первый сработавший и есть тип прокси
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
                return {"proxy": addr, "status": "alive", "protocol": proto, "country": cc,
                        "latency": int((time.monotonic() - t0) * 1000), "last_checked": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    return {"proxy": addr, "status": "dead", "last_checked": datetime.now(timezone.utc).isoformat(timespec="seconds")}

async def my_ip(s):
    for u in ["http://ip-api.com/json/?fields=query", "http://api.ipify.org?format=json"]:
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=10)) as r:
                j = await r.json(content_type=None); return j.get("query") or j.get("ip")
        except Exception: continue
    return None

async def main():
    async with aiohttp.ClientSession(headers={"User-Agent": "MakeItEarn-ProxyCheck/1.0"}) as s:
        async with s.get(PENDING_URL, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=60)) as r:
            data = await r.json(content_type=None)
        my = await my_ip(s)
    items = data.get("proxies", data) if isinstance(data, dict) else data
    # сгруппируем протоколы по адресу (один адрес могли прислать как http и socks5)
    want = {}
    for it in items:
        if isinstance(it, str): addr, proto = it, "http"
        else: addr, proto = (it.get("proxy") or it.get("ip") or "").strip(), (it.get("protocol") or "http").strip().lower()
        addr = re.sub(r"^\w+://", "", addr)
        if not IP_PORT.match(addr): continue
        if proto not in RANK: proto = "http"
        want.setdefault(addr, set()).update([proto, "http", "socks5"])   # проверим и как http, и как socks5
    print(f"на проверку: {len(want)} адресов, свой ip {my}", flush=True)
    sem = asyncio.Semaphore(CONC)
    res = await asyncio.gather(*[check(a, p, my, sem) for a, p in want.items()])
    alive = [r for r in res if r["status"] == "alive"]
    print(f"живых: {len(alive)} из {len(res)}", flush=True)
    # отправляем результат пачками, чтобы не прислать слишком большой запрос
    async with aiohttp.ClientSession(headers=HEADERS) as s:
        for i in range(0, len(res), 500):
            chunk = res[i:i+500]
            async with s.post(RESULT_URL, json={"results": chunk}, timeout=aiohttp.ClientTimeout(total=60)) as r:
                print(f"отправлено {i+len(chunk)}/{len(res)}: HTTP {r.status}", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
