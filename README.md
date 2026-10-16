[README.md](https://github.com/user-attachments/files/33545621/README.md)
# MakeItEarn - проверка прокси на GitHub Actions

Проверяет прокси на серверах GitHub (не с домашнего интернета, не на VPS). Бесплатно:
публичный репозиторий - без лимита минут.

## Как это работает
1. По расписанию (`.github/workflows/check-proxies.yml`, по умолчанию раз в час) GitHub запускает `check.py`.
2. `check.py` берёт список «на проверку» из n8n (вебхук `PENDING_URL`): новые + давно не проверенные рабочие.
3. Проверяет каждый ЧЕРЕЗ сам прокси (HTTP/SOCKS4/SOCKS5), определяет протокол, страну, скорость.
4. Шлёт результат обратно в n8n (`RESULT_URL`): alive с деталями и dead.

## Установка
1. Создай на github.com новый **публичный** репозиторий (например `makeitearn-proxy`).
2. Залей в него файлы `check.py`, `README.md` и папку `.github/`.
3. Settings → Secrets and variables → Actions → New repository secret, добавь:
   - `PENDING_URL`  = https://automation.makeitearn.com/webhook/proxy-pending
   - `RESULT_URL`   = https://automation.makeitearn.com/webhook/proxy-result
   - `WEBHOOK_TOKEN` = любой длинный пароль (тот же вписать в проверку токена в n8n; можно пропустить)
4. Вкладка Actions → check-proxies → Run workflow (проверить вручную). Дальше пойдёт по расписанию.

Поля результата совпадают с таблицей Full Free Proxy: proxy, status, protocol, country, latency, last_checked.
