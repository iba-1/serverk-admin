# php2shell (CVE-2026-109618 / CVE-2026-109619) su cPanel + CloudLinux

Mitigazione e patch per le due RCE in PHP core pubblicate il 21 ottobre 2026
([advisory php.net](https://www.php.net/archive/2026.php#2026-10-21-5),
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)).
Pensato per server cPanel/EA4 con handler `cgi`/`suphp` e versioni PHP legacy
(HardenedPHP 5.x/7.x) che non riceveranno un fix upstream.

| Script | Cosa fa | Quando |
|---|---|---|
| `01-mitigate-now.sh` | `session.upload_progress=0` su ogni PHP ≥ 5.4, `LimitRequestBody 12M` su `<Directory /home>`, installa `ea-apache24-mod_security2` con 4 regole mirate (no OWASP CRS), `LF_MODSEC=5` in CSF, restart completo di Apache. Idempotente, backup `.bak.php2shell`. | subito |
| `02-patch-when-available.sh` | aggiorna `ea-php82*`, `ea-php83*`, `alt-php74*` quando i pacchetti fixati compaiono nel repo, riavvia Apache, verifica. `--cron` per il polling ogni 30 min. | finché EA4 non pubblica il fix |
| `03-rollback-mitigations.sh` | annulla tutto il livello 1 | se serve |
| `04-verify.sh` | ogni vhost risponde; 4 richieste a forma di exploit → 403/413; 2 richieste legittime passano. Lista vhost presa da WHM API. | dopo 01 e dopo 02 |

## Le 4 regole mod_security (id 9261001–9261004)

1. `multipart/form-data` senza `Content-Length` → 403. I browser lo mandano sempre; l'exploit lo omette per aggirare `post_max_size`.
2. più di 40 parti file in una richiesta → 403 (`max_file_uploads` di PHP è 20).
3. più di 1000 campi POST → 403 (= `max_input_vars`).
4. campo `PHP_SESSION_UPLOAD_PROGRESS` → 403 (verificare prima che nessuna app lo usi: `grep -rl upload_progress` nelle docroot).

Girano in Apache prima del dispatch a `php-cgi`, quindi coprono anche le versioni PHP senza fix.

## Perché non `memory_limit = -1`

PHP lo consiglia come stopgap, ma su handler per-richiesta (`cgi`/`suphp`) con molti worker Apache equivale a consentire a una richiesta di esaurire la RAM del server. `LimitRequestBody` + regola 1 chiudono lo stesso vettore senza quel rischio.

## Uso

```bash
scp php2shell/*.sh root@server:/root/php2shell/
ssh root@server '/root/php2shell/01-mitigate-now.sh && /root/php2shell/04-verify.sh'
ssh root@server '(crontab -l; echo "*/30 * * * * /root/php2shell/02-patch-when-available.sh --cron") | crontab -'
```

Notifica opzionale di fine patch: token Moshi in `/root/.php2shell-notify-token` (mode 600).

## Dopo la patch

- `rpm -q ea-php82-php-cli ea-php83-php-cli` ≥ 8.2.35 / 8.3.36 (non fidarsi di `php -v` sui backport distro).
- Rimuovere la riga di cron.
- Le mitigazioni possono restare: non hanno impatto applicativo e coprono le versioni legacy.
