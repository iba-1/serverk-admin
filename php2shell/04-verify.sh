#!/bin/bash
# Post-mitigation check for php2shell (CVE-2026-109618 / CVE-2026-109619).
# Run on the cPanel server as root. Vhosts are discovered via WHM API, so the
# script carries no site list. Requests go to 127.0.0.1 with the Host header,
# so it also works for domains whose DNS no longer points here.
set -uo pipefail
fail=0
code() { curl -sk -o /dev/null -m 20 -w '%{http_code}' --resolve "$1:443:127.0.0.1" "https://$1$2" "${@:3}"; }

echo "== 1. session.upload_progress per PHP version =="
for v in /opt/cpanel/ea-php[5-9][0-9] /opt/alt/php[0-9][0-9]; do
  b="$v/root/usr/bin/php"; [ -x "$b" ] || b="$v/usr/bin/php"; [ -x "$b" ] || continue
  printf '%-24s upload_progress=%s\n' "$(basename "$v")" \
    "$($b -r 'echo ini_get("session.upload_progress.enabled")===false?"n/a":ini_get("session.upload_progress.enabled");' 2>/dev/null)"
done

echo "== 2. apache modules =="
if httpd -M 2>/dev/null | grep -q security2_module; then echo "security2: loaded"; else echo "security2: MISSING"; fail=1; fi

echo "== 3. every vhost answers =="
mapfile -t VHOSTS < <(/usr/local/cpanel/bin/whmapi1 --output=json php_get_vhost_versions 2>/dev/null \
  | python3 -c 'import sys,json; [print(v["vhost"]) for v in json.load(sys.stdin)["data"]["versions"]]')
for s in "${VHOSTS[@]}"; do
  h=$(code "$s" /); printf '%-45s home=%s\n' "$s" "$h"
  [[ $h =~ ^(200|301|302|401)$ ]] || fail=1
done
T=${VHOSTS[0]}

echo "== 4. exploit-shaped requests must be 403 =="
r=$(code "$T" /index.php -X POST -H "Content-Type: multipart/form-data; boundary=x" -H "Transfer-Encoding: chunked" \
     --data-binary @<(printf -- '--x\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n--x--\r\n'))
echo "multipart without Content-Length -> $r (want 403)"; [ "$r" = 403 ] || fail=1
r=$(code "$T" /index.php -X POST -F "PHP_SESSION_UPLOAD_PROGRESS=1" -F "f=@/etc/hostname")
echo "PHP_SESSION_UPLOAD_PROGRESS field -> $r (want 403)"; [ "$r" = 403 ] || fail=1
d=$(mktemp -d); for i in $(seq 1 60); do echo x > "$d/f$i"; done
args=(); for i in $(seq 1 60); do args+=(-F "f$i=@$d/f$i"); done
r=$(code "$T" /index.php -X POST "${args[@]}")
echo "60 file parts -> $r (want 403)"; [ "$r" = 403 ] || fail=1
head -c 13631488 /dev/zero > "$d/big.bin"
r=$(code "$T" /index.php -X POST -F "f=@$d/big.bin")
echo "13 MB body -> $r (want 413)"; [ "$r" = 413 ] || fail=1

echo "== 5. legitimate upload-shaped requests must pass =="
head -c 1048576 /dev/urandom > "$d/1m.bin"
r=$(code "$T" /index.php -X POST -F "a=1" -F "b=2" -F "f1=@$d/1m.bin" -F "f2=@$d/f1" -F "f3=@$d/f2")
echo "1 MB multipart, 3 files -> $r (want not 403/413)"; [[ $r =~ ^(403|413)$ ]] && fail=1
args=(); for i in $(seq 1 10); do args+=(-F "f$i=@$d/f$i"); done
r=$(code "$T" /index.php -X POST "${args[@]}")
echo "10 file parts -> $r (want not 403/413)"; [[ $r =~ ^(403|413)$ ]] && fail=1
rm -rf "$d"

echo "== 6. recent modsec denials =="
grep -E "ModSecurity.*id \"926100[1-4]\"" /etc/apache2/logs/error_log 2>/dev/null | tail -4 | cut -c1-140 || true

echo; if [ $fail = 0 ]; then echo "RESULT: OK"; else echo "RESULT: FAILURES ABOVE"; exit 1; fi
echo "Manual: do a real image upload from one application backend."
