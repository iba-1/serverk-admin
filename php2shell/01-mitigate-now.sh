#!/bin/bash
# php2shell Livello A: mitigazioni senza impatto applicativo su serverk01.
# Idempotente. Eseguire come root. Rollback: 03-rollback-mitigations.sh
set -euo pipefail

TAG=php2shell
LOG=/root/php2shell-mitigate.log
exec > >(tee -a "$LOG") 2>&1
echo "=== $(date -u +%FT%TZ) start 01-mitigate-now ==="

# ---------------------------------------------------------------- 1. php.ini
# Disabilita session.upload_progress su ogni PHP >= 5.4 (5.3 non ha la direttiva).
for ini in /opt/cpanel/ea-php[5-9][0-9]/root/etc/php.ini /opt/alt/php[0-9][0-9]/etc/php.ini; do
  [ -f "$ini" ] || continue
  case "$ini" in *ea-php53*) continue;; esac
  [ -f "$ini.bak.$TAG" ] || cp -a "$ini" "$ini.bak.$TAG"
  if grep -qE '^\s*session\.upload_progress\.enabled\s*=' "$ini"; then
    sed -i -E 's/^\s*session\.upload_progress\.enabled\s*=.*/session.upload_progress.enabled = 0/' "$ini"
  else
    printf '\n; %s mitigation (CVE-2026-109619)\nsession.upload_progress.enabled = 0\n' "$TAG" >> "$ini"
  fi
  echo "php.ini: $ini -> $(grep -E '^session\.upload_progress\.enabled' "$ini")"
done

# alt-php74 ha un php.ini vuoto: la direttiva sopra basta. Per ea-php8x cPanel
# puo' rigenerare il php.ini dal MultiPHP INI Editor: lo stesso valore va
# messo anche nel "local" ini che cPanel preserva.
for v in /opt/cpanel/ea-php[5-9][0-9]; do
  d="$v/root/etc/php.d"; [ -d "$d" ] || continue
  f="$d/zz-$TAG.ini"
  printf 'session.upload_progress.enabled = 0\n' > "$f"
  echo "php.d: $f"
done
f=/opt/alt/php74/etc/php.d/zz-$TAG.ini
[ -d /opt/alt/php74/etc/php.d ] && printf 'session.upload_progress.enabled = 0\n' > "$f" && echo "php.d: $f"

# ---------------------------------------------------------------- 2. Apache LimitRequestBody
INC=/etc/apache2/conf.d/includes/pre_virtualhost_global.conf
[ -f "$INC.bak.$TAG" ] || cp -a "$INC" "$INC.bak.$TAG"
if ! grep -q "$TAG" "$INC"; then
cat >> "$INC" <<'EOF'
# php2shell mitigation (CVE-2026-109618): cap request body for all /home docroots.
# 12 MB > any configured upload_max_filesize (max 8M) + form overhead.
# Does not apply to the cPanel proxy vhost (/var/www/html).
<Directory "/home">
    LimitRequestBody 12582912
</Directory>
EOF
fi
echo "apache include: $(grep -c LimitRequestBody "$INC") LimitRequestBody line(s)"

# ---------------------------------------------------------------- 3. mod_security2 + regole mirate
if ! rpm -q ea-apache24-mod_security2 >/dev/null 2>&1; then
  dnf -y install ea-apache24-mod_security2
fi
MSDIR=/etc/apache2/conf.d/modsec
RULES=$MSDIR/modsec2.user.conf
mkdir -p "$MSDIR"
[ -f "$RULES" ] && [ ! -f "$RULES.bak.$TAG" ] && cp -a "$RULES" "$RULES.bak.$TAG"
# Rimuove un eventuale blocco precedente e lo riscrive (idempotente).
if [ -f "$RULES" ]; then
  sed -i "/# BEGIN $TAG/,/# END $TAG/d" "$RULES"
fi
cat >> "$RULES" <<'EOF'
# BEGIN php2shell
# Targeted virtual patch for CVE-2026-109618 / CVE-2026-109619. Runs in Apache
# before the request is handed to php-cgi, so it also covers ea-php53/ea-php70.
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 12582912
SecRequestBodyNoFilesLimit 2097152
SecRequestBodyLimitAction Reject

# 1) multipart body without Content-Length (chunked). Browsers always send
#    Content-Length for multipart; the exploit omits it to bypass post_max_size.
SecRule REQUEST_HEADERS:Content-Type "@beginsWith multipart/form-data" \
  "id:9261001,phase:1,deny,status:403,log,msg:'php2shell: multipart without Content-Length',chain"
  SecRule &REQUEST_HEADERS:Content-Length "@eq 0"

# 2) absurd number of file parts (exploit sends thousands of empty ones;
#    PHP max_file_uploads is 20 on this server).
SecRule &FILES "@gt 40" \
  "id:9261002,phase:2,deny,status:403,log,msg:'php2shell: too many multipart file parts'"

# 3) absurd number of POST fields (PHP max_input_vars is 1000).
SecRule &ARGS_POST "@gt 1000" \
  "id:9261003,phase:2,deny,status:403,log,msg:'php2shell: too many POST fields'"

# 4) session upload progress field: no hosted application uses it.
SecRule ARGS_NAMES "@contains PHP_SESSION_UPLOAD_PROGRESS" \
  "id:9261004,phase:2,deny,status:403,log,msg:'php2shell: PHP_SESSION_UPLOAD_PROGRESS'"
# END php2shell
EOF
echo "modsec rules written to $RULES"

# ---------------------------------------------------------------- 4. CSF: blocca IP che colpiscono modsec
if grep -qE '^LF_MODSEC = "0"' /etc/csf/csf.conf; then
  cp -a /etc/csf/csf.conf /etc/csf/csf.conf.bak.$TAG
  sed -i 's/^LF_MODSEC = "0"/LF_MODSEC = "5"/' /etc/csf/csf.conf
  echo "csf: LF_MODSEC set to 5"
  csf -ra >/dev/null
fi

# ---------------------------------------------------------------- 5. restart completo Apache
/scripts/rebuildhttpdconf >/dev/null
/usr/sbin/httpd -t
systemctl restart httpd
sleep 2
systemctl is-active httpd
httpd -M 2>/dev/null | grep -E "security2|remoteip" || true

# ---------------------------------------------------------------- 6. verifica rapida
for v in ea-php70 ea-php82 ea-php83; do
  echo -n "$v upload_progress: "; /opt/cpanel/$v/root/usr/bin/php -r 'echo ini_get("session.upload_progress.enabled"),"\n";'
done
echo "=== $(date -u +%FT%TZ) done. Run 04-verify.sh next. ==="
