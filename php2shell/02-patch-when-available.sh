#!/bin/bash
# php2shell (CVE-2026-109618 / CVE-2026-109619) level B: update ea-php82/83 and
# alt-php74 as soon as the patched packages reach the repo (EasyApache4 v25.91,
# CloudLinux alt-php). Safe to run repeatedly.
#
# Usage:  ./02-patch-when-available.sh          (interactive)
#         ./02-patch-when-available.sh --cron   (quiet; exit 0 when nothing to do)
# Cron until patched:
#   */30 * * * * /root/php2shell/02-patch-when-available.sh --cron
#
# Optional notification: put a Moshi token in /root/.php2shell-notify-token
# (chmod 600). Never commit the token.
set -euo pipefail
LOG=/root/php2shell-patch.log
if [ "${1:-}" = "--cron" ]; then exec >> "$LOG" 2>&1; else exec > >(tee -a "$LOG") 2>&1; fi
echo "=== $(date -u +%FT%TZ) check ==="

declare -A WANT=( [ea-php82-php-cli]=8.2.35 [ea-php83-php-cli]=8.3.36 )
# alt-php74 keeps the upstream version string (7.4.33); the fix shows up as a
# release bump (>= 80) or a CVE line in the rpm changelog.

need_update=0
for p in "${!WANT[@]}"; do
  rpm -q "$p" >/dev/null 2>&1 || continue
  cur=$(rpm -q --qf '%{VERSION}' "$p")
  if [ "$(printf '%s\n%s\n' "${WANT[$p]}" "$cur" | sort -V | head -1)" != "${WANT[$p]}" ]; then
    echo "$p installed $cur < ${WANT[$p]}"; need_update=1
  else
    echo "$p installed $cur OK"
  fi
done
if rpm -q alt-php74 >/dev/null 2>&1; then
  alt_rel=$(rpm -q --qf '%{RELEASE}' alt-php74 | cut -d. -f1)
  if [ "${alt_rel:-0}" -lt 80 ] && ! rpm -q --changelog alt-php74 | grep -q "CVE-2026-109618"; then
    echo "alt-php74 release $alt_rel, no CVE-2026-109618 in changelog"; need_update=1
  fi
fi
[ "$need_update" = 0 ] && { echo "nothing to do"; exit 0; }

dnf -q clean expire-cache
avail=$(dnf -q check-update 'ea-php82-php-cli' 'ea-php83-php-cli' 'alt-php74' 2>/dev/null | awk '/^(ea|alt)-php/{print $1" "$2}' || true)
if [ -z "$avail" ]; then
  echo "fixed packages not in repo yet"
  exit 0
fi
echo "available:"; echo "$avail"

# Only the families that have an upstream fix. ea-php5x/7x (HardenedPHP) are
# CloudLinux's responsibility and are left alone.
dnf -y update 'ea-php82*' 'ea-php83*' 'alt-php74*'

/scripts/rebuildhttpdconf >/dev/null
systemctl restart httpd      # full restart: php-cgi/suPHP children belong to httpd
sleep 2
systemctl is-active httpd

echo "--- post-update versions"
for v in ea-php82 ea-php83; do [ -x /opt/cpanel/$v/root/usr/bin/php ] && /opt/cpanel/$v/root/usr/bin/php -v | head -1; done
rpm -q alt-php74 ea-php82-php-cli ea-php83-php-cli 2>/dev/null || true
echo "--- processes still mapping deleted PHP binaries (should be empty)"
grep -lE ' /(opt|usr).*php.*\(deleted\)$' /proc/[0-9]*/maps 2>/dev/null | head || true

if [ -r /root/.php2shell-notify-token ]; then
  tok=$(cat /root/.php2shell-notify-token)
  curl -s -X POST https://api.getmoshi.app/api/webhook -H "Content-Type: application/json" \
    -d "{\"token\": \"$tok\", \"title\": \"$(hostname -s) PHP patched\", \"message\": \"php2shell: ea-php82/83 + alt-php74 updated, httpd restarted\"}" >/dev/null || true
fi
echo "=== $(date -u +%FT%TZ) patched. Remove the cron entry. ==="
