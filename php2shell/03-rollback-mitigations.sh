#!/bin/bash
# Rollback completo del Livello A (01-mitigate-now.sh).
set -euo pipefail
TAG=php2shell
for b in /opt/cpanel/ea-php*/root/etc/php.ini.bak.$TAG /opt/alt/php*/etc/php.ini.bak.$TAG; do
  [ -f "$b" ] || continue
  mv -f "$b" "${b%.bak.$TAG}"; echo "restored ${b%.bak.$TAG}"
done
rm -f /opt/cpanel/ea-php*/root/etc/php.d/zz-$TAG.ini /opt/alt/php*/etc/php.d/zz-$TAG.ini
INC=/etc/apache2/conf.d/includes/pre_virtualhost_global.conf
[ -f "$INC.bak.$TAG" ] && mv -f "$INC.bak.$TAG" "$INC" && echo "restored $INC"
RULES=/etc/apache2/conf.d/modsec/modsec2.user.conf
if [ -f "$RULES.bak.$TAG" ]; then mv -f "$RULES.bak.$TAG" "$RULES"; else sed -i "/# BEGIN $TAG/,/# END $TAG/d" "$RULES" 2>/dev/null || true; fi
echo "modsec rules removed (package left installed; remove with: dnf -y remove ea-apache24-mod_security2)"
[ -f /etc/csf/csf.conf.bak.$TAG ] && mv -f /etc/csf/csf.conf.bak.$TAG /etc/csf/csf.conf && csf -ra >/dev/null && echo "csf restored"
/usr/sbin/httpd -t && /scripts/rebuildhttpdconf >/dev/null && systemctl restart httpd && systemctl is-active httpd
