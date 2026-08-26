#!/usr/bin/env bash
# =============================================================================
# cpanel-account-remove.sh
# Safe, generic termination of a cPanel account, with backup and verification.
#
# Target:  serverk01.venicebay.it (CloudLinux 8 / cPanel) — but GENERIC:
#          works on any cPanel account, passed as argument.
#
# Workflow (fail-safe):
#   Phase 1  Audit gate      -> refuses if a live domain still points here
#                              (delegates to cpanel-account-audit.sh)
#   Phase 2  Full backup     -> pkgacct -> cpmove-<user>.tar.gz, integrity +
#                              sha256 + manifest verified (restore with restorepkg)
#   Phase 3  Termination     -> whmapi1 removeacct (typed confirmation)
#   Phase 4  Post-verify     -> account gone, space freed, and the domains you
#                              flagged with --check-domain STILL return HTTP 200
#
# DRY-RUN BY DEFAULT. Nothing is deleted unless you pass --execute.
#
# Usage:
#   bash cpanel-account-remove.sh <user> [options]                 # dry-run
#   bash cpanel-account-remove.sh <user> [options] --execute       # for real
#
# Options:
#   --check-domain FQDN   URL that MUST stay up before & after (repeatable)
#   --dest DIR            backup destination (default /home/_account_archive/<ts>)
#   --keepdns             keep the DNS zone(s) (removeacct keepdns=1)
#   --execute             actually perform backup + termination
#   --yes                 skip the typed-username confirmation (automation)
#   --force               proceed even if the audit gate reports warnings
#   --help
#
# Example (grafco decommission):
#   bash cpanel-account-remove.sh grafcovebay \
#        --check-domain my.grafco.it \
#        --check-domain en.my.grafco.it \
#        --check-domain fr.my.grafco.it --execute
# =============================================================================
set -euo pipefail

# -- Args ---------------------------------------------------------------------

DRY_RUN=1
KEEPDNS=0
ASSUME_YES=0
FORCE=0
USER=""
DEST=""
declare -a CHECK_DOMAINS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --execute)      DRY_RUN=0 ;;
        --keepdns)      KEEPDNS=1 ;;
        --yes)          ASSUME_YES=1 ;;
        --force)        FORCE=1 ;;
        --dest)         DEST="${2:-}"; shift ;;
        --check-domain) CHECK_DOMAINS+=("${2:-}"); shift ;;
        --help|-h)
            sed -n '2,40p' "$0"; exit 0 ;;
        -*) echo "Unknown option: $1 (use --help)"; exit 1 ;;
        *)  USER="$1" ;;
    esac
    shift
done

[[ -n "$USER" ]] || { echo "Usage: bash $0 <user> [options] [--execute]"; exit 1; }

# -- Config -------------------------------------------------------------------

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -n "$DEST" ]] || DEST="/home/_account_archive/${TIMESTAMP}"
LOG_FILE="/root/cpanel-remove-${USER}_${TIMESTAMP}.log"
ARCHIVE="${DEST}/cpmove-${USER}.tar.gz"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDIT_SCRIPT="${SCRIPT_DIR}/cpanel-account-audit.sh"
PKGACCT="/usr/local/cpanel/scripts/pkgacct"

# -- Colors & UI --------------------------------------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

log()  { local m; m="[$(date '+%Y-%m-%d %H:%M:%S')] $1"; echo -e "$m" >> "$LOG_FILE" 2>/dev/null || true; echo -e "$m"; }
info() { echo -e "${CYAN}  ▸ $1${NC}"; }
ok()   { log "${GREEN}  ✓ $1${NC}"; }
warn() { log "${YELLOW}  ⚠ $1${NC}"; }
die()  { log "${RED}  ✗ FATAL: $1${NC}"; exit 1; }

banner() {
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}
phase_header() { echo ""; echo -e "${BOLD}── Fase $1: $2 ──${NC}"; }
will_do() {
    echo -e "${DIM}  Cosa farà:${NC}"
    while [[ $# -gt 0 ]]; do echo -e "    ${DIM}→${NC} $1"; shift; done
}

# -- Pre-flight ---------------------------------------------------------------

banner "Rimozione account cPanel: ${USER}"
[[ $DRY_RUN -eq 1 ]] && echo -e "  ${YELLOW}Modalità DRY-RUN — nessuna modifica. Aggiungi --execute per agire.${NC}"
log "Log: $LOG_FILE"

echo ""
echo -e "${BOLD}Pre-flight:${NC}"
[[ $EUID -eq 0 ]] || die "Esegui come root"
ok "Root: sì"
command -v whmapi1 >/dev/null 2>&1 || die "whmapi1 non trovato — non è un server cPanel"
ok "cPanel: presente"
[[ -f "/var/cpanel/users/$USER" ]] || die "Account '$USER' inesistente"
ok "Account '$USER': esiste"
case "$USER" in
    root|nobody|cpanel|mysql|toor) die "Utente protetto: '$USER' — rifiuto" ;;
esac
command -v curl >/dev/null 2>&1 || warn "'curl' assente — i check HTTP verranno saltati"

HOMEDIR="/home/$USER"
DISK_BEFORE=$(df -Pm /home 2>/dev/null | awk 'NR==2{print $4}' || echo 0)

echo ""
echo -e "${BOLD}Piano:${NC}"
echo "  1. Audit gate (read-only)"
echo "  2. Backup completo (pkgacct) + verifica integrità"
echo "  3. Terminazione account (whmapi1 removeacct keepdns=$KEEPDNS)"
echo "  4. Verifica post (spazio liberato + domini da mantenere ancora UP)"
if [[ ${#CHECK_DOMAINS[@]} -gt 0 ]]; then
    echo -e "  ${BOLD}Domini da mantenere UP:${NC} ${CHECK_DOMAINS[*]}"
else
    warn "Nessun --check-domain passato: la verifica di regressione post sarà limitata"
fi

# =============================================================================
# Phase 1: Audit gate
# =============================================================================

phase_header 1 "Audit gate (read-only)"

if [[ -x "$AUDIT_SCRIPT" || -f "$AUDIT_SCRIPT" ]]; then
    info "Eseguo $AUDIT_SCRIPT $USER"
    set +e
    bash "$AUDIT_SCRIPT" "$USER"
    AUDIT_RC=$?
    set -e
    case "$AUDIT_RC" in
        0) ok "Audit: nessun problema bloccante" ;;
        2) if [[ $FORCE -eq 1 ]]; then
               warn "Audit ha riportato warning ma --force è attivo — proseguo"
           else
               die "Audit ha riportato warning. Rivedi sopra, poi riesegui con --force se accettabile."
           fi ;;
        *) die "Audit fallito (rc=$AUDIT_RC)" ;;
    esac
else
    warn "cpanel-account-audit.sh non trovato accanto a questo script — gate saltato"
    [[ $FORCE -eq 1 ]] || die "Copia anche cpanel-account-audit.sh, oppure usa --force per saltare il gate"
fi

# Snapshot "before" HTTP status of the must-stay-up domains.
declare -A HTTP_BEFORE=()
if command -v curl >/dev/null 2>&1; then
    for d in "${CHECK_DOMAINS[@]}"; do
        code=$(curl -sS -o /dev/null -w '%{http_code}' -m 15 "https://${d}/" 2>/dev/null || echo "000")
        HTTP_BEFORE["$d"]="$code"
        if [[ "$code" =~ ^(2|3) ]]; then ok "Pre: https://$d -> HTTP $code"; else warn "Pre: https://$d -> HTTP $code (già non risponde!)"; fi
    done
fi

# =============================================================================
# Phase 2: Full backup
# =============================================================================

phase_header 2 "Backup completo (pkgacct)"
will_do \
    "Crea: $DEST" \
    "Esegue: $PKGACCT $USER $DEST  (file, DB, email, DNS, cron, SSL, settaggi)" \
    "Verifica: tar -tzf sull'archivio" \
    "Calcola: sha256 + manifest" \
    "Ripristino: $PKGACCT-restore via /scripts/restorepkg $ARCHIVE"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}[DRY-RUN] backup non eseguito.${NC}"
else
    [[ -x "$PKGACCT" ]] || die "$PKGACCT non trovato"
    mkdir -p "$DEST"
    chmod 700 "$DEST"
    info "Eseguo pkgacct (può richiedere qualche minuto)..."
    if "$PKGACCT" "$USER" "$DEST" >>"$LOG_FILE" 2>&1; then
        ok "pkgacct completato"
    else
        die "pkgacct fallito — vedi $LOG_FILE. Account NON toccato."
    fi
    [[ -f "$ARCHIVE" ]] || die "Archivio atteso non trovato: $ARCHIVE — abort"

    info "Verifica integrità archivio..."
    if tar -tzf "$ARCHIVE" >/dev/null 2>&1; then
        ok "tar -tzf: archivio integro"
    else
        die "Archivio corrotto ($ARCHIVE) — abort, account NON toccato"
    fi
    # Sanity: key components present
    for comp in "cpmove-${USER}/homedir" "cpmove-${USER}/mysql" "cpmove-${USER}/meta"; do
        tar -tzf "$ARCHIVE" 2>/dev/null | grep -q "^${comp}" && info "presente: ${comp}" || warn "componente non trovato nell'archivio: ${comp}"
    done
    sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256" 2>/dev/null && ok "sha256: ${ARCHIVE}.sha256"
    SIZE=$(du -h "$ARCHIVE" | awk '{print $1}')
    ok "Backup verificato: $ARCHIVE ($SIZE)"
fi

# =============================================================================
# Phase 3: Termination
# =============================================================================

phase_header 3 "Terminazione account"
REMOVE_CMD="whmapi1 removeacct user=${USER} keepdns=${KEEPDNS}"
will_do "Esegue: $REMOVE_CMD" "Rimuove home, DB, email, DNS locale (se keepdns=0), utente di sistema"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}[DRY-RUN] comando NON eseguito:${NC}  $REMOVE_CMD"
else
    if [[ $ASSUME_YES -eq 0 ]]; then
        echo ""
        echo -e "  ${RED}${BOLD}Operazione IRREVERSIBILE (rollback solo da backup).${NC}"
        read -rp "  Digita '$USER' per confermare: " typed
        [[ "$typed" == "$USER" ]] || die "Conferma non corrisponde — annullato (backup conservato in $DEST)"
    fi
    info "Eseguo: $REMOVE_CMD"
    set +e
    OUT=$(whmapi1 removeacct user="$USER" keepdns="$KEEPDNS" 2>&1)
    RC=$?
    set -e
    echo "$OUT" >> "$LOG_FILE"
    if [[ $RC -eq 0 ]] && echo "$OUT" | grep -qE '"result"\s*:\s*1|result: 1'; then
        ok "Account '$USER' terminato"
    else
        warn "removeacct output:"; echo "$OUT" | sed 's/^/      /'
        die "removeacct non ha confermato successo — verifica manualmente. Backup: $ARCHIVE"
    fi
fi

# =============================================================================
# Phase 4: Post-verification
# =============================================================================

phase_header 4 "Verifica post"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}[DRY-RUN] nessuna verifica post (niente è stato eliminato).${NC}"
else
    # Account gone?
    if [[ ! -f "/var/cpanel/users/$USER" ]]; then ok "Account rimosso da cPanel"; else warn "Account ancora presente in /var/cpanel/users/$USER"; fi
    if [[ ! -d "$HOMEDIR" ]]; then ok "Home directory rimossa"; else warn "Home ancora presente: $HOMEDIR"; fi

    # Space freed
    DISK_AFTER=$(df -Pm /home 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
    FREED=$((DISK_AFTER - DISK_BEFORE))
    ok "Spazio libero su /home: ${DISK_BEFORE}MB -> ${DISK_AFTER}MB (liberati ~${FREED}MB)"

    # Regression check on the must-stay-up domains
    REGRESSION=0
    if command -v curl >/dev/null 2>&1; then
        for d in "${CHECK_DOMAINS[@]}"; do
            code=$(curl -sS -o /dev/null -w '%{http_code}' -m 15 "https://${d}/" 2>/dev/null || echo "000")
            before="${HTTP_BEFORE[$d]:-?}"
            if [[ "$code" =~ ^(2|3) ]]; then
                ok "Post: https://$d -> HTTP $code (prima: $before)"
            else
                warn "Post: https://$d -> HTTP $code (prima: $before) — REGRESSIONE!"
                REGRESSION=$((REGRESSION + 1))
            fi
        done
    fi
    if [[ $REGRESSION -gt 0 ]]; then
        echo ""
        warn "${BOLD}$REGRESSION dominio/i da mantenere NON rispondono più. Valuta il ROLLBACK:${NC}"
        warn "  /scripts/restorepkg $ARCHIVE"
    fi
fi

# =============================================================================
# Summary + report
# =============================================================================

banner "Riepilogo"
if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN completato — niente eliminato.${NC}"
    CD_HINT=""
    for d in "${CHECK_DOMAINS[@]}"; do CD_HINT+="--check-domain $d "; done
    echo -e "  Per eseguire:  ${BOLD}bash $0 $USER ${CD_HINT}--execute${NC}"
else
    echo -e "  Account:  ${BOLD}$USER${NC} terminato"
    echo -e "  Backup:   $ARCHIVE"
    echo -e "  sha256:   ${ARCHIVE}.sha256"
    echo -e "  Rollback: /scripts/restorepkg $ARCHIVE"
    REPORT="${DEST}/report-${USER}.md"
    mkdir -p "$DEST" 2>/dev/null || true
    {
        echo "# Rimozione account cPanel — $USER"
        echo ""
        echo "- **Data:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "- **Server:** $(hostname 2>/dev/null)"
        echo "- **keepdns:** $KEEPDNS"
        echo "- **Backup:** \`$ARCHIVE\`"
        echo "- **Domini mantenuti verificati:** ${CHECK_DOMAINS[*]:-nessuno}"
        echo ""
        echo "## Rollback"
        echo '```bash'
        echo "/scripts/restorepkg $ARCHIVE"
        echo '```'
    } > "$REPORT" 2>/dev/null && ok "Report: $REPORT"
    cp "$LOG_FILE" "$DEST/" 2>/dev/null || true
fi
echo ""
log "Fine. Log: $LOG_FILE"
