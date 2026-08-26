#!/usr/bin/env bash
# =============================================================================
# cpanel-account-audit.sh
# Read-only pre-flight audit of a cPanel account before termination.
#
# Target:  serverk01.venicebay.it (CloudLinux 8 / cPanel) — but GENERIC:
#          accepts any cPanel user or domain as argument.
# Purpose: gather everything you must know before deleting an account, and
#          flag anything that makes deletion unsafe:
#            - all domains served (main / addon / sub / parked)
#            - disk usage, databases, mailboxes
#            - local DNS zones owned by the account
#            - public NS / A / MX of each domain (via dig)
#            - domains STILL pointing at THIS server  (deletion = real outage)
#            - cross-account dependency: a sibling account whose FQDN lives
#              under a zone this account owns AND that this server serves
#              authoritatively (deleting the zone would break the sibling)
#
# This script NEVER modifies anything. Safe to run any time.
#
# Usage:
#   bash cpanel-account-audit.sh <user|domain>
#   bash cpanel-account-audit.sh grafcovebay
#   bash cpanel-account-audit.sh grafco.it
#   bash cpanel-account-audit.sh <user> --quiet      # machine-parsable verdict
#
# Exit codes:
#   0  = audit ran, no blocking issues found (SAFE to remove)
#   2  = audit ran, WARNINGS found (review before removing)
#   1  = error (user not found, missing tooling, etc.)
# =============================================================================
set -euo pipefail

# -- Args ---------------------------------------------------------------------

QUIET=0
TARGET=""
for arg in "$@"; do
    case "$arg" in
        --quiet|-q) QUIET=1 ;;
        --help|-h)
            echo "Usage: bash $0 <user|domain> [--quiet]"
            exit 0
            ;;
        -*) echo "Unknown option: $arg (use --help)"; exit 1 ;;
        *)  TARGET="$arg" ;;
    esac
done

[[ -n "$TARGET" ]] || { echo "Usage: bash $0 <user|domain> [--quiet]"; exit 1; }

# -- Colors & UI --------------------------------------------------------------

if [[ $QUIET -eq 1 || ! -t 1 ]]; then
    RED='' ; GREEN='' ; YELLOW='' ; CYAN='' ; BOLD='' ; NC=''
else
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
fi

say()  { [[ $QUIET -eq 1 ]] || echo -e "$1"; }
info() { say "${CYAN}  ▸ $1${NC}"; }
ok()   { say "${GREEN}  ✓ $1${NC}"; }
warn() { say "${YELLOW}  ⚠ $1${NC}"; }
die()  { echo -e "${RED}  ✗ FATAL: $1${NC}" >&2; exit 1; }

WARN_COUNT=0
flag() { warn "$1"; WARN_COUNT=$((WARN_COUNT + 1)); }

# -- Environment sanity -------------------------------------------------------

command -v dig >/dev/null 2>&1 || die "'dig' non trovato (yum install bind-utils)"
[[ -f /etc/userdatadomains ]] || die "/etc/userdatadomains assente — non sembra un server cPanel"

# Public resolver so we see the AUTHORITATIVE public view, not the local zone.
RESOLVER="1.1.1.1"

# Server IPs (a domain resolving to any of these still lands on THIS box).
declare -a SERVER_IPS=()
[[ -f /var/cpanel/mainip ]] && SERVER_IPS+=("$(cat /var/cpanel/mainip)")
while read -r ip; do [[ -n "$ip" ]] && SERVER_IPS+=("$ip"); done < <(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' || true)

is_server_ip() {
    local candidate="$1" ip
    for ip in "${SERVER_IPS[@]}"; do [[ "$candidate" == "$ip" ]] && return 0; done
    return 1
}

# Nameservers this server is authoritative on (from cPanel config).
declare -a SERVER_NS=()
while read -r ns; do [[ -n "$ns" ]] && SERVER_NS+=("${ns,,}"); done < <(grep -E '^NS[0-9]* ' /etc/wwwacct.conf 2>/dev/null | awk '{print $2}' || true)

# -- Resolve target -> cPanel user --------------------------------------------

resolve_user() {
    local t="$1"
    if [[ -f "/var/cpanel/users/$t" ]]; then echo "$t"; return 0; fi
    # Treat as domain: look up owning user in /etc/userdatadomains
    local line
    line=$(grep -iE "^${t}: " /etc/userdatadomains 2>/dev/null | head -1 || true)
    [[ -n "$line" ]] || return 1
    echo "$line" | sed -E 's/^[^:]+: //' | cut -d= -f1
}

USER=$(resolve_user "$TARGET") || die "Impossibile risolvere '$TARGET' a un account cPanel"
[[ -f "/var/cpanel/users/$USER" ]] || die "Account cPanel '$USER' inesistente"

# Never allow auditing/removal targeting system-critical users.
case "$USER" in
    root|nobody|cpanel|mysql|""|toor) die "Utente protetto: '$USER' — rifiuto" ;;
esac

HOMEDIR=$(getent passwd "$USER" 2>/dev/null | cut -d: -f6)
[[ -n "$HOMEDIR" ]] || HOMEDIR="/home/$USER"

say ""
say "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
say "${BOLD}  Audit account cPanel: ${USER}${NC}"
say "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
info "Home: $HOMEDIR"
info "Resolver DNS pubblico: $RESOLVER"
info "IP del server: ${SERVER_IPS[*]:-sconosciuti}"
info "Nameserver del server: ${SERVER_NS[*]:-nessuno in wwwacct.conf}"

# -- Domains owned by the account ---------------------------------------------

say ""
say "${BOLD}Domini serviti dall'account:${NC}"

declare -a DOMAINS=()
declare -A DOMAIN_TYPE=()
while IFS= read -r line; do
    dom=$(echo "$line" | sed -E 's/: .*//')
    rest=$(echo "$line" | sed -E 's/^[^:]+: //')
    dtype=$(echo "$rest" | cut -d= -f5)   # user==owner==type==... -> field 3 of == split
    # field layout: user(1) '' owner(3) '' type(5) ...
    DOMAINS+=("$dom")
    DOMAIN_TYPE["$dom"]="$dtype"
done < <(awk -F': ' -v u="$USER" '{ split($2,a,"=="); if (a[1]==u) print $0 }' /etc/userdatadomains 2>/dev/null || true)

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
    flag "Nessun dominio trovato in /etc/userdatadomains per '$USER' (account vuoto?)"
else
    for d in "${DOMAINS[@]}"; do
        printf '    %s%-32s%s tipo=%s\n' "$CYAN" "$d" "$NC" "${DOMAIN_TYPE[$d]:-?}"
    done
fi

# -- DNS analysis per domain --------------------------------------------------

say ""
say "${BOLD}Analisi DNS pubblica (dig @${RESOLVER}):${NC}"

registrable_ns() {
    # Walk up labels until we get an NS answer (subdomains inherit parent NS).
    local d="$1" ns
    while [[ "$d" == *.* ]]; do
        ns=$(dig +short NS "$d" @"$RESOLVER" 2>/dev/null | tr '\n' ' ')
        [[ -n "$ns" ]] && { echo "$ns"; return 0; }
        d="${d#*.}"
    done
    echo ""
}

LIVE_HERE=0
for d in "${DOMAINS[@]}"; do
    a=$(dig +short A "$d" @"$RESOLVER" 2>/dev/null | grep -E '^[0-9]' | tr '\n' ' ' || true)
    ns=$(registrable_ns "$d")
    printf '    %s%-32s%s A: %s\n' "$BOLD" "$d" "$NC" "${a:-(nessuno)}"
    [[ $QUIET -eq 1 ]] || printf '    %-32s NS: %s\n' "" "${ns:-(nessuno)}"

    # Authoritative on THIS server?
    auth_here=0
    for pair_ns in $ns; do
        for sns in "${SERVER_NS[@]}"; do
            [[ "${pair_ns%.}" == "${sns%.}" ]] && auth_here=1
        done
    done

    # Does any A record still land on this server?
    points_here=0
    for ip in $a; do is_server_ip "$ip" && points_here=1; done

    if [[ "${DOMAIN_TYPE[$d]:-}" == "sub" ]]; then
        : # subdomains are expected to point here; not a red flag on their own
    elif [[ $points_here -eq 1 && -n "$a" ]]; then
        flag "$d punta ANCORA a questo server ($a) — eliminarlo = downtime reale"
        LIVE_HERE=$((LIVE_HERE + 1))
    elif [[ -z "$a" ]]; then
        info "$d non risolve pubblicamente (probabilmente dismesso)"
    else
        ok "$d punta altrove ($a) — già migrato, safe"
    fi

    if [[ $auth_here -eq 1 ]]; then
        info "$d: questo server È autoritativo (NS: $ns) — la zona locale è viva"
    fi
done

# -- Cross-account dependency check (the critical one) ------------------------

say ""
say "${BOLD}Dependency check cross-account:${NC}"
info "Cerco account DIVERSI il cui FQDN vive sotto una zona di questo account..."

DEP_FOUND=0
for d in "${DOMAINS[@]}"; do
    # Any other domain in userdatadomains that is *.d owned by a different user?
    while IFS= read -r line; do
        other_dom=$(echo "$line" | sed -E 's/: .*//')
        other_user=$(echo "$line" | sed -E 's/^[^:]+: //' | cut -d= -f1)
        [[ "$other_user" == "$USER" ]] && continue
        [[ "$other_dom" == *".$d" ]] || continue
        # Is this account authoritative for the parent zone d?
        pns=$(registrable_ns "$d")
        auth_here=0
        for pair_ns in $pns; do
            for sns in "${SERVER_NS[@]}"; do
                [[ "${pair_ns%.}" == "${sns%.}" ]] && auth_here=1
            done
        done
        if [[ $auth_here -eq 1 ]]; then
            flag "DIPENDENZA: $other_dom (account '$other_user') vive sotto $d e questo server è autoritativo → usa --keepdns o migra il DNS prima"
        else
            ok "$other_dom (account '$other_user') sta sotto $d ma il DNS è esterno (NS: ${pns:-?}) → rimozione zona locale innocua"
        fi
        DEP_FOUND=$((DEP_FOUND + 1))
    done < <(grep -iE ": " /etc/userdatadomains 2>/dev/null || true)
done
[[ $DEP_FOUND -eq 0 ]] && ok "Nessun account dipende dai domini di '$USER'"

# -- Local DNS zones owned -----------------------------------------------------

say ""
say "${BOLD}Zone DNS locali possedute:${NC}"
for d in "${DOMAINS[@]}"; do
    if [[ -f "/var/named/${d}.db" ]]; then
        info "/var/named/${d}.db (verrà rimossa se non usi --keepdns)"
    fi
done

# -- Databases -----------------------------------------------------------------

say ""
say "${BOLD}Database MySQL dell'account:${NC}"
DB_LIST=$(uapi --user="$USER" Mysql list_databases 2>/dev/null | grep -E '^\s*-\s' | sed 's/^\s*-\s*//' || true)
if [[ -n "$DB_LIST" ]]; then
    echo "$DB_LIST" | while read -r db; do info "$db"; done
else
    info "(nessuno o uapi non disponibile)"
fi

# -- Mailboxes -----------------------------------------------------------------

say ""
say "${BOLD}Caselle email:${NC}"
MAIL_COUNT=0
for f in "$HOMEDIR"/etc/*/passwd; do
    [[ -f "$f" ]] || continue
    dom=$(basename "$(dirname "$f")")
    n=$(wc -l < "$f" 2>/dev/null | tr -d ' ')
    info "$dom: $n casella/e"
    MAIL_COUNT=$((MAIL_COUNT + n))
done
[[ $MAIL_COUNT -eq 0 ]] && ok "Nessuna casella email locale"
for d in "${DOMAINS[@]}"; do
    mx=$(dig +short MX "$d" @"$RESOLVER" 2>/dev/null | tr '\n' ' ' || true)
    [[ -n "$mx" ]] && info "MX $d: $mx"
done

# -- Disk usage ----------------------------------------------------------------

say ""
say "${BOLD}Spazio disco:${NC}"
if [[ -d "$HOMEDIR" ]]; then
    DU=$(du -sh "$HOMEDIR" 2>/dev/null | awk '{print $1}' || echo "?")
    info "Home ($HOMEDIR): $DU"
fi

# -- Verdict -------------------------------------------------------------------

say ""
say "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [[ $WARN_COUNT -eq 0 ]]; then
    say "${GREEN}${BOLD}  VERDETTO: nessun problema bloccante — SAFE da rimuovere${NC}"
    say "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    [[ $QUIET -eq 1 ]] && echo "AUDIT_VERDICT=SAFE user=$USER warnings=0"
    exit 0
else
    say "${YELLOW}${BOLD}  VERDETTO: $WARN_COUNT warning — RIVEDI prima di rimuovere${NC}"
    say "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    [[ $QUIET -eq 1 ]] && echo "AUDIT_VERDICT=WARN user=$USER warnings=$WARN_COUNT"
    exit 2
fi
