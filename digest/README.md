# digest — report giornaliero via email

`server-digest` è uno script Perl (solo moduli core: `POSIX`, `Getopt::Long`, `Time::Local`,
`JSON::PP`) che costruisce un report HTML e lo invia via `sendmail`. È pensato per girare
da `/etc/cron.daily/` subito dopo il backup notturno di cPanel.

## Installazione

```
install -m 755 digest/server-digest /usr/local/bin/server-digest
```

Wrapper cron (`/etc/cron.daily/0logwatch`):

```
#!/bin/sh
/usr/local/bin/server-digest
exit 0
```

Destinatari, mittente e hostname non sono nello script (repo pubblico) ma in
`/etc/server-digest.conf`, `root:600`, formato `KEY=value`:

```
TECH_TO=admin@example.com      # destinatario del report giornaliero
SUMMARY_TO=owner@example.com   # destinatario del riepilogo settimanale (non ancora attivo)
FROM=server@example.com        # mittente/envelope sender (deve passare SPF del relay)
HOSTNAME=server.example.com    # default: hostname -f
```

Senza file i valori sono `root@localhost`. `--show-config` stampa i valori risolti.

## Opzioni

| Flag | Effetto |
|---|---|
| (nessuno) | Report del giorno precedente, inviato a `TECH_TO` |
| `--weekly` | Intervallo di 7 giorni (riepilogo settimanale) |
| `--dry-run` | Stampa l'HTML su stdout, non invia nulla. Utile per test e per `perl -c` |
| `--show-config` | Stampa destinatari/mittente risolti ed esce |

## Sezioni del report

| Sezione | Fonte | Cosa mostra |
|---|---|---|
| Risorse | `df`, `free`, `uptime` | Dischi (`/`, `/tmp`, `/home`), memoria, carico, swap |
| Sicurezza | logwatch (CSF/LFD, auditd, rkhunter, exim) | Blocchi firewall per tipo, modifiche a file critici, rootkit scan, auth SMTP fallite |
| Backup | vedi sotto | Set locale, copie remote, spazio per il prossimo run |
| Servizi | `exim -bpc`, `ss`, `mysqladmin`, logwatch | Coda email, connessioni HTTP, MySQL, ClamAV |
| Log completo | `logwatch --detail Med` | Output integrale in `<pre>` |

### Sezione Backup

Fonti, tutte in sola lettura:

| Fonte | Uso |
|---|---|
| `/var/cpanel/backups/config` | directory, retention, soglia di spazio minimo (`MIN_FREE_SPACE`), `KEEPLOCAL` |
| `/var/cpanel/backups/*.backup_destination` | destinazioni remote: tipo, bucket/cartella, `disabled`, `only_used_for_logs` |
| `<BACKUPDIR>/YYYY-MM-DD`, `weekly/`, `monthly/` | set locali: conteggio archivi e dimensione (somma degli `.tar.gz`, niente `du`) |
| `/usr/local/cpanel/logs/cpbackup/<epoch>.log` | esito del run (`Final state is Backup::…`), orari, account riusciti/falliti |
| `/usr/local/cpanel/logs/cpbackup_transporter.log` | trasferimenti riusciti/falliti verso ogni destinazione per il set di riferimento |
| `whmapi1 listaccts` | account attesi nel set (flag `backup` attivo, non sospesi) e spazio usato dai siti |

Righe prodotte:

- **Backup locale** — data del set di riferimento, archivi presenti / account attesi, dimensione,
  esito e durata del run. Il set di riferimento è il più recente **non in corso**: un run senza
  `Final state` e con log modificato da meno di 6 ore viene mostrato come "in corso" e non
  genera falsi allarmi. Sotto: account mancanti, set conservati rispetto alla retention.
- **Backup remoto** — una riga per ogni destinazione attiva: account caricati / attesi, ultimo
  trasferimento riuscito, falliti, elenco dei mancanti. Se nessuna destinazione è attiva
  (disabilitata o con "Only use this destination for logs"), riga rossa "NON ATTIVO".
- **Spazio per il prossimo backup** — percentuale libera sul volume di backup contro la soglia
  di cPanel. Sotto la soglia il backup notturno viene rifiutato: la riga diventa rossa.

Semafori: verde = set di ieri o oggi completo; giallo = set di 2 giorni, account mancanti o
trasferimenti falliti; rosso = oltre 2 giorni, run fallito, meno del 90% degli account, remoto vuoto
o spazio sotto soglia.

## Perché

Fino a ottobre 2026 la riga "Backup" leggeva `/var/cpanel/backups/logs/`, directory che non
esiste: il report diceva sempre "sconosciuto" mentre il server era senza backup da tre mesi
(spazio sotto la soglia del 20%) e la destinazione S3 era configurata "solo per i log", quindi
vuota. Le notifiche cPanel andavano a un altro indirizzo. Questa sezione rende visibili tutte
e tre le condizioni nel report che arriva ogni mattina.
