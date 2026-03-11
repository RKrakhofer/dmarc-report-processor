#!/usr/bin/env python3
"""DMARC Report – Auswertung der gespeicherten DMARC-Daten."""

import argparse
import os
import socket
import sqlite3
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
DB_PATH   = Path(os.getenv('DB_PATH', 'dmarc_reports.db'))
MY_DOMAIN = os.getenv('MY_DOMAIN', '')

SEP  = '-' * 80
SEP2 = '=' * 80


def fmt_row(row: sqlite3.Row, *cols: str) -> str:
    return '  '.join(f"{c}={row[c]}" for c in cols if row[c] is not None)


def section(title: str) -> None:
    print(f"\n{SEP2}\n  {title}\n{SEP2}")


def _dns_exists(hostname: str) -> bool:
    """Prüft ob ein Hostname im DNS auflösbar ist (A, AAAA oder MX genügt)."""
    for qtype in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.getaddrinfo(hostname, None, qtype)
            return True
        except socket.gaierror:
            pass
    return False


def _print_assessment(conn: sqlite3.Connection) -> None:
    """Wertet die Daten aus und gibt eine strukturierte Bewertung aus."""
    findings: list[tuple[str, str]] = []  # (symbol, text)

    # --- Spoofing-Versuche ---
    spoof = conn.execute("""
        SELECT SUM(rr.count) AS n, COUNT(DISTINCT rr.source_ip) AS ips
        FROM report_records rr
        WHERE rr.dkim_eval != 'pass' AND rr.spf_eval != 'pass'
    """).fetchone()
    spoof_n   = spoof['n']   or 0
    spoof_ips = spoof['ips'] or 0
    if spoof_n > 0:
        findings.append(('⚠', f"Spoofing-Versuche: {spoof_n} Mails von {spoof_ips} fremden IPs mit DKIM✗ + SPF✗"))
        # DNS-Check: Subdomains von MY_DOMAIN die tatsächlich existieren
        if MY_DOMAIN:
            spoof_domains = conn.execute("""
                SELECT DISTINCT rr.header_from
                FROM report_records rr
                WHERE rr.dkim_eval != 'pass'
                  AND rr.spf_eval  != 'pass'
                  AND rr.header_from IS NOT NULL
            """).fetchall()
            for srow in spoof_domains:
                hf = (srow['header_from'] or '').lower().strip()
                # Nur echte Subdomains (nicht die eigene Domain selbst)
                if hf.endswith('.' + MY_DOMAIN.lower()) and hf != MY_DOMAIN.lower():
                    exists = _dns_exists(hf)
                    if exists:
                        findings.append(('🚨', f"ECHTES PROBLEM: Subdomain '{hf}' existiert im DNS und versendet Spoofing-Mails!"))
                    else:
                        findings.append(('ℹ', f"Spoofing-Subdomain '{hf}' existiert nicht im DNS – wahrscheinlich nur Label-Fälschung"))
    else:
        findings.append(('✓', "Keine Spoofing-Versuche erkannt"))

    # --- Blockiert ---
    blocked = conn.execute("""
        SELECT SUM(rr.count) AS n
        FROM report_records rr
        WHERE rr.disposition IN ('reject','quarantine')
          AND rr.dkim_eval = 'pass'
    """).fetchone()
    blocked_n = blocked['n'] or 0
    if blocked_n > 0:
        findings.append(('✗', f"{blocked_n} eigene Mails (DKIM✓) wurden trotzdem blockiert/quarantined – SPF prüfen"))
    else:
        findings.append(('✓', "Keine eigenen Mails blockiert"))

    # --- DKIM temperror ---
    temperror = conn.execute("""
        SELECT SUM(rr.count) AS n, COUNT(DISTINCT rr.source_ip) AS ips
        FROM report_records rr
        JOIN auth_dkim_results d ON d.record_id = rr.id
        WHERE d.result = 'temperror'
    """).fetchone()
    temperror_n = temperror['n'] or 0
    if temperror_n > 0:
        findings.append(('ℹ', f"DKIM temperror bei {temperror_n} Mails – transienter DNS-Fehler beim Empfänger, kein Handlungsbedarf"))

    # --- SPF fail, DKIM pass (eigene Mails) ---
    spf_fail_own = conn.execute("""
        SELECT SUM(rr.count) AS n
        FROM report_records rr
        JOIN auth_dkim_results d ON d.record_id = rr.id
        WHERE rr.spf_eval != 'pass'
          AND rr.dkim_eval = 'pass'
          AND d.result = 'pass'
    """).fetchone()
    spf_fail_own_n = spf_fail_own['n'] or 0
    if spf_fail_own_n > 0:
        findings.append(('⚠', f"SPF fail bei {spf_fail_own_n} eigenen Mails (DKIM✓) – sendende IPs im SPF-Record ergänzen"))

    # --- DMARC-Policy ---
    policies = conn.execute("""
        SELECT domain, policy_p FROM reports GROUP BY domain, policy_p
    """).fetchall()
    for pol in policies:
        p = pol['policy_p'] or 'none'
        if p == 'none':
            findings.append(('⚠', f"DMARC-Policy für '{pol['domain']}' ist 'none' – Mails werden nur geloggt, nicht blockiert. Empfehlung: 'quarantine' oder 'reject'"))
        elif p == 'quarantine':
            findings.append(('ℹ', f"DMARC-Policy für '{pol['domain']}': 'quarantine' – erwäge 'reject' für maximalen Schutz"))
        else:
            findings.append(('✓', f"DMARC-Policy für '{pol['domain']}': '{p}'"))

    # --- Ausgabe ---
    for symbol, text in findings:
        print(f"  {symbol}  {text}")


def run(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row

    # ------------------------------------------------------------------
    # 1. Gesamtübersicht
    # ------------------------------------------------------------------
    section("GESAMTÜBERSICHT – Mails pro Absenderdomain und Empfangs-Org")
    rows = conn.execute("""
        SELECT
            r.domain                                                            AS domain,
            r.org_name                                                          AS org,
            SUM(rr.count)                                                       AS total,
            SUM(CASE WHEN rr.dkim_eval = 'pass' THEN rr.count ELSE 0 END)      AS dkim_pass,
            SUM(CASE WHEN rr.spf_eval  = 'pass' THEN rr.count ELSE 0 END)      AS spf_pass,
            SUM(CASE WHEN rr.disposition IN ('reject','quarantine')
                     THEN rr.count ELSE 0 END)                                  AS blocked
        FROM report_records rr
        JOIN reports r ON r.id = rr.report_db_id
        GROUP BY r.domain, r.org_name
        ORDER BY total DESC
    """).fetchall()

    if rows:
        print(f"  {'Domain':<30} {'Org':<25} {'Total':>6}  {'DKIM✓':>6}  {'SPF✓':>6}  {'Blockiert':>9}")
        print(f"  {SEP}")
        for row in rows:
            blocked_marker = '  ⚠' if row['blocked'] > 0 else ''
            print(
                f"  {row['domain']:<30} {row['org']:<25} "
                f"{row['total']:>6}  {row['dkim_pass']:>6}  {row['spf_pass']:>6}  "
                f"{row['blocked']:>9}{blocked_marker}"
            )
    else:
        print("  Keine Daten.")

    # ------------------------------------------------------------------
    # 2. Problematische Einträge (DKIM oder SPF fail)
    # ------------------------------------------------------------------
    section("PROBLEME – DKIM oder SPF fehlgeschlagen")
    rows = conn.execute("""
        SELECT
            datetime(r.date_end, 'unixepoch')  AS datum,
            r.org_name                          AS org,
            r.domain                            AS domain,
            rr.source_ip,
            rr.count,
            rr.disposition,
            rr.dkim_eval,
            rr.spf_eval,
            rr.header_from,
            rr.envelope_from,
            rr.reason_type,
            rr.reason_comment
        FROM report_records rr
        JOIN reports r ON r.id = rr.report_db_id
        WHERE rr.dkim_eval != 'pass'
           OR rr.spf_eval  != 'pass'
        ORDER BY r.date_end DESC
    """).fetchall()

    if rows:
        for row in rows:
            print(f"\n  {row['datum']}  {row['org']} → {row['domain']}")
            print(f"    IP={row['source_ip']}  count={row['count']}  disposition={row['disposition']}")
            print(f"    DKIM={row['dkim_eval']}  SPF={row['spf_eval']}")
            if row['header_from']:
                print(f"    header_from={row['header_from']}", end='')
                if row['envelope_from']:
                    print(f"  envelope_from={row['envelope_from']}", end='')
                print()
            if row['reason_type']:
                print(f"    reason={row['reason_type']}", end='')
                if row['reason_comment']:
                    print(f" ({row['reason_comment']})", end='')
                print()
    else:
        print("  Keine Probleme gefunden. ✓")

    # ------------------------------------------------------------------
    # 3. Blockierte Mails (reject / quarantine)
    # ------------------------------------------------------------------
    section("BLOCKIERT – disposition: reject oder quarantine")
    rows = conn.execute("""
        SELECT
            datetime(r.date_end, 'unixepoch')  AS datum,
            r.org_name                          AS org,
            r.domain                            AS domain,
            rr.source_ip,
            rr.count,
            rr.disposition,
            rr.dkim_eval,
            rr.spf_eval,
            rr.header_from
        FROM report_records rr
        JOIN reports r ON r.id = rr.report_db_id
        WHERE rr.disposition IN ('reject', 'quarantine')
        ORDER BY rr.count DESC
    """).fetchall()

    if rows:
        for row in rows:
            print(
                f"  {row['datum']}  {row['org']:<25} {row['disposition']:<12} "
                f"count={row['count']}  IP={row['source_ip']}"
                f"  DKIM={row['dkim_eval']}  SPF={row['spf_eval']}"
            )
    else:
        print("  Keine blockierten Mails. ✓")

    # ------------------------------------------------------------------
    # 4. Unbekannte Quell-IPs (DKIM fail, SPF fail – potenzielle Spoofing-Versuche)
    # ------------------------------------------------------------------
    section("VERDÄCHTIG – DKIM und SPF beide fehlgeschlagen (mögliches Spoofing)")
    rows = conn.execute("""
        SELECT
            datetime(r.date_end, 'unixepoch')  AS datum,
            r.org_name                          AS org,
            r.domain                            AS domain,
            rr.source_ip,
            rr.count,
            rr.disposition,
            rr.header_from
        FROM report_records rr
        JOIN reports r ON r.id = rr.report_db_id
        WHERE rr.dkim_eval != 'pass'
          AND rr.spf_eval  != 'pass'
        ORDER BY rr.count DESC
    """).fetchall()

    if rows:
        for row in rows:
            print(
                f"  {row['datum']}  {row['org']:<25} IP={row['source_ip']:<18} "
                f"count={row['count']}  disposition={row['disposition']}"
            )
    else:
        print("  Keine verdächtigen Einträge. ✓")

    # ------------------------------------------------------------------
    # 5. Auth-Fehler mit eigener Domain im From
    # ------------------------------------------------------------------
    domain_filter = MY_DOMAIN or None
    section(
        f"EIGENE DOMAIN IM FROM – SPF oder DKIM fail"
        + (f" (filter: {domain_filter})" if domain_filter else " (MY_DOMAIN nicht gesetzt → alle Domains)")
    )
    query_param: list = []
    if domain_filter:
        domain_clause = "AND (rr.header_from LIKE ? OR rr.envelope_from LIKE ?)"
        query_param   = [f'%{domain_filter}', f'%{domain_filter}']
    else:
        domain_clause = ""

    rows = conn.execute(f"""
        SELECT
            datetime(r.date_end, 'unixepoch')  AS datum,
            r.org_name                          AS org,
            r.domain                            AS domain,
            rr.source_ip,
            rr.count,
            rr.disposition,
            rr.dkim_eval,
            rr.spf_eval,
            rr.header_from,
            rr.envelope_from,
            rr.reason_type,
            rr.reason_comment
        FROM report_records rr
        JOIN reports r ON r.id = rr.report_db_id
        WHERE (rr.dkim_eval != 'pass' OR rr.spf_eval != 'pass')
          {domain_clause}
        ORDER BY r.date_end DESC, rr.count DESC
    """, query_param).fetchall()

    if rows:
        for row in rows:
            dkim_mark = '✓' if row['dkim_eval'] == 'pass' else '✗'
            spf_mark  = '✓' if row['spf_eval']  == 'pass' else '✗'
            print(f"\n  {row['datum']}  {row['org']} → {row['domain']}")
            print(f"    IP={row['source_ip']}  count={row['count']}  disposition={row['disposition']}")
            print(f"    DKIM{dkim_mark}  SPF{spf_mark}")
            from_parts = []
            if row['header_from']:   from_parts.append(f"header_from={row['header_from']}")
            if row['envelope_from']: from_parts.append(f"envelope_from={row['envelope_from']}")
            if from_parts:
                print(f"    {' | '.join(from_parts)}")
            if row['reason_type']:
                reason = row['reason_type']
                if row['reason_comment']:
                    reason += f" ({row['reason_comment']})"
                print(f"    reason={reason}")
    else:
        print("  Keine Einträge. ✓")

    # ------------------------------------------------------------------
    # 6. Zeitraum
    # ------------------------------------------------------------------
    section("ZEITRAUM DER REPORTS")
    row = conn.execute("""
        SELECT
            datetime(MIN(date_begin), 'unixepoch') AS von,
            datetime(MAX(date_end),   'unixepoch') AS bis,
            COUNT(DISTINCT id)                      AS reports,
            COUNT(DISTINCT message_id)              AS mails
        FROM reports
    """).fetchone()
    if row and row['von']:
        print(f"  Von:     {row['von']}")
        print(f"  Bis:     {row['bis']}")
        print(f"  Reports: {row['reports']}")
        print(f"  Mails:   {row['mails']}")
    else:
        print("  Keine Reports in der Datenbank.")

    # ------------------------------------------------------------------
    # 7. Bewertung
    # ------------------------------------------------------------------
    section("BEWERTUNG")
    _print_assessment(conn)

    print(f"\n{SEP2}\n")


def _print_envelope_to_detail(conn: sqlite3.Connection, domain: str) -> None:
    """Gibt alle Details zu Einträgen mit passendem envelope_to aus."""
    section(f"DETAILS für envelope_to: {domain}")
    rows = conn.execute("""
        SELECT
            datetime(r.date_begin, 'unixepoch')  AS von,
            datetime(r.date_end,   'unixepoch')  AS bis,
            r.org_name,
            r.org_email,
            r.report_id,
            r.domain                             AS policy_domain,
            r.adkim, r.aspf,
            r.policy_p, r.policy_sp, r.policy_pct,
            rr.source_ip,
            rr.count,
            rr.disposition,
            rr.dkim_eval,
            rr.spf_eval,
            rr.reason_type,
            rr.reason_comment,
            rr.envelope_to,
            rr.header_from,
            rr.envelope_from,
            rr.id                                AS record_id
        FROM report_records rr
        JOIN reports r ON r.id = rr.report_db_id
        WHERE rr.envelope_to LIKE ?
        ORDER BY r.date_end DESC, rr.count DESC
    """, (f'%{domain}',)).fetchall()

    if not rows:
        print(f"  Keine Einträge mit envelope_to = '{domain}' gefunden.")
        return

    for row in rows:
        dkim_mark = '✓' if row['dkim_eval'] == 'pass' else '✗'
        spf_mark  = '✓' if row['spf_eval']  == 'pass' else '✗'
        print(f"\n  Zeitraum:      {row['von']} – {row['bis']}")
        print(f"  Bericht von:   {row['org_name']}", end='')
        if row['org_email']:
            print(f" <{row['org_email']}>", end='')
        print(f"  (Report-ID: {row['report_id']})")
        print(f"  Policy-Domain: {row['policy_domain']}  adkim={row['adkim']}  aspf={row['aspf']}  p={row['policy_p']}  sp={row['policy_sp']}  pct={row['policy_pct']}")
        print(f"  Quelle:        IP={row['source_ip']}  count={row['count']}")
        print(f"  Ergebnis:      disposition={row['disposition']}  DKIM{dkim_mark}  SPF{spf_mark}")
        if row['envelope_to']:   print(f"  envelope_to:   {row['envelope_to']}")
        if row['header_from']:   print(f"  header_from:   {row['header_from']}")
        if row['envelope_from']: print(f"  envelope_from: {row['envelope_from']}")
        if row['reason_type']:
            reason = row['reason_type']
            if row['reason_comment']:
                reason += f" ({row['reason_comment']})"
            print(f"  Reason:        {reason}")

        # DKIM-Auth-Details
        dkim_rows = conn.execute("""
            SELECT domain, selector, result, human_result
            FROM auth_dkim_results WHERE record_id = ?
        """, (row['record_id'],)).fetchall()
        for d in dkim_rows:
            hr = f"  [{d['human_result']}]" if d['human_result'] else ''
            print(f"  DKIM-Auth:     domain={d['domain']}  selector={d['selector']}  result={d['result']}{hr}")

        # SPF-Auth-Details
        spf_rows = conn.execute("""
            SELECT domain, scope, result
            FROM auth_spf_results WHERE record_id = ?
        """, (row['record_id'],)).fetchall()
        for s in spf_rows:
            print(f"  SPF-Auth:      domain={s['domain']}  scope={s['scope']}  result={s['result']}")

        print(f"  {'-' * 60}")


def main() -> None:
    parser = argparse.ArgumentParser(description='DMARC Report')
    parser.add_argument('--envelope-to', metavar='DOMAIN',
                        help='Zeige alle Details für Einträge mit dieser envelope_to-Domain')
    args = parser.parse_args()

    if not DB_PATH.exists():
        print(f"Datenbank nicht gefunden: {DB_PATH}")
        return
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if args.envelope_to:
            _print_envelope_to_detail(conn, args.envelope_to)
        else:
            run(conn)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
