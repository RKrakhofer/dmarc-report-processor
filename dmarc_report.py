#!/usr/bin/env python3
"""DMARC Report – Auswertung der gespeicherten DMARC-Daten."""

import argparse
import os
import re
import socket
import sqlite3
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
DB_PATH   = Path(os.getenv('DB_PATH', 'dmarc_reports.db'))
MY_DOMAINS = [d.strip() for d in os.getenv('MY_DOMAINS', '').split(',') if d.strip()]

SEP  = '-' * 80
SEP2 = '=' * 80


def _glob_to_sql_like(pattern: str) -> str:
    """Konvertiert ein Shell-Glob-Muster in ein SQLite-LIKE-Muster (ESCAPE '\\')."""
    result = ''
    for ch in pattern:
        if ch == '%':  result += r'\%'
        elif ch == '_': result += r'\_'
        elif ch == '*': result += '%'
        elif ch == '?': result += '_'
        else:           result += ch
    return result


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
        # DNS-Check: Subdomains von MY_DOMAINS die tatsächlich existieren
        if MY_DOMAINS:
            spoof_domains = conn.execute("""
                SELECT DISTINCT rr.header_from
                FROM report_records rr
                WHERE rr.dkim_eval != 'pass'
                  AND rr.spf_eval  != 'pass'
                  AND rr.header_from IS NOT NULL
            """).fetchall()
            for srow in spoof_domains:
                hf = (srow['header_from'] or '').lower().strip()
                for _domain in MY_DOMAINS:
                    # Nur echte Subdomains (nicht die eigene Domain selbst)
                    if hf.endswith('.' + _domain.lower()) and hf != _domain.lower():
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
    domain_filter = MY_DOMAINS or None
    section(
        f"EIGENE DOMAIN IM FROM – SPF oder DKIM fail"
        + (f" (filter: {', '.join(domain_filter)})" if domain_filter else " (MY_DOMAINS nicht gesetzt → alle Domains)")
    )
    query_param: list = []
    if domain_filter:
        _clauses = ' OR '.join(["(rr.header_from LIKE ? OR rr.envelope_from LIKE ?)"] * len(domain_filter))
        domain_clause = f"AND ({_clauses})"
        query_param   = [val for d in domain_filter for val in (f'%{d}', f'%{d}')]
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


def _print_envelope_domain_list(conn: sqlite3.Connection, pattern: str) -> None:
    """Listet envelope_to-Domains und Mailanzahl, gefiltert per Glob-Muster."""
    like = _glob_to_sql_like(pattern)
    section(f"ENVELOPE-TO DOMAINS – Muster: {pattern}")
    rows = conn.execute("""
        SELECT
            rr.envelope_to                                                          AS envelope_to,
            SUM(rr.count)                                                           AS total,
            SUM(CASE WHEN rr.dkim_eval = 'pass' THEN rr.count ELSE 0 END)          AS dkim_pass,
            SUM(CASE WHEN rr.spf_eval  = 'pass' THEN rr.count ELSE 0 END)          AS spf_pass,
            SUM(CASE WHEN rr.disposition IN ('reject','quarantine')
                     THEN rr.count ELSE 0 END)                                      AS blocked,
            COUNT(DISTINCT rr.source_ip)                                            AS ips
        FROM report_records rr
        WHERE rr.envelope_to LIKE ? ESCAPE '\\'
        GROUP BY rr.envelope_to
        ORDER BY total DESC
    """, (like,)).fetchall()

    if not rows:
        print(f"  Keine Einträge mit envelope_to passend zu '{pattern}' gefunden.")
        return

    # org_names je envelope_to vorausladen (DISTINCT, sortiert)
    org_map: dict[str, list[str]] = {}
    for row in rows:
        env = row['envelope_to']
        orgs = conn.execute("""
            SELECT DISTINCT r.org_name
            FROM report_records rr
            JOIN reports r ON r.id = rr.report_db_id
            WHERE rr.envelope_to IS ?
            ORDER BY r.org_name
        """, (env,)).fetchall()
        org_map[env] = [o['org_name'] for o in orgs if o['org_name']]

    print(f"  {'envelope_to':<40} {'Total':>6}  {'DKIM✓':>6}  {'SPF✓':>6}  {'Blockiert':>9}  {'IPs':>4}  Orgs")
    print(f"  {SEP}")
    for row in rows:
        blocked_marker = '  ⚠' if row['blocked'] > 0 else ''
        env = row['envelope_to']
        orgs_str = ', '.join(org_map.get(env) or [])
        print(
            f"  {(env or '(leer)'):<40} "
            f"{row['total']:>6}  {row['dkim_pass']:>6}  {row['spf_pass']:>6}  "
            f"{row['blocked']:>9}  {row['ips']:>4}  {orgs_str}{blocked_marker}"
        )
    total_all = sum(r['total'] for r in rows)
    print(f"  {SEP}")
    print(f"  {'GESAMT (' + str(len(rows)) + ' Domains)':<40} {total_all:>6}")


def _timeline_type(value: str) -> tuple[int, str]:
    """Argparse-Type-Funktion: parst '<Zahl>[d|w|m|y]' in (count, unit)."""
    m = re.fullmatch(r'(\d+)([dwmy])', value.lower())
    if not m:
        raise argparse.ArgumentTypeError(
            f"Ungültiges Format '{value}'. Erwartet: <Zahl>[d|w|m|y]  z.B.: 30d, 4w, 12m, 2y"
        )
    return int(m.group(1)), m.group(2)


def _print_timeline(conn: sqlite3.Connection, count: int, unit: str) -> None:
    """Zeigt die Domain-Reputation als ASCII-Zeitverlauf."""
    UNIT_SECS = {'d': 86_400, 'w': 7 * 86_400, 'm': 30 * 86_400, 'y': 365 * 86_400}
    UNIT_NAME = {'d': 'Tage', 'w': 'Wochen', 'm': 'Monate', 'y': 'Jahre'}
    SQL_FMT   = {'d': '%Y-%m-%d', 'w': '%Y-W%W', 'm': '%Y-%m', 'y': '%Y'}
    BAR_WIDTH = 30

    cutoff = int(time.time()) - count * UNIT_SECS[unit]
    domain_label = f' – {', '.join(MY_DOMAINS)}' if MY_DOMAINS else ''
    section(f"REPUTATION-TIMELINE{domain_label} – letzte {count} {UNIT_NAME[unit]}")
    print(f"  Score = DKIM-Pass-Rate  |  ░ = 0 %   █ = 100 %  |  ⚠ Spoofing  ✗ Blockiert\n")

    rows = conn.execute("""
        SELECT
            strftime(?, r.date_end, 'unixepoch')                                            AS bucket,
            SUM(rr.count)                                                                    AS total,
            SUM(CASE WHEN rr.dkim_eval = 'pass' THEN rr.count ELSE 0 END)                   AS dkim_pass,
            SUM(CASE WHEN rr.spf_eval  = 'pass' THEN rr.count ELSE 0 END)                   AS spf_pass,
            SUM(CASE WHEN rr.dkim_eval != 'pass' AND rr.spf_eval != 'pass'
                     THEN rr.count ELSE 0 END)                                               AS spoof,
            SUM(CASE WHEN rr.disposition IN ('reject','quarantine')
                     THEN rr.count ELSE 0 END)                                               AS blocked
        FROM report_records rr
        JOIN reports r ON r.id = rr.report_db_id
        WHERE r.date_end >= ?
        GROUP BY bucket
        ORDER BY bucket ASC
    """, (SQL_FMT[unit], cutoff)).fetchall()

    if not rows:
        print("  Keine Daten im gewählten Zeitraum.")
        return

    print(f"  {'Zeitraum':<14}  {'Total':>6}  {'DKIM✓':>6}  {'SPF✓':>6}  {'Spoof':>5}  {'Blk':>4}  {'Score':>6}  Verlauf")
    print(f"  {SEP}")

    scores: list[float] = []
    for row in rows:
        total = row['total'] or 0
        dkim  = row['dkim_pass'] or 0
        spf   = row['spf_pass'] or 0
        spoof = row['spoof'] or 0
        blk   = row['blocked'] or 0

        if total > 0:
            score = dkim / total * 100
            scores.append(score)
            filled    = round(score / 100 * BAR_WIDTH)
            bar       = '█' * filled + '░' * (BAR_WIDTH - filled)
            score_str = f"{score:5.1f}%"
            warn = ('⚠' if spoof > 0 else '') + ('✗' if blk > 0 else '')
        else:
            bar       = '·' * BAR_WIDTH
            score_str = '     -'
            warn      = ''

        print(
            f"  {(row['bucket'] or '?'):<14}  {total:>6}  {dkim:>6}  {spf:>6}  "
            f"{spoof:>5}  {blk:>4}  {score_str}  {bar} {warn}"
        )

    # Trend
    data = [(r['total'] or 0, r['dkim_pass'] or 0) for r in rows if (r['total'] or 0) > 0]
    print(f"\n  {SEP}")
    if len(data) >= 2:
        s_first = data[0][1] / data[0][0] * 100
        s_last  = data[-1][1] / data[-1][0] * 100
        delta   = s_last - s_first
        if abs(delta) < 1.0:
            trend = '→  Stabil'
        elif delta > 0:
            trend = f'↑  Verbessert  (+{delta:.1f}%)'
        else:
            trend = f'↓  Verschlechtert  ({delta:.1f}%)'
        print(f"  Trend: {trend}  (Anfang: {s_first:.1f}%  →  Ende: {s_last:.1f}%)")
    elif scores:
        print(f"  Nur eine Periode mit Daten – kein Trend berechenbar.")
    else:
        print("  Keine Mails im Zeitraum – kein Trend berechenbar.")
    print()


def _print_arc_overrides(conn: sqlite3.Connection) -> None:
    """Listet alle Records, bei denen ein Provider die DMARC-Policy überschrieben hat."""
    section("ARC / PROVIDER-OVERRIDES – reason_type gesetzt")
    rows = conn.execute("""
        SELECT
            datetime(r.date_begin, 'unixepoch')  AS von,
            datetime(r.date_end,   'unixepoch')  AS bis,
            r.org_name,
            r.domain                             AS policy_domain,
            r.policy_p,
            rr.source_ip,
            rr.count,
            rr.disposition,
            rr.dkim_eval,
            rr.spf_eval,
            rr.reason_type,
            rr.reason_comment,
            rr.header_from,
            rr.envelope_from,
            rr.id                                AS record_id
        FROM report_records rr
        JOIN reports r ON r.id = rr.report_db_id
        WHERE rr.reason_type IS NOT NULL
        ORDER BY r.date_end DESC, rr.count DESC
    """).fetchall()

    if not rows:
        print("  Keine Provider-Overrides in der Datenbank. ✓")
        return

    print(f"  {'Zeitraum':<22}  {'Org':<25}  {'Domain':<20}  {'IP':<18}  "
          f"{'cnt':>4}  {'DKIM':>5}  {'SPF':>5}  {'disp':<12}  Reason")
    print(f"  {SEP}")
    for row in rows:
        dkim_mark = '✓' if row['dkim_eval'] == 'pass' else '✗'
        spf_mark  = '✓' if row['spf_eval']  == 'pass' else '✗'
        reason = row['reason_type']
        if row['reason_comment']:
            reason += f" ({row['reason_comment']})"
        print(
            f"  {row['bis']:<22}  {(row['org_name'] or ''):<25}  "
            f"{row['policy_domain']:<20}  {(row['source_ip'] or ''):<18}  "
            f"{row['count']:>4}  DKIM{dkim_mark}  SPF{spf_mark}  "
            f"{row['disposition']:<12}  {reason}"
        )
        if row['header_from'] or row['envelope_from']:
            from_parts = []
            if row['header_from']:   from_parts.append(f"header_from={row['header_from']}")
            if row['envelope_from']: from_parts.append(f"envelope_from={row['envelope_from']}")
            print(f"    ↳ {' | '.join(from_parts)}")

    # Zusammenfassung nach reason_type
    print(f"\n  {SEP}")
    print("  Zusammenfassung nach Override-Typ:")
    summary = conn.execute("""
        SELECT rr.reason_type, COUNT(*) AS records, SUM(rr.count) AS mails
        FROM report_records rr
        WHERE rr.reason_type IS NOT NULL
        GROUP BY rr.reason_type
        ORDER BY mails DESC
    """).fetchall()
    for s in summary:
        print(f"    {s['reason_type']:<20}  {s['records']:>3} Records  {s['mails']:>6} Mails")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description='DMARC Report')
    parser.add_argument('--envelope-to', metavar='DOMAIN',
                        help='Zeige alle Details für Einträge mit dieser envelope_to-Domain')
    parser.add_argument('-l', '--list', metavar='GLOB',
                        help='Liste envelope_to-Domains + Mailanzahl; Glob-Wildcards * und ? erlaubt (z.B. "*.google.com")')
    parser.add_argument('--arc', action='store_true',
                        help='Zeige alle Records, bei denen ein Provider die DMARC-Policy überschrieben hat (reason_type gesetzt)')
    parser.add_argument('--timeline', metavar='<N>[dwmy]', type=_timeline_type,
                        help='Reputation-Zeitverlauf: Anzahl + Einheit (d=Tage, w=Wochen, m=Monate, y=Jahre), z.B. 30d, 4w, 12m, 2y')
    args = parser.parse_args()

    if not DB_PATH.exists():
        print(f"Datenbank nicht gefunden: {DB_PATH}")
        return
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if args.timeline:
            _print_timeline(conn, *args.timeline)
        elif args.arc:
            _print_arc_overrides(conn)
        elif args.list:
            _print_envelope_domain_list(conn, args.list)
        elif args.envelope_to:
            _print_envelope_to_detail(conn, args.envelope_to)
        else:
            run(conn)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
