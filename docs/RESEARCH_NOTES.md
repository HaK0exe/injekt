# RESEARCH NOTES — injekt v2

## Sources (2024-2026)

### Techniques d'injection
- **Boolean-based** : différentiel TRUE/FALSE, Levenshtein/Jaccard, confirmation inversée (3 trials). Adaptations commentaires par DBMS (`-- -`, `--`, `#`). Réf: OWASP SQL Injection Prevention Cheat Sheet 2024, PortSwigger Web Security Academy (SQLi labs 2024).
- **Time-based** : `SLEEP()` (MySQL), `pg_sleep()` (Postgres), `WAITFOR DELAY` (MSSQL), `DBMS_PIPE.RECEIVE_MESSAGE` (Oracle). Seuil baseline + 2σ, retry sur timeout. Blind exploitation 2024: optimisation binary search ASCII 32-126.
- **Error-based** : `EXTRACTVALUE`, `UPDATE XML`, `CAST`/`CONVERT` errors, `CTXSYS.DRITHSX`. Regex version extraction. Évasion via commentaires inline `/**/`, encodages.
- **Union / Stacked / OOB** : Union enumeration `information_schema`, stacked `; SELECT ...`, OOB DNS/HTTP exfil (`LOAD_FILE`, `UTL_HTTP`, `pg_read_file`). Non implémenté en v2 sans OOB infra (roadmap).
- **JSON injection** : `JSON_EXTRACT`, `->>` operator (MySQL 8.x, Postgres 15+). Payloads JSON path.

### Évasion WAF (2024-2026)
- Encodages: URL, double-URL, hex `%2e`, unicode `%u`, UTF-8 overlong.
- Commentaires inline: `/*!32302 SELECT*/` (MySQL versioned), `/**/`, `/*foo*/`.
- Case mixing: `SeLeCt`, whitespace variants: `%0a`, `%09`, `+`.
- Chunked transfer: `Transfer-Encoding: chunked` to bypass content-length inspection.
- HTTP Parameter Pollution (HPP): duplicate `?id=1&id=2`.
- Réf: `PayloadsAllTheThings` SQLi, `sqlmap` tamper scripts (`space2comment`, `charencode`), Black Hat USA 2024 WAF bypass.

### SGBD — syntaxes fingerprint 2024-2026
- **MySQL 8.x** : `@@version` (`8.0.x`, `8.4 LTS`), `@@version_comment`, `DATABASE()`, `USER()`, `LOAD_FILE()`, `BENCHMARK(1000000,MD5(1))`.
- **Postgres 15+** : `version()` (`PostgreSQL 15.7`), `current_database()`, `current_user`, `pg_sleep()`, `pg_read_file()`.
- **MSSQL 2022** : `@@version` (`Microsoft SQL Server 2022`), `DB_NAME()`, `USER_NAME()`, `WAITFOR DELAY '00:00:05'`, `CONVERT(int,@@version)`.
- **Oracle 21c** : `SELECT banner FROM v$version`, `SYS_CONTEXT('USERENV','CURRENT_USER')`, `DBMS_PIPE.RECEIVE_MESSAGE`, `UTL_INADDR`.
- Fingerprint via error messages + banner regex + `information_schema` vs `pg_catalog`.

### OPSEC outillage pentest (2024-2026)
- **Jitter** : distribution normale (mean 750ms, sd 250ms) > cadence humaine, évite détection rythmique. `rand_distr::Normal`.
- **Rotation identité** : UA cohérent Sec-CH-UA, Accept-Language, ordre headers normalisé. Pool Chrome 126, Firefox 128, Safari 17.5.
- **Fuite DNS** : `socks5h://` (remote DNS) obligatoire, rejet `socks5://`. Tor `127.0.0.1:9050`.
- **Fingerprint TLS (JA3)** : `rustls` empreinte stable, documentée comme limitation (pas de randomisation JA3 sans `boringssl`). Mitigation: proxy.
- **Data minimization** : RAM only, `ZeroizeOnDrop`, `SecretString`, `scrubber` redaction headers sensibles, preuves hashées.
- Réf: `tor` socks5h spec, `rustls` JA3, OPSEC `MITRE ATT&CK` defense evasion.

## Extraits
- MySQL error: `XPATH syntax error: '~5.7.32~'` (EXTRACTVALUE)
- Postgres error: `pg_query(): Query failed: ERROR:  invalid input syntax for integer: "version"`
- MSSQL error: `Microsoft OLE DB Provider for ODBC Drivers error '80040e07'`
- Oracle error: `ORA-00933: SQL command not properly ended`
