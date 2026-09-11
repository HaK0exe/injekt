# injekt report

- Target: `https://example.com/?id=1`
- Findings: 2
- Requests: 42
- Tool: injekt 0.3.0

| Parameter | Technique | Severity | Confidence | FP prob | DBMS |
|---|---|---|---|---|---|
| `id@query` | boolean | **high** | 0.95 | 0.02 | - |
| `q@query` | error | **medium** | 0.78 | 0.12 | postgres |

## 1 — `id@query` (boolean)

- Severity: **high**
- Confidence: 0.95 (false-positive probability 0.02)
- DBMS: unknown
- Evidence: `boolean true_sim=0.95 false_sim=0.10 trials=3/3`
- Diff: `TRUE≈baseline FALSE≠baseline`
- Trace ref: `trace:9f2c41aa07bd3e55`

### Remediation

Use parameterized queries / prepared statements; never concatenate input into SQL. Enforce least-privilege DB accounts and validate input server-side.

```
db.query("SELECT * FROM users WHERE id = ?", [user_input])
```

## 2 — `q@query` (error)

- Severity: **medium**
- Confidence: 0.78 (false-positive probability 0.12)
- DBMS: postgres
- Evidence: `error pattern Xpath tamper=space2comment`
- WAF: vendor=cloudflare blocking=true

### Remediation

Use parameterized queries / prepared statements; never concatenate input into SQL. Enforce least-privilege DB accounts and validate input server-side.

```
db.query("SELECT * FROM users WHERE id = ?", [user_input])
```

