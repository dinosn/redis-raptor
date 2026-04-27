# Exploitability Validation Report

5 design-level vulnerabilities confirmed across Redis server, cluster bus, and replication subsystems. The highest-impact finding is the unauthenticated cluster bus (CVSS 9.6 Critical) — any network peer can inject MEET/PUBLISH/FAILOVER messages. The Lua sandbox exposes os.execute to any authenticated user with @scripting ACL (CVSS 8.8 High). Cluster secret sniffing enables full ACL bypass via the internal auth path (CVSS 8.3). No memory corruption bugs survived validation — Redis's SDS string library and bounds checking are effective.

**Target:** `/Users/krasn/tools/raptor/out/projects/redisnew/redis`
**Date:** 2026-04-27
**Pipeline:** 0 → A → B → C → D → F → 1

---

## Summary

| Metric | Value |
|--------|-------|
| Files analyzed | 238 |
| Functions checked | 7499 |
| Findings identified | 13 |
| Confirmed | 5 |
| Ruled Out | 8 |

| # | Type | CWE | File | Status | Severity | CVSS |
|---|---|---|---|---|---|---|
| 1 | Buffer Overflow | CWE-787 | `src/module.c:8188` | Ruled Out | — | — |
| 2 | Path Traversal | CWE-22 | `src/config.c:2741` | Confirmed | High | 8.0 |
| 3 | Command Injection | CWE-78 | `src/script_lua.c:1233` | Confirmed | High | 8.8 |
| 4 | Other | CWE-114 | `src/module.c:13349` | Ruled Out | — | — |
| 5 | Other | CWE-306 | `src/cluster_legacy.c:2945` | Confirmed | Critical | 9.6 |
| 6 | Deserialization | CWE-924 | `src/replication.c:3133` | Confirmed | High | 7.4 |
| 7 | Other | CWE-287 | `src/acl.c:3220` | Confirmed | High | 8.3 |
| 8 | Command Injection | CWE-78 | `.github/workflows/daily.yml:60` | Ruled Out | — | — |
| 9 | Command Injection | CWE-77 | `.github/workflows/daily.yml:44` | Ruled Out | — | — |
| 10 | Weak Cryptography | CWE-327 | `utils/redis-sha1.rb:25` | Ruled Out | — | — |
| 11 | Integer Overflow | CWE-190 | `src/networking.c:3130` | Ruled Out | — | — |
| 12 | Format String | CWE-134 | `src/redis-cli.c:3390` | Ruled Out | — | — |
| 13 | Server-Side Request Forgery | CWE-918 | `...ctor-sets/examples/cli-tool/cli.py:30` | Ruled Out | — | — |

CVSS scores reflect **inherent vulnerability impact** — not binary mitigations.

---

## Findings

### FIND-001 — Buffer Overflow in `src/module.c:8188`

| Attribute | Value |
|-----------|-------|
| Type | Buffer Overflow |
| Function | `moduleLogRaw` |
| Final Status | Ruled Out |
| CWE | CWE-787 |
| Confidence | Medium |


**Dataflow:** `MODULE LOAD with long module name -> module->name -> snprintf returns name_len > sizeof(msg) -> vsnprintf(msg + name_len, sizeof(msg) - name_len, ...) writes OOB`

---

### FIND-002 — Path Traversal in `src/config.c:2741`

| Attribute | Value |
|-----------|-------|
| Type | Path Traversal |
| Function | `setConfigDirOption` |
| Final Status | Confirmed |
| CWE | CWE-22 |
| CVSS | 8.0 (`CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H`) |
| Confidence | High |


**Dataflow:** `CONFIG SET dir <path> -> chdir(argv[0]) at config.c:2741 -> BGSAVE -> rdbSaveToFile writes dump.rdb to new cwd`

---

### FIND-003 — Command Injection in `src/script_lua.c:1233`

| Attribute | Value |
|-----------|-------|
| Type | Command Injection |
| Function | `luaLoadLibraries` |
| Final Status | Confirmed |
| CWE | CWE-78 |
| CVSS | 8.8 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) |
| Confidence | High |


**Dataflow:** `EVAL <lua_script> -> luaopen_os loaded (script_lua.c:1233) -> os.execute('cmd') -> system() in deps/lua/src/loslib.c:39`

---

### FIND-004 — Other in `src/module.c:13349`

| Attribute | Value |
|-----------|-------|
| Type | Other |
| Function | `moduleLoad` |
| Final Status | Ruled Out |
| CWE | CWE-114 |
| Confidence | High |


**Dataflow:** `MODULE LOAD <path> -> moduleLoad(c->argv[2]->ptr) -> dlopen(path) at module.c:13349`

---

### FIND-005 — Other in `src/cluster_legacy.c:2945`

| Attribute | Value |
|-----------|-------|
| Type | Other |
| Function | `clusterProcessPacket` |
| Final Status | Confirmed |
| CWE | CWE-306 |
| CVSS | 9.6 (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H`) |
| Confidence | High |


**Dataflow:** `Network attacker -> cluster bus port -> clusterReadHandler -> clusterProcessPacket -> MEET: clusterAddNode / PUBLISH: pubsubPublishMessage / FAILOVER: clusterSendFailoverAuthIfNeeded`

---

### FIND-006 — Deserialization in `src/replication.c:3133`

| Attribute | Value |
|-----------|-------|
| Type | Deserialization |
| Function | `syncWithMaster` |
| Final Status | Confirmed |
| CWE | CWE-924 |
| CVSS | 7.4 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`) |
| Confidence | Medium |


**Dataflow:** `MITM on replication port -> forge FULLRESYNC -> replica calls rdbLoadRioWithLoadingCtx with attacker-controlled RDB data`

---

### FIND-007 — Other in `src/acl.c:3220`

| Attribute | Value |
|-----------|-------|
| Type | Other |
| Function | `internalAuth` |
| Final Status | Confirmed |
| CWE | CWE-287 |
| CVSS | 8.3 (`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`) |
| Confidence | Medium |


**Dataflow:** `Sniff cluster bus PING ext -> extract internal_secret -> AUTH 'internal connection' <secret> on client port -> c->user=NULL -> all ACL checks bypassed`

---

### FIND-008 — Command Injection in `.github/workflows/daily.yml:60`

| Attribute | Value |
|-----------|-------|
| Type | Command Injection |
| Function | `run steps across ~20 jobs (test, sentinel tests, cluster tests)` |
| Final Status | Ruled Out |
| CWE | CWE-78 |
| Confidence | Medium |


**Dataflow:** `github.event.inputs.test_args (workflow_dispatch) -> direct string interpolation into bash run: command -> shell execution on CI runner`

---

### FIND-009 — Command Injection in `.github/workflows/daily.yml:44`

| Attribute | Value |
|-----------|-------|
| Type | Command Injection |
| Function | `prep step (all ~20 jobs)` |
| Final Status | Ruled Out |
| CWE | CWE-77 |
| Confidence | Medium |


**Dataflow:** `github.event.inputs.use_repo (newline-injected) -> GITHUB_ENV >> -> env.GITHUB_REPOSITORY -> actions/checkout repository: -> attacker code executed`

---

### FIND-010 — Weak Cryptography in `utils/redis-sha1.rb:25`

| Attribute | Value |
|-----------|-------|
| Type | Weak Cryptography |
| Function | `redisSha1` |
| Final Status | Ruled Out |
| CWE | CWE-327 |
| Confidence | Low |


**Dataflow:** `Redis key+value data -> Digest::SHA1.hexdigest(sha1+k) chaining -> dataset fingerprint`

---

### FIND-011 — Integer Overflow in `src/networking.c:3130`

| Attribute | Value |
|-----------|-------|
| Type | Integer Overflow |
| Function | `processMultibulkBuffer` |
| Final Status | Ruled Out |
| CWE | CWE-190 |
| Confidence | High |


**Dataflow:** `client RESP data -> string2ll -> ll -> c->multibulklen (int)`

---

### FIND-012 — Format String in `src/redis-cli.c:3390`

| Attribute | Value |
|-----------|-------|
| Type | Format String |
| Function | `cliSetPreferences` |
| Final Status | Ruled Out |
| CWE | CWE-134 |
| Confidence | High |


**Dataflow:** `.redisclirc or :set command -> argv[1] -> printf %s argument`

---

### FIND-013 — Server-Side Request Forgery in `modules/vector-sets/examples/cli-tool/cli.py:30`

| Attribute | Value |
|-----------|-------|
| Type | Server-Side Request Forgery |
| Function | `get_embedding` |
| Final Status | Ruled Out |
| CWE | CWE-918 |
| Confidence | High |


**Dataflow:** `CLI --ollama-url arg -> requests.post(url) in example script`

---

## Stage F Review

No corrections needed. All 5 confirmed findings have consistent CVSS vectors matching their access models. Ruled-out findings have appropriate disqualifiers. Proximity spread flag is moot (FIND-004 is ruled out).

---

## Output Files

```
  checklist.json
  findings.json
  attack-surface.json
  attack-tree.json
  hypotheses.json
  disproven.json
  attack-paths.json
```
