#!/usr/bin/env python3
"""rls_check.py - offline Supabase Row Level Security pre-launch checker.

Copyright (c) 2026 Proofmerge. MIT License (see LICENSE).

Reads the SQL migrations in a project folder in order, rebuilds the final
state of tables / policies / functions / views / buckets / grants, and reports
the mistakes that most often leak data in Supabase apps. Also greps the app
source for the service-role key being used where a browser can see it.

Python 3 standard library only. No network calls. Never prints secret values.

    python3 rls_check.py path/to/project
    python3 rls_check.py path/to/project --json
    python3 rls_check.py path/to/project --html report.html

Exit codes: 0 = nothing at or above --fail-on (default: high), 1 = findings at
or above it, 2 = usage error.
"""
import argparse
import base64
import html
import json
import os
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["critical", "high", "medium", "low"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "out", ".vercel", ".turbo",
    "coverage", ".venv", "venv", "__pycache__", ".svelte-kit", ".nuxt", ".output",
    "vendor", ".cache", ".expo",
}
SOURCE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
MAX_FILE_BYTES = 2_000_000

OWNER_COLUMNS = {"user_id", "userid", "owner", "owner_id", "created_by", "author_id", "uid"}
SENSITIVE_NAME = re.compile(
    r"user|profile|account|customer|payment|order|invoice|billing|subscription|secret|token|"
    r"api_?key|credential|password|message|email|address|admin|session|transaction|wallet|"
    r"card|health|patient|document|private|payout|bank|salary",
    re.I,
)
SENSITIVE_BUCKET = re.compile(
    r"document|invoice|private|upload|kyc|receipt|contract|passport|id[-_]?card|medical|"
    r"report|export|backup|attachment|file",
    re.I,
)
ADMIN_ROLES = {"service_role", "postgres", "supabase_admin", "supabase_auth_admin", "dashboard_user"}
WRITE_PRIVS = {"insert", "update", "delete", "truncate", "all"}
# Roles the Supabase Data API uses for requests from your app ("public" = every role).
API_ROLES = {"anon", "authenticated", "public"}

IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)'
QNAME = r"(" + IDENT + r"(?:\s*\.\s*" + IDENT + r")?)"
PNAME = r'("[^"]+"|[\w$]+)'
_F = re.I | re.S

IDENTITY_REF = re.compile(r'"?auth"?\s*\.\s*"?(uid|jwt|email)"?\s*\(|request\.jwt', re.I)
AUTH_USERS = r'references\s+"?auth"?\s*\.\s*"?users"?'  
WEAK_AUTH = re.compile(  # matched against squash()ed text: no spaces, parens or quotes
    r"^(?:select)?auth\.role=authenticated$|^authenticated=(?:select)?auth\.role$|"
    r"^(?:select)?auth\.(?:uid|jwt)isnotnull$"
)
PUBLIC_SERVICE_VAR = re.compile(
    r"\b((?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*"
    r"(?:SERVICE_ROLE|SERVICE_KEY|SUPABASE_SECRET)[A-Z0-9_]*)"
)
SERVICE_REF = re.compile(
    r"\b(SUPABASE_SERVICE_ROLE(?:_KEY)?|SUPABASE_SERVICE_KEY|SUPABASE_SECRET_KEY|"
    r"SERVICE_ROLE_KEY|service_?role_?key|serviceRoleKey|serviceRole)\b"
)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
SB_SECRET_RE = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}")
SERVER_PATH = re.compile(
    r"server|(^|/)api(/|$)|(^|/)functions(/|$)|(^|/)scripts?(/|$)|middleware|(^|/)actions?(/|\.|$)|"
    r"cron|webhook|(^|/)route\.[a-z]+$|\.test\.|\.spec\.|__tests__|(^|/)tests?(/|$)|\.config\.",
    re.I,
)
CLIENT_DIR = re.compile(r"(^|/)(components|pages|hooks|views|screens)(/|$)", re.I)
APP_DIR = re.compile(r"(^|/)(src|app)(/|$)", re.I)


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
class Finding:
    def __init__(self, rule, severity, target, title, file, line, why, fix):
        self.rule, self.severity, self.target, self.title = rule, severity, target, title
        self.file, self.line, self.why, self.fix = file, line, why, fix

    def as_dict(self):
        return {
            "rule": self.rule, "severity": self.severity, "target": self.target,
            "title": self.title, "file": self.file, "line": self.line,
            "why": self.why, "fix": self.fix,
        }


class Policy:
    def __init__(self, name, file, line):
        self.name, self.file, self.line = name, file, line
        self.cmd = "all"
        self.roles = []
        self.restrictive = False
        self.using = None
        self.check = None


class Table:
    def __init__(self, schema, name, file, line):
        self.schema, self.name, self.file, self.line = schema, name, file, line
        self.rls = False
        self.disabled_at = None
        self.columns = set()
        self.owner_cols = []
        self.policies = {}
        self.anon_grants = {}

    @property
    def qname(self):
        return "%s.%s" % (self.schema, self.name)


# --------------------------------------------------------------------------
# SQL lexing helpers
# --------------------------------------------------------------------------
_DOLLAR = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")


def lex_sql(text):
    """Return (clean, masked, dollar_spans), both the same length as text.

    clean  : comments blanked out.
    masked : comments, string contents and dollar-quoted bodies blanked out.
    Newlines are always kept so offsets map to line numbers.
    """
    n = len(text)
    clean = list(text)
    masked = list(text)
    spans = []

    def blank(buf, a, b):
        for k in range(a, b):
            if buf[k] != "\n":
                buf[k] = " "

    i = 0
    while i < n:
        c = text[i]
        if c == "-" and text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(clean, i, j)
            blank(masked, i, j)
            i = j
        elif c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(clean, i, j)
            blank(masked, i, j)
            i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            blank(masked, i + 1, min(j, n))
            i = j + 1
        elif c == '"':
            j = text.find('"', i + 1)
            i = n if j < 0 else j + 1
        elif c == "$":
            m = _DOLLAR.match(text, i)
            if not m:
                i += 1
                continue
            tag = m.group(0)
            j = text.find(tag, m.end())
            if j < 0:
                j = n
            blank(masked, m.end(), j)
            spans.append((m.end(), j))
            i = min(n, j + len(tag))
        else:
            i += 1
    return "".join(clean), "".join(masked), spans


def balanced(masked, open_idx):
    """Index of the ')' matching the '(' at open_idx (or len(masked))."""
    depth = 0
    for k in range(open_idx, len(masked)):
        ch = masked[k]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return k
    return len(masked)


def split_top(masked, start, end):
    """Spans between top-level commas in masked[start:end]."""
    out, depth, s = [], 0, start
    for k in range(start, end):
        ch = masked[k]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append((s, k))
            s = k + 1
    out.append((s, end))
    return out


def norm_ident(raw):
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    return raw.lower()


def split_qname(raw, default_schema="public"):
    parts = re.findall(IDENT, raw)
    if len(parts) >= 2:
        return norm_ident(parts[0]), norm_ident(parts[1])
    return default_schema, norm_ident(parts[0]) if parts else ""


def squash(expr):
    return re.sub(r"[\s()'\"]", "", (expr or "").lower())


def is_true(expr):
    return squash(expr) in ("true", "1=1", "true::boolean", "true::bool", "true=true")


# --------------------------------------------------------------------------
# Migration state machine
# --------------------------------------------------------------------------
class Schema:
    PATTERNS = [
        ("create_table", r"\bcreate\s+(?:(?:global\s+|local\s+)?(temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?" + QNAME),
        ("alter_table", r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + QNAME),
        ("drop_table", r"\bdrop\s+table\s+(?:if\s+exists\s+)?(.+)"),
        ("create_policy", r"\bcreate\s+policy\s+" + PNAME + r"\s+on\s+" + QNAME),
        ("alter_policy", r"\balter\s+policy\s+" + PNAME + r"\s+on\s+" + QNAME),
        ("drop_policy", r"\bdrop\s+policy\s+(?:if\s+exists\s+)?" + PNAME + r"\s+on\s+" + QNAME),
        ("create_function", r"\bcreate\s+(?:or\s+replace\s+)?function\s+" + QNAME),
        ("alter_function", r"\balter\s+function\s+" + QNAME),
        ("drop_function", r"\bdrop\s+function\s+(?:if\s+exists\s+)?" + QNAME),
        ("create_view", r"\bcreate\s+(?:or\s+replace\s+)?(?:(temp|temporary)\s+)?(materialized\s+)?(?:recursive\s+)?view\s+(?:if\s+not\s+exists\s+)?" + QNAME),
        ("alter_view", r"\balter\s+view\s+(?:if\s+exists\s+)?" + QNAME),
        ("drop_view", r"\bdrop\s+view\s+(?:if\s+exists\s+)?(.+)"),
        ("default_privs", r"\balter\s+default\s+privileges\b"),
        ("grant", r"\bgrant\s+(.+?)\s+on\s+(.+?)\s+to\s+(.+)"),
        ("revoke", r"\brevoke\s+(.+?)\s+on\s+(.+?)\s+from\s+(.+)"),
        ("bucket_insert", r"\binsert\s+into\s+storage\s*\.\s*buckets\b"),
        ("bucket_update", r"\bupdate\s+storage\s*\.\s*buckets\s+set\b"),
    ]
    PATTERNS = [(n, re.compile(p, _F)) for n, p in PATTERNS]

    def __init__(self):
        self.tables = {}
        self.functions = {}
        self.views = {}
        self.buckets = {}
        # schema -> {"privs": {role: set}, "file", "line", "tables": set of table keys covered}
        self.schema_grants = {}
        # schema (or "*" for all schemas) -> {"privs": {role: set}, "file", "line", "before": table keys that existed}
        self.default_grants = {}

    # ---- driver -----------------------------------------------------------
    def apply_file(self, text, file):
        self._run(text, file, 1)

    def _run(self, text, file, base_line):
        clean, masked, spans = lex_sql(text)
        start = 0
        for end in [i for i, ch in enumerate(masked) if ch == ";"] + [len(masked)]:
            if masked[start:end].strip():
                self._statement(clean, masked, spans, start, end, file, base_line)
            start = end + 1

    def _statement(self, clean, masked, spans, start, end, file, base_line):
        c_stmt, m_stmt = clean[start:end], masked[start:end]
        if re.match(r"\s*do\b", m_stmt, re.I):
            for bs, be in spans:
                if start <= bs and be <= end:
                    body = clean[bs:be]
                    if re.search(r"alter\s+table[^;]*%[^;]*enable\s+row\s+level\s+security", body, _F):
                        for t in self.tables.values():
                            t.rls, t.disabled_at = True, None
                    self._run(body, file, base_line + clean.count("\n", 0, bs))
            return
        best = None
        for name, rx in self.PATTERNS:
            m = rx.search(m_stmt)
            if m and (best is None or m.start() < best[1].start()):
                best = (name, m)
        if not best:
            return
        name, m = best
        line = base_line + clean.count("\n", 0, start + m.start())
        getattr(self, "_" + name)(m, c_stmt, m_stmt, file, line)

    def _table(self, raw):
        return self.tables.get(split_qname(raw))

    # ---- tables -----------------------------------------------------------
    def _create_table(self, m, c, ms, file, line):
        if m.group(1) and m.group(1).lower().startswith("temp"):
            return
        key = split_qname(m.group(2))
        t = self.tables.get(key)
        if t is None:
            t = self.tables[key] = Table(key[0], key[1], file, line)
        rest = ms[m.end():]
        if rest.lstrip().startswith("("):
            op = m.end() + rest.index("(")
            cl = balanced(ms, op)
            for s, e in split_top(ms, op + 1, cl):
                self._column(t, c[s:e])

    def _column(self, t, piece):
        piece = piece.strip()
        first = re.match(IDENT, piece)
        if not first:
            return
        word = first.group(0).lower()
        if word in ("constraint", "primary", "unique", "check", "foreign", "exclude", "like"):
            fk = re.search(r"foreign\s+key\s*\(\s*(" + IDENT + r")\s*\)\s*" + AUTH_USERS, piece, _F)
            if fk and norm_ident(fk.group(1)) not in t.owner_cols:
                t.owner_cols.append(norm_ident(fk.group(1)))
            return
        col = norm_ident(first.group(0))
        t.columns.add(col)
        if col in OWNER_COLUMNS or re.search(AUTH_USERS, piece, _F):
            if col not in t.owner_cols:
                t.owner_cols.append(col)

    def _alter_table(self, m, c, ms, file, line):
        key = split_qname(m.group(1))
        t = self.tables.get(key)
        if t is None:
            return
        rest = ms[m.end():]
        for am in re.finditer(r"\b(enable|disable)\s+row\s+level\s+security", rest, _F):
            if am.group(1).lower() == "enable":
                t.rls, t.disabled_at = True, None
            else:
                if t.rls:
                    t.disabled_at = (file, line + rest.count("\n", 0, am.start()))
                t.rls = False
        for am in re.finditer(r"\badd\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(" + IDENT + r")([^,]*)", rest, _F):
            if am.group(1).lower() not in ("constraint", "primary", "unique", "check", "foreign"):
                self._column(t, c[m.end() + am.start(1): m.end() + am.end(2)])
        for fk in re.finditer(r"foreign\s+key\s*\(\s*(" + IDENT + r")\s*\)\s*" + AUTH_USERS, rest, _F):
            if norm_ident(fk.group(1)) not in t.owner_cols:
                t.owner_cols.append(norm_ident(fk.group(1)))
        rn = re.search(r"\brename\s+to\s+(" + IDENT + r")", rest, _F)
        if rn:
            del self.tables[key]
            t.name = norm_ident(rn.group(1))
            self.tables[(t.schema, t.name)] = t
        sc = re.search(r"\bset\s+schema\s+(" + IDENT + r")", rest, _F)
        if sc:
            self.tables.pop((t.schema, t.name), None)
            t.schema = norm_ident(sc.group(1))
            self.tables[(t.schema, t.name)] = t

    def _drop_table(self, m, c, ms, file, line):
        for raw in re.sub(r"\b(cascade|restrict)\b", "", m.group(1), flags=re.I).split(","):
            if raw.strip():
                self.tables.pop(split_qname(raw), None)

    # ---- policies ---------------------------------------------------------
    def _policy_clauses(self, p, c, ms, pos, is_alter=False):
        rest_m, rest_c = ms[pos:], c[pos:]
        um = re.search(r"\busing\s*\(", rest_m, _F)
        after = 0
        if um:
            op = um.end() - 1
            cl = balanced(rest_m, op)
            p.using = rest_c[op + 1:cl].strip()
            after = cl
        cm = re.search(r"\bwith\s+check\s*\(", rest_m[after:], _F)
        if cm:
            op = after + cm.end() - 1
            cl = balanced(rest_m, op)
            p.check = rest_c[op + 1:cl].strip()
        head_end = min([x for x in (um.start() if um else None, (after + cm.start()) if cm else None) if x is not None] or [len(rest_m)])
        head = rest_m[:head_end]
        am = re.search(r"\bas\s+(permissive|restrictive)\b", head, _F)
        if am:
            p.restrictive = am.group(1).lower() == "restrictive"
        fm = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", head, _F)
        if fm:
            p.cmd = fm.group(1).lower()
        tm = re.search(r"\bto\s+(.+)$", head, _F)
        if tm:
            p.roles = [norm_ident(r) for r in tm.group(1).split(",") if r.strip()]

    def _create_policy(self, m, c, ms, file, line):
        t = self._table(m.group(2))
        if t is None:
            return
        p = Policy(norm_ident(m.group(1)), file, line)
        self._policy_clauses(p, c, ms, m.end())
        t.policies[p.name] = p

    def _alter_policy(self, m, c, ms, file, line):
        t = self._table(m.group(2))
        p = t.policies.get(norm_ident(m.group(1))) if t else None
        if p is None:
            return
        rn = re.search(r"\brename\s+to\s+" + PNAME, ms[m.end():], _F)
        if rn:
            del t.policies[p.name]
            p.name = norm_ident(rn.group(1))
            t.policies[p.name] = p
            return
        p.file, p.line = file, line
        self._policy_clauses(p, c, ms, m.end(), True)

    def _drop_policy(self, m, c, ms, file, line):
        t = self._table(m.group(2))
        if t:
            t.policies.pop(norm_ident(m.group(1)), None)

    # ---- functions --------------------------------------------------------
    def _create_function(self, m, c, ms, file, line):
        key = split_qname(m.group(1))
        self.functions[key] = {
            "definer": bool(re.search(r"\bsecurity\s+definer\b", ms, _F)),
            "search_path": bool(re.search(r'\bset\s+"?search_path\b', ms, _F)),
            "has_identity": bool(IDENTITY_REF.search(c)),
            "file": file, "line": line,
        }

    def _alter_function(self, m, c, ms, file, line):
        f = self.functions.get(split_qname(m.group(1)))
        if not f:
            return
        if re.search(r'\bset\s+"?search_path\b', ms, _F):
            f["search_path"] = True
        if re.search(r"\breset\s+(search_path|all)\b", ms, _F):
            f["search_path"] = False
        if re.search(r"\bsecurity\s+invoker\b", ms, _F):
            f["definer"] = False
        if re.search(r"\bsecurity\s+definer\b", ms, _F):
            f["definer"] = True

    def _drop_function(self, m, c, ms, file, line):
        self.functions.pop(split_qname(m.group(1)), None)

    # ---- views ------------------------------------------------------------
    @staticmethod
    def _invoker_value(text):
        im = re.search(r"security_invoker\"?\s*(?:=\s*'?\s*(\w+))?", text, _F)
        if not im:
            return None
        return (im.group(1) or "true").lower() in ("true", "on", "1", "yes")

    def _create_view(self, m, c, ms, file, line):
        if m.group(1) or m.group(2):
            return
        key = split_qname(m.group(3))
        as_m = re.search(r"\bas\b", ms[m.end():], _F)
        head = c[m.end(): m.end() + (as_m.start() if as_m else 0)]
        self.views[key] = {"invoker": bool(self._invoker_value(head)), "file": file, "line": line}

    def _alter_view(self, m, c, ms, file, line):
        v = self.views.get(split_qname(m.group(1)))
        if not v:
            return
        rest = c[m.end():]
        if re.search(r"\breset\s*\([^)]*security_invoker", rest, _F):
            v["invoker"] = False
        elif re.search(r"\bset\s*\(", rest, _F):
            val = self._invoker_value(rest)
            if val is not None:
                v["invoker"] = val

    def _drop_view(self, m, c, ms, file, line):
        for raw in re.sub(r"\b(cascade|restrict)\b", "", m.group(1), flags=re.I).split(","):
            if raw.strip():
                self.views.pop(split_qname(raw), None)

    # ---- grants -----------------------------------------------------------
    def _grant_targets(self, m):
        obj = m.group(2).strip()
        low = obj.lower()
        if re.match(r"(all\s+)?(function|functions|routine|routines|procedure|schema|sequence|sequences|"
                    r"type|database|domain|language|foreign|large|tablespace|parameter)\b", low):
            return None
        if re.match(r"all\s+tables\b", low):
            return None  # handled by _schema_wide (GRANT002)
        obj = re.sub(r"^table\s+", "", obj, flags=re.I)
        roles = re.split(r"\b(?:with\s+grant\s+option|granted\s+by|cascade|restrict)\b", m.group(3), flags=re.I)[0]
        roles = {norm_ident(r) for r in roles.split(",") if r.strip()}
        if not ({"anon", "public"} & roles):
            return None
        privs = re.sub(r"\([^)]*\)", "", m.group(1).lower())
        privs = re.sub(r"grant\s+option\s+for", "", privs)
        privs = {"all" if p.strip().startswith("all") else p.strip() for p in privs.split(",") if p.strip()}
        tables = [self._table(raw) for raw in obj.split(",") if raw.strip()]
        return privs, [t for t in tables if t is not None]

    @staticmethod
    def _privs_roles(privs_raw, roles_raw):
        roles = re.split(r"\b(?:with\s+grant\s+option|granted\s+by|cascade|restrict)\b", roles_raw, flags=re.I)[0]
        roles = {norm_ident(r) for r in roles.split(",") if r.strip()} & API_ROLES
        privs = re.sub(r"\([^)]*\)", "", privs_raw.lower())
        privs = re.sub(r"grant\s+option\s+for", "", privs)
        privs = {"all" if p.strip().startswith("all") else p.strip() for p in privs.split(",") if p.strip()}
        return privs, roles

    @staticmethod
    def _apply_privs(entry, privs, roles, grant):
        for r in roles:
            have = entry["privs"].setdefault(r, set())
            if grant:
                have |= privs
            elif "all" in privs:
                have.clear()
            else:
                have -= privs
                if "all" in have:  # partial revoke after GRANT ALL leaves the rest
                    have.discard("all")
                    have |= {"select", "insert", "update", "delete"} - privs
            if not have:
                entry["privs"].pop(r, None)

    def _schema_wide(self, m, file, line, grant):
        sm = re.match(r"all\s+tables\s+in\s+schema\s+(.+)", m.group(2).strip(), _F)
        if not sm:
            return False
        privs, roles = self._privs_roles(m.group(1), m.group(3))
        for raw in sm.group(1).split(","):
            if not raw.strip():
                continue
            sch = norm_ident(raw)
            entry = self.schema_grants.get(sch)
            if grant and roles:
                entry = entry or self.schema_grants.setdefault(sch, {"privs": {}, "tables": set()})
                entry.update(file=file, line=line)
                entry["tables"] |= {k for k in self.tables if k[0] == sch}
            if entry:
                self._apply_privs(entry, privs, roles, grant)
                if not entry["privs"]:
                    self.schema_grants.pop(sch, None)
        return True

    def _default_privs(self, m, c, ms, file, line):
        rest = ms[m.end():]
        gm = re.search(r"\b(grant|revoke)\s+(.+?)\s+on\s+tables\s+(?:to|from)\s+(.+)$", rest, _F)
        if not gm:
            return  # sequences, functions, types: not tracked
        head = rest[:gm.start()]
        im = re.search(r"\bin\s+schema\s+(.+)$", head, _F)
        schemas = [norm_ident(x) for x in im.group(1).split(",") if x.strip()] if im else ["*"]
        grant = gm.group(1).lower() == "grant"
        privs, roles = self._privs_roles(gm.group(2), gm.group(3))
        for sch in schemas:
            entry = self.default_grants.get(sch)
            if grant and roles:
                entry = entry or self.default_grants.setdefault(sch, {"privs": {}, "before": set(self.tables)})
                entry.update(file=file, line=line)
            if entry:
                self._apply_privs(entry, privs, roles, grant)
                if not entry["privs"]:
                    self.default_grants.pop(sch, None)

    def _grant(self, m, c, ms, file, line):
        if self._schema_wide(m, file, line, True):
            return
        got = self._grant_targets(m)
        if got:
            for t in got[1]:
                for p in got[0]:
                    t.anon_grants[p] = (file, line)

    def _revoke(self, m, c, ms, file, line):
        if self._schema_wide(m, file, line, False):
            return
        got = self._grant_targets(m)
        if got:
            for t in got[1]:
                if "all" in got[0]:
                    t.anon_grants.clear()
                for p in got[0]:
                    t.anon_grants.pop(p, None)

    # ---- storage buckets --------------------------------------------------
    @staticmethod
    def _lit(value):
        return value.strip().strip("'").strip()

    def _bucket_insert(self, m, c, ms, file, line):
        pos = m.end()
        cols = []
        rest = ms[pos:]
        if rest.lstrip().startswith("("):
            op = pos + rest.index("(")
            cl = balanced(ms, op)
            cols = [norm_ident(c[s:e]) for s, e in split_top(ms, op + 1, cl)]
            pos = cl + 1
        vm = re.search(r"\bvalues\b", ms[pos:], _F)
        if not vm:
            return
        pos += vm.end()
        upsert_public = bool(re.search(r"\bdo\s+update\s+set\b.*\bpublic\s*=\s*'?true", c[pos:], _F))
        while True:
            rest = ms[pos:]
            if not rest.lstrip().startswith("("):
                break
            op = pos + rest.index("(")
            cl = balanced(ms, op)
            vals = [c[s:e].strip() for s, e in split_top(ms, op + 1, cl)]
            row = dict(zip(cols, vals)) if cols else {}
            name = self._lit(row.get("id") or row.get("name") or (vals[0] if vals else "?"))
            if cols:
                public = self._lit(row.get("public", "false")).lower() in ("true", "t")
            else:
                public = any(self._lit(v).lower() == "true" for v in vals)
            self.buckets[name] = {"public": public or upsert_public, "file": file, "line": line}
            pos = cl + 1
            nxt = ms[pos:]
            if nxt.lstrip().startswith(","):
                pos += nxt.index(",") + 1
            else:
                break

    def _bucket_update(self, m, c, ms, file, line):
        rest = c[m.end():]
        pm = re.search(r"\bpublic\s*=\s*'?(true|false|t|f)\b", rest, _F)
        if not pm:
            return
        public = pm.group(1).lower() in ("true", "t")
        wm = re.search(r"\bwhere\b(.*)$", rest, _F)
        names = re.findall(r"'([^']+)'", wm.group(1)) if wm else list(self.buckets)
        for name in names:
            b = self.buckets.setdefault(name, {"public": False, "file": file, "line": line})
            b.update(public=public, file=file, line=line)


# --------------------------------------------------------------------------
# Rules over the final migration state
# --------------------------------------------------------------------------
def _roles_info(p):
    roles = set(p.roles)
    admin_only = bool(roles) and roles <= ADMIN_ROLES
    anon = (not roles) or bool({"anon", "public"} & roles)
    return admin_only, anon


def _owner_expr(t):
    col = t.owner_cols[0] if t.owner_cols else "<owner_column>"
    return "(select auth.uid()) = %s" % col


def _policy_fix(t, p):
    using = "using (%s)" % _owner_expr(t)
    check = "with check (%s)" % _owner_expr(t)
    clause = {"select": using, "delete": using, "insert": check}.get(p.cmd, using + " " + check)
    return ('drop policy if exists "%s" on %s;\ncreate policy "%s" on %s for %s to authenticated %s;'
            % (p.name, t.qname, p.name, t.qname, p.cmd, clause))


def _has_identity(expr, schema):
    if IDENTITY_REF.search(expr):
        return True
    for call in re.findall(r"((?:" + IDENT + r"\s*\.\s*)?" + IDENT + r")\s*\(", expr):
        key = split_qname(call)
        f = schema.functions.get(key) or next(
            (v for k, v in schema.functions.items() if k[1] == key[1]), None)
        if f and f["has_identity"]:
            return True
    return False


def _wide_grant_findings(schema, exposed):
    """GRANT002: schema-wide grants and default privileges that hand every table to the API roles."""
    out = []

    def describe(entry):
        roles = sorted(entry["privs"])
        anon_like = bool({"anon", "public"} & set(roles))
        return roles, anon_like

    def names(tables):
        shown = ", ".join(t.qname for t in tables[:3])
        return shown + (" and %d more" % (len(tables) - 3) if len(tables) > 3 else "")

    revoke_wide = ("revoke all on all tables in schema %s from anon, authenticated;  "
                   "-- then grant each table only what the app needs, after RLS and its policies exist, e.g. "
                   "grant select, insert, update, delete on %s.<table> to authenticated;")
    revoke_default = ("alter default privileges for role postgres in schema %s revoke select, insert, update, "
                      "delete on tables from anon, authenticated;  -- then grant each new table explicitly")
    for sch in exposed:
        entry = schema.schema_grants.get(sch)
        if entry:
            roles, anon_like = describe(entry)
            covered = [schema.tables[k] for k in sorted(entry["tables"]) if k in schema.tables]
            open_ = [t for t in covered if not t.rls]
            if open_:
                sev = "high" if anon_like else "medium"
                why = ("Every table that existed at this point became reachable through the Data API for %s, "
                       "including %d without RLS (%s), so all their rows are open."
                       % (", ".join(roles), len(open_), names(open_)))
            else:
                sev = "low"
                why = ("Every table that existed at this point is reachable through the Data API for %s. RLS is "
                       "the only barrier left, so a table that loses RLS is open at once. This line is often "
                       "added to silence 'permission denied' errors." % ", ".join(roles))
            out.append(Finding("GRANT002", sev, "schema " + sch,
                               "Schema-wide grant to %s on all tables" % ", ".join(roles),
                               entry["file"], entry["line"], why, revoke_wide % (sch, sch)))
        entry = schema.default_grants.get(sch) or schema.default_grants.get("*")
        if entry:
            roles, anon_like = describe(entry)
            later = [t for k, t in sorted(schema.tables.items()) if k[0] == sch and k not in entry["before"]]
            open_ = [t for t in later if not t.rls]
            if open_:
                sev = "high" if anon_like else "medium"
                why = ("Tables created after this statement are reachable through the Data API for %s as soon as "
                       "they exist, and %d of them have no RLS (%s)." % (", ".join(roles), len(open_), names(open_)))
            else:
                sev = "low"
                why = ("Every new table in this schema is reachable through the Data API for %s as soon as it is "
                       "created (Supabase's default before 30 Oct 2026). A table created without RLS is open "
                       "immediately." % ", ".join(roles))
            out.append(Finding("GRANT002", sev, "schema " + sch,
                               "Default privileges hand new tables to %s" % ", ".join(roles),
                               entry["file"], entry["line"], why, revoke_default % sch))
    return out


def evaluate(schema, exposed=("public",)):
    out = []
    for t in schema.tables.values():
        if t.schema not in exposed:
            continue
        tgt = "table " + t.qname
        sensitive = bool(SENSITIVE_NAME.search(t.name))
        if not t.rls:
            starter = ""
            if not t.policies:
                starter = ('\ncreate policy "%s_owner_all" on %s for all to authenticated using (%s) with check (%s);'
                           % (t.name, t.qname, _owner_expr(t), _owner_expr(t)))
            fix = "alter table %s enable row level security;%s" % (t.qname, starter)
            if t.disabled_at:
                out.append(Finding(
                    "RLS005", "critical", tgt, "Row level security was switched off in a later migration",
                    t.disabled_at[0], t.disabled_at[1],
                    "The table was protected, then a later migration removed the protection. Any API role with "
                    "privileges on it can now read and change every row; in Supabase projects created before "
                    "30 May 2026, anon held those privileges on every table made before 30 Oct 2026.",
                    "alter table %s enable row level security;" % t.qname))
            else:
                title = "Table has no row level security"
                if t.policies:
                    title = "Policies exist but row level security is not enabled (policies are ignored)"
                out.append(Finding(
                    "RLS001", "critical", tgt, title, t.file, t.line,
                    "Without RLS, any API role with privileges on this table can read and change every row. "
                    "Supabase projects created before 30 May 2026 gave anon those privileges automatically on "
                    "every table made before 30 Oct 2026, and any later GRANT does the same; the anon key ships "
                    "in your frontend.", fix))
        else:
            if not t.policies:
                out.append(Finding(
                    "RLS002", "low", tgt, "RLS is enabled but there is no policy", t.file, t.line,
                    "Nothing leaks, but every request from the app returns zero rows, which is the usual "
                    "reason someone later turns RLS off 'to make it work'.",
                    'create policy "%s_owner_all" on %s for all to authenticated using (%s) with check (%s);'
                    % (t.name, t.qname, _owner_expr(t), _owner_expr(t))))
            for p in t.policies.values():
                out.extend(_check_policy(schema, t, p, tgt, sensitive))
        if t.anon_grants and sensitive:
            privs = sorted(t.anon_grants)
            file, line = t.anon_grants[privs[0]]
            writes = bool(WRITE_PRIVS & set(privs))
            if t.rls and t.policies:
                sev = "low"
                why = ("The anon role has direct privileges on a sensitive-looking table, so its RLS policies "
                       "are the only thing between the internet and this data.")
            else:
                sev = "high" if writes else "medium"
                why = ("Visitors who are not logged in get direct %s access to a sensitive-looking table."
                       % ("write" if writes else "read"))
            out.append(Finding(
                "GRANT001", sev, tgt, "Explicit grant to anon (%s) on a sensitive-looking table" % ", ".join(privs),
                file, line, why, "revoke all on %s from anon;" % t.qname))

    out.extend(_wide_grant_findings(schema, exposed))

    for (sch, name), f in schema.functions.items():
        if f["definer"] and not f["search_path"]:
            out.append(Finding(
                "FUNC001", "medium", "function %s.%s" % (sch, name),
                "SECURITY DEFINER function without a fixed search_path", f["file"], f["line"],
                "This function runs with its owner's rights and bypasses RLS; without a pinned search_path "
                "a caller can make it resolve tables or functions from a schema they control.",
                "alter function %s.%s set search_path = '';  -- then schema-qualify names in the body (add the argument list if overloaded)"
                % (sch, name)))

    for (sch, name), v in schema.views.items():
        if sch in exposed and not v["invoker"]:
            out.append(Finding(
                "VIEW001", "high", "view %s.%s" % (sch, name), "View without security_invoker",
                v["file"], v["line"],
                "By default a view runs as its owner and ignores the RLS policies of the tables behind it, "
                "so it can expose rows the caller could not read directly.",
                "alter view %s.%s set (security_invoker = true);" % (sch, name)))

    for name, b in schema.buckets.items():
        if b["public"]:
            sens = bool(SENSITIVE_BUCKET.search(name))
            out.append(Finding(
                "STOR001", "high" if sens else "medium", "storage bucket " + name,
                "Storage bucket is public" + (" and its name suggests private files" if sens else ""),
                b["file"], b["line"],
                "Every file in a public bucket can be downloaded by anyone who has or guesses the URL, "
                "with no login and no policy check.",
                "update storage.buckets set public = false where id = '%s';  -- then serve files with signed URLs"
                % name.replace("'", "''")))
    return out


def _check_policy(schema, t, p, tgt, sensitive):
    admin_only, anon = _roles_info(p)
    if admin_only or p.restrictive:
        return []
    using_open = p.using is None or is_true(p.using)
    check_open = (p.check is None and using_open) or (p.check is not None and is_true(p.check))
    if p.cmd == "select":
        read_open, write_open = using_open, False
    elif p.cmd == "insert":
        read_open, write_open = False, p.check is None or is_true(p.check)
    elif p.cmd == "delete":
        read_open, write_open = False, using_open
    else:  # update / all
        read_open, write_open = False, using_open or check_open
    who = "anyone on the internet (no login needed)" if anon else "any logged-in user"
    label = 'Policy "%s" (%s)' % (p.name, p.cmd)

    if write_open:
        return [Finding(
            "RLS003", "critical" if anon else "high", tgt,
            "%s allows writes with an always-true condition" % label, p.file, p.line,
            "The condition is always true, so %s can %s rows that belong to other people."
            % (who, {"insert": "insert", "delete": "delete", "update": "change"}.get(p.cmd, "insert, change or delete")),
            _policy_fix(t, p))]
    if read_open and anon:
        risky = bool(t.owner_cols) or sensitive
        return [Finding(
            "RLS003", "medium" if risky else "low", tgt,
            "%s lets anon read every row" % label, p.file, p.line,
            ("This table looks like it holds per-user or sensitive data, and anyone on the internet can read every row and "
             "every column of it; keep this only if all of it is meant to be public."
             if risky else
             "Anyone on the internet can read all rows; that is fine only if the whole table is meant to be public."),
            _policy_fix(t, p))]

    if not t.owner_cols:
        return []
    exprs = [e for e in (p.using, p.check) if e]
    weak = bool(exprs) and all(WEAK_AUTH.match(re.sub(r"::\w+", "", squash(e))) for e in exprs)
    if read_open or weak:
        return [Finding(
            "RLS004", "high", tgt,
            "%s only checks that the user is logged in, not that the row is theirs" % label, p.file, p.line,
            "The table has an owner column (%s) but this policy never compares it to the caller, so every "
            "logged-in user gets every other user's rows." % t.owner_cols[0],
            _policy_fix(t, p))]
    if p.cmd != "select" and not _has_identity(" ".join(exprs), schema):
        return [Finding(
            "RLS004", "high", tgt,
            "%s never references auth.uid() or auth.jwt()" % label, p.file, p.line,
            "The table has an owner column (%s) but this write policy does not tie the row to the caller, "
            "so users can likely modify rows that are not theirs." % t.owner_cols[0],
            _policy_fix(t, p))]
    return []


# --------------------------------------------------------------------------
# App source scan (service-role key exposure)
# --------------------------------------------------------------------------
def _jwt_is_service_role(payload_b64):
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        return json.loads(raw.decode("utf-8", "replace")).get("role") == "service_role"
    except Exception:
        return False


def scan_source_file(rel, text):
    """Return findings for one source or .env file. Never includes secret values."""
    out = []
    base = os.path.basename(rel)
    is_env = base.startswith(".env")
    lines = text.splitlines()
    seen = set()
    tgt = "app code " + rel

    def add(rule, sev, title, line, why, fix, key):
        if key not in seen:
            seen.add(key)
            out.append(Finding(rule, sev, tgt, title, rel, line, why, fix))

    head = "\n".join(lines[:15])
    use_client = bool(re.search(r"""^\s*['"]use client['"]""", head, re.M))
    use_server = bool(re.search(r"""^\s*['"]use server['"]""", head, re.M))
    # import "server-only" makes the Next.js build fail if a client component imports this module.
    server_only = bool(re.search(r"""^\s*import\s+['"]server-only['"]""", head, re.M))
    server_path = bool(SERVER_PATH.search(rel.replace(os.sep, "/")))
    posix = rel.replace(os.sep, "/")

    for no, ln in enumerate(lines, 1):
        if len(ln) > 5000:
            ln = ln[:5000]
        for m in PUBLIC_SERVICE_VAR.finditer(ln):
            add("KEY001", "critical", "Service-role key in a browser-exposed env var (%s)" % m.group(1), no,
                "Variables with this prefix are bundled into the JavaScript every visitor downloads, and the "
                "service-role key bypasses all RLS.",
                "Rename it without the public prefix, read it only in server code, and rotate the key in "
                "Supabase (Settings > API) because it must be treated as leaked.", ("K1", m.group(1)))
        if is_env:
            continue
        for m in JWT_RE.finditer(ln):
            if _jwt_is_service_role(m.group(1)):
                add("KEY003", "critical", "Hardcoded service-role key in source (value redacted)", no,
                    "A service-role key committed to the repo gives full database access to anyone who can "
                    "read the code or the built bundle.",
                    "Remove it, load it from a server-only environment variable, and rotate the key in "
                    "Supabase (Settings > API).", ("K3", no))
        if SB_SECRET_RE.search(ln):
            add("KEY003", "critical", "Hardcoded Supabase secret key in source (value redacted)", no,
                "A secret key committed to the repo gives full database access to anyone who can read the "
                "code or the built bundle.",
                "Remove it, load it from a server-only environment variable, and rotate the key in "
                "Supabase (Settings > API).", ("K3", no))
        m = SERVICE_REF.search(PUBLIC_SERVICE_VAR.sub("", ln))
        if not m or use_server:
            continue
        if use_client:
            sev, where = "critical", 'a file marked "use client"'
        elif server_path or server_only:
            continue
        elif "import.meta.env" in ln or CLIENT_DIR.search(posix) or posix.endswith((".vue", ".svelte")):
            sev, where = "high", "what looks like client-side code"
        elif APP_DIR.search(posix):
            sev, where = "medium", "a file that is not clearly server-only"
        else:
            continue
        add("KEY002", sev, "Service-role key referenced in %s (%s)" % (where, m.group(1)), no,
            "The service-role key bypasses all RLS; if this file is ever bundled for the browser, every "
            "visitor gets full database access.",
            "Move this call into a server-only module (route handler, server action, edge function) and "
            "use the anon key in the browser.", ("K2",))
    return out


# --------------------------------------------------------------------------
# Project scan
# --------------------------------------------------------------------------
def _read(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _inside(root_real, path):
    """True when path (after resolving symlinks) stays inside the project folder."""
    real = os.path.realpath(path)
    return real == root_real or real.startswith(root_real + os.sep)


def scan_project(root, exposed=("public",)):
    sql_files, src_files = [], []
    root_real = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full) and not _inside(root_real, full):
                continue  # never read files outside the project through a symlink
            rel = os.path.relpath(full, root)
            ext = os.path.splitext(fn)[1].lower()
            if ext == ".sql":
                sql_files.append(rel)
            elif ext in SOURCE_EXT or fn.startswith(".env"):
                src_files.append(rel)
    # Migrations run in file-name order; anything outside a migrations folder goes after them.
    sql_files.sort(key=lambda r: (0 if "migrations" in r.replace(os.sep, "/").split("/") else 1, r))
    src_files.sort()

    schema = Schema()
    for rel in sql_files:
        text = _read(os.path.join(root, rel))
        if text is not None:
            schema.apply_file(text, rel.replace(os.sep, "/"))
    findings = evaluate(schema, exposed)
    for rel in src_files:
        text = _read(os.path.join(root, rel))
        if text is not None:
            findings.extend(scan_source_file(rel.replace(os.sep, "/"), text))

    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.target, f.rule, f.line))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    return {
        "tool": "rls_check", "version": VERSION,
        "scanned": {
            "sql_files": len(sql_files), "source_files": len(src_files),
            "tables": sum(1 for t in schema.tables.values() if t.schema in exposed),
            "schemas": list(exposed),
        },
        "summary": counts,
        "findings": findings,
    }


def grouped(findings):
    groups = {}
    for f in findings:
        groups.setdefault(f.target, []).append(f)
    return sorted(groups.items(), key=lambda kv: (min(SEV_RANK[f.severity] for f in kv[1]), kv[0]))


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
LIMITS = ("Static reading of migration files only: changes made in the Supabase dashboard are invisible to "
          "this tool, and it does not test policies against a live database or replace a human review.")
COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}


def render_text(result, root, fail_on, color=False):
    def paint(sev, s):
        return COLORS[sev] + s + "\033[0m" if color else s

    sc, counts = result["scanned"], result["summary"]
    out = ["Supabase RLS pre-launch check v%s - %s" % (VERSION, root),
           "Read %d SQL file(s) and %d app source file(s); %d table(s) in exposed schema(s): %s"
           % (sc["sql_files"], sc["source_files"], sc["tables"], ", ".join(sc["schemas"])), ""]
    if sc["sql_files"] == 0:
        out += ["NOTE: no .sql files found, so no tables or policies were checked. If the schema was built in "
                "the dashboard, run `supabase db pull` first.", ""]
    for target, items in grouped(result["findings"]):
        out.append(target)
        for f in items:
            out.append("  %s %s  %s" % (paint(f.severity, "[%s]" % f.severity.upper()), f.rule, f.title))
            out.append("      where: %s:%d" % (f.file, f.line))
            out.append("      why:   %s" % f.why)
            fix = f.fix.split("\n")
            out.append("      fix:   %s" % fix[0])
            out.extend("             %s" % x for x in fix[1:])
        out.append("")
    failed = exit_code(result, fail_on) == 1
    out.append("Summary: " + ", ".join("%d %s" % (counts[s], s) for s in SEVERITIES)
               + "  ->  " + ("FAIL" if failed else "PASS") + " (fail-on: %s)" % fail_on)
    if not result["findings"]:
        out.append("No findings. That means none of the known patterns matched, not that the app is secure.")
    out.append("Limits: " + LIMITS)
    return "\n".join(out)


def render_json(result, fail_on):
    data = dict(result)
    data["findings"] = [f.as_dict() for f in result["findings"]]
    data["fail_on"] = fail_on
    data["passed"] = exit_code(result, fail_on) == 0
    data["limitations"] = LIMITS
    return json.dumps(data, indent=2)


def render_html(result, root, fail_on):
    e = html.escape
    counts, sc = result["summary"], result["scanned"]
    failed = exit_code(result, fail_on) == 1
    parts = ["""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Supabase RLS pre-launch check</title>
<style>
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#1c2330;background:#f5f6f8;margin:0;padding:24px}
main{max-width:920px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;font-family:ui-monospace,Menlo,monospace}
.meta{color:#5b6475;font-size:13px}.pills{margin:16px 0}.pill{display:inline-block;padding:4px 10px;border-radius:12px;margin-right:6px;font-size:13px;font-weight:600;color:#fff}
.critical{background:#b3261e}.high{background:#d9541e}.medium{background:#b58100}.low{background:#3d6fa5}.pass{background:#2a7d46}
.card{background:#fff;border:1px solid #dfe3ea;border-radius:8px;padding:14px 16px;margin:8px 0}
.card h3{font-size:15px;margin:0 0 6px}.rule{font-family:ui-monospace,Menlo,monospace;color:#5b6475;font-size:12px;margin-left:6px}
.where{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#5b6475}
pre{background:#10151f;color:#e6edf3;padding:10px 12px;border-radius:6px;overflow:auto;font-size:12.5px;margin:8px 0 0;white-space:pre-wrap}
footer{margin-top:28px;color:#5b6475;font-size:13px}
</style></head><body><main>"""]
    parts.append("<h1>Supabase RLS pre-launch check</h1>")
    parts.append('<div class="meta">Project: %s &middot; %d SQL file(s), %d app source file(s), %d table(s) in %s &middot; rls_check v%s</div>'
                 % (e(os.path.basename(os.path.abspath(root))), sc["sql_files"], sc["source_files"], sc["tables"],
                    e(", ".join(sc["schemas"])), e(VERSION)))
    parts.append('<div class="pills"><span class="pill %s">%s</span>' % ("critical" if failed else "pass", "FAIL" if failed else "PASS"))
    for s in SEVERITIES:
        parts.append('<span class="pill %s">%d %s</span>' % (s, counts[s], s))
    parts.append("</div>")
    if not result["findings"]:
        parts.append('<div class="card">No findings. None of the known patterns matched; this does not prove the app is secure.</div>')
    for target, items in grouped(result["findings"]):
        parts.append("<h2>%s</h2>" % e(target))
        for f in items:
            parts.append(
                '<div class="card"><h3><span class="pill %s">%s</span>%s<span class="rule">%s</span></h3>'
                '<div class="where">%s:%d</div><p>%s</p><pre>%s</pre></div>'
                % (f.severity, e(f.severity.upper()), e(f.title), e(f.rule), e(f.file), f.line, e(f.why), e(f.fix)))
    parts.append("<footer><p><strong>Limits.</strong> %s</p>"
                 "<p>Want a human to check the rest? Launch Security Check &mdash; https://proofmerge.com</p></footer>" % e(LIMITS))
    parts.append("</main></body></html>")
    return "\n".join(parts)


def exit_code(result, fail_on="high"):
    limit = SEV_RANK[fail_on]
    return 1 if any(SEV_RANK[f.severity] <= limit for f in result["findings"]) else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rls_check.py",
        description="Offline Supabase RLS pre-launch checker (reads SQL migrations and app source).")
    ap.add_argument("path", nargs="?", default=".", help="project folder (default: current directory)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the text report")
    ap.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    ap.add_argument("--schemas", default="public", help="comma-separated exposed schemas (default: public)")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high",
                    help="lowest severity that makes the exit code 1 (default: high)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("--version", action="version", version="rls_check " + VERSION)
    args = ap.parse_args(argv)

    if not os.path.isdir(args.path):
        print("error: not a directory: %s" % args.path, file=sys.stderr)
        return 2
    exposed = tuple(s.strip().lower() for s in args.schemas.split(",") if s.strip()) or ("public",)
    result = scan_project(args.path, exposed)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(result, args.path, args.fail_on))
    if args.json:
        print(render_json(result, args.fail_on))
    else:
        color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
        print(render_text(result, args.path, args.fail_on, color))
        if args.html:
            print("HTML report written to %s" % args.html)
    return exit_code(result, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())

# MIT License
#
# Copyright (c) 2026 Proofmerge
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
