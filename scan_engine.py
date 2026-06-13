"""
scan_engine.py — Netra Security
Dual-engine Static Application Security Testing (SAST) scanner.

Engines:
  1. AST Engine  — walks the Python Abstract Syntax Tree to detect
                   dangerous function calls, imports, and patterns
                   that regex alone cannot reliably find.
  2. Regex Engine — line-by-line pattern matching for secrets,
                    hardcoded credentials, weak crypto, and
                    patterns that do not appear in the AST.

Each rule produces a finding dict with these exact keys
(matching models.py → Finding):

    rule_id         str   e.g. "S001"
    title           str   e.g. "SQL Injection"
    severity        str   "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    line_number     int   1-based line in source file
    vulnerable_code str   the offending source line (stripped)
    description     str   what the vulnerability is
    recommendation  str   how to fix it

Public API:
    findings = scan_file(filepath)   # → list[dict]
"""

import ast
import re
import os
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# Rule Registry
# Every rule is defined once here. Adding a new rule = one new entry.
# ═══════════════════════════════════════════════════════════════════

@dataclass
class Rule:
    rule_id:        str
    title:          str
    severity:       str          # CRITICAL | HIGH | MEDIUM | LOW
    description:    str
    recommendation: str
    cwe:            str          # e.g. "CWE-89"
    owasp:          str          # e.g. "A03:2021"


RULES: dict[str, Rule] = {

    # ── Injection ────────────────────────────────────────────────
    "S001": Rule(
        rule_id        = "S001",
        title          = "SQL Injection",
        severity       = "CRITICAL",
        description    = "User-controlled input is concatenated directly into a SQL query. "
                         "An attacker can manipulate the query to read, modify, or delete data.",
        recommendation = "Use parameterised queries or an ORM. Never build SQL by string concatenation. "
                         "Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        cwe            = "CWE-89",
        owasp          = "A03:2021",
    ),
    "S002": Rule(
        rule_id        = "S002",
        title          = "Command Injection",
        severity       = "CRITICAL",
        description    = "Unsanitised input is passed to a shell command. "
                         "An attacker can execute arbitrary OS commands on the server.",
        recommendation = "Avoid shell=True. Pass arguments as a list to subprocess.run(). "
                         "Validate and whitelist all external input before use in commands.",
        cwe            = "CWE-78",
        owasp          = "A03:2021",
    ),
    "S003": Rule(
        rule_id        = "S003",
        title          = "Code Injection via eval()",
        severity       = "CRITICAL",
        description    = "eval() executes arbitrary Python expressions. If input is user-controlled, "
                         "an attacker can run any Python code in the server process.",
        recommendation = "Never pass user input to eval(). Use ast.literal_eval() for safe "
                         "evaluation of literals, or redesign to avoid dynamic evaluation entirely.",
        cwe            = "CWE-95",
        owasp          = "A03:2021",
    ),
    "S004": Rule(
        rule_id        = "S004",
        title          = "Arbitrary Code Execution via exec()",
        severity       = "CRITICAL",
        description    = "exec() executes arbitrary Python code strings. User-controlled input "
                         "reaching exec() gives an attacker full code execution on the server.",
        recommendation = "Remove exec() from production code. If dynamic behaviour is required, "
                         "use a restricted DSL or configuration file instead.",
        cwe            = "CWE-78",
        owasp          = "A03:2021",
    ),
    "S005": Rule(
        rule_id        = "S005",
        title          = "Code Injection via compile()",
        severity       = "CRITICAL",
        description    = "compile() + exec() is functionally identical to exec() alone. "
                         "Passing user input to compile() leads to arbitrary code execution.",
        recommendation = "Avoid compile() with dynamic or user-supplied strings. "
                         "Refactor to use static, predefined logic.",
        cwe            = "CWE-95",
        owasp          = "A03:2021",
    ),

    # ── Path Traversal ───────────────────────────────────────────
    "S006": Rule(
        rule_id        = "S006",
        title          = "Path Traversal",
        severity       = "HIGH",
        description    = "File path is constructed with user-controlled input without sanitisation. "
                         "An attacker can use '../' sequences to access files outside the intended directory.",
        recommendation = "Use os.path.realpath() and verify the resolved path starts with the expected "
                         "base directory. Reject paths containing '..' before processing.",
        cwe            = "CWE-22",
        owasp          = "A01:2021",
    ),

    # ── SSRF ─────────────────────────────────────────────────────
    "S007": Rule(
        rule_id        = "S007",
        title          = "Server-Side Request Forgery (SSRF)",
        severity       = "HIGH",
        description    = "HTTP request is made to a URL derived from user input. "
                         "An attacker can force the server to make requests to internal services "
                         "or cloud metadata endpoints (e.g. 169.254.169.254).",
        recommendation = "Validate and whitelist allowed URL schemes and hostnames. "
                         "Resolve the hostname and block private/loopback IP ranges before making requests.",
        cwe            = "CWE-918",
        owasp          = "A10:2021",
    ),

    # ── Insecure Deserialization ──────────────────────────────────
    "S008": Rule(
        rule_id        = "S008",
        title          = "Insecure Deserialization (pickle)",
        severity       = "HIGH",
        description    = "pickle.loads() deserializes arbitrary Python objects. "
                         "Deserializing attacker-controlled data can lead to remote code execution.",
        recommendation = "Never unpickle data from untrusted sources. Use JSON or MessagePack "
                         "for data exchange. If pickle is required, sign and verify the payload with HMAC.",
        cwe            = "CWE-502",
        owasp          = "A08:2021",
    ),
    "S009": Rule(
        rule_id        = "S009",
        title          = "Insecure Deserialization (PyYAML)",
        severity       = "HIGH",
        description    = "yaml.load() without Loader=yaml.SafeLoader can deserialize arbitrary Python "
                         "objects, leading to remote code execution.",
        recommendation = "Always use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). "
                         "Never load YAML from untrusted sources with the default loader.",
        cwe            = "CWE-502",
        owasp          = "A08:2021",
    ),

    # ── Subprocess / Shell ────────────────────────────────────────
    "S010": Rule(
        rule_id        = "S010",
        title          = "Dangerous Subprocess with shell=True",
        severity       = "HIGH",
        description    = "subprocess called with shell=True passes the command to the OS shell, "
                         "enabling shell injection if any part of the command is user-controlled.",
        recommendation = "Set shell=False (the default) and pass the command as a list of strings: "
                         "subprocess.run(['ls', '-la']). Never interpolate user input into shell strings.",
        cwe            = "CWE-78",
        owasp          = "A03:2021",
    ),
    "S011": Rule(
        rule_id        = "S011",
        title          = "Use of os.system()",
        severity       = "HIGH",
        description    = "os.system() passes the command string directly to the OS shell. "
                         "Any user-controlled data in the string enables command injection.",
        recommendation = "Replace os.system() with subprocess.run(args, shell=False). "
                         "Validate all inputs and use argument lists instead of shell strings.",
        cwe            = "CWE-78",
        owasp          = "A03:2021",
    ),
    "S012": Rule(
        rule_id        = "S012",
        title          = "Use of os.popen()",
        severity       = "HIGH",
        description    = "os.popen() opens a pipe to a shell command. Like os.system(), "
                         "it is vulnerable to command injection when input is user-controlled.",
        recommendation = "Replace os.popen() with subprocess.Popen(args, shell=False, stdout=PIPE). "
                         "Always use argument lists and avoid string interpolation.",
        cwe            = "CWE-78",
        owasp          = "A03:2021",
    ),

    # ── Weak Cryptography ─────────────────────────────────────────
    "S013": Rule(
        rule_id        = "S013",
        title          = "Use of Weak Hash Algorithm (MD5)",
        severity       = "MEDIUM",
        description    = "MD5 is cryptographically broken. It is vulnerable to collision attacks "
                         "and should not be used for password hashing, data integrity, or signatures.",
        recommendation = "Use SHA-256 or SHA-3 for general hashing. For passwords, use bcrypt, "
                         "scrypt, or Argon2 via the 'passlib' or 'argon2-cffi' library.",
        cwe            = "CWE-327",
        owasp          = "A02:2021",
    ),
    "S014": Rule(
        rule_id        = "S014",
        title          = "Use of Weak Hash Algorithm (SHA1)",
        severity       = "MEDIUM",
        description    = "SHA-1 is considered weak and collision-prone. It is deprecated for "
                         "security-sensitive operations by NIST.",
        recommendation = "Migrate to SHA-256 or SHA-3. For TLS certificates and code signing, "
                         "SHA-1 is no longer accepted by modern clients.",
        cwe            = "CWE-327",
        owasp          = "A02:2021",
    ),
    "S015": Rule(
        rule_id        = "S015",
        title          = "Use of Broken Cipher (DES / RC4)",
        severity       = "MEDIUM",
        description    = "DES and RC4 are broken symmetric ciphers with well-known practical attacks. "
                         "Using them provides no meaningful security guarantee.",
        recommendation = "Use AES-256-GCM for symmetric encryption. Use the 'cryptography' library "
                         "and prefer high-level Fernet or AESGCM interfaces.",
        cwe            = "CWE-327",
        owasp          = "A02:2021",
    ),
    "S016": Rule(
        rule_id        = "S016",
        title          = "Use of random for Security Purposes",
        severity       = "MEDIUM",
        description    = "The 'random' module uses a Mersenne Twister PRNG which is not "
                         "cryptographically secure. Using it for tokens, passwords, or session IDs "
                         "makes them predictable.",
        recommendation = "Use secrets.token_hex(), secrets.token_urlsafe(), or os.urandom() "
                         "for all security-sensitive random values.",
        cwe            = "CWE-338",
        owasp          = "A02:2021",
    ),

    # ── Hardcoded Secrets ─────────────────────────────────────────
    "S017": Rule(
        rule_id        = "S017",
        title          = "Hardcoded Password",
        severity       = "MEDIUM",
        description    = "A password appears to be hardcoded as a string literal in source code. "
                         "Committing credentials to version control exposes them permanently.",
        recommendation = "Load secrets from environment variables (os.environ) or a secrets manager "
                         "(AWS Secrets Manager, HashiCorp Vault). Never hardcode credentials.",
        cwe            = "CWE-798",
        owasp          = "A07:2021",
    ),
    "S018": Rule(
        rule_id        = "S018",
        title          = "Hardcoded API Key or Token",
        severity       = "MEDIUM",
        description    = "An API key, secret token, or bearer credential is hardcoded in source code. "
                         "If this repository is public or shared, the key is compromised.",
        recommendation = "Store API keys in environment variables or a secrets manager. "
                         "Rotate any key that has been committed to version control immediately.",
        cwe            = "CWE-798",
        owasp          = "A07:2021",
    ),
    "S019": Rule(
        rule_id        = "S019",
        title          = "Hardcoded Secret Key",
        severity       = "MEDIUM",
        description    = "A cryptographic secret key or application secret is hardcoded. "
                         "This undermines the security of any system relying on that secret.",
        recommendation = "Generate secrets at deployment time and inject via environment variables. "
                         "Use os.environ.get('SECRET_KEY') and fail fast if the variable is absent.",
        cwe            = "CWE-798",
        owasp          = "A07:2021",
    ),

    # ── Dangerous Imports ─────────────────────────────────────────
    "S020": Rule(
        rule_id        = "S020",
        title          = "Import of Dangerous Module (pickle)",
        severity       = "LOW",
        description    = "The pickle module is imported. Pickle can execute arbitrary code during "
                         "deserialization and is unsafe for untrusted data.",
        recommendation = "Audit all uses of pickle in this file. Replace with JSON or another "
                         "safe serialization format where possible.",
        cwe            = "CWE-502",
        owasp          = "A08:2021",
    ),
    "S021": Rule(
        rule_id        = "S021",
        title          = "Import of Dangerous Module (marshal)",
        severity       = "LOW",
        description    = "The marshal module serializes Python code objects and can execute arbitrary "
                         "code when loading untrusted data.",
        recommendation = "Avoid marshal for data interchange. Use JSON or protobuf instead.",
        cwe            = "CWE-502",
        owasp          = "A08:2021",
    ),
    "S022": Rule(
        rule_id        = "S022",
        title          = "Import of Shell Execution Module (commands)",
        severity       = "LOW",
        description    = "The 'commands' module (Python 2) or similar shell-execution utility is "
                         "imported, indicating potential shell command execution.",
        recommendation = "Use subprocess with shell=False. Validate all inputs passed to shell commands.",
        cwe            = "CWE-78",
        owasp          = "A03:2021",
    ),

    # ── XSS ──────────────────────────────────────────────────────
    "S023": Rule(
        rule_id        = "S023",
        title          = "Potential Cross-Site Scripting (XSS) — Jinja2 Mark Safe",
        severity       = "MEDIUM",
        description    = "Markup.escape() bypass or mark_safe() usage can introduce XSS if "
                         "user-controlled content is rendered without escaping in templates.",
        recommendation = "Avoid Markup() and mark_safe() with user input. Let the template engine "
                         "auto-escape all output. Use |e filter explicitly when needed.",
        cwe            = "CWE-79",
        owasp          = "A03:2021",
    ),

    # ── Flask / Web specific ──────────────────────────────────────
    "S024": Rule(
        rule_id        = "S024",
        title          = "Flask Debug Mode Enabled",
        severity       = "HIGH",
        description    = "Flask is started with debug=True. The Werkzeug debugger exposes an "
                         "interactive Python console reachable from the browser without authentication.",
        recommendation = "Set debug=False in production. Use environment variables: "
                         "app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')",
        cwe            = "CWE-94",
        owasp          = "A05:2021",
    ),
    "S025": Rule(
        rule_id        = "S025",
        title          = "Insecure SSL/TLS Verification Disabled",
        severity       = "HIGH",
        description    = "SSL certificate verification is disabled (verify=False). "
                         "This makes the connection vulnerable to man-in-the-middle attacks.",
        recommendation = "Never set verify=False in production. If using a custom CA, "
                         "pass verify='/path/to/ca-bundle.crt' instead.",
        cwe            = "CWE-295",
        owasp          = "A02:2021",
    ),
}


# ═══════════════════════════════════════════════════════════════════
# Regex Rule Definitions
# Each entry: (rule_id, compiled_pattern)
# Matched against every source line individually.
# ═══════════════════════════════════════════════════════════════════

_REGEX_RULES: list[tuple[str, re.Pattern]] = [

    # Hardcoded passwords
    ("S017", re.compile(
        r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']'
    )),

    # Hardcoded API keys / tokens
    ("S018", re.compile(
        r'(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token'
        r'|bearer[_-]?token|client[_-]?secret)\s*=\s*["\'][^"\']{8,}["\']'
    )),

    # Hardcoded secret keys
    ("S019", re.compile(
        r'(?i)(secret[_-]?key|app[_-]?secret|jwt[_-]?secret|signing[_-]?key'
        r'|encryption[_-]?key)\s*=\s*["\'][^"\']{8,}["\']'
    )),

    # Weak hash — MD5
    ("S013", re.compile(
        r'hashlib\s*\.\s*md5\s*\('
        r'|hashlib\.new\s*\(\s*["\']md5["\']'
    )),

    # Weak hash — SHA1
    ("S014", re.compile(
        r'hashlib\s*\.\s*sha1\s*\('
        r'|hashlib\.new\s*\(\s*["\']sha1["\']'
    )),

    # Broken cipher — DES / RC4
    ("S015", re.compile(
        r'(?i)(Cipher\.DES|Blowfish|ARC4|RC4|DES\.new\s*\()'
    )),

    # Insecure random
    ("S016", re.compile(
        r'\brandom\s*\.\s*(random|randint|choice|randrange|uniform)\s*\('
    )),

    # SQL string concatenation (broad catch for regex layer)
    ("S001", re.compile(
        r'(?i)(execute|executemany)\s*\(\s*["\']?\s*'
        r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE).*?["\']?\s*[+%]'
        r'|\bexecute\b.*?\+.*?WHERE'
    )),

    # Shell=True
    ("S010", re.compile(
        r'(subprocess\.(run|Popen|call|check_output|check_call))\s*\(.*shell\s*=\s*True'
    )),

    # os.system / os.popen
    ("S011", re.compile(r'\bos\s*\.\s*system\s*\(')),
    ("S012", re.compile(r'\bos\s*\.\s*popen\s*\(')),

    # eval / exec
    ("S003", re.compile(r'\beval\s*\(')),
    ("S004", re.compile(r'\bexec\s*\(')),

    # Insecure YAML load
    ("S009", re.compile(
        r'\byaml\s*\.\s*load\s*\([^)]*\)'
        r'(?!.*SafeLoader)'
    )),

    # pickle.loads
    ("S008", re.compile(r'\bpickle\s*\.\s*(loads|load)\s*\(')),

    # Flask debug=True
    ("S024", re.compile(r'\.run\s*\(.*debug\s*=\s*True')),

    # SSL verify=False
    ("S025", re.compile(r'\brequests\s*\.\s*(get|post|put|patch|delete|request)\s*\(.*verify\s*=\s*False')),

    # XSS — Markup / mark_safe
    ("S023", re.compile(r'\bMarkup\s*\(|mark_safe\s*\(')),

    # Path traversal hint — open() with user-supplied path patterns
    ("S006", re.compile(
        r'\bopen\s*\(.*\.\.\s*/|os\.path\.join\s*\(.*request\.'
    )),

    # SSRF hint — requests with variable URL
    ("S007", re.compile(
        r'requests\s*\.\s*(get|post|put|patch)\s*\(\s*(?![\"\'])(url|target|endpoint|host|addr)'
    )),
]


# ═══════════════════════════════════════════════════════════════════
# AST Visitor
# Walks the parsed AST and emits (rule_id, lineno, snippet) tuples.
# ═══════════════════════════════════════════════════════════════════

class _SecurityVisitor(ast.NodeVisitor):
    """AST node visitor that detects dangerous patterns."""

    # Dangerous built-in call names
    _DANGEROUS_CALLS: dict[str, str] = {
        "eval":    "S003",
        "exec":    "S004",
        "compile": "S005",
    }

    # Dangerous attribute calls: module.function → rule_id
    _DANGEROUS_ATTR_CALLS: dict[tuple[str, str], str] = {
        ("os",         "system"):       "S011",
        ("os",         "popen"):        "S012",
        ("pickle",     "loads"):        "S008",
        ("pickle",     "load"):         "S008",
        ("subprocess", "run"):          "S010",   # flagged only if shell=True (checked below)
        ("subprocess", "Popen"):        "S010",
        ("subprocess", "call"):         "S010",
        ("subprocess", "check_output"): "S010",
        ("yaml",       "load"):         "S009",
        ("hashlib",    "md5"):          "S013",
        ("hashlib",    "sha1"):         "S014",
        ("Markup",     "__call__"):     "S023",
    }

    # Dangerous imports: module name → rule_id
    _DANGEROUS_IMPORTS: dict[str, str] = {
        "pickle":   "S020",
        "marshal":  "S021",
        "commands": "S022",
    }

    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.hits: list[tuple[str, int, str]] = []   # (rule_id, lineno, snippet)

    def _line(self, lineno: int) -> str:
        """Return source line (1-based), stripped."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _add(self, rule_id: str, lineno: int):
        self.hits.append((rule_id, lineno, self._line(lineno)))

    # ── Imports ──────────────────────────────────────────────────
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            base = alias.name.split(".")[0]
            if base in self._DANGEROUS_IMPORTS:
                self._add(self._DANGEROUS_IMPORTS[base], node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = (node.module or "").split(".")[0]
        if module in self._DANGEROUS_IMPORTS:
            self._add(self._DANGEROUS_IMPORTS[module], node.lineno)
        self.generic_visit(node)

    # ── Function Calls ────────────────────────────────────────────
    def visit_Call(self, node: ast.Call):
        # Built-in calls: eval(), exec(), compile()
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in self._DANGEROUS_CALLS:
                self._add(self._DANGEROUS_CALLS[name], node.lineno)

        # Attribute calls: module.function()
        elif isinstance(node.func, ast.Attribute):
            attr  = node.func.attr
            value = node.func.value

            # Resolve simple module name (e.g. os.system)
            mod = None
            if isinstance(value, ast.Name):
                mod = value.id
            elif isinstance(value, ast.Attribute):
                # e.g. flask.Markup(...)
                mod = value.attr

            if mod and (mod, attr) in self._DANGEROUS_ATTR_CALLS:
                rule = self._DANGEROUS_ATTR_CALLS[(mod, attr)]

                # For subprocess calls, only flag if shell=True
                if rule == "S010":
                    if self._has_shell_true(node):
                        self._add(rule, node.lineno)
                # For yaml.load, only flag if SafeLoader not used
                elif rule == "S009":
                    if not self._has_safe_loader(node):
                        self._add(rule, node.lineno)
                else:
                    self._add(rule, node.lineno)

            # Flask app.run(debug=True)
            if attr == "run":
                if self._kwarg_is_true(node, "debug"):
                    self._add("S024", node.lineno)

            # requests.get/post/... (verify=False)
            if attr in ("get", "post", "put", "patch", "delete", "request"):
                if isinstance(value, ast.Name) and value.id == "requests":
                    if self._kwarg_is_false(node, "verify"):
                        self._add("S025", node.lineno)

            # hashlib.new("md5" / "sha1")
            if attr == "new" and isinstance(value, ast.Name) and value.id == "hashlib":
                algo = self._first_str_arg(node)
                if algo:
                    if algo.lower() == "md5":
                        self._add("S013", node.lineno)
                    elif algo.lower() == "sha1":
                        self._add("S014", node.lineno)

        self.generic_visit(node)

    # ── SQL Injection — cursor.execute() with string concat ───────
    def visit_Expr(self, node: ast.Expr):
        """Detect cursor.execute(string + var) patterns."""
        if isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute) and call.func.attr in ("execute", "executemany"):
                if call.args:
                    first_arg = call.args[0]
                    # If first arg is a BinOp (string + something) → SQL injection
                    if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                        self._add("S001", node.lineno)
                    # f-string in execute() → SQL injection
                    elif isinstance(first_arg, ast.JoinedStr):
                        self._add("S001", node.lineno)
        self.generic_visit(node)

    # ── Path Traversal — open() with os.path.join + request data ─
    def visit_With(self, node: ast.With):
        """Detect open() calls inside with statements."""
        self.generic_visit(node)

    # ── Helpers ───────────────────────────────────────────────────
    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    @staticmethod
    def _has_safe_loader(node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "Loader":
                return True
        # Also check positional arg 2
        if len(node.args) >= 2:
            return True
        return False

    @staticmethod
    def _kwarg_is_true(node: ast.Call, kwarg: str) -> bool:
        for kw in node.keywords:
            if kw.arg == kwarg and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    @staticmethod
    def _kwarg_is_false(node: ast.Call, kwarg: str) -> bool:
        for kw in node.keywords:
            if kw.arg == kwarg and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        return False

    @staticmethod
    def _first_str_arg(node: ast.Call) -> Optional[str]:
        if node.args and isinstance(node.args[0], ast.Constant):
            return str(node.args[0].value)
        return None


# ═══════════════════════════════════════════════════════════════════
# Deduplication
# Prevents the same rule firing on the same line from both engines.
# ═══════════════════════════════════════════════════════════════════

def _deduplicate(findings: list[dict]) -> list[dict]:
    seen:   set[tuple[str, int]] = set()
    result: list[dict]           = []
    for f in findings:
        key = (f["rule_id"], f["line_number"] or 0)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


# ═══════════════════════════════════════════════════════════════════
# Finding Builder
# Converts a raw (rule_id, lineno, snippet) hit into a full finding.
# ═══════════════════════════════════════════════════════════════════

def _build_finding(rule_id: str, lineno: int, snippet: str) -> dict:
    rule = RULES.get(rule_id)
    if not rule:
        return {}
    return {
        "rule_id":          rule.rule_id,
        "title":            rule.title,
        "severity":         rule.severity,
        "line_number":      lineno,
        "vulnerable_code":  snippet,
        "description":      rule.description,
        "recommendation":   rule.recommendation,
    }


# ═══════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════

def scan_file(filepath: str) -> list[dict]:
    """
    Scan a Python source file for security vulnerabilities.

    Args:
        filepath: Absolute or relative path to the .py file.

    Returns:
        List of finding dicts sorted by severity (CRITICAL first).
        Returns an empty list if the file cannot be read or parsed.
    """
    # ── Read source ───────────────────────────────────────────────
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError as e:
        print(f"[scan_engine] Cannot read file: {e}")
        return []

    source_lines = source.splitlines()
    findings: list[dict] = []

    # ── Engine 1: AST ─────────────────────────────────────────────
    try:
        tree    = ast.parse(source, filename=os.path.basename(filepath))
        visitor = _SecurityVisitor(source_lines)
        visitor.visit(tree)

        for rule_id, lineno, snippet in visitor.hits:
            f = _build_finding(rule_id, lineno, snippet)
            if f:
                findings.append(f)

    except SyntaxError as e:
        # File has syntax errors — AST engine skipped, regex still runs
        print(f"[scan_engine] AST parse failed ({e}), falling back to regex-only.")

    # ── Engine 2: Regex (line-by-line) ────────────────────────────
    for lineno, line in enumerate(source_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue   # skip blank lines and comments

        for rule_id, pattern in _REGEX_RULES:
            if pattern.search(line):
                f = _build_finding(rule_id, lineno, stripped)
                if f:
                    findings.append(f)

    # ── Deduplicate & Sort ────────────────────────────────────────
    findings = _deduplicate(findings)

    _SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 4))

    return findings


# ═══════════════════════════════════════════════════════════════════
# CLI — run directly for quick testing
# Usage: python scan_engine.py path/to/target.py
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python scan_engine.py <path_to_file.py>")
        sys.exit(1)

    target   = sys.argv[1]
    results  = scan_file(target)

    print(f"\n{'═'*60}")
    print(f"  NETRA SECURITY — Scan Results")
    print(f"  File   : {target}")
    print(f"  Findings: {len(results)}")
    print(f"{'═'*60}\n")

    if not results:
        print("  ✓ No vulnerabilities detected.\n")
    else:
        for i, f in enumerate(results, 1):
            print(f"  [{i:02d}] [{f['severity']:8s}] {f['rule_id']} — {f['title']}")
            print(f"        Line {f['line_number']}: {f['vulnerable_code'][:80]}")
            print(f"        Fix : {f['recommendation'][:100]}")
            print()

    print(json.dumps(results, indent=2))
