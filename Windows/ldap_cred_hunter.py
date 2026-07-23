#!/usr/bin/env python3
"""
ldap_creds_hunter.py - Filters ldapsearch output (LDIF format) looking for
possible passwords/hints in free-text attributes, and extracts a list of
usernames (sAMAccountName) from the domain.

Usage:
    ldapsearch -H ldap://IP/ -x -D 'user@dom' -w 'pass' -b 'DC=dom,DC=htb' "(objectClass=*)" > dump.ldif
    python3 ldap_creds_hunter.py dump.ldif

    Or via stdin:
    ldapsearch ... | python3 ldap_creds_hunter.py
"""
import sys
import re
from collections import defaultdict

# Attributes where people commonly leave passwords/hints by mistake
PASSWORD_HINT_ATTRS = [
    "description",
    "info",
    "comment",
    "userPassword",
    "unixUserPassword",
    "unicodePwd",
    "msSFU30Password",
    "gecos",
    "notes",
    "extensionName",
]

# Keywords that increase suspicion that a description/info holds a real password
SUSPICIOUS_KEYWORDS = re.compile(
    r"(pass|pwd|credential|login|user:|pw:|initial|secret)",
    re.IGNORECASE,
)


def parse_ldif(lines):
    """
    Parses LDIF with line continuation (RFC 2849: a line starting with a
    space is a continuation of the previous one).
    Returns a list of entries, each a dict attr -> [values].
    """
    entries = []
    current = defaultdict(list)
    pending_attr = None
    pending_value = None

    def flush_pending():
        nonlocal pending_attr, pending_value
        if pending_attr is not None:
            current[pending_attr].append(pending_value)
        pending_attr = None
        pending_value = None

    for raw_line in lines:
        line = raw_line.rstrip("\n")

        if line.startswith(" "):
            # continuation of the previous line (split base64, etc.)
            if pending_value is not None:
                pending_value += line[1:]
            continue

        # a new entry starts at a "dn:"
        if line.startswith("dn:") and current:
            flush_pending()
            entries.append(dict(current))
            current = defaultdict(list)

        flush_pending()

        if not line or line.startswith("#"):
            continue

        # split "attr:: base64value" or "attr: value"
        m = re.match(r"^([\w;.-]+)(::?)\s?(.*)$", line)
        if not m:
            continue
        attr, sep, value = m.groups()
        pending_attr = attr
        pending_value = value
        if sep == "::":
            pending_attr = attr + "__b64"

    flush_pending()
    if current:
        entries.append(dict(current))

    return entries


def get_dn(entry):
    for k in ("dn", "dn__b64"):
        if k in entry:
            return entry[k][0]
    return "(no dn)"


def get_attr(entry, name):
    """Returns the values of an attribute, ignoring ones that came as base64 (__b64)."""
    vals = []
    if name in entry:
        vals.extend(entry[name])
    if (name + "__b64") in entry:
        # we don't decode base64 here: if it came as b64 it's usually binary
        # (SIDs, GUIDs), not readable text, so we skip it for the hunt
        pass
    return vals


def hunt_passwords(entries):
    print("=" * 70)
    print(" SEARCHING FOR POSSIBLE PASSWORDS / HINTS")
    print("=" * 70)
    found_any = False

    for entry in entries:
        dn = get_dn(entry)
        for attr in PASSWORD_HINT_ATTRS:
            for value in get_attr(entry, attr):
                if not value.strip():
                    continue
                flag = " <== SUSPICIOUS" if SUSPICIOUS_KEYWORDS.search(value) else ""
                # Only show description/info/comment if they aren't the typical
                # boilerplate system phrases (built-in accounts, etc.) to cut
                # down on noise, unless they contain a suspicious keyword.
                is_builtin_noise = re.search(
                    r"(Built-in account|Default container|Designated administrators|"
                    r"Key Distribution Center|DNS Administrators|Members (can|of|are)|"
                    r"All (domain|workstations)|Servers in this group|A backward compat)",
                    value,
                )
                if is_builtin_noise and not flag:
                    continue
                found_any = True
                print(f"\n[{attr}] {dn}")
                print(f"    -> {value}{flag}")

    if not found_any:
        print("\nNo suspicious values found in the usual attributes.")
        print("(description/info/comment had no relevant content, no userPassword)")


def hunt_usernames(entries):
    print("\n" + "=" * 70)
    print(" USERNAME LIST (sAMAccountName)")
    print("=" * 70)

    users = []
    for entry in entries:
        sam = get_attr(entry, "sAMAccountName")
        if not sam:
            continue
        name = sam[0]
        # skip machine accounts (end in $)
        if name.endswith("$"):
            continue
        upn = get_attr(entry, "userPrincipalName")
        desc = get_attr(entry, "description")
        users.append((name, upn[0] if upn else "", desc[0] if desc else ""))

    users.sort()
    for name, upn, desc in users:
        line = f"  {name}"
        if upn:
            line += f"   ({upn})"
        if desc:
            line += f"   # {desc}"
        print(line)

    print(f"\nTotal users (excluding machine accounts): {len(users)}")

    # separate file with just names, ready for hydra/kerbrute/etc.
    out_path = "usernames.txt"
    with open(out_path, "w") as f:
        for name, _, _ in users:
            f.write(name + "\n")
    print(f"Saved plain list to: {out_path}")


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", errors="replace") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()

    entries = parse_ldif(lines)
    print(f"Parsed LDAP entries: {len(entries)}\n")

    hunt_passwords(entries)
    hunt_usernames(entries)


if __name__ == "__main__":
    main()
