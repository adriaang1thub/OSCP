#!/usr/bin/env python3
#
# ============================================================================
#  lateral_movs_rpc.py
# ============================================================================
#
#  DESCRIPTION:
#    Post-authentication AD triage tool for lateral movement.
#    Given a single set of valid domain credentials (even a low-priv service
#    account), it enumerates every domain user over RPC (rpcclient), then for
#    each user pulls their group memberships and RESOLVES the group RIDs to
#    real group names. It then ranks users by how many "relevant" groups they
#    belong to (ignoring "Domain Users", which everyone has), so the accounts
#    most likely to have interactive/remote access (WinRM, RDP, special
#    privileges) float to the top.
#
#    Why this matters: in many AD boxes you land with creds for account A but
#    A can't log in anywhere. The user sitting in the most (or the most
#    interesting) groups is usually your next hop. This tool surfaces that
#    user automatically instead of you eyeballing 30+ accounts by hand.
#
#  COMBINE WITH BLOODHOUND:
#    Use this as a fast first pass to pick a target, then confirm the actual
#    access path in BloodHound:
#      - collect:  bloodhound-python -d <domain> -u <user> -p <pass> \
#                  -ns <dc_ip> -c All
#      - in the GUI, mark your top candidate as Owned and run:
#          * "Shortest Path to Domain Admins from Owned Principals"
#          * "Find Workstations where Domain Users can RDP"
#          * search the user -> Node Info -> "Execution Rights" (CanRDP / CanPSRemote)
#    This script tells you WHO to look at; BloodHound tells you WHAT you can
#    do with them.
#
#  USAGE:
#    python3 lateral_movs_rpc.py
#    (it will prompt for user / password / domain / DC IP)
#
#  REQUIREMENTS: rpcclient (samba-common-bin)
# ============================================================================

import subprocess
import sys
import re

# Colors
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
RED = '\033[0;31m'
BOLD = '\033[1m'
NC = '\033[0m'

# Cache group-name lookups so we don't hit the DC twice for the same RID
group_name_cache = {}


def run_rpc(creds, host, command):
    try:
        result = subprocess.run(
            ['rpcclient', '-U', creds, host, '-c', command],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout
    except Exception as e:
        print(f"{RED}[-] Error running rpcclient: {e}{NC}")
        return ""


def get_group_name(creds, host, group_rid):
    if group_rid in group_name_cache:
        return group_name_cache[group_rid]
    output = run_rpc(creds, host, f"querygroup {group_rid}")
    name = f"Unknown({group_rid})"
    for line in output.split('\n'):
        if 'Group Name' in line:
            # Format: "\tGroup Name:\tDomain Users"
            parts = line.split(':', 1)
            if len(parts) == 2 and parts[1].strip():
                name = parts[1].strip()
                break
    group_name_cache[group_rid] = name
    return name


def get_user_groups(creds, host, rid):
    """Return a list of (group_rid, group_name) for a user."""
    output = run_rpc(creds, host, f"queryusergroups {rid}")
    groups = []
    for line in output.split('\n'):
        # REAL format: "\tgroup rid:[0x201] attr:[0x7]"  (space, not underscore)
        if 'rid:[' in line:
            m = re.search(r'rid:\[(0x[0-9a-fA-F]+)\]', line)
            if m:
                grid = m.group(1)
                gname = get_group_name(creds, host, grid)
                groups.append((grid, gname))
    return groups


def parse_users(output):
    """Return {username: rid}, skipping built-in accounts."""
    ignore = {'administrator', 'guest', 'krbtgt'}
    users = {}
    for line in output.split('\n'):
        if 'user:[' in line and 'rid:[' in line:
            um = re.search(r'user:\[([^\]]*)\]', line)
            rm = re.search(r'rid:\[(0x[0-9a-fA-F]+)\]', line)
            if um and rm:
                username = um.group(1)
                if username.lower() not in ignore:
                    users[username] = rm.group(1)
    return users


def banner():
    print(f"{BOLD}{BLUE}")
    print("  ============================================================")
    print("   lateral_movs_rpc  -  AD lateral-movement target picker")
    print("  ============================================================")
    print(f"{NC}")
    print(f"{CYAN}  Ranks domain users by relevant group membership so the")
    print(f"  account most likely to have a shell (WinRM/RDP) shows first.")
    print(f"  Pair it with BloodHound to confirm the real access path.{NC}\n")


def main():
    banner()

    user = input("RPC user: ")
    password = input("Password: ")
    domain = input("Domain: ")
    host = input("DC IP/Host: ")

    creds = f"{domain}\\{user}%{password}"

    print(f"\n{BLUE}[*] Enumerating domain users on {domain}...{NC}")
    output = run_rpc(creds, host, "enumdomusers")
    if not output or "user:" not in output:
        print(f"{RED}[-] Failed to enumerate users (check creds / host / connectivity){NC}")
        sys.exit(1)

    users = parse_users(output)
    print(f"{GREEN}[+] {len(users)} users found (Administrator/Guest/krbtgt excluded){NC}\n")
    if not users:
        sys.exit(1)

    print(f"{BLUE}[*] Querying group membership for each user...{NC}\n")

    user_data = []  # (username, relevant_count, all_groups, relevant_groups)
    for username, rid in users.items():
        groups = get_user_groups(creds, host, rid)
        # "Domain Users" is held by everyone -> exclude from the ranking weight
        relevant = [g for g in groups if g[1].lower() != 'domain users']
        user_data.append((username, len(relevant), groups, relevant))

    # Sort by relevant group count (desc), then by total groups (desc)
    user_data.sort(key=lambda x: (x[1], len(x[2])), reverse=True)

    print(f"{YELLOW}=== USERS RANKED BY RELEVANT GROUP MEMBERSHIP ==={NC}")
    print(f"{YELLOW}('Domain Users' is ignored for scoring since everyone has it){NC}\n")

    for username, rel_count, all_groups, relevant in user_data:
        if rel_count >= 1:
            print(f"{GREEN}{username}{NC} - {YELLOW}{rel_count} relevant group(s){NC}")
            for grid, gname in all_groups:
                if gname.lower() == 'domain users':
                    print(f"      {gname} ({grid})")
                else:
                    print(f"    {CYAN}-> {gname}{NC} ({grid})")
            print()

    print(f"{BLUE}=== TOP 3 CANDIDATES (most relevant groups) ==={NC}\n")
    top = [u for u in user_data if u[1] >= 1][:3]
    for i, (username, rel_count, all_groups, relevant) in enumerate(top, 1):
        names = ', '.join(g[1] for g in relevant)
        print(f"{i}. {GREEN}{username}{NC} ({rel_count}): {names}")

    if top:
        best = top[0][0]
        print(f"\n{GREEN}[+] Start with:{NC}")
        print(f"{BOLD}{GREEN}    evil-winrm -i {host} -u {best} -p PASSWORD -d {domain}{NC}")
        print(f"\n{YELLOW}[i] If that user can't log in remotely, don't stop here:{NC}")
        print(f"{YELLOW}    load the domain into BloodHound, mark {best} as Owned, and hunt")
        print(f"{YELLOW}    lateral-movement paths from it (CanPSRemote / CanRDP / group")
        print(f"    delegation / ACL abuses) toward a box you can actually land on.{NC}\n")
    else:
        print(f"\n{YELLOW}[!] No user has relevant groups beyond 'Domain Users'.{NC}")
        print(f"{YELLOW}    Pivot to BloodHound and look for ACL-based paths instead.{NC}\n")


if __name__ == "__main__":
    main()
