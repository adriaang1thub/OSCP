#!/bin/bash
###############################################################################
# enumloot.sh — SMB loot enumeration (recursive download + triage)
#
#It recursives enumerates all what you download from SMB without having to search giving to you the direct route, once executed in the downloaded smb folder it will search recursively down the smb directory 
# WORKFLOW (previous steps before running this script):
#
#   1. Prepare working dir — download replicates the share's directory tree
#      here, so keep it contained:
#         mkdir smb && cd smb
#
#   2. Recursive download from SMB (null session):
#         smbclient //IP/Shared_Folder -N \
#             -c 'prompt OFF; recurse ON; mget *'
#
#      Flags:
#         -N          no password (null / anonymous session)
#         prompt OFF  don't ask file by file
#         recurse ON  descend into all subdirectories
#         mget *      grab everything
#
#      NOTE: smbclient ALWAYS replicates the folder structure — there is no
#      flag to download flat. To get files flat, mount the share
#      (mount -t cifs ...) and use `find ... -exec cp -t . {} +`, or flatten
#      afterwards with `find . -type f -exec mv -t . {} +`.
#
#      Authenticated variant (if you have creds):
#         smbclient //IP/Shared_Folder -U 'user%pass' \
#             -c 'prompt OFF; recurse ON; mget *'
#
#   3. Run this script to enumerate the downloaded loot:
#         cp ~/scripts/enumloot.sh .
#         ./enumloot.sh            # enumerates CWD downwards
#         ./enumloot.sh /some/dir  # or pass another dir as argument
#
#   4. Go straight for the good stuff (AD / GPP):
#         grep -rin cpassword . --include='*.xml'   # cpassword in Groups.xml
#         gpp-decrypt '<cpassword>'                 # decrypt it (AES-256, MS key)
#
#      Typical loot:
#         Groups.xml    -> GPP cpassword (decryptable)
#         Registry.pol  -> GPO settings (strings -el / regpol)
#         unattend.xml  -> deployment creds
#
# BEHAVIOUR: lists ALL files (relative path + size), hides nothing, and only
# *marks* the interesting ones. Starts at the given dir (or CWD) and walks
# ONLY downwards, never upwards.
###############################################################################

BASE="${1:-.}"
cd "$BASE" || { echo "[-] Cannot cd into '$BASE'"; exit 1; }

find . -type f -printf '%s\t%P\n' | sort -k2 | while IFS=$'\t' read -r size path; do
  low="${path,,}"
  tag=""
  case "$low" in
    *cpassword*|*groups.xml|*.kdbx|*.ppk|*id_rsa*|*.key|*.pem|*unattend*|*sysprep*|*.vnc)
        tag="[!! CREDS]" ;;
    *.xml|*.config|*.ini|*.conf|*.yml|*.yaml|*.json|*.inf|*.pol)
        tag="[config]" ;;
    *.ps1|*.bat|*.vbs|*.cmd|*.sh|*.py)
        tag="[script]" ;;
    *.txt|*.log|*.bak|*.old|*.csv|*.md)
        tag="[readable]" ;;
  esac
  printf '%9s  %-60s %s\n' "$size" "$path" "$tag"
done
