#!/usr/bin/env python3
# whatport.py - traduce puertos a servicios (OSCP-oriented)
# uso:
#   netstat -ano | python3 whatport.py
#   python3 whatport.py output.txt
#   python3 whatport.py 15432 445 8443
#   nmap ... -oG - | python3 whatport.py
# extrae los puertos de cualquier formato (netstat linux/windows, nmap, lista suelta)

import sys, re

# puerto -> (servicio, nota OSCP / que hacer)
PORTS = {
    21:   ("FTP",            "anon login? ftp <ip>; get/put; version -> searchsploit"),
    22:   ("SSH",            "creds? claves? user enum; hydra si hay lista"),
    23:   ("Telnet",         "banner, creds en claro"),
    25:   ("SMTP",           "VRFY/RCPT user enum; open relay; shellshock via mail"),
    53:   ("DNS",            "dig axfr @<ip> <dom> (zone transfer); es DC?"),
    69:   ("TFTP/UDP",       "sin auth; get/put ficheros; RCE si webroot"),
    80:   ("HTTP",           "gobuster/feroxbuster; whatweb; nikto"),
    88:   ("Kerberos",       ">>> ES UN DC <<< AS-REP roast, kerbrute"),
    110:  ("POP3",           "leer correo; USER/PASS"),
    111:  ("RPCbind",        "rpcinfo -p; showmount -e (NFS)"),
    123:  ("NTP/UDP",        "ntpdate <ip> antes de kerberos (clock skew)"),
    135:  ("MSRPC",          "impacket-rpcdump; endpoint mapper; DCOM"),
    137:  ("NetBIOS/UDP",    "nbtscan; nmblookup -A"),
    139:  ("NetBIOS-SSN",    "SMB legacy; enum4linux-ng"),
    143:  ("IMAP",           "leer correo"),
    161:  ("SNMP/UDP",       "snmpwalk -v2c -c public; onesixtyone; usuarios/procesos"),
    389:  ("LDAP",           ">>> AD <<< ldapdomaindump; nxc ldap; get-desc-users"),
    443:  ("HTTPS",          "gobuster; whatweb -k; cert (nombres/dominio)"),
    445:  ("SMB",            ">>> CLAVE <<< nxc smb --shares; enum4linux-ng; null session"),
    464:  ("kpasswd",        "AD - cambio de pass kerberos (es DC)"),
    500:  ("IKE/VPN UDP",    "ike-scan -M -A; sacar PSK -> crackear"),
    512:  ("rexec",          "servicios r* legacy"),
    513:  ("rlogin",         "rlogin -l root <ip>; .rhosts"),
    514:  ("rsh",            "servicios r* legacy"),
    587:  ("SMTP submission","igual que 25"),
    593:  ("RPC over HTTP",  "AD - ncacn_http"),
    623:  ("IPMI/UDP",       "dump de hashes BMC; msf ipmi"),
    636:  ("LDAPS",          "AD - ldap sobre ssl; cert"),
    873:  ("rsync",          "rsync <ip>:: (listar modulos sin auth)"),
    1099: ("Java RMI",       "ysoserial; deserialization RCE"),
    1433: ("MSSQL",          "impacket-mssqlclient; xp_cmdshell; -windows-auth"),
    1434: ("MSSQL browser/UDP","ms-sql-info; te da el puerto real de la instancia"),
    1521: ("Oracle TNS",     "odat; sid brute; default creds"),
    2049: ("NFS",            "showmount -e <ip>; mount; no_root_squash"),
    2121: ("FTP alt",        "igual que 21"),
    2375: ("Docker API",     "docker -H <ip>:2375; RCE trivial (monta /)"),
    3000: ("HTTP-alt/Node",  "app web; a veces Grafana/Gitea"),
    3268: ("Global Catalog", ">>> AD <<< LDAP GC; nxc ldap"),
    3269: ("GC LDAPS",       "AD - GC sobre ssl"),
    3306: ("MySQL",          "mysql -h <ip> -u root; creds; UDF RCE"),
    3389: ("RDP",            "xfreerdp /u:.. /v:..; NLA; BlueKeep?"),
    4444: ("Metasploit def", "puerto tipico de listener (tuyo o de otro)"),
    5000: ("HTTP/API/Flask", "API REST; gobuster -p pattern {GOBUSTER}/v1"),
    5001: ("HTTP/API-alt",   "API REST; mismo enfoque que 5000"),
    5040: ("Windows RPC",    "servicio interno windows"),
    5432: ("PostgreSQL",     "psql -h <ip> -U postgres; creds; COPY ... PROGRAM RCE"),
    5433: ("PostgreSQL alt", "igual que 5432"),
    5555: ("HP DataProtector/ADB","segun contexto"),
    5601: ("Kibana",         "CVE de RCE conocidos por version"),
    5900: ("VNC",            "vncviewer; sin/con pass; hydra"),
    5985: ("WinRM HTTP",     ">>> evil-winrm -i <ip> -u .. -p .. <<< si eres admin/pwn3d"),
    5986: ("WinRM HTTPS",    "evil-winrm -S; kerberos"),
    6379: ("Redis",          "redis-cli -h <ip>; sin auth; RCE via webroot/SSH key"),
    6443: ("Kubernetes API", "kubectl; anon?"),
    7001: ("WebLogic",       "deserialization RCE; muchos CVE"),
    8000: ("HTTP-alt",       "app web / dev server"),
    8005: ("Tomcat shutdown","suele venir con 8080/8443 tomcat"),
    8009: ("AJP Tomcat",     "Ghostcat CVE-2020-1938 (LFI/RCE)"),
    8080: ("HTTP-alt",       "Tomcat/proxy/Jenkins; /manager; gobuster"),
    8081: ("HTTP-alt",       "Nexus/proxy; segun banner"),
    8443: ("HTTPS-alt",      "app web mgmt (ManageEngine, Tomcat, VMware...) whatweb -k"),
    8888: ("HTTP-alt",       "Jupyter? app web"),
    9000: ("HTTP/PHP-FPM/SonarQube","segun banner; PHP-FPM RCE"),
    9090: ("HTTP-alt/Cockpit","panel web; a veces chisel/prometheus"),
    9200: ("Elasticsearch",  "curl <ip>:9200; CVE por version; sin auth"),
    9389: ("AD Web Services", "AD - ADWS (es DC)"),
    10000:("Webmin",         "CVE RCE conocidos por version"),
    11211:("Memcached",      "stats; datos en claro"),
    13326:("MySQL alt",      "ManageEngine mysql interno"),
    15432:("PostgreSQL alt", "PG en puerto no estandar (ManageEngine amdb!); psql -p 15432"),
    27017:("MongoDB",        "mongo <ip>; sin auth; volcar dbs"),
    44444:("ManageEngine",   "puerto interno de ManageEngine AppManager"),
    47001:("WinRM (WSMan)",  "servicio HTTP de winrm"),
}

def is_dc(found):
    return any(p in found for p in (88, 389, 636, 3268, 5722, 9389))

def main():
    # junta stdin + args de fichero/puertos
    data = ""
    args = sys.argv[1:]
    files, direct = [], []
    for a in args:
        if a.isdigit():
            direct.append(int(a))
        else:
            files.append(a)
    for f in files:
        try:
            with open(f) as fh:
                data += fh.read()
        except Exception as e:
            print(f"[!] no pude leer {f}: {e}", file=sys.stderr)
    # solo lee stdin si viene por pipe/redireccion (no terminal interactiva)
    if not sys.stdin.isatty():
        try:
            data += sys.stdin.read()
        except Exception:
            pass

    found = set(direct)

    # patrones que capturan puertos en netstat linux/win y nmap
    # captura SOLO el puerto tras el ultimo : de una direccion (addr:port)
    # asi evita los octetos de IPs (192.168.134.95 -> no captura 168/134/95)
    for m in re.finditer(r':(\d{1,5})\b', data):
        p = int(m.group(1))
        if 1 <= p <= 65535:
            found.add(p)
    for m in re.finditer(r'\b(\d{1,5})/(?:tcp|udp)\b', data):  # nmap NNN/tcp
        found.add(int(m.group(1)))

    # filtra ruido: puertos efimeros altos que no estan en el dict
    known = sorted(p for p in found if p in PORTS)
    # unknown: solo >=80 para no ensuciar con PIDs/numeros sueltos de netstat
    unknown = sorted(p for p in found if p not in PORTS and 80 <= p < 49152)

    if not known and not unknown:
        print("No encontre puertos. Pasa netstat/nmap por stdin o puertos como args.")
        return

    if is_dc(set(known)):
        print("="*70)
        print("  >>> DOMAIN CONTROLLER detectado (88/389/636/3268/9389) <<<")
        print("      sudo ntpdate <ip>  |  BloodHound  |  nxc ldap/smb")
        print("="*70)

    print(f"\n{'PUERTO':<8}{'SERVICIO':<22}NOTA")
    print("-"*70)
    for p in known:
        svc, note = PORTS[p]
        print(f"{p:<8}{svc:<22}{note}")

    if unknown:
        print("\n[?] puertos abiertos SIN ficha (mira banner con nc/nmap -sV):")
        print("    " + ", ".join(str(p) for p in unknown))

    print()

if __name__ == "__main__":
    main()
