#!/usr/bin/env python3
"""
xray - port classifier for nmap output (formato -oN / normal).

Uso:
    xray targeted5
    xray targeted5 --all          # muestra tambien los coherentes en detalle
    xray targeted5 --json out.json
    cat targeted5 | xray -

Idea:
    - Parsea un fichero de salida nmap normal (el de -oN).
    - Clasifica cada puerto abierto en:
        [OK]     conocido y coherente  -> el servicio detectado cuadra con el puerto
        [RARO]   raruno                -> servicio conocido en puerto no estandar,
                                          o puerto alto/efimero, o discrepancia
        [???]    outstanding           -> puerto sin entrada en la base de datos
    - Resume por servicio (web, smb, winrm, rpc...) para leer de un vistazo.
    - No re-vuelca toda la info de nmap; solo el veredicto y por que.

Base de datos: definida abajo (PORTDB / SERVICE_ALIASES). Cubre well-known,
registrados habituales y el kit tipico de pentesting Linux + Windows.
"""

import sys
import re
import json
import argparse

# ---------------------------------------------------------------------------
#  PORT DATABASE
#  port -> (service_family, description, platform)
#  platform: 'nix', 'win', 'both'
#  service_family is the family used later to check what
#  nmap detected. If nmap says 'http' and here it is 'web', it counts as coherent
#  (see SERVICE_ALIASES).
# ---------------------------------------------------------------------------
PORTDB = {
    # --- classic / well-known ---
    7:     ("echo",      "Echo",                                   "both"),
    9:     ("discard",   "Discard / sometimes Wake-on-LAN",          "both"),
    13:    ("daytime",   "Daytime",                                "both"),
    19:    ("chargen",   "Chargen",                                "both"),
    20:    ("ftp-data",  "FTP data",                               "both"),
    21:    ("ftp",       "FTP control",                            "both"),
    22:    ("ssh",       "SSH",                                    "both"),
    23:    ("telnet",    "Telnet",                                 "both"),
    25:    ("smtp",      "SMTP",                                   "both"),
    37:    ("time",      "Time",                                   "both"),
    42:    ("wins",      "WINS (Windows Name Service)",            "win"),
    43:    ("whois",     "WHOIS",                                  "both"),
    49:    ("tacacs",    "TACACS+",                                "both"),
    53:    ("dns",       "DNS",                                    "both"),
    67:    ("dhcp",      "DHCP server",                            "both"),
    68:    ("dhcp",      "DHCP client",                            "both"),
    69:    ("tftp",      "TFTP",                                   "both"),
    70:    ("gopher",    "Gopher",                                 "both"),
    79:    ("finger",    "Finger",                                 "both"),
    80:    ("web",       "HTTP",                                   "both"),
    81:    ("web",       "HTTP alternative",                       "both"),
    88:    ("kerberos",  "Kerberos (KDC) - strong DC signal",    "win"),
    102:   ("s7",        "Siemens S7 / MS Exchange (ISO-TSAP)",    "both"),
    110:   ("pop3",      "POP3",                                   "both"),
    111:   ("rpcbind",   "RPCbind / portmapper (NFS)",             "nix"),
    113:   ("ident",     "Ident",                                  "both"),
    119:   ("nntp",      "NNTP",                                   "both"),
    123:   ("ntp",       "NTP",                                    "both"),
    135:   ("msrpc",     "MSRPC endpoint mapper",                  "win"),
    137:   ("netbios",   "NetBIOS name service",                   "win"),
    138:   ("netbios",   "NetBIOS datagram",                       "win"),
    139:   ("netbios",   "NetBIOS session (SMB over NetBIOS)",     "win"),
    143:   ("imap",      "IMAP",                                   "both"),
    161:   ("snmp",      "SNMP",                                   "both"),
    162:   ("snmp",      "SNMP trap",                              "both"),
    177:   ("xdmcp",     "XDMCP",                                  "nix"),
    179:   ("bgp",       "BGP",                                    "both"),
    194:   ("irc",       "IRC",                                    "both"),
    201:   ("appletalk", "AppleTalk",                              "both"),
    264:   ("bgmp",      "Check Point FW1 / BGMP",                 "both"),
    389:   ("ldap",      "LDAP - DC signal",                     "win"),
    427:   ("slp",       "SLP",                                    "both"),
    443:   ("web-ssl",   "HTTPS",                                  "both"),
    444:   ("snpp",      "SNPP / a veces web custom",              "both"),
    445:   ("smb",       "SMB (microsoft-ds)",                     "win"),
    464:   ("kpasswd",   "Kerberos password change",               "win"),
    465:   ("smtps",     "SMTPS",                                  "both"),
    500:   ("ike",       "IKE / IPsec",                            "both"),
    502:   ("modbus",    "Modbus",                                 "both"),
    512:   ("rexec",     "rexec",                                  "nix"),
    513:   ("rlogin",    "rlogin / rwho",                          "nix"),
    514:   ("rsh",       "RSH / syslog",                           "nix"),
    515:   ("lpd",       "LPD (printing)",                        "both"),
    520:   ("rip",       "RIP",                                    "both"),
    523:   ("db2",       "IBM DB2",                                "both"),
    540:   ("uucp",      "UUCP",                                   "nix"),
    543:   ("klogin",    "Kerberos login",                         "nix"),
    544:   ("kshell",    "Kerberos shell",                         "nix"),
    548:   ("afp",       "AFP (Apple Filing)",                     "both"),
    554:   ("rtsp",      "RTSP",                                   "both"),
    587:   ("submission","SMTP submission",                        "both"),
    593:   ("rpc-http",  "MSRPC over HTTP (ncacn_http)",           "win"),
    623:   ("ipmi",      "IPMI / BMC",                             "both"),
    631:   ("ipp",       "IPP / CUPS",                             "both"),
    636:   ("ldaps",     "LDAPS - DC signal",                    "win"),
    646:   ("ldp",       "LDP (MPLS)",                             "both"),
    777:   ("multiling", "Multiling HTTP",                         "both"),
    789:   ("redlion",   "Red Lion / Crimson",                     "both"),
    873:   ("rsync",     "rsync",                                  "nix"),
    902:   ("vmware",    "VMware ESXi / vCenter agent",            "both"),
    989:   ("ftps-data", "FTPS data",                              "both"),
    990:   ("ftps",      "FTPS control",                           "both"),
    993:   ("imaps",     "IMAPS",                                  "both"),
    995:   ("pop3s",     "POP3S",                                  "both"),
    1080:  ("socks",     "SOCKS proxy",                            "both"),
    1099:  ("rmi",       "Java RMI registry",                      "both"),
    1194:  ("openvpn",   "OpenVPN",                                "both"),
    1214:  ("kazaa",     "Kazaa",                                  "both"),
    1241:  ("nessus",    "Nessus",                                 "both"),
    1311:  ("dell-omsa", "Dell OpenManage",                        "both"),
    1352:  ("lotus",     "Lotus Notes",                            "both"),
    1433:  ("mssql",     "MS SQL Server",                          "win"),
    1434:  ("mssql-udp", "MS SQL monitor (UDP)",                   "win"),
    1521:  ("oracle",    "Oracle DB (TNS)",                        "both"),
    1604:  ("citrix",    "Citrix ICA (UDP)",                       "win"),
    1723:  ("pptp",      "PPTP VPN",                               "both"),
    1741:  ("cacti",     "Cacti / NetXMS",                         "both"),
    1812:  ("radius",    "RADIUS auth",                            "both"),
    1813:  ("radius",    "RADIUS accounting",                      "both"),
    1883:  ("mqtt",      "MQTT",                                   "both"),
    1900:  ("ssdp",      "SSDP / UPnP",                            "both"),
    2000:  ("cisco-sccp","Cisco SCCP",                            "both"),
    2049:  ("nfs",       "NFS",                                    "nix"),
    2082:  ("cpanel",    "cPanel",                                 "both"),
    2083:  ("cpanel",    "cPanel SSL",                             "both"),
    2100:  ("oracle-xdb","Oracle XDB FTP",                        "both"),
    2181:  ("zookeeper", "ZooKeeper",                              "both"),
    2222:  ("ssh-alt",   "SSH alternativo / DirectAdmin",          "both"),
    2375:  ("docker",    "Docker API (no TLS!)",                  "both"),
    2376:  ("docker-tls","Docker API (TLS)",                       "both"),
    2379:  ("etcd",      "etcd cliente",                           "both"),
    2380:  ("etcd",      "etcd peer",                              "both"),
    2404:  ("iec104",    "IEC 60870-5-104",                        "both"),
    2483:  ("oracle",    "Oracle DB (no SSL)",                     "both"),
    2484:  ("oracle",    "Oracle DB (SSL)",                        "both"),
    2601:  ("zebra",     "Quagga/Zebra vty",                       "nix"),
    2604:  ("ospf",      "Quagga OSPF vty",                        "nix"),
    2701:  ("sms",       "SCCM remote control",                    "win"),
    3000:  ("dev-web",   "Grafana / Node / Rails dev web",         "both"),
    3128:  ("squid",     "Squid proxy",                            "both"),
    3260:  ("iscsi",     "iSCSI target",                           "both"),
    3268:  ("gc",        "Global Catalog LDAP - DC",               "win"),
    3269:  ("gc-ssl",    "Global Catalog LDAPS - DC",              "win"),
    3299:  ("saprouter", "SAProuter",                              "both"),
    3306:  ("mysql",     "MySQL / MariaDB",                        "both"),
    3389:  ("rdp",       "RDP (Terminal Services)",                "win"),
    3128:  ("squid",     "Squid proxy",                            "both"),
    3541:  ("voispeed",  "VoiSpeed",                               "both"),
    3632:  ("distcc",    "distcc (historic RCE)",                 "nix"),
    3690:  ("svn",       "Subversion",                             "both"),
    3702:  ("wsd",       "WS-Discovery",                           "win"),
    3749:  ("cimtrak",   "CimTrak",                                "both"),
    4000:  ("dev",       "Dev / ICQ / Remote Anything",            "both"),
    4022:  ("dnox",      "DNOX",                                   "both"),
    4040:  ("spark-ui",  "Spark / ngrok inspector",                "both"),
    4443:  ("web-ssl",   "HTTPS alternative / Pharos",             "both"),
    4444:  ("metasploit","Metasploit default / shell handler",     "both"),
    4445:  ("shell",     "Common shell handler",                    "both"),
    4505:  ("saltstack", "SaltStack publish",                      "both"),
    4506:  ("saltstack", "SaltStack ret (CVE-2020-11651)",         "both"),
    4646:  ("nomad",     "HashiCorp Nomad",                        "both"),
    4711:  ("mcafee",    "McAfee ePO",                             "both"),
    4750:  ("bmc",       "BMC / a veces custom",                   "both"),
    4786:  ("smi",       "Cisco Smart Install",                    "both"),
    4848:  ("glassfish", "GlassFish admin",                        "both"),
    4899:  ("radmin",    "Radmin",                                 "win"),
    5000:  ("dev-web",   "Flask / UPnP / Docker registry / web",   "both"),
    5001:  ("dev-web",   "web alternativo / Slingbox",             "both"),
    5006:  ("web-app",   "custom app",                             "both"),
    5040:  ("win-dcom",  "Windows DCOM/CDPSvc (common on Windows)",     "win"),
    5060:  ("sip",       "SIP",                                    "both"),
    5061:  ("sips",      "SIP TLS",                                "both"),
    5222:  ("xmpp",      "XMPP cliente",                           "both"),
    5269:  ("xmpp",      "XMPP servidor",                          "both"),
    5353:  ("mdns",      "mDNS",                                   "both"),
    5355:  ("llmnr",     "LLMNR",                                  "win"),
    5432:  ("postgres",  "PostgreSQL",                             "both"),
    5555:  ("adb",       "Android ADB / HP data / Freeciv",        "both"),
    5601:  ("kibana",    "Kibana",                                 "both"),
    5666:  ("nrpe",      "Nagios NRPE",                            "nix"),
    5671:  ("amqps",     "AMQP TLS",                               "both"),
    5672:  ("amqp",      "AMQP / RabbitMQ",                        "both"),
    5723:  ("scom",      "System Center Operations Manager",       "win"),
    5800:  ("vnc-http",  "VNC over HTTP",                          "both"),
    5900:  ("vnc",       "VNC",                                    "both"),
    5901:  ("vnc",       "VNC :1",                                 "both"),
    5985:  ("winrm",     "WinRM HTTP (WSMan)",                     "win"),
    5986:  ("winrm-ssl", "WinRM HTTPS (WSMan)",                    "win"),
    6000:  ("x11",       "X11",                                    "nix"),
    6001:  ("x11",       "X11 :1",                                 "nix"),
    6082:  ("varnish",   "Varnish admin",                          "both"),
    6379:  ("redis",     "Redis",                                  "both"),
    6443:  ("kube-api",  "Kubernetes API server",                  "both"),
    6514:  ("syslog-tls","Syslog TLS",                             "both"),
    6566:  ("sane",      "SANE (scanner)",                         "nix"),
    6588:  ("proxy",     "AnalogX proxy",                          "both"),
    6667:  ("irc",       "IRC",                                   "both"),
    6697:  ("irc-ssl",   "IRC TLS",                                "both"),
    7001:  ("weblogic",  "Oracle WebLogic",                        "both"),
    7002:  ("weblogic",  "WebLogic SSL",                           "both"),
    7070:  ("realserver","RealServer / web alt",                   "both"),
    7077:  ("spark",     "Spark master",                           "both"),
    7080:  ("web-alt",   "web alternativo (LiteSpeed)",            "both"),
    7443:  ("web-ssl",   "HTTPS alternative",                      "both"),
    7474:  ("neo4j",     "Neo4j HTTP",                             "both"),
    7687:  ("neo4j-bolt","Neo4j Bolt",                             "both"),
    7777:  ("web-alt",   "web/app alternative",                    "both"),
    8000:  ("web-alt",   "HTTP alternative (dev)",                 "both"),
    8008:  ("web-alt",   "HTTP alternative",                       "both"),
    8009:  ("ajp",       "Apache JServ (Ghostcat CVE-2020-1938)",  "both"),
    8010:  ("web-alt",   "web alternative",                        "both"),
    8080:  ("web-proxy", "HTTP proxy / Tomcat / web app",          "both"),
    8081:  ("web-alt",   "web alt / SonarQube",                    "both"),
    8083:  ("web-alt",   "web alt / InfluxDB / vestacp",           "both"),
    8086:  ("influxdb",  "InfluxDB",                               "both"),
    8088:  ("web-alt",   "web alt / Hadoop",                       "both"),
    8089:  ("splunkd",   "Splunk daemon",                          "both"),
    8090:  ("web-alt",   "Confluence / web alt",                   "both"),
    8140:  ("puppet",    "Puppet master",                          "both"),
    8161:  ("activemq",  "ActiveMQ web console",                   "both"),
    8180:  ("web-alt",   "web alternative",                        "both"),
    8222:  ("vmware-vc", "VMware VAMI",                            "both"),
    8291:  ("mikrotik",  "MikroTik Winbox",                        "both"),
    8333:  ("bitcoin",   "Bitcoin",                                "both"),
    8383:  ("web-ssl",   "web SSL alt",                            "both"),
    8443:  ("web-ssl",   "HTTPS alt / Tomcat / Plesk",             "both"),
    8500:  ("consul",    "HashiCorp Consul",                       "both"),
    8530:  ("wsus",      "WSUS HTTP",                              "win"),
    8531:  ("wsus-ssl",  "WSUS HTTPS",                             "win"),
    8600:  ("consul-dns","Consul DNS",                             "both"),
    8649:  ("ganglia",   "Ganglia",                                "nix"),
    8686:  ("jmx",       "JMX / Java management",                  "both"),
    8880:  ("web-alt",   "web alt / WebSphere",                    "both"),
    8888:  ("web-alt",   "web alt / Jupyter / GNS3",               "both"),
    8983:  ("solr",      "Apache Solr",                            "both"),
    9000:  ("web-app",   "PHP-FPM / SonarQube / Portainer / web",  "both"),
    9001:  ("tor",       "Tor / Supervisor / web",                 "both"),
    9042:  ("cassandra", "Cassandra CQL",                          "both"),
    9060:  ("websphere", "WebSphere admin",                        "both"),
    9080:  ("web-alt",   "WebSphere / web alt",                    "both"),
    9090:  ("web-admin", "Cockpit / Prometheus / openshift / web", "both"),
    9091:  ("web-alt",   "web alt / transmission",                 "both"),
    9092:  ("kafka",     "Apache Kafka",                           "both"),
    9100:  ("jetdirect", "Printer JetDirect / raw",                "both"),
    9200:  ("elastic",   "Elasticsearch",                          "both"),
    9300:  ("elastic",   "Elasticsearch transport",                "both"),
    9389:  ("adws",      "AD Web Services (ADWS) - DC",            "win"),
    9443:  ("web-ssl",   "HTTPS alt / admin",                      "both"),
    9990:  ("wildfly",   "WildFly/JBoss mgmt",                     "both"),
    9999:  ("web-alt",   "web/app alt / abyss",                    "both"),
    10000: ("webmin",    "Webmin / NDMP",                          "both"),
    10250: ("kubelet",   "Kubelet API",                            "both"),
    10443: ("web-ssl",   "web SSL alt",                            "both"),
    11211: ("memcached", "Memcached",                              "both"),
    27017: ("mongodb",   "MongoDB",                                "both"),
    27018: ("mongodb",   "MongoDB shard",                          "both"),
    28017: ("mongodb-web","MongoDB status web",                    "both"),
    47001: ("winrm-http","WinRM listener via http.sys (WSMan)",        "win"),
    49152: ("msrpc-dyn", "MSRPC dynamic (Windows ephemeral)",           "win"),
}

# Windows dynamic RPC port range (high ephemeral)
WIN_EPHEMERAL = range(49152, 65536)

# ---------------------------------------------------------------------------
#  ALIASES: how to map what nmap puts in the SERVICE column to our
#  families, to decide if it matches. Key = token nmap prints,
#  value = expected family in PORTDB.
# ---------------------------------------------------------------------------
SERVICE_ALIASES = {
    "http": {"web", "web-alt", "web-proxy", "dev-web", "web-app", "web-admin",
             "winrm", "winrm-http", "ssdp", "webmin", "splunkd"},
    "https": {"web-ssl", "winrm-ssl", "web-alt"},
    "ssl/http": {"web-ssl", "web", "web-alt", "winrm-ssl"},
    "ssl/https": {"web-ssl", "winrm-ssl"},
    "ssl/wsmans": {"winrm-ssl"},
    "wsmans": {"winrm-ssl"},
    "microsoft-ds": {"smb"},
    "netbios-ssn": {"netbios"},
    "netbios-ns": {"netbios"},
    "msrpc": {"msrpc", "msrpc-dyn", "rpc-http"},
    "ms-wbt-server": {"rdp"},
    "ms-sql-s": {"mssql"},
    "ms-sql-m": {"mssql-udp"},
    "domain": {"dns"},
    "kerberos-sec": {"kerberos"},
    "ldap": {"ldap", "gc"},
    "ldapssl": {"ldaps", "gc-ssl"},
    "globalcatLDAP": {"gc"},
    "globalcatLDAPssl": {"gc-ssl"},
    "ftp": {"ftp", "ftps", "ftp-data"},
    "ssh": {"ssh", "ssh-alt"},
    "smtp": {"smtp", "submission", "smtps"},
    "pop3": {"pop3", "pop3s"},
    "imap": {"imap", "imaps"},
    "mysql": {"mysql"},
    "postgresql": {"postgres"},
    "oracle-tns": {"oracle"},
    "vnc": {"vnc", "vnc-http"},
    "snmp": {"snmp"},
    "rpcbind": {"rpcbind"},
    "nfs": {"nfs"},
    "redis": {"redis"},
    "mongodb": {"mongodb"},
    "docker": {"docker", "docker-tls"},
}

# Service families for the human-readable summary.
FAMILY_LABEL = {
    "web": "WEB (HTTP)", "web-ssl": "WEB (HTTPS)", "web-alt": "WEB (alt)",
    "web-proxy": "WEB/proxy", "dev-web": "WEB (dev)", "web-app": "WEB app",
    "web-admin": "WEB admin",
    "smb": "SMB", "netbios": "NetBIOS", "msrpc": "MSRPC", "msrpc-dyn": "MSRPC dyn",
    "rpc-http": "MSRPC/HTTP",
    "winrm": "WinRM", "winrm-ssl": "WinRM (SSL)", "winrm-http": "WinRM (http.sys)",
    "rdp": "RDP", "ldap": "LDAP", "ldaps": "LDAPS", "gc": "GC", "gc-ssl": "GC SSL",
    "kerberos": "Kerberos", "dns": "DNS", "mssql": "MSSQL", "mysql": "MySQL",
    "postgres": "PostgreSQL", "oracle": "Oracle", "ftp": "FTP", "ssh": "SSH",
    "smtp": "SMTP", "snmp": "SNMP", "nfs": "NFS", "rpcbind": "RPCbind",
    "redis": "Redis", "mongodb": "MongoDB", "vnc": "VNC", "ssdp": "SSDP/UPnP",
    "mdns": "mDNS", "llmnr": "LLMNR", "win-dcom": "Win DCOM",
}

# ANSI
class C:
    R = "\033[1;31m"; G = "\033[1;32m"; Y = "\033[1;33m"
    B = "\033[1;34m"; M = "\033[1;35m"; CY = "\033[1;36m"
    GREY = "\033[1;90m"; W = "\033[1;37m"; X = "\033[0m"

def color(s, c, enabled):
    return f"{c}{s}{C.X}" if enabled else s


# ---------------------------------------------------------------------------
#  PARSER de nmap -oN
# ---------------------------------------------------------------------------
PORT_LINE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)$"
)

def parse_nmap(text):
    """Devuelve lista de dicts: port, proto, state, service, version."""
    results = []
    target = None
    for line in text.splitlines():
        m = re.search(r"Nmap scan report for (.+)", line)
        if m:
            target = m.group(1).strip()
            continue
        m = PORT_LINE.match(line.strip())
        if not m:
            continue
        port = int(m.group(1))
        proto = m.group(2)
        state = m.group(3)
        service = m.group(4)
        version = m.group(5).strip()
        if state != "open":
            continue
        results.append({
            "port": port, "proto": proto, "state": state,
            "service": service, "version": version,
        })
    return target, results


# nmap-service -> family map, port-independent. To recognise a
# known service even if it is on a port we have not catalogued.
SERVICE_TO_FAMILY = {
    "ftp": "ftp", "ssh": "ssh", "telnet": "telnet", "smtp": "smtp",
    "domain": "dns", "http": "web", "https": "web-ssl", "ssl/http": "web-ssl",
    "pop3": "pop3", "imap": "imap", "snmp": "snmp", "msrpc": "msrpc",
    "netbios-ssn": "netbios", "microsoft-ds": "smb", "ms-wbt-server": "rdp",
    "ms-sql-s": "mssql", "mysql": "mysql", "postgresql": "postgres",
    "oracle-tns": "oracle", "vnc": "vnc", "redis": "redis", "mongodb": "mongodb",
    "rpcbind": "rpcbind", "nfs": "nfs", "ldap": "ldap", "kerberos-sec": "kerberos",
    "rsync": "rsync", "smb": "smb", "wsmans": "winrm-ssl", "ssl/wsmans": "winrm-ssl",
}

def guess_family_from_service(svc):
    svc = svc.lower().rstrip("?")
    if svc in SERVICE_TO_FAMILY:
        return SERVICE_TO_FAMILY[svc]
    base = svc.split("/")[-1]
    if base in SERVICE_TO_FAMILY:
        return SERVICE_TO_FAMILY[base]
    if "http" in svc:
        return "web-ssl" if "ssl" in svc else "web"
    if "ftp" in svc:
        return "ftp"
    return None


# ---------------------------------------------------------------------------
#  CLASIFICADOR
# ---------------------------------------------------------------------------
def classify(entry):
    """
    Devuelve (categoria, familia, nota).
    categoria: 'ok' | 'raro' | 'unknown'
    """
    port = entry["port"]
    svc = entry["service"].lower()
    known = PORTDB.get(port)

    # 1) Port not in the DB
    if known is None:
        if port in WIN_EPHEMERAL:
            # high Windows ephemeral: normal if it is msrpc
            if "msrpc" in svc or "rpc" in svc:
                return ("ok", "msrpc-dyn", "Windows dynamic RPC port (ephemeral). Expected.")
            return ("suspicious", None,
                    f"High ephemeral port ({port}) serving '{svc}'. "
                    f"Usually this range is msrpc; verify that is what it is.")
        # Port unknown, but is the SERVICE identifiable?
        fam_guess = guess_family_from_service(svc)
        if fam_guess:
            return ("suspicious", fam_guess,
                    f"{FAMILY_LABEL.get(fam_guess, fam_guess)} on a NON-standard port "
                    f"({port}). Service recognised but off its usual port. "
                    f"Typical of hidden apps / services moved on purpose.")
        return ("unknown", None,
                f"Port {port} is not in the database and the service '{svc}' "
                f"is not recognisable either. Investigate manually.")

    fam, desc, plat = known
    # 2) Known port: does the detected service match the expected family?
    expected = SERVICE_ALIASES.get(svc)
    coherent = False
    if expected is not None and fam in expected:
        coherent = True
    else:
        # loose match: service token appears in the family name
        base_svc = svc.split("/")[-1]
        if base_svc and (base_svc in fam or fam in base_svc):
            coherent = True
        # tentative nmap services ending in "?" (microsoft-ds?, wsmans?)
        if svc.endswith("?"):
            base = svc.rstrip("?")
            exp2 = SERVICE_ALIASES.get(base)
            if exp2 and fam in exp2:
                coherent = True

    if coherent:
        return ("ok", fam, desc)

    # 3) Known port but service does NOT match -> genuinely suspicious
    return ("suspicious", fam,
            f"Port {port} is usually {fam} ({desc}), but nmap detected '{svc}'. "
            f"Mismatch: service on an unusual port or a custom app.")


def http_on_nonstandard(entry):
    """Marca webs en puertos no clasicos (utiles para buscar apps escondidas)."""
    svc = entry["service"].lower()
    port = entry["port"]
    is_web = ("http" in svc) or svc in ("ssl/http",)
    classic = port in (80, 443, 8080, 8443)
    return is_web and not classic


# ---------------------------------------------------------------------------
#  RENDER
# ---------------------------------------------------------------------------
def render(target, entries, use_color=True, show_all=False):
    out = []
    p = out.append

    oks, suspicious, unknowns = [], [], []
    for e in entries:
        cat, fam, note = classify(e)
        e["_cat"], e["_fam"], e["_note"] = cat, fam, note
        (oks if cat == "ok" else suspicious if cat == "suspicious" else unknowns).append(e)

    tgt = target or "?"
    p(color(f"\n  xray :: {tgt}", C.CY, use_color))
    p(color(f"  {len(entries)} open ports  "
            f"|  {len(oks)} coherent  "
            f"{len(suspicious)} suspicious  "
            f"{len(unknowns)} uncatalogued\n", C.GREY, use_color))

    # --- Known services summary (one line each) ---
    fam_ports = {}
    for e in oks:
        fam = e["_fam"]
        fam_ports.setdefault(fam, []).append(e["port"])
    if fam_ports:
        p(color("  KNOWN", C.G, use_color))
        for fam, ports in sorted(fam_ports.items(),
                                 key=lambda kv: min(kv[1])):
            label = FAMILY_LABEL.get(fam, fam)
            plist = ",".join(str(x) for x in sorted(ports))
            line = f"    {color(plist, C.W, use_color):<28} {label}"
            p(line)
        p("")

    # --- SUSPICIOUS ---
    if suspicious:
        p(color("  SUSPICIOUS  (service on an unexpected port / mismatch)", C.Y, use_color))
        for e in sorted(suspicious, key=lambda x: x["port"]):
            head = f"    {e['port']}/{e['proto']}  {e['service']}"
            p(color(head, C.Y, use_color))
            p(color(f"        -> {e['_note']}", C.GREY, use_color))
            if e["version"]:
                p(color(f"        version: {e['version']}", C.GREY, use_color))
        p("")

    # --- OUTSTANDING ---
    if unknowns:
        p(color("  OUTSTANDING  (port with no known service in the database)", C.R, use_color))
        for e in sorted(unknowns, key=lambda x: x["port"]):
            head = f"    {e['port']}/{e['proto']}  {e['service']}"
            p(color(head, C.R, use_color))
            p(color(f"        -> {e['_note']}", C.GREY, use_color))
            if e["version"]:
                p(color(f"        version: {e['version']}", C.GREY, use_color))
        p("")

    # --- Extra hint: web on non-standard ports ---
    hidden_web = [e for e in entries if http_on_nonstandard(e)]
    if hidden_web:
        p(color("  WEB ON NON-STANDARD PORTS  (candidates for hidden apps)", C.M, use_color))
        for e in sorted(hidden_web, key=lambda x: x["port"]):
            ver = f"  [{e['version']}]" if e["version"] else ""
            p(color(f"    http(s)://TARGET:{e['port']}/{ver}", C.M, use_color))
        p(color("    (curl -i each one; nmap labels http.sys and IIS/.NET the same as WinRM)", C.GREY, use_color))
        p("")

    # --- Optional full detail ---
    if show_all and oks:
        p(color("  COHERENT DETAIL", C.GREY, use_color))
        for e in sorted(oks, key=lambda x: x["port"]):
            ver = f"  {e['version']}" if e["version"] else ""
            p(color(f"    {e['port']}/{e['proto']}  {e['service']}{ver}", C.GREY, use_color))
        p("")

    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="Classify ports from an nmap output: known vs suspicious vs outstanding.")
    ap.add_argument("file", help="nmap -oN file (or '-' for stdin)")
    ap.add_argument("--all", action="store_true", help="also show detail of coherent ports")
    ap.add_argument("--no-color", action="store_true", help="no ANSI colours")
    ap.add_argument("--json", metavar="OUT", help="dump classification to JSON")
    args = ap.parse_args()

    if args.file == "-":
        text = sys.stdin.read()
    else:
        try:
            with open(args.file, "r", errors="replace") as f:
                text = f.read()
        except FileNotFoundError:
            sys.exit(f"xray: file not found '{args.file}'")

    target, entries = parse_nmap(text)
    if not entries:
        sys.exit("xray: no open ports found in the output. "
                 "Is this an nmap -oN (normal format) file?")

    use_color = sys.stdout.isatty() and not args.no_color
    print(render(target, entries, use_color=use_color, show_all=args.all))

    if args.json:
        for e in entries:
            if "_cat" not in e:
                cat, fam, note = classify(e)
                e["_cat"], e["_fam"], e["_note"] = cat, fam, note
        payload = {
            "target": target,
            "ports": [
                {"port": e["port"], "proto": e["proto"], "service": e["service"],
                 "version": e["version"], "category": e["_cat"],
                 "family": e["_fam"], "note": e["_note"]}
                for e in entries
            ],
        }
        with open(args.json, "w") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON escrito en {args.json}")


if __name__ == "__main__":
    main()
