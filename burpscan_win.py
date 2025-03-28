import argparse
import xml.etree.ElementTree as ET
from lxml import etree
import subprocess
import requests
import sys
import io
import re
import ipaddress
import os

# ----------------------------
# Argument Parsing
# ----------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "       python burpscan.py <file.nessus>\n"
            "       python burpscan.py <file.xml>\n"
            "       python burpscan.py <file.txt>\n"
            "       python burpscan.py '<IP>'\n"
            "       python burpscan.py '<CIDR>'\n"
            "       python burpscan.py '<URL>'\n"
            "       OR\n"
            "       type <whatever> | python burpscan.py\n"
            "       echo '<whatever>' | python burpscan.py\n\n"
            "This script will selectively run an unauthenticated active scan in Burp Suite.\n"
            "Ensure you visually inspect each input to confirm it can handle a scan without causing issues!\n\n"
            "- Go to Settings -> Suite -> REST API\n"
            "- Select 'Service running'\n"
            "- Purge httpx from Kali and install ProjectDiscovery's version\n"
            "- Install and set up bchecks and any other extensions you prefer."
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "input", 
        nargs="?", 
        help="Path to .nessus/.xml/.txt file OR IP/domain/CIDR/URL OR use stdin"
    )
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable verbose debug output"
    )
    parser.add_argument(
        "--api-key", 
        help="API key (You can add one in Burp Suite settings)"
    )

    return parser.parse_args()

# ----------------------------
# Parsers for Nessus and Nmap
# ----------------------------

def parse_nessus(xml_bytes_io, debug=False):
    root = ET.parse(xml_bytes_io).getroot()
    targets = set()
    for report_host in root.findall(".//ReportHost"):
        ip = report_host.get('name')
        for report_item in report_host.findall(".//ReportItem"):
            port = report_item.get('port')
            protocol = report_item.get('protocol', 'tcp').lower()
            if protocol == "tcp":
                targets.add(f"{ip}:{port}")
    if debug:
        print(f"[DEBUG] Parsed {len(targets)} TCP targets from Nessus")
    return sorted(targets)

def parse_nmap(xml_bytes_io, debug=False):
    root = etree.parse(xml_bytes_io).getroot()
    targets = set()
    for host in root.xpath('//host'):
        addr_elem = host.find('address')
        if addr_elem is None or addr_elem.get('addrtype') != 'ipv4':
            continue
        ip = addr_elem.get('addr')
        ports = host.findall('.//port')
        for port in ports:
            portid = int(port.get('portid'))
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            targets.add(f"{ip}:{portid}")
    if debug:
        print(f"[DEBUG] Parsed {len(targets)} open TCP ports from Nmap")
    return sorted(targets)

# ----------------------------
# XML Cleaner and Format Detection
# ----------------------------

def detect_and_parse_xml(source_stream, debug=False):
    raw_bytes = source_stream.read().lstrip()
    raw_text = raw_bytes.decode('utf-8', errors='ignore')
    cleaned_text = re.sub(r'<\?xml.*?\?>', '', raw_text)
    cleaned_text = re.sub(r'<!DOCTYPE[^>]*>', '', cleaned_text)
    cleaned_text = re.sub(r'<\?xml-stylesheet[^>]*\?>', '', cleaned_text)

    if "<NessusClientData_v2" in cleaned_text:
        match = re.search(r"(<NessusClientData_v2.*?</NessusClientData_v2>)", cleaned_text, re.DOTALL)
        if not match:
            print("❌ Couldn't extract valid .nessus content.")
            sys.exit(1)
        final_text = match.group(1)
        if debug: print("[DEBUG] Detected .nessus format")
    elif "<nmaprun" in cleaned_text:
        match = re.search(r"(<nmaprun.*?</nmaprun>)", cleaned_text, re.DOTALL)
        if not match:
            print("❌ Couldn't extract valid Nmap XML content.")
            sys.exit(1)
        final_text = match.group(1)
        if debug: print("[DEBUG] Detected Nmap .xml format")
    else:
        print("❌ Unknown XML format. Expected .nessus or Nmap .xml")
        sys.exit(1)

    if debug:
        print("[DEBUG] Cleaned XML preview:")
        print(final_text[:300])

    try:
        return parse_nessus(io.BytesIO(final_text.encode('utf-8')), debug) if 'NessusClientData_v2' in final_text \
            else parse_nmap(io.BytesIO(final_text.encode('utf-8')), debug)
    except Exception as e:
        print(f"❌ Failed to parse XML: {e}")
        sys.exit(1)

# ----------------------------
# Scan Pipeline
# ----------------------------

def run_httpx_filter(targets, debug=False):
    if debug:
        print(f"[DEBUG] Running httpx on {len(targets)} targets")
        for t in targets:
            print(f"[httpx input] {t}")
    try:
        process = subprocess.run(
            ["httpx", "-silent"],
            input="\n".join(targets),
            text=True,
            capture_output=True,
            check=True
        )
        output = process.stdout.strip().splitlines()
        if debug:
            print(f"[DEBUG] httpx returned {len(output)} targets:")
            for line in output:
                print(f"[httpx output] {line}")
        return list(dict.fromkeys(output))
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running httpx: {e.stderr}")
        sys.exit(1)

def send_burp_scan(url, api_url, debug=False):
    payload = {
        "urls": [url],
        "protocol_option": "specified"
    }
    try:
        response = requests.post(api_url, json=payload)
        if debug:
            print(f"[DEBUG] Sent to Burp API: {payload}")
            print(f"[DEBUG] Response: {response.status_code} {response.text}")
        if response.status_code == 201:
            print(f"✅ Scan started for {url}")
        else:
            print(f"❌ Failed to scan {url}: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error contacting Burp API: {e}")

def prompt_user(prompt):
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return 'n'

# ----------------------------
# Helper for direct input
# ----------------------------

def is_ip_or_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False

def is_domain(value):
    return re.match(r"^(?!\-)([a-zA-Z0-9\-]{1,63}(?<!\-)\.)+[a-zA-Z]{2,}$", value) is not None

def parse_plain_text_lines(lines, debug=False):
    targets = []
    for target in lines:
        target = target.strip()
        if not target:
            continue
        if re.match(r"^https?://[^\s]+$", target):
            targets.append(target)
        elif re.match(r"^[a-zA-Z0-9\-\.]+:\d+$", target):
            targets.append(target)
        elif is_ip_or_cidr(target):
            net = ipaddress.ip_network(target, strict=False)
            targets.extend([f"{ip}:80" for ip in net.hosts()])
        elif is_domain(target) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            targets.extend([f"{target}:80", f"{target}:443"])
        else:
            print(f"⚠ Skipping unrecognised input: {target}")
    return targets

# ----------------------------
# Main
# ----------------------------

def main():
    args = parse_arguments()
    api_key = args.api_key or ""
    api_url = f"http://localhost:1337/{api_key}/v0.1/scan" if api_key else "http://localhost:1337/v0.1/scan"

    raw_targets = []

    if args.input:
        if os.path.isfile(args.input):
            try:
                with open(args.input, 'rb') as f:
                    header = f.read(2048)
                    f.seek(0)

                    if header.strip().startswith(b"<"):
                        if args.debug:
                            print("[DEBUG] File appears to be XML, attempting to parse")
                        raw_targets = detect_and_parse_xml(f, args.debug)
                    else:
                        if args.debug:
                            print("[DEBUG] File appears to be plain text, parsing line by line")
                        lines = f.read().decode().splitlines()
                        raw_targets = parse_plain_text_lines(lines, args.debug)
            except Exception as e:
                print(f"❌ Failed to open file: {e}")
                sys.exit(1)
        elif is_ip_or_cidr(args.input) or is_domain(args.input):
            if args.debug:
                print(f"[DEBUG] Treating input as direct target: {args.input}")
            if is_ip_or_cidr(args.input):
                net = ipaddress.ip_network(args.input, strict=False)
                raw_targets = [f"{ip}:80" for ip in net.hosts()]
            else:
                raw_targets = [f"{args.input}:80", f"{args.input}:443"]
        elif re.match(r"^https?://[^\s]+$", args.input):
            raw_targets = [args.input]
        else:
            print("❌ Input is neither a valid file nor a recognised target format.")
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("❌ No input file, piped XML, or target provided.")
            sys.exit(1)

        raw_input = sys.stdin.read().strip()
        if not raw_input:
            print("❌ No input received via stdin.")
            sys.exit(1)

        if raw_input.startswith("<"):
            if args.debug:
                print("[DEBUG] Treating stdin as XML")
            raw_targets = detect_and_parse_xml(io.BytesIO(raw_input.encode()), args.debug)
        else:
            if args.debug:
                print(f"[DEBUG] Treating stdin as plain text targets:\n{raw_input}")
            lines = raw_input.splitlines()
            raw_targets = parse_plain_text_lines(lines, args.debug)

    if not raw_targets:
        print("🚫 No valid targets found.")
        sys.exit(1)

    print("🔍 Running httpx to verify live services...")
    httpx_targets = run_httpx_filter(raw_targets, args.debug)

    if not httpx_targets:
        print("🚫 No live HTTP/S services detected.")
        sys.exit(1)

    print(f"\n📋 {len(httpx_targets)} valid targets found.\n")

    selected = []
    for target in httpx_targets:
        choice = prompt_user(f"Scan {target}? [y/N]: ")
        if choice == 'y':
            selected.append(target)

    if not selected:
        print("\n🚫 No targets selected.")
        return

    print()
    for target in selected:
        send_burp_scan(target, api_url, args.debug)

if __name__ == "__main__":
    main()
