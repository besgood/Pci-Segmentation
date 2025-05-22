import argparse
import nmap
import pandas as pd
import time
import os
import json
import subprocess
from tqdm import tqdm
from itertools import islice
from datetime import datetime

BEST_PRACTICE_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 443, 445,
                       1433, 1521, 3306, 3389, 5432, 5900]

# --- Resume Utilities ---

def save_resume_state(file, scanned_batches):
    with open(file, 'w') as f:
        json.dump(scanned_batches, f)

def load_resume_state(file):
    if os.path.exists(file):
        with open(file, 'r') as f:
            return json.load(f)
    return []

def clear_resume_state(file):
    if os.path.exists(file):
        os.remove(file)

# --- Argument Parsing ---

def parse_args():
    parser = argparse.ArgumentParser(description="PCI Segmentation Test and Compliance Report Generator")
    parser.add_argument('--hostfile', required=True, help='Path to file with target IPs')
    parser.add_argument('--portscope', choices=['top100', 'top1000', 'top10000', 'all'], help='Port scope for Nmap scan')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'both'], help='Protocol(s) to scan (only for Nmap)')
    parser.add_argument('--sourceip', required=True, help='Manually specify source IP')
    parser.add_argument('--output', required=True, help='Base name for output files')
    parser.add_argument('--scanner', choices=['nmap', 'masscan'], default='nmap', help='Scanner to use (default: nmap)')
    parser.add_argument('--best-practice', action='store_true', help='Use best practice PCI port list')
    return parser.parse_args()

# --- Helper Functions ---

def chunked_iterable(iterable, size):
    it = iter(iterable)
    return iter(lambda: list(islice(it, size)), [])

def get_port_range(scope):
    return {
        "top100": " --top-ports 100",
        "top1000": "",
        "top10000": " --top-ports 10000",
        "all": " -p-"
    }.get(scope, "")

def format_ports(port_list):
    return ",".join(str(p) for p in port_list)

def run_nmap_batch(hosts, port_scope, protocol, best_practice):
    nm = nmap.PortScanner()
    host_str = ' '.join(hosts)
    ports = format_ports(BEST_PRACTICE_PORTS) if best_practice else None
    port_arg = f"-p {ports}" if ports else get_port_range(port_scope)
    scan_flags = "-sS" if protocol == 'tcp' else "-sU"
    args = f"-Pn -T4 {port_arg} --min-parallelism 10 --max-retries 1"
    if protocol == 'udp':
        args += " --max-scan-delay 100"

    nm.scan(hosts=host_str, arguments=f"{scan_flags} {args}")
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                state = nm[host][proto][port]['state']
                results.append({
                    'IP Address': host,
                    'Protocol': proto.upper(),
                    'Port': port,
                    'Port State': state
                })
    return results

def run_masscan(hosts, output_file, best_practice):
    port_arg = format_ports(BEST_PRACTICE_PORTS) if best_practice else "0-65535"
    results = []
    for host in hosts:
        cmd = [
            "masscan", host,
            "-p", port_arg,
            "--rate", "10000",
            "-oJ", output_file
        ]
        subprocess.run(cmd, capture_output=True)
        with open(output_file) as f:
            data = json.load(f)
            for entry in data:
                results.append({
                    "IP Address": entry['ip'],
                    "Protocol": entry['proto'].upper(),
                    "Port": entry['port'],
                    "Port State": "open"
                })
    return results

def save_excel(results, source_ip, batches, filename):
    writer = pd.ExcelWriter(filename, engine='openpyxl')
    df = pd.DataFrame(results)
    df.sort_values(by=['IP Address', 'Protocol', 'Port'], inplace=True)
    df.to_excel(writer, sheet_name='Scan Results', index=False)
    pd.DataFrame([{'Source IP': source_ip}]).to_excel(writer, sheet_name='Source Info', index=False)
    pd.DataFrame([{'Batch Number': idx, 'Target IP': ip} for idx, subset in batches.items() for ip in subset]).to_excel(writer, sheet_name='Target Batches', index=False)
    writer.close()

def analyze_compliance(df):
    summary = []
    for ip, group in df.groupby('IP Address'):
        open_ports = group[group['Port State'] == 'open']
        summary.append({
            'IP Address': ip,
            'Total Ports Scanned': len(group),
            'Open Ports': len(open_ports),
            'Open Port List': ', '.join(map(str, open_ports['Port'].tolist())),
            'Compliance Status': 'PASS' if open_ports.empty else 'FAIL'
        })
    return pd.DataFrame(summary)

def save_compliance_excel(df_summary, filename):
    df_summary.to_excel(filename, index=False)

def save_html_report(df_summary, source_ip, filename):
    rows = ""
    for _, row in df_summary.iterrows():
        cls = "pass" if row['Compliance Status'] == 'PASS' else "fail"
        rows += f"<tr class='{cls}'><td>{row['IP Address']}</td><td>{row['Total Ports Scanned']}</td><td>{row['Open Ports']}</td><td>{row['Open Port List']}</td><td>{row['Compliance Status']}</td></tr>"
    html = f"""<!DOCTYPE html><html><head><style>
    .pass {{ background-color: #d4edda; }} .fail {{ background-color: #f8d7da; }}
    table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #ccc; padding: 8px; }}
    </style></head><body><h2>PCI Segmentation Compliance Report</h2>
    <p><strong>Source IP:</strong> {source_ip}</p>
    <table><tr><th>IP Address</th><th>Total Ports</th><th>Open Ports</th><th>Open Port List</th><th>Status</th></tr>{rows}</table></body></html>"""
    with open(filename, 'w') as f:
        f.write(html)

# --- Main ---

def main():
    args = parse_args()

    with open(args.hostfile) as f:
        hosts = [line.strip() for line in f if line.strip()]

    if args.scanner == 'nmap' and args.protocol == 'udp':
        confirm = input("WARNING: UDP scans are slow and often unreliable. Continue? [y/N]: ").strip().lower()
        if confirm != 'y':
            print("Aborted.")
            return

    resume_file = f"{args.output}_resume.json"
    scanned_batches = load_resume_state(resume_file)
    all_results = []
    batch_map = {}

    batches = list(chunked_iterable(hosts, 20))
    total_batches = len(batches)

    with tqdm(total=total_batches, desc="Scanning Batches", initial=len(scanned_batches), unit="batch") as pbar:
        for i, batch in enumerate(batches, 1):
            if i in scanned_batches:
                continue
            batch_map[i] = batch

            try:
                if args.scanner == 'nmap':
                    if args.protocol in ['tcp', 'both']:
                        all_results.extend(run_nmap_batch(batch, args.portscope, 'tcp', args.best_practice))
                    if args.protocol in ['udp', 'both']:
                        all_results.extend(run_nmap_batch(batch, args.portscope, 'udp', args.best_practice))
                elif args.scanner == 'masscan':
                    out_file = f"{args.output}_masscan_batch{i}.json"
                    all_results.extend(run_masscan(batch, out_file, args.best_practice))
            except KeyboardInterrupt:
                print("\nInterrupted. Saving progress.")
                save_resume_state(resume_file, scanned_batches)
                exit(1)

            scanned_batches.append(i)
            save_resume_state(resume_file, scanned_batches)
            pbar.update(1)

    clear_resume_state(resume_file)

    scan_excel = f"{args.output}_scan.xlsx"
    save_excel(all_results, args.sourceip, batch_map, scan_excel)

    df_scan = pd.DataFrame(all_results)
    df_summary = analyze_compliance(df_scan)

    save_compliance_excel(df_summary, f"{args.output}_compliance.xlsx")
    save_html_report(df_summary, args.sourceip, f"{args.output}_report.html")
    print("\nScan and reporting complete.")

if __name__ == "__main__":
    main()
