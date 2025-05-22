import argparse
import subprocess
import pandas as pd
import time
import os
import json
from tqdm import tqdm
from itertools import islice
from datetime import datetime
import nmap

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>PCI Segmentation Report</title>
    <style>
        body {{ font-family: Arial; padding: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .pass {{ background-color: #d4edda; }}
        .fail {{ background-color: #f8d7da; }}
    </style>
</head>
<body>
    <h2>PCI Segmentation Compliance Report</h2>
    <p><strong>Source IP:</strong> {source_ip}</p>
    <p><strong>Scanned Hosts:</strong> {host_count}</p>

    <table>
        <tr>
            <th>IP Address</th>
            <th>Total Ports</th>
            <th>Open Ports</th>
            <th>Open Port List</th>
            <th>Status</th>
        </tr>
        {rows}
    </table>
</body>
</html>
"""

# Best-practice port list (TCP only for now)
BEST_PRACTICE_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143,
                       443, 445, 1433, 1521, 3306, 3389, 5432, 5900]

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
    parser.add_argument('--portscope', choices=['top100', 'top1000', 'top10000', 'all'], help='Port scope to scan')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'both'], help='Protocol(s) to scan')
    parser.add_argument('--sourceip', required=True, help='Manually specify source IP')
    parser.add_argument('--output', required=True, help='Base name for output files')
    parser.add_argument('--scanner', choices=['nmap', 'masscan'], default='nmap', help='Scanner to use (default: nmap)')
    parser.add_argument('--best-practice', action='store_true', help='Use PCI best-practice ports')
    return parser.parse_args()

# --- Helpers ---

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

def run_nmap_scan(hosts, port_scope, protocol, best_practice):
    nm = nmap.PortScanner()
    host_str = ' '.join(hosts)
    if best_practice:
        port_str = '-p ' + ','.join(str(p) for p in BEST_PRACTICE_PORTS)
    else:
        port_str = get_port_range(port_scope)

    args = f"-Pn -T4 {port_str} --min-parallelism 10 --max-retries 1"

    results = []
    if protocol in ['tcp', 'both']:
        print(f"\nScanning (TCP): {host_str}")
        nm.scan(hosts=host_str, arguments=f"-sS {args}")
        results += parse_nmap_results(nm)

    if protocol in ['udp', 'both']:
        confirm = input("WARNING: UDP scans are slow and unreliable. Continue? (y/n): ").lower()
        if confirm != 'y':
            return results
        print(f"\nScanning (UDP): {host_str}")
        nm.scan(hosts=host_str, arguments=f"-sU {args} --max-scan-delay 100")
        results += parse_nmap_results(nm)

    return results

def parse_nmap_results(nm):
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                results.append({
                    'IP Address': host,
                    'Protocol': proto.upper(),
                    'Port': port,
                    'Port State': state
                })
    return results

def run_masscan_scan(hosts, output_file, best_practice):
    ports = ','.join(str(p) for p in BEST_PRACTICE_PORTS) if best_practice else '0-65535'
    host_str = ','.join(hosts)
    cmd = [
        'masscan', host_str,
        '-p', ports,
        '--rate', '10000',
        '-oJ', output_file
    ]
    print(f"Running Masscan: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    with open(output_file) as f:
        data = json.load(f)
    results = []
    for entry in data:
        for port in entry['ports']:
            results.append({
                'IP Address': entry['ip'],
                'Protocol': port['proto'].upper(),
                'Port': port['port'],
                'Port State': 'open'
            })
    return results

def save_excel(results, source_ip, batches, filename):
    writer = pd.ExcelWriter(filename, engine='openpyxl')
    df = pd.DataFrame(results)
    df.sort_values(by=['IP Address', 'Protocol', 'Port'], inplace=True)
    df.to_excel(writer, sheet_name='Scan Results', index=False)

    pd.DataFrame([{'Source IP': source_ip}]).to_excel(writer, sheet_name='Source Info', index=False)

    batch_rows = [{'Batch Number': idx, 'Target IP': ip} for idx, subset in batches.items() for ip in subset]
    pd.DataFrame(batch_rows).to_excel(writer, sheet_name='Target Batches', index=False)

    writer.close()
    print(f"Excel scan report saved to: {filename}")

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
    print(f"Compliance summary saved to: {filename}")

def save_html_report(summary_df, source_ip, filename):
    rows = ""
    for _, row in summary_df.iterrows():
        status_class = "pass" if row['Compliance Status'] == 'PASS' else "fail"
        rows += f"""
        <tr class=\"{status_class}\">
            <td>{row['IP Address']}</td>
            <td>{row['Total Ports Scanned']}</td>
            <td>{row['Open Ports']}</td>
            <td>{row['Open Port List']}</td>
            <td>{row['Compliance Status']}</td>
        </tr>
        """
    html = HTML_TEMPLATE.format(source_ip=source_ip, host_count=len(summary_df), rows=rows)
    with open(filename, 'w') as f:
        f.write(html)
    print(f"HTML report saved to: {filename}")

# --- Main ---

def main():
    args = parse_args()

    with open(args.hostfile) as f:
        hosts = [line.strip() for line in f if line.strip()]

    resume_file = f"{args.output}_resume.json"
    scanned_batches = load_resume_state(resume_file)
    all_results = []
    batch_map = {}

    batches = list(chunked_iterable(hosts, 20))
    total_batches = len(batches)

    print(f"\nStarting scan using {args.scanner.upper()}. Resuming from batch {len(scanned_batches) + 1} of {total_batches}")

    with tqdm(total=total_batches, desc="Scanning Batches", initial=len(scanned_batches), unit="batch") as pbar:
        for i, batch in enumerate(batches, 1):
            if i in scanned_batches:
                continue
            batch_map[i] = batch

            try:
                if args.scanner == 'nmap':
                    all_results.extend(run_nmap_scan(batch, args.portscope, args.protocol, args.best_practice))
                elif args.scanner == 'masscan':
                    tmp_file = f"masscan_output_batch{i}.json"
                    all_results.extend(run_masscan_scan(batch, tmp_file, args.best_practice))
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

    compliance_excel = f"{args.output}_compliance.xlsx"
    html_report = f"{args.output}_report.html"
    save_compliance_excel(df_summary, compliance_excel)
    save_html_report(df_summary, args.sourceip, html_report)

    print("\nScan and report generation complete.")

if __name__ == "__main__":
    main()
