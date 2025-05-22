import argparse
import nmap
import pandas as pd
import time
import os
import json
from tqdm import tqdm
from itertools import islice
from datetime import datetime

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
    parser.add_argument('--portscope', required=True, choices=['top100', 'top1000', 'top10000', 'all'], help='Port scope to scan')
    parser.add_argument('--sourceip', required=True, help='Manually specify source IP')
    parser.add_argument('--output', required=True, help='Base name for output files')
    return parser.parse_args()

# --- Protocol Prompt ---

def get_protocol_choice():
    print("Select protocol to scan:")
    print("1) TCP")
    print("2) UDP (warning: very slow and often unreliable)")
    print("3) BOTH (TCP + UDP)")

    choice = input("Enter choice (1/2/3): ").strip()
    if choice == "1":
        return "tcp"
    elif choice == "2":
        confirm = input("UDP can be slow and produce false positives. Proceed? (y/n): ").strip().lower()
        if confirm == 'y':
            return "udp"
        else:
            print("Aborting.")
            exit(1)
    elif choice == "3":
        confirm = input("UDP can slow down the scan significantly. Proceed with BOTH? (y/n): ").strip().lower()
        if confirm == 'y':
            return "both"
        else:
            print("Aborting.")
            exit(1)
    else:
        print("Invalid selection.")
        return get_protocol_choice()

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

def run_scan_batch(hosts, port_scope, protocol, scanned_batches, resume_file, batch_index):
    nm = nmap.PortScanner()
    host_str = ' '.join(hosts)
    port_range = get_port_range(port_scope)
    args = f"-Pn -T4 {port_range} --min-parallelism 10 --max-retries 1"

    scan_flags = '-sS' if protocol == 'tcp' else '-sU'
    if protocol == 'udp':
        args += ' --max-scan-delay 100'

    print(f"\nScanning ({protocol.upper()}): {host_str}")
    try:
        nm.scan(hosts=host_str, arguments=f"{scan_flags} {args}")
    except Exception as e:
        print(f"Scan failed for batch {batch_index} with error: {e}")
        return []

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

    scanned_batches.append(batch_index)
    save_resume_state(resume_file, scanned_batches)
    return results

def save_excel(results, source_ip, batches, filename):
    writer = pd.ExcelWriter(filename, engine='xlsxwriter')
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
    df_summary.to_excel(filename, index=False, engine='xlsxwriter')
    print(f"Compliance summary saved to: {filename}")

def save_html_report(summary_df, source_ip, filename):
    rows = ""
    for _, row in summary_df.iterrows():
        status_class = "pass" if row['Compliance Status'] == 'PASS' else "fail"
        rows += f"""
        <tr class="{status_class}">
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
    args.protocol = get_protocol_choice()

    with open(args.hostfile) as f:
        hosts = [line.strip() for line in f if line.strip()]

    resume_file = f"{args.output}_resume.json"
    scanned_batches = load_resume_state(resume_file)
    all_results = []
    batch_map = {}

    batches = list(chunked_iterable(hosts, 20))
    total_batches = len(batches)

    print(f"\nStarting scan. Resuming from batch {len(scanned_batches) + 1} of {total_batches}")

    with tqdm(total=total_batches, desc="Scanning Batches", initial=len(scanned_batches), unit="batch") as pbar:
        for i, batch in enumerate(batches, 1):
            if i in scanned_batches:
                continue  # Skip already scanned

            batch_map[i] = batch

            try:
                if args.protocol in ['tcp', 'both']:
                    all_results.extend(run_scan_batch(batch, args.portscope, 'tcp', scanned_batches, resume_file, i))
                if args.protocol in ['udp', 'both']:
                    all_results.extend(run_scan_batch(batch, args.portscope, 'udp', scanned_batches, resume_file, i))
            except KeyboardInterrupt:
                print("\nInterrupted. Saving progress.")
                save_resume_state(resume_file, scanned_batches)
                exit(1)

            pbar.update(1)

            choice = input("\nPress ENTER to continue or type 'pause' to pause: ").strip().lower()
            if choice == 'pause':
                print("\nPaused. Press ENTER to resume...")
                input()

    clear_resume_state(resume_file)

    # Output
    scan_excel = f"{args.output}_scan.xlsx"
    save_excel(all_results, args.sourceip, batch_map, scan_excel)

    df_scan = pd.DataFrame(all_results)
    df_summary = analyze_compliance(df_scan)

    compliance_excel = f"{args.output}_compliance.xlsx"
    html_report = f"{args.output}_report.html"
    save_compliance_excel(df_summary, compliance_excel)
    save_html_report(df_summary, args.sourceip, html_report)

    # Summary Stats
    total_hosts = len(df_summary)
    total_pass = (df_summary['Compliance Status'] == 'PASS').sum()
    total_fail = total_hosts - total_pass
    total_open_ports = df_scan[df_scan['Port State'] == 'open'].shape[0]

    print("\n--- Scan Summary ---")
    print(f"Total Hosts Scanned : {total_hosts}")
    print(f"Compliant Hosts     : {total_pass}")
    print(f"Non-Compliant Hosts : {total_fail}")
    print(f"Total Open Ports    : {total_open_ports}")
    print("\nScan and report generation complete.")

if __name__ == "__main__":
    main()
