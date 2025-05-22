
# PCI Segmentation Scan Tool

This tool performs a network segmentation scan to validate PCI compliance, checking for open ports on target systems.

---

## Requirements

### 1. Install Python Packages

```bash
pip install nmap pandas xlsxwriter tqdm
```

### 2. Install Nmap

- **Linux (Debian/Ubuntu):** `sudo apt install nmap`
- **macOS:** `brew install nmap`
- **Windows:** [https://nmap.org/download.html](https://nmap.org/download.html)

---

## How to Use

### Step 1: Prepare a list of target IPs

Create a file `targets.txt` with one IP address per line.

```
192.168.1.10
192.168.1.20
```

### Step 2: Run the Scanner

```bash
python pci_segmentation_scan.py --hostfile targets.txt --portscope top100 --sourceip 192.168.1.1 --output scanresults
```

You will be prompted to select TCP, UDP, or both, and confirm if you want to proceed with slower UDP scans.

### Options

- `--hostfile`: File containing list of target IPs
- `--portscope`: `top100`, `top1000`, `top10000`, `all`
- `--sourceip`: IP of the scanning machine
- `--output`: Prefix name for output files

---

## Output

- `scanresults_scan.xlsx`: Full scan result
- `scanresults_compliance.xlsx`: Summary of compliance (PASS/FAIL)
- `scanresults_report.html`: Color-coded HTML report

---

## Notes

- UDP scans are significantly slower and less reliable. Proceed only if necessary.
- The script supports resuming interrupted scans.
