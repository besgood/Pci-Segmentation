PCI Segmentation Scanner
=========================

This tool performs PCI segmentation testing and generates compliance reports in Excel and HTML formats.

Requirements:
-------------
- Python 3.x
- `nmap` and the `python-nmap` module (for Nmap scanning)
- `masscan` installed and in system path (for Masscan scanning)
- `pandas`, `openpyxl`, `tqdm`

Install required Python packages:

    pip install nmap pandas openpyxl tqdm

Usage:
------

    python pci_scan.py --hostfile targets.txt --sourceip 192.168.1.10 --output pci_results [OPTIONS]

Required Arguments:
-------------------
--hostfile       : Path to a file with one target IP per line
--sourceip       : Source IP used during the scan
--output         : Base name for output files

Scanner Selection:
------------------
--scanner        : Choose `nmap` (default) or `masscan`

Scan Port Selection:
--------------------
--portscope      : Use with Nmap to define scope (`top100`, `top1000`, `top10000`, `all`)
--best-practice  : Ignores `--portscope` and scans a curated list of PCI-relevant ports

Protocol Options (only applies to Nmap):
----------------------------------------
--protocol       : `tcp`, `udp`, or `both`

Examples:
---------
Scan using Nmap with best practice ports:

    python pci_scan.py --hostfile targets.txt --sourceip 192.168.1.10 --output pci_results --scanner nmap --best-practice --protocol tcp

Scan using Masscan with best practice ports:

    python pci_scan.py --hostfile targets.txt --sourceip 192.168.1.10 --output pci_results --scanner masscan --best-practice

Resume a previous interrupted scan:

    Simply run the same command again; progress is automatically saved and resumed.

Outputs:
--------
- Excel file with full scan results
- Excel file with PASS/FAIL compliance summary
- HTML report for visual review

