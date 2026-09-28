"""
===================================================================
Cybersecurity Network Monitoring System
Module: Report Generator (report_generator.py)
-------------------------------------------------------------------
Description: Generates structured security monitoring reports in 
             Text (.txt) and CSV (.csv) formats inside reports/ directory.
Target OS  : Kali Linux / Linux (Cross-platform compatible)
Python     : 3.x (Standard Libraries Only)
===================================================================
"""

import os
import csv
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    """
    Class responsible for generating network security monitoring reports
    in plain text and CSV formats.
    """

    def __init__(self, reports_dir: str = "reports"):
        """
        Initialize report generator and ensure destination directory exists.
        
        :param reports_dir: Folder path where reports will be saved.
        """
        self.reports_dir = reports_dir
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir, exist_ok=True)

    def generate_observation(self, scan_data: Dict[str, Any]) -> str:
        """
        Generates an automated security observation summary based on scan findings.

        :param scan_data: Dictionary containing target status and port results.
        :return: Concise paragraph summarizing network security observation.
        """
        status = scan_data.get("host_status", "DOWN")
        latency = scan_data.get("response_time_ms", 0.0)
        packet_loss = scan_data.get("packet_loss_pct", 100.0)
        ports = scan_data.get("ports", {})

        if status == "DOWN" or packet_loss == 100.0:
            return (
                "CRITICAL OBSERVATION: Target host is UNREACHABLE or DOWN. "
                "Packet loss is 100%. Host may be offline, blocking ICMP ping requests, "
                "or experiencing network isolation."
            )

        open_ports = [f"Port {p} ({info['service']})" for p, info in ports.items() if info["status"] == "OPEN"]
        closed_ports = [f"Port {p}" for p, info in ports.items() if info["status"] != "OPEN"]

        obs = f"Host is UP with latency of {latency} ms and {packet_loss}% packet loss. "
        
        if open_ports:
            obs += f"Reachable open ports/services: {', '.join(open_ports)}. "
        else:
            obs += "No tested ports were OPEN. All queried ports are CLOSED/FILTERED. "

        if packet_loss > 0:
            obs += f"Note: Moderate packet loss ({packet_loss}%) detected; check network congestion or firewall rules."
        else:
            obs += "Network stability appears optimal with 0% packet loss."

        return obs

    def export_text_report(self, scan_data: Dict[str, Any]) -> str:
        """
        Generates a formatted text report file.

        :param scan_data: Dictionary containing target scan results.
        :return: Filepath of created .txt report.
        """
        timestamp_str = scan_data.get("timestamp", datetime.now().strftime("%d-%m-%Y %H:%M:%S"))
        filename_ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        filepath = os.path.join(self.reports_dir, f"network_report_{filename_ts}.txt")

        observation = self.generate_observation(scan_data)

        content = []
        content.append("====================================================")
        content.append("         CYBERSECURITY NETWORK MONITOR REPORT       ")
        content.append("====================================================")
        content.append(f"Target Host     : {scan_data.get('target', 'N/A')}")
        content.append(f"IP Address      : {scan_data.get('ip_address', 'N/A')}")
        
        extracted_ips = scan_data.get("extracted_ips", [])
        if extracted_ips:
            content.append("EXTRACTED IP LIST (Line by Line):")
            for ip in extracted_ips:
                content.append(f"  - {ip}")

        content.append(f"Host Status     : {scan_data.get('host_status', 'DOWN')}")
        content.append(f"Response Time   : {scan_data.get('response_time_ms', 0.0)} ms")
        content.append(f"Packet Loss     : {scan_data.get('packet_loss_pct', 100.0)}%")
        content.append("----------------------------------------------------")
        content.append("PORT STATUS DETAILS:")
        
        ports = scan_data.get("ports", {})
        if ports:
            for port, info in sorted(ports.items()):
                content.append(f"  - Port {port:<5} ({info.get('service', 'Service')}): {info.get('status', 'CLOSED/FILTERED')}")
        else:
            content.append("  - No ports scanned.")

        content.append("----------------------------------------------------")
        content.append(f"Timestamp       : {timestamp_str}")
        content.append("----------------------------------------------------")
        content.append("SECURITY OBSERVATION:")
        content.append(f"{observation}")
        content.append("====================================================\n")

        report_text = "\n".join(content)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_text)

        return filepath

    def export_csv_report(self, scan_data: Dict[str, Any]) -> str:
        """
        Appends scan data to a CSV log file at reports/network_monitor.csv.

        :param scan_data: Dictionary containing target scan results.
        :return: Filepath of the CSV file.
        """
        filepath = os.path.join(self.reports_dir, "network_monitor.csv")
        file_exists = os.path.isfile(filepath)

        ports = scan_data.get("ports", {})
        open_ports_summary = ",".join([str(p) for p, info in ports.items() if info["status"] == "OPEN"]) or "None"

        extracted_ips = scan_data.get("extracted_ips", [])
        extracted_ips_str = "; ".join(extracted_ips) if extracted_ips else scan_data.get("ip_address", "N/A")

        row = {
            "Timestamp": scan_data.get("timestamp", datetime.now().strftime("%d-%m-%Y %H:%M:%S")),
            "Target Host": scan_data.get("target", "N/A"),
            "IP Address": scan_data.get("ip_address", "N/A"),
            "Extracted IPs": extracted_ips_str,
            "Host Status": scan_data.get("host_status", "DOWN"),
            "Response Time (ms)": scan_data.get("response_time_ms", 0.0),
            "Packet Loss (%)": scan_data.get("packet_loss_pct", 100.0),
            "Open Ports": open_ports_summary,
            "Observation": self.generate_observation(scan_data)
        }

        fieldnames = [
            "Timestamp", "Target Host", "IP Address", "Extracted IPs", "Host Status",
            "Response Time (ms)", "Packet Loss (%)", "Open Ports", "Observation"
        ]

        with open(filepath, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

        return filepath
