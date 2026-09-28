"""
===================================================================
Cybersecurity Network Monitoring System
Module: Main Application Entry Point (main.py)
-------------------------------------------------------------------
Description: Interactive terminal dashboard UI for network monitoring,
             port status checking, and security report generation.
Target OS  : Kali Linux / Linux (Cross-platform compatible)
Python     : 3.x (Standard Libraries Only)
===================================================================
"""

import sys
import os
from datetime import datetime
from network_monitor import NetworkMonitor
from port_scanner import PortScanner
from report_generator import ReportGenerator

def print_header():
    """Prints the application banner."""
    print("====================================================")
    print("            CYBERSECURITY NETWORK MONITOR           ")
    print("====================================================")

def display_menu(current_target: str):
    """Displays the interactive CLI menu options."""
    print("\n----------------------------------------------------")
    print(f" Current Target Host/IP: {current_target if current_target else 'None (Not Set)'}")
    print("----------------------------------------------------")
    print("[1] Check Host (Ping & Latency)")
    print("[2] Check Port Availability")
    print("[3] Full Network Scan")
    print("[4] Generate Security Report (TXT & CSV)")
    print("[5] Change Target Host/IP")
    print("[6] Extract IP Address from Domain (Line-by-Line)")
    print("[7] All-in-One Complete Audit (IP Extract + Ping + Port Scan + Report)")
    print("[8] Exit")
    print("----------------------------------------------------")

def get_target_input(net_monitor: NetworkMonitor) -> tuple[str, str]:
    """Prompts the user for a hostname or IP address and validates/resolves it."""
    while True:
        target_in = input("\nEnter Host/IP (e.g., google.com or 8.8.8.8): ").strip()
        if not target_in:
            print("[!] Host/IP cannot be empty. Please try again.")
            continue

        print(f"[*] Resolving target '{target_in}'...")
        success, ip_addr, msg = net_monitor.resolve_host(target_in)
        if success:
            print(f"[+] {msg}")
            return target_in, ip_addr
        else:
            print(f"[!] {msg}")
            retry = input("Do you want to re-enter host? (y/n): ").strip().lower()
            if retry != 'y':
                return target_in, target_in

def parse_ports_input() -> list[int]:
    """Prompts the user to enter port numbers to check."""
    default_ports = [22, 80, 443]
    print(f"\nEnter ports to check separated by commas (Default: 22, 80, 443)")
    user_input = input("Select ports [Press Enter for default]: ").strip()
    
    if not user_input:
        return default_ports

    ports = []
    for item in user_input.split(','):
        item = item.strip()
        if item.isdigit():
            port_num = int(item)
            if 1 <= port_num <= 65535:
                ports.append(port_num)
            else:
                print(f"[!] Ignoring invalid port number: {port_num}")
        else:
            print(f"[!] Ignoring non-numeric entry: {item}")

    return ports if ports else default_ports

def print_result_dashboard(scan_data: dict):
    """Prints formatted network monitoring result dashboard."""
    print("\n---")
    print("## NETWORK MONITORING RESULT")
    print("----------------------------------------------------")
    print(f"Host            : {scan_data.get('target', 'N/A')}")
    print(f"Primary IP      : {scan_data.get('ip_address', 'N/A')}")
    
    extracted_ips = scan_data.get("extracted_ips", [])
    if extracted_ips:
        print("Extracted IPs   :")
        for ip in extracted_ips:
            print(f"  - {ip}")
            
    print(f"Host Status     : {scan_data.get('host_status', 'DOWN')}")
    print(f"Response Time   : {scan_data.get('response_time_ms', 0.0)} ms")
    print(f"Packet Loss     : {scan_data.get('packet_loss_pct', 100.0)}%")
    
    ports = scan_data.get("ports", {})
    if ports:
        for p, info in sorted(ports.items()):
            print(f"Port {p:<10} : {info['status']}")
    else:
        print("Port Status     : No ports checked")

    print(f"Timestamp       : {scan_data.get('timestamp', 'N/A')}")
    print("----------------------------------------------------")

def main():
    """Main CLI control loop."""
    print_header()

    net_monitor = NetworkMonitor(timeout=2.0)
    port_scanner = PortScanner(timeout=1.5)
    report_gen = ReportGenerator(reports_dir="reports")

    target_host = ""
    target_ip = ""
    latest_scan_data = {}

    # Prompt user for initial host
    target_host, target_ip = get_target_input(net_monitor)

    while True:
        display_menu(target_host)
        try:
            choice = input("Select option: ").strip()

            if choice == "1":
                # Option 1: Check Host
                print(f"\n[*] Checking Host Availability for {target_host} ({target_ip})...")
                ping_res = net_monitor.check_host_status(target_ip, count=4)
                timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

                latest_scan_data = {
                    "target": target_host,
                    "ip_address": target_ip,
                    "host_status": ping_res["status"],
                    "response_time_ms": ping_res["response_time_ms"],
                    "packet_loss_pct": ping_res["packet_loss_pct"],
                    "ports": {},
                    "timestamp": timestamp
                }

                print("\n--- HOST STATUS RESULT ---")
                print(f"Host            : {target_host}")
                print(f"IP Address      : {target_ip}")
                print(f"Host Status     : {ping_res['status']}")
                print(f"Response Time   : {ping_res['response_time_ms']} ms")
                print(f"Packet Loss     : {ping_res['packet_loss_pct']}%")
                print(f"Timestamp       : {timestamp}")
                print("--------------------------")

            elif choice == "2":
                # Option 2: Check Port Availability
                ports_to_check = parse_ports_input()
                print(f"\n[*] Checking TCP ports {ports_to_check} on {target_ip}...")
                port_res = port_scanner.scan_ports(target_ip, ports_to_check)
                timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

                if not latest_scan_data or latest_scan_data.get("target") != target_host:
                    latest_scan_data = {
                        "target": target_host,
                        "ip_address": target_ip,
                        "host_status": "UNKNOWN",
                        "response_time_ms": 0.0,
                        "packet_loss_pct": 0.0,
                        "ports": port_res,
                        "timestamp": timestamp
                    }
                else:
                    latest_scan_data["ports"].update(port_res)
                    latest_scan_data["timestamp"] = timestamp

                print("\n--- PORT STATUS RESULT ---")
                print(f"Target IP       : {target_ip}")
                for p, info in sorted(port_res.items()):
                    print(f"Port {p:<5} ({info['service']}) : {info['status']}")
                print(f"Timestamp       : {timestamp}")
                print("--------------------------")

            elif choice == "3":
                # Option 3: Full Network Scan
                print(f"\n[*] Running Full Network Scan for {target_host} ({target_ip})...")
                print("[*] 1/2 Checking host reachability and latency...")
                ping_res = net_monitor.check_host_status(target_ip, count=4)

                default_ports = [22, 80, 443]
                print(f"[*] 2/2 Checking common ports ({default_ports})...")
                port_res = port_scanner.scan_ports(target_ip, default_ports)

                timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

                latest_scan_data = {
                    "target": target_host,
                    "ip_address": target_ip,
                    "host_status": ping_res["status"],
                    "response_time_ms": ping_res["response_time_ms"],
                    "packet_loss_pct": ping_res["packet_loss_pct"],
                    "ports": port_res,
                    "timestamp": timestamp
                }

                print_result_dashboard(latest_scan_data)

            elif choice == "4":
                # Option 4: Generate Security Report
                if not latest_scan_data:
                    print("\n[!] No scan data available yet. Running a Full Network Scan first...")
                    ping_res = net_monitor.check_host_status(target_ip, count=4)
                    port_res = port_scanner.scan_ports(target_ip, [22, 80, 443])
                    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                    latest_scan_data = {
                        "target": target_host,
                        "ip_address": target_ip,
                        "host_status": ping_res["status"],
                        "response_time_ms": ping_res["response_time_ms"],
                        "packet_loss_pct": ping_res["packet_loss_pct"],
                        "ports": port_res,
                        "timestamp": timestamp
                    }

                print(f"\n[*] Generating security monitoring reports for {target_host}...")
                txt_path = report_gen.export_text_report(latest_scan_data)
                csv_path = report_gen.export_csv_report(latest_scan_data)

                print(f"[+] Text Report saved: {txt_path}")
                print(f"[+] CSV Log updated  : {csv_path}")
                print("----------------------------------------------------")
                print("SECURITY OBSERVATION SUMMARY:")
                print(report_gen.generate_observation(latest_scan_data))

            elif choice == "5":
                # Option 5: Change Target Host/IP
                target_host, target_ip = get_target_input(net_monitor)
                latest_scan_data = {}

            elif choice == "6":
                # Option 6: Extract IP Address from Domain (Line-by-Line)
                print(f"\n[*] Extracting IP Address for Domain: '{target_host}'...")
                success, ips, line_str = net_monitor.extract_domain_ips(target_host)
                if success:
                    print(f"\n[+] Extracted IP Address(es) for '{target_host}' (Line by Line):")
                    print("----------------------------------------------------")
                    print(line_str)
                    print("----------------------------------------------------")
                    latest_scan_data["target"] = target_host
                    latest_scan_data["extracted_ips"] = ips
                    if ips:
                        target_ip = ips[0]
                        latest_scan_data["ip_address"] = target_ip
                else:
                    print(f"[!] {line_str}")

            elif choice == "7":
                # Option 7: All-in-One Complete Audit (IP Extract + Ping + Port Scan + Report)
                print(f"\n====================================================")
                print(f"       RUNNING ALL-IN-ONE COMPLETE AUDIT           ")
                print(f"====================================================")
                
                # 1. Domain IP Extraction
                print(f"\n[1/4] Extracting IP Address for Domain: '{target_host}'...")
                success, ips, line_str = net_monitor.extract_domain_ips(target_host)
                if success:
                    print(f"[+] Extracted IP Address(es) (Line by Line):")
                    print("----------------------------------------------------")
                    print(line_str)
                    print("----------------------------------------------------")
                    effective_ip = ips[0] if ips else target_ip
                else:
                    print(f"[!] Warning: {line_str}")
                    ips = [target_ip] if target_ip else []
                    effective_ip = target_ip

                # 2. Host Availability Ping Scan
                print(f"\n[2/4] Checking Host Availability & Latency for {effective_ip}...")
                ping_res = net_monitor.check_host_status(effective_ip, count=4)
                
                # 3. Port Availability Check
                default_ports = [22, 80, 443]
                print(f"\n[3/4] Checking Common Ports ({default_ports}) on {effective_ip}...")
                port_res = port_scanner.scan_ports(effective_ip, default_ports)

                timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

                latest_scan_data = {
                    "target": target_host,
                    "ip_address": effective_ip,
                    "extracted_ips": ips,
                    "host_status": ping_res["status"],
                    "response_time_ms": ping_res["response_time_ms"],
                    "packet_loss_pct": ping_res["packet_loss_pct"],
                    "ports": port_res,
                    "timestamp": timestamp
                }

                print_result_dashboard(latest_scan_data)

                # 4. Generate Security Reports
                print(f"\n[4/4] Generating Security Reports...")
                txt_path = report_gen.export_text_report(latest_scan_data)
                csv_path = report_gen.export_csv_report(latest_scan_data)

                print(f"[+] Text Report saved: {txt_path}")
                print(f"[+] CSV Log updated  : {csv_path}")
                print("----------------------------------------------------")
                print("SECURITY OBSERVATION SUMMARY:")
                print(report_gen.generate_observation(latest_scan_data))
                print("====================================================")

            elif choice == "8":
                # Option 8: Exit
                print("\n[+] Exiting Cybersecurity Network Monitor. Goodbye!")
                sys.exit(0)

            else:
                print("\n[!] Invalid option selected. Please enter a number between 1 and 8.")

        except KeyboardInterrupt:
            print("\n\n[!] Operation cancelled by user. Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"\n[!] An error occurred during execution: {str(e)}")

if __name__ == "__main__":
    main()
