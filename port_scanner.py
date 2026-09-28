"""
===================================================================
Cybersecurity Network Monitoring System
Module: Port Scanner (port_scanner.py)
-------------------------------------------------------------------
Description: Checks availability of TCP network ports on target host
             using socket stream connections.
Target OS  : Kali Linux / Linux (Cross-platform compatible)
Python     : 3.x (Standard Libraries Only)
===================================================================
"""

import socket
from typing import Dict, List, Tuple

class PortScanner:
    """
    Class responsible for checking TCP port accessibility
    and identifying common network services.
    """

    # Common network ports and associated standard service names
    COMMON_SERVICES: Dict[int, str] = {
        21: "FTP (File Transfer Protocol)",
        22: "SSH (Secure Shell)",
        23: "Telnet",
        25: "SMTP (Simple Mail Transfer)",
        53: "DNS (Domain Name System)",
        80: "HTTP (Web Server)",
        110: "POP3 (Post Office Protocol)",
        143: "IMAP (Internet Message Access)",
        443: "HTTPS (Secure Web Server)",
        3306: "MySQL Database",
        5432: "PostgreSQL Database",
        8080: "HTTP-Proxy / Alt Web"
    }

    def __init__(self, timeout: float = 1.5):
        """
        Initialize PortScanner with connection timeout.
        
        :param timeout: Seconds to wait before marking port as CLOSED/FILTERED.
        """
        self.timeout = timeout

    def check_port(self, target_ip: str, port: int) -> Tuple[str, str]:
        """
        Checks if a specific TCP port is OPEN or CLOSED/FILTERED on the target IP.

        :param target_ip: Target host IPv4 address.
        :param port: TCP port number (1-65535).
        :return: Tuple of (status_string, service_description).
        """
        service_name = self.COMMON_SERVICES.get(port, f"Custom Port ({port})")
        
        try:
            # Create AF_INET (IPv4), SOCK_STREAM (TCP) socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # connect_ex returns 0 if connection succeeded (Port is OPEN)
            result = sock.connect_ex((target_ip, port))
            sock.close()

            if result == 0:
                return "OPEN", service_name
            else:
                return "CLOSED/FILTERED", service_name

        except socket.timeout:
            return "CLOSED/FILTERED", service_name
        except socket.error as e:
            return "CLOSED/FILTERED", f"{service_name} (Socket error: {e})"
        except Exception as e:
            return "CLOSED/FILTERED", f"{service_name} (Error: {e})"

    def scan_ports(self, target_ip: str, ports: List[int]) -> Dict[int, Dict[str, str]]:
        """
        Scans a list of specified ports on the target host.

        :param target_ip: Host IP address.
        :param ports: List of integer port numbers.
        :return: Dictionary mapping port number to status and service info.
        """
        results = {}
        for port in ports:
            status, service = self.check_port(target_ip, port)
            results[port] = {
                "status": status,
                "service": service
            }
        return results
