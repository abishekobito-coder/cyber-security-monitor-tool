"""
===================================================================
Cybersecurity Network Monitoring System
Module: Network Monitor (network_monitor.py)
-------------------------------------------------------------------
Description: Handles hostname resolution, ICMP ping checks,
             response time measurement, and packet loss calculation.
Target OS  : Kali Linux / Linux (Cross-platform compatible)
Python     : 3.x (Standard Libraries Only)
===================================================================
"""

import socket
import subprocess
import platform
import re
import time
from typing import Dict, Tuple, Any

class NetworkMonitor:
    """
    Class responsible for host discovery, IP resolution,
    ping execution, packet loss analysis, and latency measurement.
    """

    def __init__(self, timeout: float = 2.0):
        """
        Initialize the NetworkMonitor with a default timeout setting.
        
        :param timeout: Maximum seconds to wait for network responses.
        """
        self.timeout = timeout

    def resolve_host(self, target: str) -> Tuple[bool, str, str]:
        """
        Resolves a hostname (e.g., google.com) to an IP address (e.g., 142.250.190.46),
        or validates an already provided IP address.

        :param target: Hostname string or IP address input by user.
        :return: Tuple containing (success_bool, ip_address, message).
        """
        target = target.strip()
        if not target:
            return False, "", "Host or IP address cannot be empty."

        try:
            # socket.gethostbyname resolves domain names to IPv4 addresses
            ip_address = socket.gethostbyname(target)
            return True, ip_address, f"Successfully resolved '{target}' to {ip_address}"
        except socket.gaierror:
            # Handles Name or Service not known errors
            return False, target, f"Error: Unable to resolve hostname '{target}'. Invalid host or no network connection."
        except Exception as e:
            return False, target, f"Unexpected DNS resolution error: {str(e)}"

    def extract_domain_ips(self, domain: str) -> Tuple[bool, list, str]:
        """
        Extracts all IP addresses associated with a domain name and returns them
        formatted line by line (separated by \\n).

        :param domain: Hostname or domain name (e.g. google.com).
        :return: Tuple containing (success_bool, ip_list, line_by_line_string).
        """
        domain = domain.strip()
        if not domain:
            return False, [], "Domain name cannot be empty."

        try:
            # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            _, _, ip_list = socket.gethostbyname_ex(domain)
            unique_ips = list(dict.fromkeys(ip_list))
            line_by_line = "\n".join(unique_ips)
            return True, unique_ips, line_by_line
        except socket.gaierror:
            try:
                # Fallback to getaddrinfo for IPv4/IPv6 if gethostbyname_ex fails
                addr_info = socket.getaddrinfo(domain, None)
                ips = list(dict.fromkeys([info[4][0] for info in addr_info if info[4]]))
                line_by_line = "\n".join(ips)
                if ips:
                    return True, ips, line_by_line
                return False, [], f"Error: Unable to resolve domain '{domain}'."
            except Exception:
                return False, [], f"Error: Unable to resolve domain '{domain}'."
        except Exception as e:
            return False, [], f"Unexpected error extracting IP for domain '{domain}': {str(e)}"

    def check_host_status(self, target_ip: str, count: int = 4) -> Dict[str, Any]:
        """
        Sends ICMP ping requests to the target IP address to evaluate host status,
        response time, and packet loss percentage.

        :param target_ip: IP address or hostname to ping.
        :param count: Number of ICMP ping packets to send.
        :return: Dictionary containing status (UP/DOWN), response time, packet loss %.
        """
        result = {
            "target": target_ip,
            "status": "DOWN",
            "response_time_ms": 0.0,
            "packet_loss_pct": 100.0,
            "packets_sent": count,
            "packets_received": 0,
            "error_msg": ""
        }

        # Determine OS specific parameters for the ping command
        system_os = platform.system().lower()
        if system_os == "windows":
            # Windows ping syntax: ping -n <count> -w <timeout_in_ms> <target>
            cmd = ["ping", "-n", str(count), "-w", str(int(self.timeout * 1000)), target_ip]
        else:
            # Linux / Kali Linux ping syntax: ping -c <count> -W <timeout_in_sec> <target>
            cmd = ["ping", "-c", str(count), "-W", str(int(self.timeout)), target_ip]

        try:
            start_clock = time.time()
            # Execute ping command in background via subprocess
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=(count * self.timeout) + 5
            )
            elapsed_time = (time.time() - start_clock) * 1000  # converted to ms

            output = proc.stdout

            # Check if ping returned success indicators
            if proc.returncode == 0 or "TTL=" in output.upper() or "ttl=" in output:
                result["status"] = "UP"

            # 1. Parse Packet Loss Percentage
            # Linux output example: "4 packets transmitted, 4 received, 0% packet loss"
            # Windows output example: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
            loss_match = re.search(r'(\d+)%\s*(?:packet\s*)?loss', output, re.IGNORECASE)
            if loss_match:
                result["packet_loss_pct"] = float(loss_match.group(1))
                received_packets = int(count * (1.0 - (result["packet_loss_pct"] / 100.0)))
                result["packets_received"] = received_packets
            else:
                if result["status"] == "UP":
                    result["packet_loss_pct"] = 0.0
                    result["packets_received"] = count
                else:
                    result["packet_loss_pct"] = 100.0
                    result["packets_received"] = 0

            # 2. Parse Average Response Time (ms)
            # Linux format: rtt min/avg/max/mdev = 24.521/25.100/26.012/0.512 ms
            # Windows format: Average = 24ms
            avg_match = re.search(r'(?:avg|Average)\s*=\s*([0-9.]+)', output, re.IGNORECASE)
            if avg_match:
                result["response_time_ms"] = round(float(avg_match.group(1)), 2)
            elif result["status"] == "UP":
                # Fallback to calculated RTT if regex parse misses specific OS pattern
                result["response_time_ms"] = round(elapsed_time / count, 2)
            else:
                result["response_time_ms"] = 0.0

            # Final verification: If packet loss is 100%, host is DOWN
            if result["packet_loss_pct"] == 100.0:
                result["status"] = "DOWN"

        except subprocess.TimeoutExpired:
            result["status"] = "DOWN"
            result["packet_loss_pct"] = 100.0
            result["error_msg"] = "Ping operation timed out."
        except FileNotFoundError:
            result["error_msg"] = "System 'ping' utility not found."
            result.update(self._fallback_socket_check(target_ip))
        except Exception as e:
            result["error_msg"] = f"Ping error: {str(e)}"

        return result

    def _fallback_socket_check(self, target_ip: str) -> Dict[str, Any]:
        """
        Fallback mechanism using TCP socket ping if ICMP binary is unavailable.
        Checks TCP port 80/443 reachability to determine UP/DOWN status.
        """
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            res = s.connect_ex((target_ip, 80))
            s.close()
            rtt = round((time.time() - start) * 1000, 2)
            if res == 0:
                return {"status": "UP", "response_time_ms": rtt, "packet_loss_pct": 0.0, "packets_sent": 1, "packets_received": 1}
        except Exception:
            pass
        return {"status": "DOWN", "response_time_ms": 0.0, "packet_loss_pct": 100.0, "packets_sent": 1, "packets_received": 0}
