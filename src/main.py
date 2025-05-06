import os
import re
import sys
import time
import wmi
import psutil
import requests
import logging
from typing import List, Dict

file_logger = logging.getLogger('file_logger')
file_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("safeipadress.log", mode='a', encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
file_logger.addHandler(file_handler)

console_logger = logging.getLogger('console_logger')
console_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_logger.addHandler(console_handler)

IGNORED_PORTS = {80, 443, 53, 21, 22, 25, 110, 143, 993, 995, 3306, 3389}

LOCAL_IP = re.compile(
    r'^('
    r'127\.0\.0\.1|'
    r'10\.(?:\d{1,3}\.){2}\d{1,3}|'
    r'192\.168\.(?:\d{1,3}\.)\d{1,3}|'
    r'172\.(1[6-9]|2[0-9]|3[0-1])\.(?:\d{1,3}\.)\d{1,3}|'
    r'172\.17\.(?:\d{1,3}\.)\d{1,3}|'
    r'169\.254\.(?:\d{1,3}\.)\d{1,3}|'
    r'100\.(6[4-9]|7[0-9]|8[0-9]|9[0-9]|1[0-1][0-9]|12[0-7])\.(?:\d{1,3}\.)\d{1,3}|'
    r'192\.0\.2\.(?:\d{1,3})|'
    r'198\.18\.(?:\d{1,3}\.)\d{1,3}|'
    r'198\.51\.100\.(?:\d{1,3})|'
    r'203\.0\.113\.(?:\d{1,3})|'
    r'::1|'
    r'fc[0-9a-fA-F]{2}:'
    r'|fd[0-9a-fA-F]{2}:'
    r'|fe80:'
    r')'
)

def is_ip_in_logs(ip: str) -> bool:
    if not os.path.exists("safeipadress.log"):
        return False
    with open("safeipadress.log", "r", encoding='utf-8') as log_file:
        return any(f"IP: {ip}" in line for line in log_file)

def is_local_ip(ip: str) -> bool:
    return bool(LOCAL_IP.match(ip))

def get_ips() -> List[Dict[str, str]]:
    wmi_obj = wmi.WMI()
    connections = []

    for process in wmi_obj.Win32_Process():
        try:
            if 'anydesk' in process.Name.lower():
                for conn in psutil.Process(process.ProcessId).net_connections():
                    if conn.status in ('SYN_SENT', 'ESTABLISHED') and conn.raddr:
                        ip, port = conn.raddr.ip, conn.raddr.port
                        if port not in IGNORED_PORTS and not is_local_ip(ip):
                            if not any(c['IP'] == ip for c in connections):
                                connections.append({"IP": ip, "Port": str(port)})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return connections

def get_ip_info(ip_data: Dict[str, str]) -> Dict[str, str]:
    ip = ip_data['IP']
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        response.raise_for_status()
        data = response.json()
        return {
            "IP": ip,
            "Port": ip_data['Port'],
            "Country": data.get('country', 'Unknown'),
            "Region": data.get('regionName', 'Unknown'),
            "City": data.get('city', 'Unknown'),
            "ISP": data.get('isp', 'Unknown'),
            "AS": data.get('as', 'Unknown')
        }
    except requests.exceptions.RequestException:
        return {**ip_data,
                "Country": "Unknown",
                "Region": "Unknown",
                "City": "Unknown",
                "ISP": "Unknown",
                "AS": "Unknown"}

def save_connection_info(info: Dict[str, str]) -> None:
    file_logger.info("="*40)
    file_logger.info("Suspicious connection detected!")
    file_logger.info("="*40)
    for key, value in info.items():
        file_logger.info(f'{key:<10}: {value}')
    file_logger.info("="*40)
    file_handler.flush()

def main():
    console_logger.info("Monitoring AnyDesk connections... [CTRL+C to exit]")
    try:
        while True:
            connections = get_ips()

            if connections:
                console_logger.info(f"Found {len(connections)} external connection(s)")
                for conn in connections:
                    if not is_ip_in_logs(conn['IP']):
                        console_logger.info(f"New connection to: {conn['IP']}:{conn['Port']}")
                        ip_info = get_ip_info(conn)
                        save_connection_info(ip_info)
                        console_logger.info("Details saved to log file")
            else:
                console_logger.info("No external connections detected")

            time.sleep(5)

    except KeyboardInterrupt:
        console_logger.info("\nMonitoring stopped")
        sys.exit(0)

if __name__ == '__main__':
    main()
