import os
import sys
import wmi
import psutil
import requests
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

IGNORED_PORTS = {80, 443, 53, 21, 22, 25, 110, 143, 993, 995, 3306, 3389}

LOCAL_NETWORKS = {
    '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '127.0.0.1', '::1'
}

def is_local_ip(ip: str) -> bool:
    return any(ip.startswith(network) for network in LOCAL_NETWORKS)

def get_ips() -> List[Dict[str, str]]:
    wmi_obj = wmi.WMI()
    connections = []

    for process in wmi_obj.Win32_Process():
        try:
            if 'anydesk' in process.Name.lower():
                for conn in psutil.Process(process.ProcessId).connections():
                    if conn.status in ('SYN_SENT', 'ESTABLISHED') and conn.raddr.ip:
                        conn_ip = conn.raddr.ip
                        conn_port = conn.raddr.port

                        if (conn_port not in IGNORED_PORTS and 
                            not is_local_ip(conn_ip)):
                            if not any(c['IP'] == conn_ip and c['Port'] == conn_port for c in connections):
                                connections.append({
                                    "IP": conn_ip,
                                    "Port": str(conn_port)
                                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return connections

def get_ip_info(conn_data: Dict[str, str]) -> Dict[str, str]:
    conn_ip = conn_data['IP']
    try:
        response = requests.get(f'http://ip-api.com/json/{conn_ip}', timeout=5)
        response.raise_for_status() 
        data = response.json()
        return {
            "IP": conn_ip,
            "Port": conn_data['Port'],
            "Country": data.get('country', 'Unknown'),
            "Region": data.get('regionName', 'Unknown'),
            "City": data.get('city', 'Unknown'),
            "ISP": data.get('isp', 'Unknown'),
            "AS": data.get('as', 'Unknown')
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to get IP info for {conn_ip}: {e}")
        return {
            "IP": conn_ip,
            "Port": conn_data['Port'],
            "Country": "Unknown",
            "Region": "Unknown",
            "City": "Unknown",
            "ISP": "Unknown",
            "AS": "Unknown"
        }

def try_exit() -> None:
    logging.info("Exiting program...")
    sys.exit(0)

def main() -> None:
    msg = 'Anydesk is turned off or no active external connections detected... [CTRL+C to exit]'

    while True:
        try:
            connections = get_ips()
            logging.info(f"Scanning connections... Found {len(connections)} external connection(s).")

            if connections:
                for conn_data in connections:
                    logging.info("\n" + "="*40)
                    logging.info("SUSPICIOUS CONNECTION DETECTED!")
                    logging.info("="*40)
                    infos = get_ip_info(conn_data)
                    for key, value in infos.items():
                        logging.info(f'{key:<10}: {value}')
                    logging.info("="*40 + "\n")
            else:
                logging.info(msg)

            import time
            time.sleep(5)
                
        except KeyboardInterrupt:
            logging.info('Program finished, exiting...')
            try_exit()

if __name__ == '__main__':
    main()