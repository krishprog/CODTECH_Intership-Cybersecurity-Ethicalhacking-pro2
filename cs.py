import socket
import requests
from scapy.all import sr1, IP, TCP
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
def scan_ports(target_ip, port_range):
    open_ports = []
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports
def check_software_version(target_url):
    try:
        response = requests.get(target_url, timeout=5, verify=False)
        headers = response.headers
        server_info = headers.get('Server', 'Unknown')
        if "Apache" in server_info:
            print("Apache server detected")
            if "2.4.41" in server_info:
                print("Apache version 2.4.41 detected - check for vulnerabilities")
        elif "nginx" in server_info:
            print("Nginx server detected")
        else:
            print("Unknown server:", server_info)
    except requests.RequestException as e:
        print(f"Error checking software version: {e}")
def check_misconfigurations(target_ip):
    print(f"Scanning for open ports on {target_ip}...")
    open_ports = scan_ports(target_ip, range(1, 1025))  
    if open_ports:
        print(f"Open ports found: {open_ports}")
    else:
        print("No open ports found.")
def main():
    target_ip = '192.168.1.1'  
    target_url = 'https://www.w3schools.com/'  
    print("Starting vulnerability scan...")
    check_misconfigurations(target_ip)
    check_software_version(target_url)
    print("Scan completed.")
if __name__ == "__main__":
    main()
'''
#output
Starting vulnerability scan...
Scanning for open ports on 192.168.1.1...
No open ports found.
Nginx server detected
Scan completed.

'''