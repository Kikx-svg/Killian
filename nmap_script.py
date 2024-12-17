import nmap

def scan_network(network_range):
    nm = nmap.PortScanner()
    print(f"Scanning network {network_range}...")
    
    # Scanner les machines et les ports ouverts (port range 1-1024 pour gagner en temps)
    nm.scan(hosts=network_range, arguments='-p 1-1024')  # Scanner les ports communs
    
    devices = []
    
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f'Host : {host} ({nm[host].hostname()})')
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                devices.append({
                    'ip': host,
                    'hostname': nm[host].hostname(),
                    'ports': list(ports)
                })
    return devices

# Exemple d'utilisation
network_range = '192.168.1.0/24'  # Remplace par ton propre range réseau si nécessaire
scan_results = scan_network(network_range)
print(scan_results)
