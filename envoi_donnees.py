import requests
import json

def send_data_to_server(data, server_url):
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(server_url, data=json.dumps(data), headers=headers)
        if response.status_code == 200:
            print("Data sent successfully.")
        else:
            print(f"Failed to send data: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

# Exemple d'envoi des données collectées
server_url = "http://your-server-address/api/harvester-data"
data = {
    'ip': get_local_ip(),
    'latency': ping_latency("google.com"),
    'scan_results': scan_network('192.168.1.0/24'),
    'version': '1.0'
}
send_data_to_server(data, server_url)
