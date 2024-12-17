import os
import platform

def ping_latency(target):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # Effectuer le ping et récupérer la latence
    command = f"ping {param} 4 {target}"
    response = os.popen(command).read()
    
    # Extraire la latence moyenne
    if "time=" in response:
        latency = response.split("time=")[1].split(" ")[0]
        print(f"Latency to {target}: {latency} ms")
        return latency
    else:
        print("Failed to ping the target.")
        return None

# Exemple d'utilisation
target = 'google.com'
latency = ping_latency(target)
print(f"Latency: {latency} ms")
