import tkinter as tk
from tkinter import ttk, messagebox, filedialog  # Ajout de filedialog ici
import nmap
import socket
import subprocess
import os
import shutil
import threading
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Configuration de l'application
class AppConfig:
    VERSION = "1.0.0"  # Version par défaut
    SCANS_DIR = "scans"  # Répertoire pour stocker les rapports de scan
    TARGET_SERVER = "8.8.8.8"  # Cible pour le test de latence

# Fonction pour scanner le réseau
def scanner_reseau(plage_ip):
    nm = nmap.PortScanner()
    print(f"Scan en cours pour la plage : {plage_ip}")
    nm.scan(plage_ip, arguments='-sV')  # Option -sV pour récupérer les services et versions
    
    # Collecte des informations
    scan_data = {}
    for host in nm.all_hosts():
        host_info = {
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "ports": nm[host]['tcp'] if 'tcp' in nm[host] else {}
        }
        scan_data[host] = host_info
    
    # Enregistrer le rapport de scan
    save_scan_report(scan_data)
    return scan_data

# Fonction pour enregistrer le rapport de scan en PDF
def save_scan_report(scan_data):
    if not os.path.exists(AppConfig.SCANS_DIR):
        os.makedirs(AppConfig.SCANS_DIR)
    filename = os.path.join(AppConfig.SCANS_DIR, f"scan_{int(time.time())}.pdf")
    
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFont("Helvetica", 12)
    
    # Ajout d'un logo (remplacez par votre chemin)
    logo_path = "/home/amacaire/MSPR/epsi.png"  # Remplacez par le chemin vers votre logo
    c.drawImage(logo_path, 50, 700, width=200, height=50)  # Ajustez la position et la taille
    
    # En-tête
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Rapport de Scan Réseau")
    c.setFont("Helvetica", 12)
    c.drawString(100, 730, f"Date et Heure : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Création du tableau
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, 710, "Nom d'Hôte")
    c.drawString(200, 710, "Adresse IP")
    c.drawString(350, 710, "Ports Ouverts")
    c.drawString(500, 710, "État")

    c.setFont("Helvetica", 10)
    y = 690

    for host, info in scan_data.items():
        hostname = info['hostname'] if info['hostname'] else "N/A"
        ip = host
        ports_info = []
        if info['ports']:
            for port, port_info in info['ports'].items():
                service = port_info.get('name', 'N/A')
                product = port_info.get('product', 'N/A')
                version = port_info.get('version', 'N/A')
                ports_info.append(f"Port {port}: {service} ({product}, {version})")
            ports_list = ', '.join(ports_info)
        else:
            ports_list = 'Aucun port ouvert trouvé.'
        
        # Ajouter les informations au tableau
        c.drawString(50, y, hostname)
        c.drawString(200, y, ip)
        c.drawString(350, y, ports_list)
        c.drawString(500, y, info['state'])
        y -= 20  # Espacement entre les lignes

    # Pied de page
    c.setFont("Helvetica-Oblique", 10)
    c.drawString(50, 30, "Rapport généré par Seahawks Harvester")
    c.drawString(50, 15, "Tous droits réservés. Contact: info@seahawks.com")

    c.save()
    print(f"Rapport de scan enregistré sous {filename}")

# Fonction pour mesurer la latence
def ping_latency(target):
    try:
        output = subprocess.check_output(["ping", "-c", "4", target])
        latency = sum(float(line.split('time=')[-1].split(' ')[0]) for line in output.decode().splitlines() if 'time=' in line) / 4
        return latency
    except Exception as e:
        return None

# Classe principale de l'application
class Dashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Seahawks Harvester Dashboard")
        self.geometry("800x600")
        self.configure(bg="#f0f0f0")
        
        self.create_widgets()
        
        # Démarrer le thread de mise à jour
        self.update_data_thread = threading.Thread(target=self.update_data, daemon=True)
        self.update_data_thread.start()

    def create_widgets(self):
        # Menu
        self.menu_bar = tk.Menu(self)
        self.config(menu=self.menu_bar)

        self.scan_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Scan", menu=self.scan_menu)
        self.scan_menu.add_command(label="Démarrer un Scan", command=self.start_scan)

        self.report_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Mes Scans", menu=self.report_menu)
        self.report_menu.add_command(label="Afficher les Rapports", command=self.show_reports)

        # Frame pour l'affichage des informations
        self.info_frame = tk.Frame(self, bg="#f0f0f0")
        self.info_frame.pack(pady=10)

        # Adresse IP locale
        self.local_ip_label = tk.Label(self.info_frame, text=f"Adresse IP locale : {self.get_local_ip()}", font=("Helvetica", 14), bg="#f0f0f0")
        self.local_ip_label.pack(pady=5)

        # Nom de la VM
        self.vm_name_label = tk.Label(self.info_frame, text=f"Nom de la VM : {socket.gethostname()}", font=("Helvetica", 14), bg="#f0f0f0")
        self.vm_name_label.pack(pady=5)

        # Latence
        self.latency_label = tk.Label(self.info_frame, text="Latence WAN : N/A ms", font=("Helvetica", 14), bg="#f0f0f0")
        self.latency_label.pack(pady=5)

        # Version de l'application
        self.version_label = tk.Label(self.info_frame, text=f"Version : {AppConfig.VERSION}", font=("Helvetica", 14), bg="#f0f0f0")
        self.version_label.pack(pady=5)

        # Tableau des machines connectées
        self.table_frame = tk.Frame(self)
        self.table_frame.pack(pady=10)

        self.table = ttk.Treeview(self.table_frame, columns=("Hostname", "State", "Ports"), show='headings')
        self.table.heading("Hostname", text="Hostname")
        self.table.heading("State", text="État")
        self.table.heading("Ports", text="Ports Ouverts")
        self.table.pack()

    # Méthode pour démarrer un scan
    def start_scan(self):
        self.table.delete(*self.table.get_children())
        scan_results = scanner_reseau("10.60.153.0/24")  # Adapter selon ton LAN

        for host, info in scan_results.items():
            ports_info = ', '.join(f"Port {port}: {port_info.get('name', 'N/A')} ({port_info.get('product', 'N/A')}, {port_info.get('version', 'N/A')})"
                                   for port, port_info in info['ports'].items())
            self.table.insert("", "end", values=(info['hostname'], info['state'], ports_info))

        self.show_alert("Scan terminé", "Le scan du réseau est terminé et les résultats ont été mis à jour.")

    # Méthode pour afficher les rapports de scan
    def show_reports(self):
        report_window = tk.Toplevel(self)
        report_window.title("Rapports de Scan")
        report_window.geometry("400x300")
        
        reports = os.listdir(AppConfig.SCANS_DIR)
        
        report_listbox = tk.Listbox(report_window)
        for report in reports:
            report_listbox.insert(tk.END, report)
        report_listbox.pack(expand=True, fill=tk.BOTH)

        # Bouton pour ouvrir le rapport sélectionné
        open_button = tk.Button(report_window, text="Ouvrir Rapport", command=lambda: self.open_report(report_listbox.get(tk.ACTIVE)))
        open_button.pack(pady=10)

        # Bouton pour télécharger le rapport sélectionné
        download_button = tk.Button(report_window, text="Télécharger Rapport", command=lambda: self.download_report(report_listbox.get(tk.ACTIVE)))
        download_button.pack(pady=10)

    # Méthode pour ouvrir le rapport PDF sélectionné
    def open_report(self, report_name):
        report_path = os.path.join(AppConfig.SCANS_DIR, report_name)
        if os.path.exists(report_path):
            try:
                subprocess.run(["xdg-open", report_path])  # Ouvre le fichier PDF avec le programme par défaut
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'ouvrir le rapport : {str(e)}")
        else:
            messagebox.showerror("Erreur", "Le rapport n'existe pas.")

    # Méthode pour télécharger le rapport PDF sélectionné
    def download_report(self, report_name):
        report_path = os.path.join(AppConfig.SCANS_DIR, report_name)
        if os.path.exists(report_path):
            download_dir = filedialog.askdirectory(title="Choisir un répertoire de téléchargement")
            if download_dir:
                shutil.copy(report_path, download_dir)
                messagebox.showinfo("Succès", f"Rapport téléchargé avec succès dans {download_dir}.")
        else:
            messagebox.showerror("Erreur", "Le rapport n'existe pas.")

    # Méthode pour obtenir l'adresse IP locale
    def get_local_ip(self):
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)

    # Méthode pour mettre à jour les données (latence)
    def update_data(self):
        while True:
            latency = ping_latency(AppConfig.TARGET_SERVER)
            if latency is not None:
                self.latency_label.config(text=f"Latence WAN : {latency:.2f} ms")
            time.sleep(10)  # Mettre à jour toutes les 10 secondes

    # Méthode pour afficher des alertes
    def show_alert(self, title, message):
        messagebox.showinfo(title, message)

if __name__ == "__main__":
    if not os.path.exists(AppConfig.SCANS_DIR):
        os.makedirs(AppConfig.SCANS_DIR)  # Créer le répertoire des scans si nécessaire
    app = Dashboard()
    app.mainloop()
