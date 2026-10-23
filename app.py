from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
import threading
import requests
import sqlite3
import os
import sys


if getattr(sys, 'frozen', False):
    template_folder = os.path.join(sys._MEIPASS, 'templates')
    app = Flask(__name__, template_folder=template_folder)
else:
    app = Flask(__name__)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

geo_cache = {}
THREAT_IPS = {'8.8.8.8', '1.1.1.1', '104.21.51.50'} 
THREAT_COUNTRIES = {'Russia', 'North Korea', 'China'}

def get_device_vendor(mac):
    if not mac: return "Unknown"
    mac = mac.upper()
    if mac.startswith(("00:50:56", "00:0C:29", "00:05:69")): return "VMware"
    if mac.startswith(("F0:9E:63", "28:CF:E9", "00:25:00")): return "Apple"
    if mac.startswith(("00:14:22", "44:A8:42", "18:DB:F2")): return "Dell"
    if mac.startswith(("B8:27:EB", "DC:A6:32", "E4:5F:01")): return "Raspberry Pi"
    if mac.startswith(("00:1A:11", "F8:8A:5E")): return "Google"
    if mac.startswith(("00:24:D7", "18:33:9D", "00:01:42")): return "Cisco"
    if mac.startswith(("FC:AA:14", "B4:F7:A1", "C8:3A:35")): return "Tenda"
    return mac

def setup_database():
    conn = sqlite3.connect('netpulse.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS traffic_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  src TEXT, dst TEXT, protocol TEXT, 
                  city TEXT, country TEXT, is_threat BOOLEAN)''')
    conn.commit()
    conn.close()

def save_to_db(src, dst, protocol, city, country, is_threat):
    try:
        conn = sqlite3.connect('netpulse.db')
        c = conn.cursor()
        c.execute("INSERT INTO traffic_log (src, dst, protocol, city, country, is_threat) VALUES (?, ?, ?, ?, ?, ?)",
                  (src, dst, protocol, city, country, is_threat))
        conn.commit()
        conn.close()
    except Exception as e:
        pass

def get_geo_location(ip):
    if ip.startswith(('192.168.', '10.', '127.', '172.')):
        return None
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response['status'] == 'success':
            geo_data = {
                'lat': response['lat'], 'lon': response['lon'],
                'country': response['country'], 'city': response['city']
            }
            geo_cache[ip] = geo_data 
            return geo_data
    except: pass
    return None

def start_sniffing():
    print("Sniffer Started... (Auto-detecting Network Interface)")
    # --- අලුත්: iface="ens160" අයින් කළා. දැන් ඕනෑම මැෂින් එකක ඔටෝ වැඩ කරනවා ---
    sniff(prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        mac_src, mac_dst = "Unknown", "Unknown"
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
        
        protocol = "Other"
        if packet.haslayer(TCP):
            if packet[TCP].dport == 443 or packet[TCP].sport == 443: protocol = "HTTPS"
            elif packet[TCP].dport == 80 or packet[TCP].sport == 80: protocol = "HTTP"
            else: protocol = "TCP"
        elif packet.haslayer(UDP):
            if packet[UDP].dport == 53 or packet[UDP].sport == 53: protocol = "DNS"
            else: protocol = "UDP"
        elif packet.haslayer(ICMP): protocol = "ICMP"

        geo_info = get_geo_location(dst_ip)
        if not geo_info: geo_info = get_geo_location(src_ip)

        city = geo_info['city'] if geo_info else "Local"
        country = geo_info['country'] if geo_info else "Local"
        
        is_threat = src_ip in THREAT_IPS or dst_ip in THREAT_IPS or country in THREAT_COUNTRIES
        
        save_to_db(src_ip, dst_ip, protocol, city, country, is_threat)

        data = {
            'src': src_ip, 'dst': dst_ip, 'geo': geo_info,
            'proto': protocol, 'is_threat': is_threat,
            'device_src': get_device_vendor(mac_src),
            'device_dst': get_device_vendor(mac_dst)
        }
        socketio.emit('new_packet', data)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    setup_database()
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
