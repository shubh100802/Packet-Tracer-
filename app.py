from flask import Flask, render_template, jsonify
from scapy.all import sniff
import socket
import datetime

app = Flask(__name__)

def network_monitoring_for_visualization_version(pkt):
    packet_data = []
    time = datetime.datetime.now()

    if pkt.haslayer('TCP'):
        if socket.gethostbyname(socket.gethostname()) == pkt['IP'].dst:
            packet_data.append({
                'time': str(time),
                'type': 'TCP-IN',
                'size': len(pkt['TCP']),
                'src_mac': pkt.src,
                'dst_mac': pkt.dst,
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst
            })
        elif socket.gethostbyname(socket.gethostname()) == pkt['IP'].src:
            packet_data.append({
                'time': str(time),
                'type': 'TCP-OUT',
                'size': len(pkt['TCP']),
                'src_mac': pkt.src,
                'dst_mac': pkt.dst,
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst
            })

    # Similarly handle UDP and ICMP packets

    return packet_data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contribution')
def contribution():
    return render_template('contribution.html')

@app.route('/guidance')
def guidance():
    return render_template('guidance.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/data')
def get_packet_data():
    while True:
        packet_data = sniff(prn=network_monitoring_for_visualization_version, count=10)  # Change count as needed
        formatted_data = []
        for packet in packet_data:
            formatted_data.extend(network_monitoring_for_visualization_version(packet))
        
        print(jsonify(formatted_data))
        return jsonify(formatted_data)

if __name__ == '__main__':
    app.run(debug=True)
