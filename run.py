#!/usr/bin/env python3
import socket
from app import app, socketio

def get_local_ip():
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "localhost"

if __name__ == '__main__':
    local_ip = get_local_ip()
    print("Starting Machinic Encounters Catalog...")
    print(f"QR Code visitors can access at: http://{local_ip}:5000")
    print(f"Dashboard for projection at: http://{local_ip}:5000/dashboard")
    print(f"Network access: http://{local_ip}:5000")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
