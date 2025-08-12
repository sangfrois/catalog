#!/usr/bin/env python3
from app import app, socketio

if __name__ == '__main__':
    print("🤖 Starting Machinic Encounters Catalog...")
    print("📱 QR Code visitors can access at: http://localhost:5000")
    print("📊 Dashboard for projection at: http://localhost:5000/dashboard")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
