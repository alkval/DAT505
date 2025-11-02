#!/usr/bin/env python3
"""Fake Web Server - DAT505"""

from flask import Flask, request
import argparse

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>DNS Spoofing Demonstration</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        h1 { color: #e74c3c; }
        .info { background: #f0f0f0; padding: 20px; margin: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>DNS Spoofing Successful!</h1>
    <div class="info">
        <p><strong>Your IP:</strong> {client_ip}</p>
        <p><strong>Requested Domain:</strong> {host}</p>
        <p>This page is served by the attacker's web server.</p>
    </div>
    <p>DAT505 Network Security Assignment</p>
</body>
</html>
"""

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    client_ip = request.remote_addr
    host = request.host
    print(f"{client_ip} -> {request.method} {host}{request.path}")
    return HTML_TEMPLATE.format(client_ip=client_ip, host=host)

def main():
    parser = argparse.ArgumentParser(description="Fake Web Server")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port (default: 80)")
    parser.add_argument("-H", "--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    args = parser.parse_args()
    
    print(f"Starting fake web server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()
