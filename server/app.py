import os
from flask import Flask
from flask import Flask, jsonify, request
import requests
from extensions import limiter  # ⬅️ import the same limiter

app = Flask(__name__)
PORT = int(os.environ.get("PORT", 5001))
limiter.init_app(app)


@app.route('/')
def home():
    return "Hello, Flask server is running!"

@app.route('/api/ids/intrusion-trigger', methods=['POST'])
def trigger_intrusion():
    data = request.get_json()
    print("Received data:", data)

    # Extract values if present
    src_ip = data.get('src_ip')
    dst_ip = data.get('dst_ip')
    intrusion_type = data.get('intrusion_type')
    timestamp = data.get('timestamp')

    print(f"[RECORD LOGS]: {src_ip} {dst_ip} {intrusion_type} {timestamp}")

    return jsonify({
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'intrusion_type': intrusion_type,
        'timestamp': timestamp
    })

if __name__ == '__main__':
    app.run(debug=True, port=PORT)