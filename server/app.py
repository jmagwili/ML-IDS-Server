import os
from flask import Flask
from flask import Flask, jsonify, request
import requests
from extensions import limiter, generate_file  # ⬅️ import the same limiter
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)
INPUT_PATH = os.getenv('INPUT_PATH')
OUTPUT_PATH = os.getenv('OUTPUT_PATH')
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
    generate_file(INPUT_PATH, OUTPUT_PATH, intrusion_type)

    return jsonify({
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'intrusion_type': intrusion_type,
        'timestamp': timestamp
    })





if __name__ == '__main__':
    app.run(debug=True, port=PORT)