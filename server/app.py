import os
from flask import Flask
from flask import Flask, jsonify, request
import requests
from extensions import limiter, generate_file  # ⬅️ import the same limiter
from dotenv import load_dotenv
import os
import requests


load_dotenv()
app = Flask(__name__)
INPUT_PATH = os.getenv('INPUT_PATH')
OUTPUT_PATH = os.getenv('OUTPUT_PATH')
PORT = int(os.environ.get("PORT", 5001))
NODE_SERVER_PORT = int(os.environ.get("NODE_IDS_PORT", 5114))
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
    getConfidence = generate_file(INPUT_PATH, OUTPUT_PATH, intrusion_type, src_ip, dst_ip)
    if getConfidence is not None:
        confidence_value = f"{getConfidence * 100:.0f}"
    else:
        confidence_value = None

    endpoint = f"http://localhost:{NODE_SERVER_PORT}/api/ids"
    intrusionDetails = {
        "origin": src_ip,
        "destination": dst_ip,
        "category": intrusion_type,
        "confidence_level": confidence_value,
    }

    response = requests.post(endpoint, json=intrusionDetails)
    return jsonify(response.json())

    




if __name__ == '__main__':
    app.run(debug=True, port=PORT)