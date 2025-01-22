from flask import Flask, request, jsonify
import threading
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def home():
    return 'Test Server'

@app.route('/admin_<path>')
def admin(path):
    return ('', 403)

@app.route('/api/<path>')
def api(path):
    return jsonify({"path": path})

@app.route('/auth', methods=['POST'])
@app.route('/auth/<path:sub>', methods=['POST'])
def auth(sub=None):
    data = request.get_json()
    app.logger.info(f"Auth attempt on subpath='{sub}' with data: {data}")
    if data and data.get('username') == 'admin' and data.get('password') == '123':
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "failed"}), 401

@app.route('/protected')
def protected():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return jsonify({"status": "authorized"}), 200
    return jsonify({"status": "unauthorized"}), 401

def run_test_server():
    app.run(port=5000)