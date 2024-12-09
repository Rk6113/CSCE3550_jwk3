# Precious Nwachokor pcn0031
import os
import json
import time
import base64
from datetime import datetime, timedelta, timezone
import sqlite3
import uuid
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import argon2
from argon2 import PasswordHasher
import jwt


def fetch_encryption_key():
    env_key = os.getenv("NOT_MY_KEY")

    if env_key is None:
        random_key = os.urandom(32)
        encoded_key = base64.urlsafe_b64encode(random_key).decode('utf-8')
        os.environ["NOT_MY_KEY"] = encoded_key

    return base64.urlsafe_b64decode(os.environ["NOT_MY_KEY"])


def store_encrypted_key(key, expiry_time, enc_key):
    cipher = Cipher(algorithms.AES(enc_key), modes.CFB(b'\0' * 16), backend=default_backend())
    encrypted_key = cipher.encryptor().update(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

    insert_query = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    conn.execute(insert_query, (encrypted_key, int(expiry_time.timestamp())))
    conn.commit()


def create_secure_password():
    return str(uuid.uuid4())


class RequestLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_history = {}

    def is_request_allowed(self, ip_address):
        current_time = time.time()
        if ip_address not in self.request_history:
            self.request_history[ip_address] = [current_time]
            return True
        
        self.request_history[ip_address] = [t for t in self.request_history[ip_address] if current_time - t < self.time_window]
        
        if len(self.request_history[ip_address]) < self.max_requests:
            self.request_history[ip_address].append(current_time)
            return True
        return False


request_limiter = RequestLimiter(max_requests=10, time_window=1)


class CustomHTTPHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            self.record_auth_request()

            headers = {"kid": "goodKID"}
            token_data = {
                "user": "username",
                "exp": datetime.now(timezone.utc) + timedelta(hours=1)
            }

            if not request_limiter.is_request_allowed(self.client_address[0]):
                self.send_response(429)
                self.end_headers()
                return

            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_data["exp"] = datetime.now(timezone.utc) - timedelta(hours=1)

            jwt_token = jwt.encode(token_data, private_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(jwt_token, "utf-8"))

        elif parsed_path.path == "/register":
            self.register_user()
        else:
            self.send_response(405)
            self.end_headers()

    def register_user(self):
        content_length = int(self.headers['Content-Length'])
        request_body = self.rfile.read(content_length)
        user_data = json.loads(request_body.decode('utf-8'))

        new_password = create_secure_password()
        hashed_password = ph.hash(new_password)

        self.save_new_user(user_data['username'], hashed_password, user_data.get('email'))

        response_data = {"password": new_password}
        self.send_response(201)
        self.end_headers()
        self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

    def save_new_user(self, username, hashed_password, email=None):
        conn.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, hashed_password, email))
        conn.commit()

    def record_auth_request(self):
        ip_address = self.client_address[0]
        log_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        user_id = 1

        conn.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)", (ip_address, log_time, user_id))
        conn.commit()


conn = sqlite3.connect("totally_not_my_privateKeys.db")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expiry_time = datetime.now(timezone.utc) + timedelta(hours=1)
store_encrypted_key(private_key, expiry_time, fetch_encryption_key())

expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expiry_time = datetime.now(timezone.utc) - timedelta(hours=1)
store_encrypted_key(expired_key, expiry_time, fetch_encryption_key())

app = Flask(__name__)
limiter = Limiter(app)
ph = PasswordHasher()

web_server = HTTPServer(("localhost", 8080), CustomHTTPHandler)
try:
    web_server.serve_forever()
except KeyboardInterrupt:
    pass

web_server.server_close()
