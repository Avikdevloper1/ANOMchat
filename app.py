# ==============================================================================
# ANOMchat ENTERPRISE - RAILWAY HARDENED BACKEND
# ==============================================================================
from gevent import monkey
monkey.patch_all()

import os
import time
import re
import json
import logging
import requests
import secrets
from functools import wraps
from flask import Flask, render_template, request, jsonify, abort
from flask_socketio import SocketIO, emit, join_room, disconnect

# 1. ENTERPRISE CONFIGURATION
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(64))
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # Max upload 1MB

# Disable default logs to protect IP privacy
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# SOCKET SETUP (Async Gevent for High Performance)
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='gevent', 
    ping_timeout=20, 
    ping_interval=10
)

# ==============================================================================
# 2. SECURITY ENGINE (OWASP & VALIDATION)
# ==============================================================================

class Security:
    # Regex for Whitelisting (Strict Input Validation)
    RE_ID = re.compile(r'^ID-[A-F0-9]{5}$')   # e.g., ID-A1B2C
    RE_ROOM = re.compile(r'^[A-Z0-9_]{5,64}$') # Room IDs
    RE_SAFE_TEXT = re.compile(r'^[\w\-\s\.\?@#$%^&*()!+,:;"\']{1,5000}$') 

    @staticmethod
    def sanitize(text):
        """Removes potential XSS vectors even though React handles it"""
        if not isinstance(text, str): return ""
        return text.replace('<', '&lt;').replace('>', '&gt;')[:5000]

    @staticmethod
    def validate_structure(data, schema):
        """Ensures JSON payload matches expected types"""
        if not isinstance(data, dict): return False
        for key, expected_type in schema.items():
            if key not in data: return False
            if not isinstance(data[key], expected_type): return False
        return True

# Rate Limiter (Token Bucket Algorithm)
# Prevents DoS attacks by limiting requests per IP
LIMITS = {}
def rate_limit(burst=10, rate=1): # 1 request per second, burst of 10
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get IP safely behind Railway Load Balancer
            ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
            now = time.time()
            
            if ip not in LIMITS: LIMITS[ip] = {'tokens': burst, 'last': now}
            
            bucket = LIMITS[ip]
            delta = now - bucket['last']
            bucket['tokens'] = min(burst, bucket['tokens'] + delta * rate)
            bucket['last'] = now
            
            if bucket['tokens'] < 1:
                # Disconnect the socket if spamming
                disconnect()
                return False
                
            bucket['tokens'] -= 1
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ==============================================================================
# 3. VPN ENFORCEMENT & ANONYMITY
# ==============================================================================
VPN_CACHE = {}

def is_secure_vpn():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    
    # 1. Allow Internal Traffic (Railway Health Checks)
    if ip == '127.0.0.1' or ip.startswith('10.'): return True

    # 2. Check Cache
    now = time.time()
    if ip in VPN_CACHE:
        if now - VPN_CACHE[ip]['t'] < 600: return VPN_CACHE[ip]['s']

    # 3. External API Check
    try:
        # Note: This is the only privacy trade-off.
        # We must query an external DB to verify VPN status.
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,hosting,proxy", timeout=2)
        if r.json().get('status') == 'success':
            # Logic: If hosting/proxy is TRUE, then VPN is ACTIVE (Secure)
            is_vpn = r.json().get('hosting') or r.json().get('proxy')
            VPN_CACHE[ip] = {'s': is_vpn, 't': now}
            return is_vpn
    except:
        pass
    
    return False # Fail Closed

# ==============================================================================
# 4. HTTP SECURITY HEADERS
# ==============================================================================
@app.after_request
def apply_headers(response):
    # Professional Headers to block XSS and Clickjacking
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; " # Anti-Clickjacking
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Server'] = 'ANONYMOUS' # Hide Flask version
    return response

# ==============================================================================
# 5. ROUTES & EVENTS
# ==============================================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/vpn_check')
@rate_limit(burst=5, rate=0.2) # Strict limit on API
def vpn_check():
    secure = is_secure_vpn()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    # In production, DO NOT send IP back to client for max anonymity, 
    # but required here for the "lock screen" UI to show the user.
    return jsonify({"secure": secure, "ip": ip})

@socketio.on('join')
@rate_limit(burst=10, rate=1)
def handle_join(data):
    # Validation
    if not Security.validate_structure(data, {'room': str}): return
    # Sanitize Room ID (Prevent long strings/injections)
    room = data['room'].strip()
    if not Security.RE_ROOM.match(room): return
    
    join_room(room)

@socketio.on('friend_req')
@rate_limit(burst=3, rate=0.1) # Max 3 requests per 10 seconds
def handle_req(data):
    # Validation Schema
    if not Security.validate_structure(data, {'target_id': str, 'sender_id': str}): return
    
    target = data['target_id']
    sender = data['sender_id']
    
    # Check formats
    if not Security.RE_ID.match(target) or not Security.RE_ID.match(sender): return
    
    emit('friend_req', data, to=target)

@socketio.on('chat_msg')
@rate_limit(burst=20, rate=5) # Allow chatting fast
def handle_msg(data):
    # Validation
    if not Security.validate_structure(data, {'room': str, 'blob': dict}): return
    
    room = data['room']
    blob = data['blob']
    
    # 1. Validate Room
    if not Security.RE_ROOM.match(room): return
    
    # 2. Sanitize/Validate Blob content
    # Note: We don't decrypt, but we check structure
    if 'sender' not in blob or 'text' not in blob: return
    if len(blob['text']) > 5000: return # Buffer Overflow Protection
    
    # 3. HTML Entity Encode (Defense in Depth against XSS)
    blob['text'] = Security.sanitize(blob['text'])

    emit('chat_msg', blob, to=room)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)