# ==============================================================================
# ANOMchat v5.0 - RAILWAY PRODUCTION EDITION
# ==============================================================================
from gevent import monkey
monkey.patch_all()

import os
import time
import re
import json
import logging
import secrets
import requests
from functools import wraps
from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO, emit, join_room, disconnect
from werkzeug.middleware.proxy_fix import ProxyFix

# 1. PRODUCTION CONFIGURATION
class Config:
    # Get secret from Railway Env or generate random one
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(64))
    VPN_CACHE_TTL = 300 
    DEBUG = False # Disable debug in production

# Logging configuration
logging.basicConfig(level=logging.ERROR)

app = Flask(__name__)
app.config.from_object(Config)

# Critical for Railway: Fixes IP detection behind Load Balancer
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

socketio = SocketIO(
    app,
    cors_allowed_origins="*", 
    async_mode='gevent',
    ping_timeout=20,
    ping_interval=10
)

# ==============================================================================
# 2. VALIDATION & UTILS
# ==============================================================================
class Validator:
    RE_ETH_ADDR = re.compile(r'^0x[a-fA-F0-9]{40}$')
    RE_HEX_64 = re.compile(r'^[a-fA-F0-9]{64}$')

    @staticmethod
    def is_eth_address(val):
        return bool(val and isinstance(val, str) and Validator.RE_ETH_ADDR.match(val))

    @staticmethod
    def is_room_id(val):
        return bool(val and isinstance(val, str) and Validator.RE_HEX_64.match(val))

    @staticmethod
    def validate_structure(data, schema):
        if not isinstance(data, dict): return False
        for key, expected_type in schema.items():
            if key not in data: return False
            if not isinstance(data[key], expected_type): return False
        return True

class RateLimiter:
    buckets = {}
    @staticmethod
    def check(ip, key, capacity, rate):
        now = time.time()
        b_key = f"{ip}:{key}"
        if b_key not in RateLimiter.buckets:
            RateLimiter.buckets[b_key] = {'tokens': capacity, 'last': now}
        bucket = RateLimiter.buckets[b_key]
        delta = now - bucket['last']
        bucket['tokens'] = min(capacity, bucket['tokens'] + delta * rate)
        bucket['last'] = now
        if bucket['tokens'] >= 1:
            bucket['tokens'] -= 1
            return True
        return False

# ==============================================================================
# 3. SECURITY & VPN LOGIC
# ==============================================================================
VPN_CACHE = {}

def get_ip():
    # Railway passes the real IP in X-Forwarded-For
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

def is_vpn_secure(ip):
    # Bypass for Railway Health Checks or Local Dev
    if ip == '127.0.0.1' or ip.startswith('10.'): return True

    now = time.time()
    if ip in VPN_CACHE and now - VPN_CACHE[ip]['ts'] < Config.VPN_CACHE_TTL:
        return VPN_CACHE[ip]['status']

    try:
        # Check IP Reputation
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,hosting,proxy", timeout=2)
        if r.status_code == 200 and r.json().get('status') == 'success':
            d = r.json()
            is_secure = d.get('hosting') is True or d.get('proxy') is True
            VPN_CACHE[ip] = {'status': is_secure, 'ts': now}
            return is_secure
    except:
        pass
    return False # Default to Block if check fails

def secure_endpoint(limit_type='general', burst=10, rate=0.5):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = get_ip()
            # Optional: Disable VPN check via Env Var for testing
            if os.environ.get('DISABLE_VPN_CHECK') != 'true':
                if not is_vpn_secure(ip):
                    disconnect()
                    return False
            if not RateLimiter.check(ip, limit_type, burst, rate):
                return False
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ==============================================================================
# 4. ROUTES
# ==============================================================================
@app.route('/')
def index():
    return render_template_string(CLIENT_UI)

@app.route('/api/status')
def status():
    ip = get_ip()
    safe = is_vpn_secure(ip)
    # If VPN check disabled via Env
    if os.environ.get('DISABLE_VPN_CHECK') == 'true': safe = True
    return jsonify({"secure": safe, "ip": ip})

@socketio.on('join_network')
@secure_endpoint('auth', 10, 1)
def handle_join(data):
    if Validator.validate_structure(data, {'id': str}) and Validator.is_eth_address(data['id']):
        join_room(data['id'])

@socketio.on('handshake')
@secure_endpoint('handshake', 5, 0.2)
def handle_handshake(data):
    if Validator.validate_structure(data, {'target': str, 'payload': dict}):
        emit('handshake_in', data['payload'], to=data['target'])

@socketio.on('join_chat')
@secure_endpoint('join', 10, 1)
def handle_room(data):
    if Validator.validate_structure(data, {'room': str}) and Validator.is_room_id(data['room']):
        join_room(data['room'])

@socketio.on('secure_msg')
@secure_endpoint('msg', 50, 5)
def handle_msg(data):
    if Validator.validate_structure(data, {'room': str, 'blob': dict}):
        emit('secure_msg', data['blob'], to=data['room'], include_self=False)

# ==============================================================================
# 5. UI
# ==============================================================================
CLIENT_UI = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>ANOM Cloud</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/ethers/5.7.2/ethers.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script src="https://unpkg.com/html5-qrcode" type="text/javascript"></script>
<style>
    :root { --bg: #09090b; --surf: #18181b; --primary: #6366f1; --text: #f4f4f5; --mono: 'JetBrains Mono', monospace; }
    body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; margin: 0; height: 100vh; display: flex; flex-direction: column; }
    .hidden { display: none !important; }
    .view { display: none; flex: 1; flex-direction: column; padding: 20px; max-width: 600px; margin: 0 auto; width: 100%; }
    .view.active { display: flex; }
    .card { background: var(--surf); border: 1px solid #27272a; padding: 20px; border-radius: 12px; margin-bottom: 15px; }
    .btn { background: var(--primary); color: #fff; border: none; padding: 14px; width: 100%; border-radius: 8px; font-weight: 600; cursor: pointer; margin-top: 10px; }
    .input { background: #000; border: 1px solid #3f3f46; color: #fff; padding: 14px; width: 100%; border-radius: 8px; font-family: var(--mono); box-sizing: border-box; }
    #chat-log { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; padding-bottom: 20px; }
    .msg { padding: 10px 15px; border-radius: 12px; max-width: 80%; word-break: break-word; font-size: 0.9rem; }
    .msg.me { align-self: flex-end; background: var(--primary); color: #fff; }
    .msg.them { align-self: flex-start; background: var(--surf); border: 1px solid #3f3f46; }
    #lock-screen { position: fixed; inset: 0; background: var(--bg); z-index: 999; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
</style>
</head>
<body>

<div id="lock-screen" class="hidden">
    <h2 style="color:#ef4444;">Connection Unsecured</h2>
    <p style="color:#a1a1aa;">VPN Required to access this node.</p>
</div>

<div id="v-home" class="view active">
    <div style="text-align: center; margin: 40px 0;">
        <h1>ANOM<span style="color:var(--primary)">//</span>CLOUD</h1>
    </div>
    <div class="card">
        <button class="btn" onclick="Id.gen()">Generate ID</button>
    </div>
</div>

<div id="v-id" class="view">
    <h3>Your Secret Key</h3>
    <div class="card">
        <div id="mnem" style="font-family:var(--mono); color:var(--primary);"></div>
    </div>
    <button class="btn" onclick="Id.login()">Login</button>
</div>

<div id="v-dash" class="view">
    <div class="card" style="text-align:center;">
        <div id="qr" style="background:#fff; padding:10px; display:inline-block; border-radius:6px;"></div>
        <div id="addr" style="font-family:var(--mono); font-size:0.75rem; color:#a1a1aa; margin-top:10px; word-break:break-all;"></div>
    </div>
    <div class="card">
        <input id="peer" class="input" placeholder="Peer Address (0x...)">
        <div style="display:flex; gap:10px;">
            <button class="btn" onclick="Scan.start()">Scan</button>
            <button class="btn" onclick="Chat.req()">Connect</button>
        </div>
    </div>
</div>

<div id="v-chat" class="view">
    <div style="border-bottom:1px solid #333; padding-bottom:10px; margin-bottom:10px; display:flex; justify-content:space-between;">
        <span>Secure Channel</span>
        <button onclick="location.reload()" style="background:none; border:none; color:#ef4444; cursor:pointer;">Exit</button>
    </div>
    <div id="chat-log"></div>
    <div style="display:flex; gap:10px;">
        <input id="msg" class="input" placeholder="Message...">
        <button class="btn" style="width:auto; margin:0;" onclick="Chat.send()">></button>
    </div>
</div>

<div id="scan-modal" class="hidden" style="position:fixed; inset:0; background:#000; z-index:200;">
    <div id="reader" style="width:100%;"></div>
    <button class="btn" onclick="Scan.stop()" style="margin:20px;">Close</button>
</div>

<script>
const Nav = { to: (id) => { document.querySelectorAll('.view').forEach(e=>e.classList.remove('active')); document.getElementById(id).classList.add('active'); }};
const UI = { msg: (t,s) => { const d=document.createElement('div'); d.className=`msg ${s}`; d.textContent=t; const c=document.getElementById('chat-log'); c.appendChild(d); c.scrollTop=c.scrollHeight; }};

setInterval(async ()=>{
    try {
        const r = await fetch('/api/status'); const d=await r.json();
        const l = document.getElementById('lock-screen');
        if(d.secure) l.classList.add('hidden'); else { l.classList.remove('hidden'); Net.sock?.disconnect(); }
    } catch(e){}
}, 5000);

const Crypto = {
    w:null, ecdh:null, aes:null,
    init: async()=> Crypto.ecdh=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-521"},true,["deriveBits"]),
    derive: async(jwk)=>{
        const k=await crypto.subtle.importKey("jwk",jwk,{name:"ECDH",namedCurve:"P-521"},false,[]);
        const b=await crypto.subtle.deriveBits({name:"ECDH",public:k},Crypto.ecdh.privateKey,256);
        Crypto.aes=await crypto.subtle.importKey("raw",b,{name:"AES-GCM"},false,["encrypt","decrypt"]);
    },
    enc: async(t)=>{
        const iv=crypto.getRandomValues(new Uint8Array(12));
        const b=await crypto.subtle.encrypt({name:"AES-GCM",iv},Crypto.aes,new TextEncoder().encode(t));
        return {i:Array.from(iv),d:Array.from(new Uint8Array(b))};
    },
    dec: async(p)=>{
        try { return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(p.i)},Crypto.aes,new Uint8Array(p.d))); } catch(e){return null;}
    }
};

const Id = {
    gen: ()=>{ Crypto.w=ethers.Wallet.createRandom(); document.getElementById('mnem').innerText=Crypto.w.mnemonic.phrase; Nav.to('v-id'); },
    login: async()=>{ await Crypto.init(); document.getElementById('addr').innerText=Crypto.w.address; new QRCode(document.getElementById('qr'),{text:Crypto.w.address,width:150,height:150}); Nav.to('v-dash'); Net.init(); }
};

const Net = {
    sock:null,
    init: ()=>{
        Net.sock=io();
        Net.sock.on('connect',()=>{Net.sock.emit('join_network',{id:Crypto.w.address})});
        Net.sock.on('handshake_in',Chat.handle);
        Net.sock.on('secure_msg',Chat.recv);
    }
};

const Chat = {
    peer:null, room:null,
    req: async()=>{
        const p=document.getElementById('peer').value.trim();
        if(!ethers.utils.isAddress(p)) return alert("Invalid Address");
        Chat.peer=p;
        const k=await crypto.subtle.exportKey("jwk",Crypto.ecdh.publicKey);
        const s=await Crypto.w.signMessage(JSON.stringify(k));
        Net.sock.emit('handshake',{target:p,payload:{s:Crypto.w.address,t:'OFFER',k,sig:s}});
        alert("Request Sent");
    },
    handle: async(d)=>{
        const r=ethers.utils.verifyMessage(JSON.stringify(d.k),d.sig);
        if(r!==d.s) return alert("Sig Fail");
        if(d.t==='OFFER'){
            if(!confirm(`Connect to ${d.s.substring(0,6)}?`)) return;
            Chat.peer=d.s; await Crypto.derive(d.k);
            const k=await crypto.subtle.exportKey("jwk",Crypto.ecdh.publicKey);
            const s=await Crypto.w.signMessage(JSON.stringify(k));
            Net.sock.emit('handshake',{target:d.s,payload:{s:Crypto.w.address,t:'ANSWER',k,sig:s}});
            Chat.ready();
        } else if(d.t==='ANSWER' && d.s===Chat.peer){
            await Crypto.derive(d.k); Chat.ready();
        }
    },
    ready: ()=>{
        const r=[Crypto.w.address,Chat.peer].sort().join('_');
        Chat.room=ethers.utils.sha256(ethers.utils.toUtf8Bytes(r)).substring(2);
        Net.sock.emit('join_chat',{room:Chat.room});
        Nav.to('v-chat');
    },
    send: async()=>{
        const e=document.getElementById('msg'); const t=e.value.trim(); if(!t)return;
        const p=await Crypto.enc(t);
        Net.sock.emit('secure_msg',{room:Chat.room,blob:p});
        UI.msg(t,'me'); e.value="";
    },
    recv: async(p)=>{ const t=await Crypto.dec(p); if(t)UI.msg(t,'them'); }
};

const Scan = {
    o:null,
    start: ()=>{ document.getElementById('scan-modal').classList.remove('hidden'); Scan.o=new Html5QrcodeScanner("reader",{fps:10}); Scan.o.render(t=>{document.getElementById('peer').value=t; Scan.stop();}); },
    stop: ()=>{ if(Scan.o)Scan.o.clear(); document.getElementById('scan-modal').classList.add('hidden'); }
};
</script>
</body>
</html>
"""

if __name__ == '__main__':
    # RAILWAY REQUIREMENT: Read PORT from environment
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)