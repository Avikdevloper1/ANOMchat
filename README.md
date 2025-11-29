# ANOMchat // ENTERPRISE EDITION (v5.0)

![Security Status](https://img.shields.io/badge/Security-Hardened-00ff9d?style=for-the-badge&logo=shield)
![Encryption](https://img.shields.io/badge/Encryption-ECDH--P521%20%2B%20AES--256--GCM-blue?style=for-the-badge)
![Logs](https://img.shields.io/badge/Logs-Zero_Retention-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20Mobile%20%7C%20Termux-lightgrey?style=for-the-badge)

**ANOMchat** is a high-performance, zero-knowledge communication infrastructure designed for environments requiring absolute anonymity. It features military-grade encryption, active network heuristic analysis (VPN enforcement), and a RAM-only architecture that leaves no forensic trace.

---

## 🛡️ Key Security Features

### 1. Zero-Knowledge Architecture
- **Client-Side Generation:** Private keys are generated in the browser using CSPRNG. The server never sees the private key or the unencrypted messages.
- **Ephemeral Sessions:** Keys exist only in volatile memory (RAM). Refreshing the page destroys the cryptographic session.

### 2. Cryptographic Standards
- **Key Exchange:** Elliptic Curve Diffie-Hellman on **Curve P-521** (Exceeds banking standards).
- **Transport:** **AES-256-GCM** with unique initialization vectors (IV) for every message.
- **Integrity:** Every handshake packet is digitally signed by the user's identity wallet to prevent Man-in-the-Middle (MitM) attacks.

### 3. Active VPN Enforcement
- **Heuristic Analysis:** The server actively polls incoming connection metadata.
- **Gatekeeper Logic:** Connections originating from residential ISPs (Raw IP) are **rejected**. Only connections routed through Data Centers, VPNs, or Proxies are permitted to establish a socket.

### 4. Defense-in-Depth
- **OWASP Hardened:** Strict Content-Security-Policy (CSP), HSTS, and X-Frame-Options.
- **Input Sanitization:** Regex-based white-listing for all socket events.
- **Rate Limiting:** Token Bucket algorithm prevents DDoS and spam bot swarms.

---

## 💻 Tech Stack

- **Backend:** Python Flask + Gevent (Async High-Performance Networking).
- **Frontend:** React.js 18 + Tailwind CSS (Served via Jinja2).
- **Protocol:** WebSockets (Socket.IO) over SSL/TLS.
- **Storage:** None. (In-Memory Python Dictionaries only).

---

## 🚀 Deployment

### Option A: Railway / Cloud (Production)

1. **Fork/Clone** this repository.
2. Ensure `Procfile`, `requirements.txt`, and `app.py` are present.
3. Deploy to Railway.
4. **Environment Variables:**
   - `SECRET_KEY`: (Optional) A long random hex string.
   - `PORT`: (Managed by Railway).

### Option B: Localhost (Development)

```bash
# 1. Install Dependencies
pip install flask flask-socketio gevent requests

# 2. Run the Server
python app.py

# 3. Access
# Navigate to http://127.0.0.1:5000
