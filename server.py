# ======================= IMPORTS =======================
import os
import json
import socket
import secrets
import hashlib
import datetime
import threading

from Crypto.PublicKey import RSA, ElGamal
from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ======================= FILE PATHS =======================
USERS_FILE = 'users.json'
CERTIFICATES_FILE = 'certificates.json'
BLOCKCHAIN_FILE = 'blockchain.json'
SERVER_KEYS_FILE = 'server_keys.json'

# ======================= JSON HELPERS =======================
def load_json(filename, default):
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            json.dump(default, f)
    with open(filename, 'r') as f:
        try:
            return json.load(f)
        except:
            return default

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# ======================= GLOBAL DATA =======================
users = load_json(USERS_FILE, {})
certificates = load_json(CERTIFICATES_FILE, {})
blockchain = load_json(BLOCKCHAIN_FILE, [])

data_lock = threading.Lock()
# ================= SERVER RSA KEY SETUP =================

def load_or_create_server_keys():
    if not os.path.exists(SERVER_KEYS_FILE):
        key = RSA.generate(2048)
        server_keys = {
            "private": key.export_key().decode(),
            "public": key.publickey().export_key().decode()
        }
        with open(SERVER_KEYS_FILE, "w") as f:
            json.dump(server_keys, f, indent=4)
        return server_keys

    with open(SERVER_KEYS_FILE, "r") as f:
        server_keys = json.load(f)

    if "private" not in server_keys or "public" not in server_keys:
        raise Exception("server_keys.json corrupted. Delete and restart.")

    return server_keys

server_keys = load_or_create_server_keys()
rsa_private_key = RSA.import_key(server_keys["private"])
rsa_public_key = RSA.import_key(server_keys["public"])

def sign_certificate(cert_data):
    h = SHA256.new(json.dumps(cert_data, sort_keys=True).encode())
    return pkcs1_15.new(rsa_private_key).sign(h).hex()

# ======================= BLOCKCHAIN =======================
def create_block(session_id, cert_serial, enc_doc, iv, aes_key,
                 doc_hash, signature, status):

    prev_hash = "0" * 64
    if blockchain:
        prev_hash = hashlib.sha256(
            json.dumps(blockchain[-1], sort_keys=True).encode()
        ).hexdigest()

    return {
        "prev_hash": prev_hash,
        "session_id": session_id,
        "cert_serial": cert_serial,
        "encrypted_document": enc_doc,
        "iv": iv,
        "aes_key": aes_key,
        "document_hash": doc_hash,
        "signature": signature,
        "status": status,
        "timestamp": str(datetime.datetime.now())
    }

# ======================= NETWORK =======================
HOST = '127.0.0.1'
PORT = 65432
def get_reference_hash():
    # Search from latest to oldest
    for block in reversed(blockchain):
        if (
            block["status"] == "APPROVED"
            and block["encrypted_document"]
            and block["session_id"].startswith("ADMIN_")
        ):
            return block["document_hash"]
    return None

# ======================= CLIENT HANDLER =======================
def handle_client(conn, addr):
    global users, certificates, blockchain
    try:
        data = conn.recv(8192)
        if not data:
            return

        message = json.loads(data.decode())
        mtype = message.get('type')
        payload = message.get('payload', {})

        # ================= REGISTER ADMIN =================
        if mtype == 'REGISTER_ADMIN':
            name = payload.get('name')
            reg_no = payload.get('reg_no')
            pin = payload.get('pin')

            user_id = f"ADMIN_{reg_no}"

            elg = ElGamal.generate(256, Random.new().read)
            pub = {'p': int(elg.p), 'g': int(elg.g), 'y': int(elg.y)}

            users[user_id] = {
                'name': name,
                'role': 'ADMIN',
                'pin': pin,
                'elgamal_pub': pub
            }

            cert = {
                'subject_id': user_id,
                'role': 'ADMIN',
                'elgamal_public_key': pub,
                'issued_at': str(datetime.datetime.now()),
                'serial_number': f'CERT-{secrets.randbelow(100000)}'
            }

            certificates[user_id] = cert

            with data_lock:
                save_json(USERS_FILE, users)
                save_json(CERTIFICATES_FILE, certificates)

            conn.send(json.dumps({
                'status': 'SUCCESS',
                'data': {
                    'user_id': user_id,
                    'certificate': cert,
                    'ca_signature': sign_certificate(cert),
                    'priv_x': int(elg.x)
                }
            }).encode())

        # ================= REGISTER USER =================
        elif mtype == 'REGISTER_USER':
            name = payload.get('name')
            pin = payload.get('pin')

            user_id = f"USER_{secrets.randbelow(100000)}"

            elg = ElGamal.generate(256, Random.new().read)
            pub = {'p': int(elg.p), 'g': int(elg.g), 'y': int(elg.y)}

            users[user_id] = {
                'name': name,
                'role': 'USER',
                'pin': pin,
                'elgamal_pub': pub
            }

            cert = {
                'subject_id': user_id,
                'role': 'USER',
                'elgamal_public_key': pub,
                'issued_at': str(datetime.datetime.now()),
                'serial_number': f'CERT-{secrets.randbelow(100000)}'
            }

            certificates[user_id] = cert

            with data_lock:
                save_json(USERS_FILE, users)
                save_json(CERTIFICATES_FILE, certificates)

            conn.send(json.dumps({
                'status': 'SUCCESS',
                'data': {
                    'user_id': user_id,
                    'certificate': cert,
                    'priv_x': int(elg.x)
                }
            }).encode())

        # ================= LOGIN =================
        elif mtype == 'LOGIN':
            uid = payload.get('user_id')
            pin = payload.get('pin')

            if uid not in users or users[uid]['pin'] != pin:
                conn.send(json.dumps({'status': 'FAIL', 'message': 'Invalid credentials'}).encode())
                return

            if uid not in certificates or certificates[uid].get('revoked'):
                conn.send(json.dumps({'status': 'FAIL', 'message': 'Certificate revoked'}).encode())
                return

            conn.send(json.dumps({
                'status': 'SUCCESS',
                'role': users[uid]['role']
            }).encode())

        # ================= ADMIN UPLOAD =================
        elif mtype == 'UPLOAD_REFERENCE':
            uid = payload.get('session_id')
            # Prevent duplicate reference upload
            ref_hash = payload.get("document_hash")

            for block in blockchain:
                if block["document_hash"] == ref_hash and block["status"] == "APPROVED":
                    conn.send(json.dumps({
                        "status": "FAIL",
                        "message": "Reference already exists for this document"
                    }).encode())
                    return

            block = create_block(
                uid,
                certificates[uid]['serial_number'],
                payload.get('encrypted_document'),
                payload.get('iv'),
                payload.get('aes_key'),
                payload.get('document_hash'),
                payload.get('signature'),
                'APPROVED'
            )

            blockchain.append(block)
            with data_lock:
                save_json(BLOCKCHAIN_FILE, blockchain)

            conn.send(json.dumps({'status': 'SUCCESS', 'message': 'Reference stored'}).encode())

        # ================= USER REQUEST =================
        elif mtype == 'UPLOAD_DOCUMENT':
            uid = payload.get('user_id')
            doc_hash = payload.get('document_hash')

            reference_hash = get_reference_hash()

            if reference_hash is None:
                status = "PENDING"
            elif doc_hash == reference_hash:
                status = "APPROVED"
            else:
                status = "PENDING"   # hybrid fix: NEVER auto-reject
            for block in blockchain:
                if block['session_id'] == uid and block['document_hash'] == doc_hash:
                    conn.send(json.dumps({
                        'status': 'FAIL',
                        'message': 'Document already submitted'
                    }).encode())
                    return

            blockchain.append(create_block(
                uid,
                certificates[uid]['serial_number'],
                "", "", "",
                doc_hash,
                {},
                status
            ))

            with data_lock:
                save_json(BLOCKCHAIN_FILE, blockchain)

            conn.send(json.dumps({
                'status': 'SUCCESS',
                'message': f'Document {status.lower()}'
            }).encode())

        # ================= APPROVE DOCUMENT =================
        elif mtype == 'APPROVE_DOCUMENT':
            admin_id = payload.get('admin_id')
            doc_hash = payload.get('document_hash')

            if users.get(admin_id, {}).get('role') != 'ADMIN':
                conn.send(json.dumps({'status': 'FAIL', 'message': 'Not authorized'}).encode())
                return

            for block in blockchain:
                if block['document_hash'] == doc_hash and block['status'] == 'PENDING':
                    block['status'] = 'APPROVED'
                    block['approved_by'] = admin_id
                    block['approved_at'] = str(datetime.datetime.now())
                    with data_lock:
                        save_json(BLOCKCHAIN_FILE, blockchain)
                    conn.send(json.dumps({'status': 'SUCCESS', 'message': 'Document approved'}).encode())
                    return

            conn.send(json.dumps({'status': 'FAIL', 'message': 'Pending document not found'}).encode())

        # ================= VIEW BLOCKCHAIN =================
        elif mtype == 'VIEW_BLOCKCHAIN':
            conn.send(json.dumps({'status': 'SUCCESS', 'blockchain': blockchain}).encode())

        # ================= VIEW USERS =================
        elif mtype == 'VIEW_USERS':
            conn.send(json.dumps({'status': 'SUCCESS', 'users': users}).encode())

        # ================= CHECK STATUS =================
        elif mtype == 'CHECK_REQUEST_STATUS':
            uid = payload.get('user_id')
            result = [{'document_hash': b['document_hash'], 'status': b['status']}
                      for b in blockchain if b['session_id'] == uid]
            conn.send(json.dumps({'status': 'SUCCESS', 'requests': result}).encode())

        else:
            conn.send(json.dumps({'status': 'FAIL', 'message': 'Unknown request'}).encode())

    except Exception as e:
        conn.send(json.dumps({'status': 'FAIL', 'message': str(e)}).encode())

    finally:
        conn.close()

# ======================= START SERVER =======================
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server running on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    start_server()
