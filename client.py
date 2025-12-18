# ======================= IMPORTS =======================
import os
import json
import socket
import hashlib
import math

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ElGamal
from Crypto import Random

# ======================= CONFIG =======================
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432
KEYS_FILE = 'local_keys.json'

# ======================= SOCKET COMM =======================
def send_receive(message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.send(json.dumps(message).encode())
            data = s.recv(8192)
            if not data:
                return {"status": "FAIL", "message": "No response from server"}
            return json.loads(data.decode())
    except ConnectionRefusedError:
        return {"status": "FAIL", "message": "Server not running"}
    except Exception as e:
        return {"status": "FAIL", "message": str(e)}

# ======================= LOCAL KEY STORAGE =======================
if not os.path.exists(KEYS_FILE):
    with open(KEYS_FILE, 'w') as f:
        json.dump({}, f)

def save_local_key(user_id, priv_x):
    with open(KEYS_FILE, 'r') as f:
        keys = json.load(f)
    keys[user_id] = str(priv_x)
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=4)

def get_local_priv_key(user_id):
    if not os.path.exists(KEYS_FILE):
        return None
    with open(KEYS_FILE, 'r') as f:
        keys = json.load(f)
    return int(keys[user_id]) if user_id in keys else None

# ======================= REGISTRATION =======================
def register_admin():
    name = input("Name: ").strip()
    reg_no = input("Registration No: ").strip()
    pin = input("Set PIN: ").strip()

    resp = send_receive({
        "type": "REGISTER_ADMIN",
        "payload": {
            "name": name,
            "reg_no": reg_no,
            "pin": pin
        }
    })

    print(resp)
    if resp.get("status") == "SUCCESS":
        save_local_key(resp["data"]["user_id"], resp["data"]["priv_x"])
        print("Admin private key stored locally.")

def register_user():
    name = input("Name: ").strip()
    pin = input("Set PIN: ").strip()

    resp = send_receive({
        "type": "REGISTER_USER",
        "payload": {
            "name": name,
            "pin": pin
        }
    })

    print(resp)
    if resp.get("status") == "SUCCESS":
        save_local_key(resp["data"]["user_id"], resp["data"]["priv_x"])
        print("User private key stored locally.")

# ======================= LOGIN =======================
def login():
    user_id = input("Enter UserID: ").strip()
    pin = input("Enter PIN: ").strip()

    resp = send_receive({
        "type": "LOGIN",
        "payload": {
            "user_id": user_id,
            "pin": pin
        }
    })

    if resp.get("status") != "SUCCESS":
        print(resp.get("message"))
        return

    role = resp.get("role")
    print(f"Login successful as {role}")

    if role == "ADMIN":
        admin_interface(user_id)
    else:
        user_interface(user_id)

# ======================= ADMIN MENU =======================
def admin_interface(admin_id):
    while True:
        print("\n=== ADMIN MENU ===")
        print("1. Upload Reference Document")
        print("2. Review / Approve Pending Requests")
        print("3. Logout")

        choice = input("Choice: ").strip()
        if choice == "1":
            upload_document(admin_id, is_admin=True)
        elif choice == "2":
            approve_requests(admin_id)
        elif choice == "3":
            break
        else:
            print("Invalid option")

# ======================= USER MENU =======================
def user_interface(user_id):
    while True:
        print("\n=== USER MENU ===")
        print("1. Upload Document (Verification Request)")
        print("2. Check Request Status")
        print("3. Logout")

        choice = input("Choice: ").strip()
        if choice == "1":
            upload_document(user_id, is_admin=False)
        elif choice == "2":
            check_request_status(user_id)
        elif choice == "3":
            break
        else:
            print("Invalid option")

# ======================= DOCUMENT UPLOAD =======================
def upload_document(user_id, is_admin=False):
    file_path = input("Enter document path: ").strip()
    if not os.path.exists(file_path):
        print("File not found.")
        return

    with open(file_path, 'r', encoding='utf-8') as f:
        document = f.read()

    doc_hash = hashlib.sha256(document.encode()).hexdigest()

    # -------- USER FLOW --------
    if not is_admin:
        resp = send_receive({
            "type": "UPLOAD_DOCUMENT",
            "payload": {
                "user_id": user_id,
                "document_hash": doc_hash
            }
        })
        print(resp)
        return

    # -------- ADMIN FLOW --------
    priv_x = get_local_priv_key(user_id)
    if priv_x is None:
        print("Admin private key not found.")
        return

    # Fetch admin public key
    resp = send_receive({"type": "VIEW_USERS", "payload": {}})
    users = resp.get("users", {})
    pub = users[user_id]["elgamal_pub"]

    p, g, y = int(pub["p"]), int(pub["g"]), int(pub["y"])
    h_int = int(doc_hash, 16)

    # AES encryption
    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC)
    enc_doc = cipher.encrypt(pad(document.encode(), AES.block_size))

    # ElGamal signature
    while True:
        k = Random.random.StrongRandom().randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h_int - priv_x * r)) % (p - 1)

    payload = {
        "session_id": user_id,
        "encrypted_document": enc_doc.hex(),
        "iv": cipher.iv.hex(),
        "aes_key": aes_key.hex(),
        "document_hash": doc_hash,
        "signature": {
            "r": str(r),
            "s": str(s)
        }
    }

    resp = send_receive({
        "type": "UPLOAD_REFERENCE",
        "payload": payload
    })

    print(resp)

# ======================= APPROVE REQUESTS =======================
def approve_requests(admin_id):
    resp = send_receive({"type": "VIEW_BLOCKCHAIN", "payload": {}})
    if resp.get("status") != "SUCCESS":
        print("Failed to fetch blockchain")
        return

    blockchain = resp.get("blockchain", [])
    pending = [b for b in blockchain if b.get("status") == "PENDING"]

    if not pending:
        print("No pending requests.")
        return

    for i, b in enumerate(pending, 1):
        print(f"{i}. User: {b['session_id']} | Hash: {b['document_hash']}")

    choice = input("Approve which (0 cancel): ").strip()
    if choice == "0":
        return

    try:
        target = pending[int(choice) - 1]
    except:
        print("Invalid selection")
        return

    resp = send_receive({
        "type": "APPROVE_DOCUMENT",
        "payload": {
            "admin_id": admin_id,
            "document_hash": target["document_hash"]
        }
    })

    print(resp.get("message"))

# ======================= STATUS CHECK =======================
def check_request_status(user_id):
    resp = send_receive({
        "type": "CHECK_REQUEST_STATUS",
        "payload": {"user_id": user_id}
    })

    if resp.get("status") == "SUCCESS":
        for r in resp.get("requests", []):
            print(f"Hash: {r['document_hash']} | Status: {r['status']}")
    else:
        print(resp.get("message"))

# ======================= MAIN MENU =======================
def main_menu():
    while True:
        print("\n=== MAIN MENU ===")
        print("1. Login")
        print("2. Register")
        print("3. Exit")

        choice = input("Choice: ").strip()
        if choice == "1":
            login()
        elif choice == "2":
            register_menu()
        elif choice == "3":
            break
        else:
            print("Invalid option")

def register_menu():
    while True:
        print("\n=== REGISTER MENU ===")
        print("1. Register Admin")
        print("2. Register User")
        print("3. Back")

        choice = input("Choice: ").strip()
        if choice == "1":
            register_admin()
        elif choice == "2":
            register_user()
        elif choice == "3":
            break
        else:
            print("Invalid option")

# ======================= ENTRY POINT =======================
if __name__ == "__main__":
    main_menu()
