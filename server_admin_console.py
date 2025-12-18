import os, json, datetime

USERS_FILE = 'users.json'
CERTIFICATES_FILE = 'certificates.json'
BLOCKCHAIN_FILE = 'blockchain.json'

# ----------------------- JSON helpers -----------------------
def load_json(filename, default):
    if not os.path.exists(filename):
        return default
    with open(filename,'r') as f:
        try:
            return json.load(f)
        except:
            return default

def save_json(filename, data):
    with open(filename,'w') as f:
        json.dump(data, f, indent=4)

# ----------------------- View registered users/admins -----------------------
def view_users_admins():
    users_data = load_json(USERS_FILE, {}) #
    if not users_data:
        print("No registered users/admins found.")
        return
    for uid, u in users_data.items():
        print(f"{uid}: Name={u['name']} Role={u['role']}") #

# ----------------------- View blockchain -----------------------
# ----------------------- View blockchain -----------------------
# ----------------------- View blockchain -----------------------
def view_blockchain():
    blockchain = load_json(BLOCKCHAIN_FILE, [])
    if not blockchain:
        print("Blockchain is empty.")
        return
    print("\n--- Current Blockchain Ledger ---")
    for i, b in enumerate(blockchain):
        # Display the link to the previous block
        prev = b.get('prev_hash', 'N/A')
        curr = b.get('document_hash', 'N/A')
        print(f"Block {i} | Prev: {prev[:10]}... | Hash: {curr[:10]}... | Status: {b.get('status')}")
# ----------------------- Approve pending documents -----------------------
def approve_pending_docs():
    blockchain = load_json(BLOCKCHAIN_FILE, [])
    # Only show items that actually need manual intervention
    pending = [b for b in blockchain if b.get('status') == 'PENDING']
    
    if not pending:
        print("No pending documents to approve.")
        return
    
    print("\n--- Pending Requests ---")
    for i, doc in enumerate(pending, 1):
        print(f"{i}. User: {doc['session_id']} | Hash: {doc['document_hash']}")
    
    choice = input("\nEnter number to APPROVE (or '0' to cancel): ").strip()
    if choice == '0':
        return
    try:
        idx = int(choice) - 1
        # Update the specific block in the original blockchain list
        pending[idx]['status'] = 'APPROVED'
        save_json(BLOCKCHAIN_FILE, blockchain)
        print("Document has been approved and updated in the ledger.")
    except (ValueError, IndexError):
        print("Invalid selection.")
# ----------------------- Revoke certificate -----------------------
def revoke_certificate():
    certs = load_json(CERTIFICATES_FILE, {}) #
    if not certs:
        print("No certificates to revoke.")
        return
    # Convert keys to list for indexing
    cert_list = list(certs.items())
    for i, (uid, cert) in enumerate(cert_list, 1):
        print(f"{i}. UserID: {uid} Serial: {cert['serial_number']} Role: {cert['role']}")
    
    choice = input("Enter number to revoke (or '0' to cancel): ").strip()
    if choice == '0':
        return
    try:
        idx = int(choice) - 1
        uid = cert_list[idx][0]
        # Remove from active certificates
        certs[uid]['revoked'] = True
        certs[uid]['revoked_at'] = str(datetime.datetime.now())
        save_json(CERTIFICATES_FILE, certs)
        print(f"Certificate for {uid} revoked successfully!")
    except:
        print("Invalid choice.")

# ----------------------- Server menu -----------------------
def server_menu():
    while True:
        print("\n=== SERVER ADMIN MENU ===")
        print("1. View Blockchain")
        print("2. View Registered Users/Admins")
        print("3. Approve Pending Documents")
        print("4. Revoke Certificate")
        print("5. Exit")
        choice = input("Enter choice: ").strip() #
        if choice == '1':
            view_blockchain()
        elif choice == '2':
            view_users_admins()
        elif choice == '3':
            approve_pending_docs()
        elif choice == '4':
            revoke_certificate()
        elif choice == '5':
            break
        else:
            print("Invalid choice.")

# ----------------------- Run -----------------------
if __name__ == '__main__':
    print("=== SERVER ADMIN CONSOLE ===")
    server_menu()