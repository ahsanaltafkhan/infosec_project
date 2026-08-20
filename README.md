# InfoSec Project

## Overview
This repository contains a secure client-server application designed to demonstrate core information security principles. The system utilizes cryptographic key exchanges, certificate validation, a blockchain-based ledger for tamper-evident record-keeping, and an administrative console for manual approvals and user management.

## Repository Structure

**Core Scripts**
*   `server.py`: The main server-side application handling incoming client connections and security protocols.
*   `client.py`: The client-side application used to connect to the server securely.
*   `server_admin_console.py`: A dedicated script for administrative tasks and registry management.

**Databases & Ledgers**
*   `blockchain.json`: Stores the immutable blockchain ledger data.
*   `users.json`: A JSON database containing standard user information.
*   `sessions.json`: Tracks active user sessions securely.
*   `admin_registry.txt`: A text-based registry of admin users and their IDs.

**Cryptography & Security**
*   `server_keys.json`: Stores the server's cryptographic keys.
*   `local_keys.json`: Stores the client's local cryptographic keys.
*   `certificates.json`: Manages the digital certificates used for identity verification.

**Miscellaneous**
*   `W.txt`: A text file designated for manual approval workflows.
*   `A.txt`: Auxiliary text file.

## Prerequisites
*   Python 3.x
*   Required cryptographic libraries (e.g., `cryptography`, `hashlib`) as defined in the Python scripts.

## Setup and Usage

### 1. Initialize the Server
Start the server to begin listening for secure connections and to initialize the keys and blockchain ledger.
```bash
python server.py
