import socket
import threading
import json
import hashlib

HOST = "127.0.0.1"
PORT = 5579

users_file = "users.json"

# ---- USER UTILS ----
def load_users():
    try:
        with open(users_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(users_file, "w") as f:
        json.dump(users, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---- CLIENT HANDLER ----
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    users = load_users()
    logged_in_user = None

    while True:
        try:
            msg = conn.recv(1024).decode()
            if not msg:
                break

            parts = msg.strip().split(" ", 2)
            command = parts[0]

            # ---- REGISTER ----
            if command == "/register" and len(parts) == 3:
                username, password = parts[1], parts[2]
                if username in users:
                    conn.send("REGISTER_FAIL Username already exists".encode())
                else:
                    users[username] = hash_password(password)
                    save_users(users)
                    conn.send("REGISTER_OK Account created successfully".encode())

            # ---- LOGIN ----
            elif command == "/login" and len(parts) == 3:
                username, password = parts[1], parts[2]
                if username not in users:
                    conn.send("LOGIN_FAIL User not found".encode())
                elif users[username] != hash_password(password):
                    conn.send("LOGIN_FAIL Invalid password".encode())
                else:
                    logged_in_user = username
                    conn.send(f"LOGIN_OK Welcome {username}".encode())

            # ---- QUIT ----
            elif command == "/quit":
                conn.send("Goodbye!".encode())
                break

            # ---- BROADCAST CHAT ----
            else:
                if logged_in_user:
                    broadcast(f"{logged_in_user}: {msg}", conn)
                else:
                    conn.send("LOGIN_FAIL Please login first".encode())

        except Exception as e:
            print(f"[ERROR] {e}")
            break

    conn.close()
    print(f"[DISCONNECTED] {addr} disconnected.")

# ---- BROADCAST TO ALL ----
clients = []

def broadcast(message, sender_conn):
    for client in clients:
        if client != sender_conn:
            try:
                client.send(message.encode())
            except:
                clients.remove(client)

# ---- MAIN SERVER LOOP ----
def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # <-- add this line
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    print("[STARTING] Server is starting...")
    start()
