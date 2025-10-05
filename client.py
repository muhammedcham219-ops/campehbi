import socket
import threading
import tkinter as tk
from tkinter import messagebox
import datetime

HOST = "127.0.0.1"
PORT = 5579

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Login - Chat App")

        # --- Login Frame ---
        self.login_frame = tk.Frame(master)
        self.login_frame.pack(pady=20)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.register_button = tk.Button(self.login_frame, text="Register", command=self.register)
        self.register_button.grid(row=3, column=0, columnspan=2, pady=5)

        # --- Chat Frame (hidden until login) ---
        self.chat_frame = tk.Frame(master)

        self.chat_log = tk.Text(self.chat_frame, state="disabled", width=50, height=20, wrap="word")
        self.chat_log.pack(padx=10, pady=10)

        self.message_entry = tk.Entry(self.chat_frame, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 10))
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.chat_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=10, pady=(0, 10))

        # --- Socket Setup ---
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))

        self.stop_thread = False
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

    # ---- LOGIN / REGISTER ----
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        self.client_socket.send(f"/login {username} {password}".encode())

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        self.client_socket.send(f"/register {username} {password}".encode())

    def show_chat(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack()

    # ---- SEND MESSAGE ----
    def send_message(self, event=None):
        msg = self.message_entry.get().strip()
        if msg:
            timestamp = datetime.datetime.now().strftime("%H:%M")
            self.client_socket.send(msg.encode())
            if hasattr(self, "username"):
                self.update_chat_log(f"{self.username} ({timestamp}): {msg}")
            else:
                self.update_chat_log(f"Me ({timestamp}): {msg}")
            self.message_entry.delete(0, tk.END)

    # ---- RECEIVE LOOP ----
    def receive_messages(self):
        while not self.stop_thread:
            try:
                message = self.client_socket.recv(1024).decode()
                if not message:
                    break

                # Handle tagged server messages
                if message.startswith("LOGIN_OK"):
                    self.username = self.username_entry.get().strip()
                    self.master.after(0, lambda: [
                        messagebox.showinfo("Login", message),
                        self.show_chat()
                    ])
                elif message.startswith("LOGIN_FAIL"):
                    self.master.after(0, lambda: messagebox.showerror("Login Failed", message))
                elif message.startswith("REGISTER_OK"):
                    self.master.after(0, lambda: messagebox.showinfo("Register", message))
                elif message.startswith("REGISTER_FAIL"):
                    self.master.after(0, lambda: messagebox.showerror("Register Failed", message))
                else:
                    # Normal chat messages
                    timestamp = datetime.datetime.now().strftime("%H:%M")
                    self.master.after(0, self.update_chat_log, f"{message} ({timestamp})")

            except:
                break

    # ---- CHAT LOG ----
    def update_chat_log(self, message):
        self.chat_log.config(state="normal")
        self.chat_log.insert(tk.END, message + "\n")
        self.chat_log.config(state="disabled")
        self.chat_log.yview(tk.END)

    def on_close(self):
        self.stop_thread = True
        try:
            self.client_socket.send(b"/quit")
            self.client_socket.close()
        except:
            pass
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.protocol("WM_DELETE_WINDOW", client.on_close)
    root.mainloop()
