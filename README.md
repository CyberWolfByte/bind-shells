# Unencrypted vs Encrypted Bind Shell (Windows)

This project features two Python scripts: one establishes an AES-encrypted bind shell for secure remote command execution, while the other provides a basic bind shell setup, enabling command execution and result retrieval across client-server communications using standard Python modules.

## Disclaimer

The tools and scripts provided in this repository are made available for educational purposes only and are intended to be used for testing and protecting systems with the consent of the owners. The author does not take any responsibility for the misuse of these tools. It is the end user's responsibility to obey all applicable local, state, national, and international laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Under no circumstances should this tool be used for malicious purposes. The author of this tool advocates for the responsible and ethical use of security tools. Please use this tool responsibly and ethically, ensuring that you have proper authorization before engaging any system with the techniques demonstrated by this project.

## Features

**unencrypted_bind_shell.py**: This Python script provides a basic implementation of bind shell functionality, enabling both server and client operations. On the server side, it listens for incoming connections to receive and execute commands, while on the client side, it sends commands to a remote server for execution. Utilizing standard Python modules such as `socket` for network communication, `subprocess` for executing commands, `threading` for managing multiple connections, and `argparse` for command-line options, the script simplifies the process of setting up a bind shell. It supports executing commands received from a client on the server's operating system and returning the results, as well as sending commands to a remote server from a client and displaying the output, making it versatile for both server and client roles in a bind shell setup.

**encrypted_bind_shell.py**: This Python script establishes an encrypted bind shell, utilizing AES encryption to secure communications between a client and a server. This method allows for executing commands on a remote system securely, with the results sent back to the initiator encrypted.

## Prerequisites

- **Operating System**: Tested on Windows 10 x64, version 22H2.
- **Python Version**: Python 3.6+
- **pycryptodome**: Provides AES functionality along with other cryptographic operations.

## Installation

1. **Python Environment Setup**: Ensure Python and pip are installed. Install the required libraries using:
    
    ```bash
    pip install pycryptodome
    ```
    
2. **Download Scripts**: Clone or download the scripts from the project repository to your local machine.

## Usage

1. **Running the Unencrypted Bind Shell Script**:
    
    ```bash
    python unencrypted_bind_shell.py -h
    usage: unencrypted_bind_shell.py [-h] [-l] [-c CONNECT]
    
    Encrypted Bind Shell Project
    
    options:
      -h, --help            show this help message and exit
      -l, --listen          Setup a bind shell
      -c CONNECT, --connect CONNECT
                            Connect to a bind shell
    ```
    
    - Start the server script in one terminal:
        
        ```bash
        python unencrypted_bind_shell.py -l
        ```
        
    - Connect from the client in another terminal:
        
        ```bash
        python unencrypted_bind_shell.py -c 127.0.0.1
        ```
        
2. **Running the Encrypted Bind Shell Script**:
    - To start the server, run:
        
        ```bash
        python encrypted_bind_shell.py -l
        ```
        
    - To connect as a client, open another terminal and run with encryption key generated from the server `-k`:
        
        ```bash
        python encrypted_bind_shell.py -c 127.0.0.1 -k <AES-ENCRYPTION_KEY>
        ```
        
3. **Interactive Usage**:
    - Follow the on-screen prompts to send commands from the client to the server.
    - Observe command execution results returned to the client for verification.

## How It Works

### Unencrypted Bind Shell:

- **Bind Shell Server Mode (`server_mode`):** When started in server mode, the script sets up a TCP server that listens on a specified port (default 1234) for incoming connections. For each connection, it spawns a new thread (`handle_client`) that handles the session. This thread prompts the connected client to enter commands, executes them on the server's underlying system via `cmd`, and sends back the command output.
- **Client Mode (`client_mode`):** In client mode, the script connects to a specified remote bind shell server. It starts two threads: one for sending commands to the server (`send_commands`) and another for receiving and displaying the command output (`receive_output`).
- **Command Execution (`execute_command`):** This function takes a command as input, executes it using the Windows Command Prompt (`cmd /c`), captures the output or any errors, and returns the result.
- **Handling Client Connections (`handle_client`):** Upon establishing a connection, this function sends a welcome message to the client, then enters a loop where it continuously prompts for commands, executes them, and sends back the results until the client disconnects or sends an "exit" command.
- **Sending Commands and Receiving Output:** The `send_commands` function allows the user to input commands from the terminal, which are sent to the server. The `receive_output` function continuously listens for messages from the server, displaying the results of executed commands.
- **Command-Line Arguments:** The script uses `argparse` to allow the user to start the script in either server mode (`l` or `-listen`) or client mode (`c` or `-connect` with the server's IP address).

### Encrypted Bind Shell:

- **AESCipher Class:** Manages encryption and decryption using the AES algorithm. It initializes with an optional key; if none is provided, it generates a random 32-byte key. This class provides methods to encrypt plaintext and decrypt ciphertext, handling the conversion between strings and bytes as necessary.
- **Encrypted Communication:** Utilizes the `AESCipher` class to encrypt commands sent to the server and decrypt responses. This ensures data privacy and integrity, protecting against eavesdropping and tampering.
- **Command Execution:** The server executes received commands using the native command shell (`cmd` on Windows) and returns the output, all encrypted for security.
- **Threading for Concurrency:** Uses Python's `threading` module to handle multiple client connections simultaneously and manage sending/receiving data streams without blocking.
- **Argument Parsing:** Employs `argparse` to configure the script either as a server (listening mode) or as a client (connecting mode), with an optional encryption key for establishing a known encryption context.
- **Server Mode (`server_mode`):** Initializes a socket to listen for incoming connections. Upon a connection, it spawns a thread to handle the client using `handle_client`, which manages command reception, decryption, execution, and encrypted response transmission.
- **Client Mode (`client_mode`):** Connects to the specified server and starts threads for sending commands and receiving responses, ensuring interactive command execution capability.
- **Communication Functions:** `encrypted_send` sends encrypted messages over the socket, and `execute_command` runs system commands, returning the results. `handle_client`, `send_commands`, and `receive_output` manage the command execution flow and result presentation.

## Output Example

### Unencrypted Bind Shell:

**Client Connection**

```bash
python unencrypted_bind_shell.py -c 127.0.0.1
Successfully connected to the remote bind shell. Type your commands below:
Connection established successfully
Please enter a command (type 'exit' to disconnect): whoami
luna\gerry merino

ipconfig
Please enter a command (type 'exit' to disconnect):
Windows IP Configuration

Unknown adapter OpenVPN Wintun:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : localdomain
   Link-local IPv6 Address . . . . . : fe80::7a71:c5a3:d0fb:45f3%8
   IPv4 Address. . . . . . . . . . . : 172.16.250.128
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.250.2

Unknown adapter OpenVPN TAP-Windows6:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Unknown adapter OpenVPN Data Channel Offload:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

**Server Connection**

```bash
python unencrypted_bind_shell.py -l
Initializing bind shell. Listening for incoming connections...
New connection established from: ('127.0.0.1', 50658)
Received command from client: whoami
Executing command: whoami
Received command from client: ipconfig
Executing command: ipconfig
```

**No Encryption in Transit**

While this script provides a basic implementation of a bind shell, it doesn't implement encryption for data transmission. This means that all commands sent and received are in plaintext, which could be intercepted and read by a third party. For educational purposes and controlled environments, this might be acceptable, but for any real-world application, especially over the internet, implementing secure communications (e.g., using SSL/TLS for socket connections) is crucial to protect data integrity and confidentiality.

![Unencrypted Traffic](/images/no_encryption.png)

### Encrypted Bind Shell:

**Client Connection**

```bash
python encrypted_bind_shell.py -c 127.0.0.1 -k 8419e6355eec7ee967e27a4b9850855a6f93ba150dc8420bd0290af46bea110d
Successfully connected to the remote bind shell. Type your commands below:
Connection established successfully
Please enter a command (type 'exit' to disconnect): whoami
luna\gerry merino
Please enter a command (type 'exit' to disconnect): cd
C:\Users\Gerry Merino\Documents\python201
Please enter a command (type 'exit' to disconnect): ipconfig

Windows IP Configuration

Unknown adapter OpenVPN Wintun:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : localdomain
   Link-local IPv6 Address . . . . . : fe80::7a71:c5a3:d0fb:45f3%8
   IPv4 Address. . . . . . . . . . . : 172.16.250.128
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.250.2

Unknown adapter OpenVPN TAP-Windows6:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Unknown adapter OpenVPN Data Channel Offload:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
Please enter a command (type 'exit' to disconnect):
```

**Server Connection**

```bash
python encrypted_bind_shell.py -l
Encryption Key: 8419e6355eec7ee967e27a4b9850855a6f93ba150dc8420bd0290af46bea110d
Initializing bind shell. Listening for incoming connections...
New connection established from: ('127.0.0.1', 50699)
Received command from client: whoami
Received command from client: cd
Received command from client: ipconfig
```

**Encryption in Transit**

<aside>
⚠️ Using ECB mode (`AES.MODE_ECB`) for encryption is generally not recommended due to security weaknesses. Consider using a more secure mode like CBC or GCM with proper IV management for real-world applications.

</aside>

![Enncryption In Transit](/images/encryption_enabled.png)

## Contributing

If you have an idea for an improvement or if you're interested in collaborating, you are welcome to contribute. Please feel free to open an issue or submit a pull request.

## License

This project is licensed under the GNU General Public (GPL) License - see the [LICENSE](LICENSE) file for details.
