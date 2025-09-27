# backend.py
import socket
import threading
import json
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
BROADCAST_PORT = 50000  # Port for UDP discovery broadcasts
TCP_PORT = 50001        # Port for TCP communication (messaging, files)
BROADCAST_INTERVAL = 5  # Seconds between "I'm online" broadcasts
HEARTBEAT_CHECK = 10    # Seconds to wait before considering a user offline
BUFFER_SIZE = 4096      # Buffer size for network operations

# WARNING: This is a pre-shared key. For a real-world application,
# you should implement a key exchange mechanism like Diffie-Hellman.
PRE_SHARED_KEY = b'my_super_secret_chat_key_32_b'

class EncryptionHandler:
    """Handles AES-GCM encryption and decryption for all TCP traffic."""
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes long")
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext):
        """Encrypts plaintext and returns a dictionary containing nonce and ciphertext."""
        nonce = os.urandom(12)  # GCM recommended nonce size
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return {'nonce': nonce.hex(), 'ciphertext': ciphertext.hex(), 'tag': encryptor.tag.hex()}

    def decrypt(self, encrypted_data):
        """Decrypts a dictionary of encrypted data and returns the plaintext."""
        nonce = bytes.fromhex(encrypted_data['nonce'])
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
        tag = bytes.fromhex(encrypted_data['tag'])
        
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class Backend:
    def __init__(self, username, callbacks):
        self.username = username
        self.avatar = "default.png" # Placeholder for avatar filename
        self.theme = "light" # Placeholder for theme name
        self.callbacks = callbacks
        self.online_users = {}  # { 'username': {'ip': str, 'last_seen': float, 'avatar': str, 'theme': str} }
        self.offline_queue = {} # { 'username': [message_object, ...] }
        self.ip_address = self._get_ip_address()
        self.running = True

        self.encryption_handler = EncryptionHandler(PRE_SHARED_KEY)
        
        # Start all networking threads
        self._start_threads()

    def _get_ip_address(self):
        """Finds the local IP address of the machine."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def _start_threads(self):
        """Initializes and starts all the background threads for networking."""
        threading.Thread(target=self._udp_broadcast, daemon=True).start()
        threading.Thread(target=self._udp_listen, daemon=True).start()
        threading.Thread(target=self._tcp_listen, daemon=True).start()
        threading.Thread(target=self._heartbeat, daemon=True).start()
        print(f"Backend started for {self.username} at {self.ip_address}")

    # --- UDP Discovery Section ---
    def _udp_broadcast(self):
        """Periodically broadcasts a presence packet to the LAN."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while self.running:
                message = {
                    'type': 'presence',
                    'username': self.username,
                    'avatar': self.avatar,
                    'theme': self.theme
                }
                sock.sendto(json.dumps(message).encode('utf-8'), ('<broadcast>', BROADCAST_PORT))
                time.sleep(BROADCAST_INTERVAL)

    def _udp_listen(self):
        """Listens for presence broadcasts from other users."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('', BROADCAST_PORT))
            while self.running:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                try:
                    message = json.loads(data.decode('utf-8'))
                    if message.get('type') == 'presence' and message['username'] != self.username:
                        self._update_user_list(message, addr[0])
                except (json.JSONDecodeError, KeyError):
                    continue

    # --- TCP Communication Section ---
    def _tcp_listen(self):
        """Listens for incoming TCP connections for messages and files."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.ip_address, TCP_PORT))
            server_socket.listen()
            while self.running:
                conn, addr = server_socket.accept()
                threading.Thread(target=self._handle_tcp_client, args=(conn,), daemon=True).start()
    
    def _handle_tcp_client(self, conn):
        """Handles a single incoming TCP connection."""
        try:
            # First message is always the encrypted metadata
            encrypted_metadata = conn.recv(BUFFER_SIZE)
            if not encrypted_metadata: return
            
            metadata = json.loads(self.encryption_handler.decrypt(json.loads(encrypted_metadata.decode('utf-8'))))
            
            msg_type = metadata.get('type')

            if msg_type == 'text_message':
                self.callbacks['on_message_received'](metadata)
            elif msg_type == 'sound_effect':
                self.callbacks['on_sound_received'](metadata)
            elif msg_type == 'file_transfer_request':
                # Ask frontend if it wants to accept the file
                if self.callbacks['on_file_request'](metadata):
                    self._send_tcp_message(metadata['sender_ip'], {
                        'type': 'file_transfer_accept',
                        'filename': metadata['filename']
                    })
                    # The frontend will now call a function to start receiving
                else:
                    # Send rejection (optional)
                    pass
            elif msg_type == 'file_transfer_accept':
                # The user we sent a file request to has accepted. Start sending.
                # This logic is initiated from the send_file method, not here.
                # This is just for acknowledgement.
                print(f"File transfer for {metadata['filename']} accepted.")
            elif msg_type == 'file_data':
                 self._receive_file_data(conn, metadata)

        except Exception as e:
            print(f"Error handling TCP client: {e}")
        finally:
            conn.close()

    def _send_tcp_message(self, recipient_ip, message_obj, is_file_data=False):
        """Encrypts and sends a message object to a specific IP via TCP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((recipient_ip, TCP_PORT))
                
                if not is_file_data:
                    # Standard message sending
                    plaintext = json.dumps(message_obj).encode('utf-8')
                    encrypted_payload = self.encryption_handler.encrypt(plaintext)
                    sock.sendall(json.dumps(encrypted_payload).encode('utf-8'))
                else:
                    # File data sending is handled separately in send_file
                    pass

        except ConnectionRefusedError:
            print(f"Connection refused from {recipient_ip}. User might be offline.")
            if message_obj.get('type') == 'text_message':
                self._queue_offline_message(message_obj)
        except Exception as e:
            print(f"Error sending TCP message: {e}")

    # --- Feature Logic ---
    def send_chat_message(self, text, recipient_username=None):
        """Sends a text message to a specific user or to all users (broadcast)."""
        mentioned_users = [word[1:] for word in text.split() if word.startswith('@') and word[1:] in self.online_users]
        
        message = {
            'type': 'text_message',
            'sender_username': self.username,
            'content': text,
            'mentions': mentioned_users,
            'timestamp': time.time()
        }
        
        if recipient_username: # Private message
            if recipient_username in self.online_users:
                recipient_ip = self.online_users[recipient_username]['ip']
                self._send_tcp_message(recipient_ip, message)
            else:
                print(f"User {recipient_username} is offline. Queuing message.")
                self._queue_offline_message(message, recipient_username)
        else: # Group message
            for user in self.online_users.values():
                self._send_tcp_message(user['ip'], message)

    def send_sound_effect(self, sound_name, recipient_username=None):
        """Sends a request to play a sound effect."""
        message = {
            'type': 'sound_effect',
            'sender_username': self.username,
            'sound_name': sound_name
        }
        if recipient_username:
             if recipient_username in self.online_users:
                self._send_tcp_message(self.online_users[recipient_username]['ip'], message)
        else:
            for user in self.online_users.values():
                self._send_tcp_message(user['ip'], message)
    
    def send_file(self, filepath, recipient_username):
        """Handles the entire file sending process in a new thread."""
        if recipient_username not in self.online_users:
            self.callbacks['on_error'](f"User {recipient_username} is not online.")
            return

        threading.Thread(target=self._file_sender_thread, args=(filepath, recipient_username), daemon=True).start()

    def _file_sender_thread(self, filepath, recipient_username):
        """The actual logic for sending a file."""
        try:
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            recipient_ip = self.online_users[recipient_username]['ip']

            # 1. Send file transfer request
            request_message = {
                'type': 'file_transfer_request',
                'sender_username': self.username,
                'sender_ip': self.ip_address,
                'filename': filename,
                'filesize': filesize
            }
            self._send_tcp_message(recipient_ip, request_message)
            
            # The recipient's backend will now ask their frontend for confirmation
            # and send back a 'file_transfer_accept'. For simplicity, we'll
            # just proceed here. In a real app, you'd wait for the accept message.
            time.sleep(1) # Give them time to accept/reject

            # 2. Open a new connection to send file data
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((recipient_ip, TCP_PORT))

                # 2a. Send metadata first
                file_metadata = {
                    'type': 'file_data',
                    'filename': filename,
                    'filesize': filesize
                }
                plaintext_meta = json.dumps(file_metadata).encode('utf-8')
                encrypted_meta = self.encryption_handler.encrypt(plaintext_meta)
                sock.sendall(json.dumps(encrypted_meta).encode('utf-8') + b'\n')

                # 2b. Send encrypted file content
                with open(filepath, 'rb') as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE - 28) # Leave space for encryption overhead
                        if not chunk: break
                        encrypted_chunk = self.encryption_handler.encrypt(chunk)
                        sock.sendall(json.dumps(encrypted_chunk).encode('utf-8') + b'\n')
            
            self.callbacks['on_info'](f"File '{filename}' sent successfully to {recipient_username}.")

        except Exception as e:
            self.callbacks['on_error'](f"Failed to send file: {e}")

    def _receive_file_data(self, conn, metadata):
        """Handles receiving the actual file data from a connection."""
        try:
            filename = metadata['filename']
            # Sanitize filename
            filename = os.path.basename(filename)
            # Typically save to a 'downloads' folder
            save_path = os.path.join(os.path.expanduser('~'), 'Downloads', filename)

            self.callbacks['on_info'](f"Receiving file '{filename}'...")
            
            with open(save_path, 'wb') as f:
                # Use a buffer to handle multiple JSON objects in one recv call
                buffer = b''
                while True:
                    data = conn.recv(BUFFER_SIZE * 2)
                    if not data: break
                    buffer += data
                    while b'\n' in buffer:
                        part, buffer = buffer.split(b'\n', 1)
                        if part:
                           encrypted_chunk = json.loads(part.decode('utf-8'))
                           decrypted_chunk = self.encryption_handler.decrypt(encrypted_chunk)
                           f.write(decrypted_chunk)
            
            self.callbacks['on_info'](f"File '{filename}' received and saved to Downloads.")
        except Exception as e:
            self.callbacks['on_error'](f"Error receiving file: {e}")

    # --- User Management & Heartbeat ---
    def _update_user_list(self, user_data, ip_address):
        """Adds a new user or updates the last_seen time for an existing one."""
        username = user_data['username']
        is_new_user = username not in self.online_users

        self.online_users[username] = {
            'ip': ip_address,
            'last_seen': time.time(),
            'avatar': user_data.get('avatar', 'default.png'),
            'theme': user_data.get('theme', 'light')
        }
        
        if is_new_user:
            print(f"User connected: {username} at {ip_address}")
            self._check_offline_queue(username) # Check if we have messages for them
            self.callbacks['on_user_list_change'](self.get_online_users())

    def _heartbeat(self):
        """Periodically checks for stale user connections."""
        while self.running:
            time.sleep(HEARTBEAT_CHECK)
            now = time.time()
            offline_users = [
                user for user, data in self.online_users.items()
                if now - data['last_seen'] > HEARTBEAT_CHECK
            ]
            
            if offline_users:
                for user in offline_users:
                    print(f"User disconnected: {user}")
                    del self.online_users[user]
                self.callbacks['on_user_list_change'](self.get_online_users())

    def _queue_offline_message(self, message, recipient_username):
        """Stores a message for a user who is currently offline."""
        if recipient_username not in self.offline_queue:
            self.offline_queue[recipient_username] = []
        self.offline_queue[recipient_username].append(message)
        self.callbacks['on_info'](f"Message for {recipient_username} queued.")

    def _check_offline_queue(self, username):
        """When a user comes online, send any queued messages."""
        if username in self.offline_queue:
            messages_to_send = self.offline_queue.pop(username)
            self.callbacks['on_info'](f"User {username} is back online. Sending {len(messages_to_send)} queued messages.")
            for msg in messages_to_send:
                recipient_ip = self.online_users[username]['ip']
                self._send_tcp_message(recipient_ip, msg)

    # --- Public Methods for Frontend ---
    def get_online_users(self):
        """Returns a list of usernames of currently online users."""
        return list(self.online_users.keys())
    
    def update_profile(self, avatar=None, theme=None):
        """Allows the frontend to update user's avatar or theme."""
        if avatar: self.avatar = avatar
        if theme: self.theme = theme
        # The new info will be sent in the next UDP broadcast

    def shutdown(self):
        """Gracefully shuts down the backend networking."""
        self.running = False
        # Optional: send a 'logoff' broadcast message
        print("Backend shutting down.")


# --- Example Usage (for testing the backend directly) ---
if __name__ == '__main__':
    # These callback functions would be methods in your GUI class
    def handle_message(msg):
        sender = msg['sender_username']
        content = msg['content']
        print(f"\n[Message from {sender}]: {content}")
        if msg['mentions']:
            print(f"  (You were mentioned!)")

    def handle_user_change(users):
        print(f"\n[User List Update]: {users}")

    def handle_file_request(metadata):
        print(f"\n[File Request]: {metadata['sender_username']} wants to send you '{metadata['filename']}' ({metadata['filesize']} bytes).")
        # In a real app, a GUI popup would ask the user.
        return True # Auto-accept for testing

    def handle_info(message):
        print(f"\n[INFO]: {message}")
    
    def handle_error(message):
        print(f"\n[ERROR]: {message}")

    def handle_sound(message):
        print(f"\n[SOUND]: {message['sender_username']} wants you to play '{message['sound_name']}.mp3'")

    test_callbacks = {
        'on_message_received': handle_message,
        'on_user_list_change': handle_user_change,
        'on_file_request': handle_file_request,
        'on_info': handle_info,
        'on_error': handle_error,
        'on_sound_received': handle_sound,
    }

    my_username = input("Enter your username: ")
    backend = Backend(my_username, test_callbacks)

    print("\nBackend is running. Type messages and press Enter to send.")
    print("Type '/file [username] [filepath]' to send a file.")
    print("Type '/sound [username] [soundname]' to send a sound effect.")
    print("Type '/quit' to exit.")

    while True:
        try:
            text = input(f"[{my_username}]> ")
            if text.lower() == '/quit':
                backend.shutdown()
                break
            elif text.startswith('/file'):
                parts = text.split(' ', 2)
                if len(parts) == 3:
                    backend.send_file(filepath=parts[2], recipient_username=parts[1])
                else:
                    print("Usage: /file <username> <path_to_file>")
            elif text.startswith('/sound'):
                parts = text.split(' ', 2)
                if len(parts) == 3:
                    backend.send_sound_effect(sound_name=parts[2], recipient_username=parts[1])
                else:
                    print("Usage: /sound <username> <sound_name>")
            else:
                # Check for private message format "@username message"
                if text.startswith('@') and ' ' in text:
                    recipient, message = text.split(' ', 1)
                    backend.send_chat_message(message, recipient_username=recipient[1:])
                else:
                    backend.send_chat_message(text) # Broadcast to all
        except KeyboardInterrupt:
            backend.shutdown()
            break