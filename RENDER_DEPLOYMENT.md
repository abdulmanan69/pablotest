# Render Deployment Guide for pablosboson

## Prerequisites
- GitHub account
- Render account (free tier)

## Deployment Steps

### 1. Prepare Your Repository
1. Push your code to a GitHub repository
2. Ensure all files are committed:
   - Modified `server/server.py` (with PORT environment variable)
   - Modified `client/client.py` (with environment variable support)
   - Updated `requirements.txt` (with all dependencies)
   - `Dockerfile` (for containerized deployment)
   - `render.yaml` (Render configuration)

### 2. Deploy to Render

#### Option A: Using render.yaml (Recommended)
1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New" → "Blueprint"
3. Connect your GitHub repository
4. Render will automatically detect `render.yaml` and deploy

#### Option B: Manual Setup
1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: pablosboson-server
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `cd server && python server.py`
   - **Plan**: Free

### 3. Configure Environment Variables
In your Render service settings, add:
- `SECRET_KEY`: Generate a secure random string
- `PORT`: Will be automatically set by Render

### 4. Access Your Application
- Your app will be available at: `https://yourapp.onrender.com`
- Default login: `admin` / `pablosboson2024`

### 5. Connect Clients
On client machines, set the environment variable:
- Windows: `set SERVER_IP=yourapp.onrender.com`
- Linux/Mac: `export SERVER_IP=yourapp.onrender.com`

Then run: `python client/client.py`

## Important Notes

### Security
- Change the default admin password after first login
- Use strong environment variables for production
- Consider the security implications of this tool

### Render Free Tier Limitations
- Apps sleep after 15 minutes of inactivity
- 750 hours/month limit
- Cold start time when waking up
- No persistent file storage

### Troubleshooting
- Check Render logs if deployment fails
- Ensure all dependencies are in requirements.txt
- Verify PORT environment variable is being used
- Test locally before deploying

## Local Testing
Before deploying, test locally:
```bash
# Install dependencies
pip install -r requirements.txt

# Run server
cd server
python server.py

# In another terminal, run client
cd client
python client.py
```

## Support
- Check Render documentation for deployment issues
- Review application logs in Render dashboard
- Ensure your code works locally before deploying