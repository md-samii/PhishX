from app import app

# Expose app and handler for Vercel WSGI / Serverless runtime compatibility
handler = app
