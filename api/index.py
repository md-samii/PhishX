import sys
import os

# Add backend directory to sys.path so app.py and model files are accessible
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Change current working directory to backend so model files load correctly
os.chdir(backend_dir)

from app import app

# Expose app and handler for Vercel WSGI / Serverless runtime compatibility
handler = app
