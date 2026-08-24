import sys
import os

# Add current directory (api/) and parent directory to sys.path
api_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(api_dir)

for path in [api_dir, parent_dir]:
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from app import app
except ImportError:
    try:
        from api.app import app
    except ImportError:
        from backend.app import app

app = app
handler = app
