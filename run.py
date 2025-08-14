import uvicorn
import socket
from main import app

def find_free_port(start_port=8000):
    """Find a free port starting from start_port"""
    port = start_port
    while port < start_port + 100:  # Try up to 100 ports
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return port
        except OSError:
            port += 1
    raise RuntimeError("No free port found")

if __name__ == "__main__":
    try:
        free_port = find_free_port(8000)
        print(f"🚀 Starting Lunox.io clone on http://0.0.0.0:{free_port}")
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=free_port,
            reload=True,
            log_level="info"
        )
    except RuntimeError as e:
        print(f"❌ Error: {e}")
    except KeyboardInterrupt:
        print("\n👋 Shutting down gracefully...")
