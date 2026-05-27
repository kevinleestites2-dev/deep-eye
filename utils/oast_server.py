"""
OAST (Out-of-Band Application Security Testing) Callback Server
Receives out-of-band callbacks from blind vulnerabilities (SSRF, XXE, RCE)
"""

import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List
from datetime import datetime
from utils.logger import get_logger

logger = get_logger(__name__)

_callbacks = []
_callbacks_lock = threading.Lock()


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs all incoming requests."""

    def do_GET(self):
        self._log_callback('GET')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_POST(self):
        self._log_callback('POST')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_PUT(self):
        self._log_callback('PUT')
        self.send_response(200)
        self.end_headers()

    def _log_callback(self, method: str):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
        }
        with _callbacks_lock:
            _callbacks.append(entry)
        logger.info(f"[OAST] Callback received: {method} {self.path} from {self.client_address[0]}")

    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        pass


class OASTCallbackServer:
    """Out-of-band callback server for blind vulnerability detection."""

    def __init__(self, host: str = '0.0.0.0', port: int = 9999):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        """Start OAST server in background daemon thread."""
        global _callbacks
        _callbacks = []

        self.server = HTTPServer((self.host, self.port), _CallbackHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        logger.info(f"[OAST] Callback server started on {self.host}:{self.port}")

    def stop(self):
        """Stop OAST server."""
        if self.server:
            self.server.shutdown()
            self.server = None
            logger.info("[OAST] Callback server stopped")

    def get_callback_url(self) -> str:
        """Get the URL targets should call back to."""
        return f"http://{self.host}:{self.port}/callback"

    def get_callbacks(self) -> List[Dict]:
        """Get all received callbacks."""
        with _callbacks_lock:
            return list(_callbacks)

    def has_callbacks(self) -> bool:
        """Check if any callbacks were received."""
        with _callbacks_lock:
            return len(_callbacks) > 0

    def clear(self):
        """Clear callback history."""
        global _callbacks
        with _callbacks_lock:
            _callbacks = []
