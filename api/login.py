# api/login.py
from http.server import BaseHTTPRequestHandler
import json

from auth_utils import create_token


# TẠM THỜI: hard-code user/password cho demo
# Production: nên lấy từ ENV hoặc DB, không lưu plaintext trong code.
USERS = {
    "admin": "admin123",
    "test": "Test!234",
}


class handler(BaseHTTPRequestHandler):
    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")  # có thể giới hạn domain GitHub Pages
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors()
        self.end_headers()

    def do_POST(self):
        try:
            content_len = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(content_len or 0)
            try:
                data = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                data = {}

            username = (data.get("username") or "").strip()
            password = (data.get("password") or "").strip()

            if not username or not password:
                self._respond_json(
                    400,
                    {"success": False, "error": "username/password is required"},
                )
                return

            expected = USERS.get(username)
            if not expected or expected != password:
                self._respond_json(
                    401,
                    {"success": False, "error": "invalid username or password"},
                )
                return

            token = create_token(username)
            resp = {
                "success": True,
                "user": username,
                "token": token,
                "expires_in": 3600,
            }
            self._respond_json(200, resp)

        except Exception as e:
            self._respond_json(500, {"success": False, "error": str(e)})

    def _respond_json(self, status_code: int, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self._set_cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
