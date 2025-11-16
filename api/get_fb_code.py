from http.server import BaseHTTPRequestHandler
import json
import re

from hotmail_oauth import GetOAuth2Token, get_latest_emails
from auth_utils import verify_token, AuthError        # <-- thêm dòng này

def process_credential(raw: str):
    """
    Nhận 1 dòng:
      Username|Password|access_token|refresh_token|Client_id|Proxy
    (có thể thiếu 1 số field như script gốc)
    Trả về dict:
      {
        "email": ...,
        "used": "access_token" | "refresh_token" | "password_login" | None,
        "access_token": ...,
        "refresh_token": ...,
        "fb_code": ... hoặc None,
        "emails": [ {subject, from_addr, from_name, received, preview}, ... ]
      }
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("credential is empty")

    parts = [p.strip() for p in raw.split("|")] if raw else []
    n = len(parts)

    email = parts[0] if n > 0 else ""
    password = parts[1] if n > 1 else ""
    access_token_input = parts[2] if n > 2 else ""
    refresh_token_input = parts[3] if n > 3 else ""

    client_id_input = ""
    proxy_str = ""

    if n >= 6:
        # Username|Password|access_token|refresh_token|Client_id|Proxy
        client_id_input = parts[4]
        proxy_str = parts[5]
    elif n == 5:
        #   a) Format cũ: Username|Password|access_token|refresh_token|Proxy
        #   b) Format mới: Username|Password||refresh_token|Client_id
        last = parts[4]
        lower_last = last.lower()
        if (
            ":" in last
            or "@" in last
            or lower_last.startswith("http://")
            or lower_last.startswith("https://")
            or lower_last.startswith("socks")
        ):
            proxy_str = last
        else:
            client_id_input = last

    # Chuẩn bị proxies
    proxies = None
    if proxy_str:
        proxies = {
            "http": proxy_str,
            "https": proxy_str,
        }

    # Truyền client_id (nếu có) vào class gốc
    auth = GetOAuth2Token(client_id=client_id_input or None, proxies=proxies)

    def fetch_emails_with_token(token: str):
        return get_latest_emails(token, top=3, proxies=proxies)

    emails = None
    final_access_token = access_token_input
    final_refresh_token = refresh_token_input
    used = None

    # 1) Thử access_token có sẵn
    if final_access_token:
        try:
            emails = fetch_emails_with_token(final_access_token)
            used = "access_token"
        except Exception:
            emails = None
            used = None

    # 2) Nếu fail và có refresh_token => refresh
    if emails is None and final_refresh_token:
        try:
            token_result = auth.refresh_access_token(final_refresh_token)
            final_access_token = token_result.get("access_token")
            final_refresh_token = token_result.get("refresh_token", final_refresh_token)
            emails = fetch_emails_with_token(final_access_token)
            used = "refresh_token"
        except Exception:
            emails = None

    # 3) Nếu vẫn fail => login bằng username/password
    if emails is None:
        token_result = auth.run(email, password)
        final_access_token = token_result.get("access_token")
        final_refresh_token = token_result.get("refresh_token")
        emails = fetch_emails_with_token(final_access_token)
        used = "password_login"

    # 4) Tìm mã bảo mật Facebook trong 3 email
    fb_code = None
    for mail in emails:
        subject = (mail.get("subject") or "").strip()
        from_addr = (mail.get("from_addr") or "").lower()
        from_name = (mail.get("from_name") or "").strip()

        if from_addr == "security@facebookmail.com" and from_name == "Facebook":
            m = re.search(r"(\d{4,8})\s+là mã bảo mật Facebook của bạn", subject)
            if m:
                fb_code = m.group(1)
                break

    return {
        "email": email,
        "used": used,
        "access_token": final_access_token,
        "refresh_token": final_refresh_token,
        "fb_code": fb_code,
        "emails": emails or [],
    }


class handler(BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_POST(self):
        try:
            # 1) Check auth token
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                self._respond_json(
                    401,
                    {"success": False, "error": "missing Authorization bearer token"},
                )
                return

            token = auth_header.split(" ", 1)[1].strip()
            try:
                username = verify_token(token)
            except AuthError as e:
                self._respond_json(
                    401,
                    {"success": False, "error": f"invalid token: {e}"},
                )
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length or 0)
            try:
                data = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                data = {}

            credential = data.get("credential", "")

            result = process_credential(credential)

            resp_obj = {
                "success": True,
                "error": None,
                **result,
            }
            resp_json = json.dumps(resp_obj, ensure_ascii=False).encode("utf-8")

            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp_json)))
            self.end_headers()
            self.wfile.write(resp_json)
        except Exception as e:
            resp_obj = {
                "success": False,
                "error": str(e),
            }
            resp_json = json.dumps(resp_obj, ensure_ascii=False).encode("utf-8")

            self.send_response(500)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp_json)))
            self.end_headers()
            self.wfile.write(resp_json)
