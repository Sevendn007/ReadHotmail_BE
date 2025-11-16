from urllib.parse import urlencode, urlparse, parse_qs
import re
import requests


# ============================
# CLASS LẤY / REFRESH TOKEN OAUTH2
# ============================

class GetOAuth2Token:
    def __init__(self, client_id=None, proxies=None):
        """
        client_id: nếu None thì dùng client_id mặc định.
        proxies: dict {"http": proxy, "https": proxy} hoặc None.
        """
        # Nếu không truyền client_id thì dùng mặc định như cũ
        self.client_id = client_id or "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
        self.redirect_uri = "https://localhost"
        self.base_url = "https://login.live.com"
        self.token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        self.proxies = proxies  # dict {"http": proxy, "https": proxy} hoặc None

    def _get_headers(self, additional_headers: dict = None):
        headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Thunderbird/128.2.3",
        }
        if additional_headers:
            headers.update(additional_headers)
        return headers

    def _handle_consent_page(self, post_url: str, resp_content: str, cookies: dict):
        """
        Xử lý màn hình consent "Ứng dụng đang yêu cầu quyền..."
        """
        post_headers = self._get_headers(
            {"content-type": "application/x-www-form-urlencoded"}
        )

        matches = re.finditer(
            r'<input type="hidden" name="(.*?)" id="(.*?)" value="(.*?)"',
            resp_content,
        )
        form_data = {m.group(1): m.group(3) for m in matches}

        if not form_data:
            raise RuntimeError("Không lấy được hidden input trên trang consent")

        encoded_data = urlencode(form_data)
        # Lần 1
        requests.post(
            post_url,
            data=encoded_data,
            headers=post_headers,
            cookies=cookies,
            allow_redirects=False,
            proxies=self.proxies,
        )

        # Lần 2: chọn Yes
        form_data["ucaction"] = "Yes"
        encoded_data = urlencode(form_data)
        consent_resp = requests.post(
            post_url,
            data=encoded_data,
            headers=post_headers,
            cookies=cookies,
            allow_redirects=False,
            proxies=self.proxies,
        )

        redirect_url = consent_resp.headers.get("Location")
        if not redirect_url:
            raise RuntimeError("Không nhận được Location sau khi consent")

        final_resp = requests.get(
            redirect_url,
            headers=post_headers,
            cookies=cookies,
            allow_redirects=False,
            proxies=self.proxies,
        )
        final_location = final_resp.headers.get("Location", redirect_url)
        return final_location

    def _handle_add_proofs_page(self, add_url: str, cookies: dict):
        """
        Xử lý màn hình 'Let's protect your account' (proofs/Add?...).
        Tự động bấm 'Skip for now'.
        Trả về redirect_url mới (thường là oauth20_authorize.srf?...code=...).
        """
        headers = self._get_headers()

        # 1) Load trang proofs/Add
        resp = requests.get(
            add_url,
            headers=headers,
            cookies=cookies,
            allow_redirects=True,
            proxies=self.proxies,
        )
        html = resp.text

        # 2) Tìm link "Skip for now ..."
        m = re.search(
            r'<a[^>]+href="([^"]+)"[^>]*>\s*Skip for now',
            html,
            re.IGNORECASE,
        )
        if not m:
            # Lưu ra file để debug nếu cần
            with open("debug_add_proofs.html", "w", encoding="utf-8") as f:
                f.write(html)
            raise RuntimeError(
                "Không tìm được link 'Skip for now' trên trang proofs/Add. Xem debug_add_proofs.html để chỉnh regex."
            )

        skip_url = m.group(1)
        if skip_url.startswith("/"):
            skip_url = "https://account.live.com" + skip_url

        # 3) Gọi request tới link Skip
        skip_resp = requests.get(
            skip_url,
            headers=headers,
            cookies=resp.cookies.get_dict(),
            allow_redirects=False,
            proxies=self.proxies,
        )

        # 4) Lấy Location mới (thường là login.live.com/oauth20_authorize.srf?...code=...)
        new_redirect = skip_resp.headers.get("Location")
        if not new_redirect:
            new_redirect = skip_url

        return new_redirect

    def _extract_post_url(self, html: str) -> str:
        match = re.search(
            r'https://login\.live\.com/ppsecure/post\.srf\?([^"\'\\]+)', html
        )
        if not match:
            raise RuntimeError("Không tìm post.srf")

        post_url = "https://login.live.com/ppsecure/post.srf?" + match.group(1)
        return post_url

    def _extract_ppft(self, html: str) -> str:
        # Cách mới trong JS (sFTTag)
        m = re.search(
            r'sFTTag":"<input type=\\\"hidden\\\" name=\\\"PPFT\\\" id=\\\".*?\\\" value=\\\"(.*?)\\\"',
            html,
        )
        if m:
            return m.group(1)

        # Fallback cũ
        m2 = re.search(
            r'<input type="hidden" name="PPFT" id=".*?" value="(.*?)"', html
        )
        if m2:
            return m2.group(1)

        raise RuntimeError("Không tìm thấy PPFT trong login page")

    def _extract_code_from_url(self, url: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        code_list = qs.get("code")
        if not code_list:
            raise RuntimeError("Không tìm thấy code trong URL redirect")
        return code_list[0]

    def run(self, email: str, password: str):
        """
        Login bằng username/password để lấy access_token + refresh_token.
        """
        auth_url = f"{self.base_url}/oauth20_authorize.srf"
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "offline_access Mail.ReadWrite",
            "login_hint": email,
        }
        auth_url = f"{auth_url}?{urlencode(params)}"

        headers = self._get_headers()
        post_headers = self._get_headers(
            {"content-type": "application/x-www-form-urlencoded"}
        )

        # GET login page (qua proxy nếu có)
        resp = requests.get(
            auth_url, headers=headers, allow_redirects=True, proxies=self.proxies
        )
        html = resp.text

        post_url = self._extract_post_url(html)
        ppft = self._extract_ppft(html)

        login_data = {
            "ps": "2",
            "PPFT": ppft,
            "PPSX": "Passp",
            "NewUser": "1",
            "login": email,
            "loginfmt": email,
            "passwd": password,
            "type": "11",
            "LoginOptions": "1",
            "i13": "1",
        }

        login_resp = requests.post(
            post_url,
            data=login_data,
            headers=post_headers,
            cookies=resp.cookies.get_dict(),
            allow_redirects=False,
            proxies=self.proxies,
        )

        redirect_url = login_resp.headers.get("Location")

        # Nếu bị chuyển sang proofs/Add (Let's protect your account)
        if redirect_url and "proofs/Add" in redirect_url:
            redirect_url = self._handle_add_proofs_page(
                redirect_url, login_resp.cookies.get_dict()
            )

        if not redirect_url:
            match = re.search(r'id="fmHF"\s+action="(.*?)"', login_resp.text)
            if not match:
                raise RuntimeError(
                    "Không tìm thấy form fmHF để tiếp tục login (có thể 2FA)."
                )
            post_url_2 = match.group(1)

            if "Update?mkt=" in post_url_2:
                redirect_url = self._handle_consent_page(
                    post_url_2, login_resp.text, login_resp.cookies.get_dict()
                )
            elif "Add?mkt=" in post_url_2:
                # Một số case action là Add?mkt= sẽ dẫn tới proofs/Add
                if post_url_2.startswith("/"):
                    post_url_2 = "https://account.live.com" + post_url_2
                redirect_url = self._handle_add_proofs_page(
                    post_url_2, login_resp.cookies.get_dict()
                )
            else:
                raise RuntimeError("2FA hoặc xác minh bảo mật – không auto được")

        code = self._extract_code_from_url(redirect_url)

        token_data = {
            "code": code,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        token_resp = requests.post(
            self.token_url, data=token_data, headers=post_headers, proxies=self.proxies
        )

        token_json = token_resp.json()
        if token_resp.status_code != 200:
            raise RuntimeError(
                f"Lấy token thất bại: {token_resp.status_code} - {token_json}"
            )

        return token_json

    def refresh_access_token(self, refresh_token: str):
        """
        Lấy access_token mới từ refresh_token.
        """
        headers = self._get_headers(
            {"content-type": "application/x-www-form-urlencoded"}
        )
        data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "redirect_uri": self.redirect_uri,
            "scope": "offline_access Mail.ReadWrite",
        }
        resp = requests.post(
            self.token_url, data=data, headers=headers, proxies=self.proxies
        )
        token_json = resp.json()
        if resp.status_code != 200:
            raise RuntimeError(
                f"Refresh token thất bại: {resp.status_code} - {token_json}"
            )
        return token_json


# ============================
# HÀM LẤY 3 EMAIL MỚI NHẤT (GRAPH) + CHUẨN HOÁ FIELD
# ============================

def get_latest_emails(access_token: str, top: int = 3, proxies=None):
    """
    Lấy `top` email mới nhất bằng Microsoft Graph, trả về list dict:
    {
        id, subject, from_addr, from_name, received, preview
    }
    """
    url = "https://graph.microsoft.com/v1.0/me/messages"
    params = {
        "$top": top,
        "$orderby": "receivedDateTime desc",
        "$select": "id,subject,from,receivedDateTime,bodyPreview",
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    resp = requests.get(url, headers=headers, params=params, proxies=proxies)

    if resp.status_code != 200:
        raise RuntimeError(f"Lỗi khi lấy email: {resp.status_code} - {resp.text}")

    data = resp.json()
    raw_messages = data.get("value", [])

    emails = []
    for msg in raw_messages:
        sender = (msg.get("from") or {}).get("emailAddress", {}) or {}
        emails.append(
            {
                "id": msg.get("id"),
                "subject": msg.get("subject"),
                "from_addr": sender.get("address"),
                "from_name": sender.get("name"),
                "received": msg.get("receivedDateTime"),
                "preview": msg.get("bodyPreview"),
            }
        )
    return emails

# ============================
# MAIN SCRIPT
# ============================

if __name__ == "__main__":
    # Hỗ trợ nhiều format:
    #  1) Username|Password|access_token|refresh_token|Proxy              (cũ)
    #  2) Username|Password|access_token|refresh_token|Client_id|Proxy    (mới)
    #  3) Username|Password||refresh_token|Client_id                      (mới, không access_token, không Proxy)
    raw = input(
        "Nhập: Username|Password|access_token|refresh_token|Client_id|Proxy\n"
        "(Có thể bỏ access_token / Client_id / Proxy nếu không có)\n> "
    ).strip()

    parts = [p.strip() for p in raw.split("|")] if raw else []
    n = len(parts)

    # Các field cơ bản
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
        # Có 2 khả năng:
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
            # Khả năng cao là Proxy
            proxy_str = last
        else:
            # Còn lại coi như Client_id
            client_id_input = last
    # n <= 4 => không có client_id, không có proxy

    # Chuẩn bị proxies cho requests
    proxies = None
    if proxy_str:
        proxies = {
            "http": proxy_str,
            "https": proxy_str,
        }

    # Truyền client_id (nếu có) vào class
    auth = GetOAuth2Token(client_id=client_id_input or None, proxies=proxies)

    def fetch_emails_with_token(token: str):
        return get_latest_emails(token, top=3, proxies=proxies)

    emails = None
    final_access_token = access_token_input
    final_refresh_token = refresh_token_input

    try:
        # 1) Nếu có sẵn access_token → thử dùng luôn
        if final_access_token:
            try:
                emails = fetch_emails_with_token(final_access_token)
                print("Dùng access_token có sẵn để lấy email.")
            except Exception as e:
                print("Access token có sẵn không dùng được, sẽ thử refresh_token:", e)
                emails = None

        # 2) Nếu chưa có email và có refresh_token → thử refresh (dùng client_id đã truyền)
        if emails is None and final_refresh_token:
            try:
                token_result = auth.refresh_access_token(final_refresh_token)
                print("Refresh token thành công:")
                print(token_result)

                final_access_token = token_result.get("access_token")
                # refresh_token có thể được rotate, cập nhật lại nếu cần
                final_refresh_token = token_result.get(
                    "refresh_token", final_refresh_token
                )

                emails = fetch_emails_with_token(final_access_token)
                print("Dùng access_token sau refresh để lấy email.")
            except Exception as e:
                print(
                    "Refresh token không dùng được, sẽ thử login bằng username/password:",
                    e,
                )
                emails = None

        # 3) Nếu vẫn chưa có email → login bằng username/password
        if emails is None:
            token_result = auth.run(email, password)
            print("Token response (mới):")
            print(token_result)

            final_access_token = token_result.get("access_token")
            final_refresh_token = token_result.get("refresh_token")

            emails = fetch_emails_with_token(final_access_token)

        # =============================
        # 4) Kiểm tra email mã bảo mật Facebook
        # =============================
        fb_code = None
        for mail in emails:
            subject = (mail.get("subject") or "").strip()
            from_addr = (mail.get("from_addr") or "").lower()
            from_name = (mail.get("from_name") or "").strip()

            if from_addr == "security@facebookmail.com" and from_name == "Facebook":
                m = re.search(
                    r"(\d{4,8})\s+là mã bảo mật Facebook của bạn", subject
                )
                if m:
                    fb_code = m.group(1)
                    break

        if fb_code:
            # Nếu có mã bảo mật → chỉ in mã
            print(fb_code)
        else:
            # Nếu không có → in 3 email như hiện tại
            print("\n=== 3 EMAIL MỚI NHẤT ===")
            for i, mail in enumerate(emails, start=1):
                print(f"\nEmail #{i}")
                print("Subject :", mail.get("subject"))
                if mail.get("from_addr"):
                    print(
                        "From    :",
                        f'{mail.get("from_name")} <{mail.get("from_addr")}>',
                    )
                else:
                    print("From    :", None)
                print("Received:", mail.get("received"))
                print("Preview :", mail.get("preview"))

    except Exception as e:
        print("Có lỗi xảy ra:", e)