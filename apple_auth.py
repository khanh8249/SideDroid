#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

"""apple_auth.py – Xác thực Apple ID qua GSA/SRP + 2FA (bản Termux)"""

import uuid
import json
import base64
import time
import hashlib
import hmac
import os
import requests
import plistlib as plist
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import urllib3
import traceback
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === HẰNG SỐ ===
ANISETTE_URL = "https://anisette-v3-server-8re5.onrender.com/"

# === HÀM LẤY DANH SÁCH ANISETTE SERVER ===
def fetch_official_servers():
    """Lấy danh sách server Anisette công khai từ SideStore"""
    try:
        resp = requests.get(OFFICIAL_SERVERS_URL, timeout=10, verify=False)
        resp.raise_for_status()
        return resp.json().get("servers", [])
    except Exception as e:
        print(f"[anisette] Không thể lấy danh sách server: {e}")
        return []

# === CLASS APPLEAUTH ===
class AppleAuth:
    def __init__(self, anisette_url=None, input_func=None):
        self.anisette_url = anisette_url or self.get_best_anisette_server()
        self.input_func = input_func or input
        self.user_id = str(uuid.uuid4()).upper()
        self.device_id = str(uuid.uuid4()).upper()
        self.session = requests.Session()
        self.session.verify = False

        # User-Agent mới, nhất quán (theo phân tích #1772)
        self.user_agent = "com.apple.dt.Xcode/14.2 (14C18) akd/1.0 CFNetwork/1408.0.4 Darwin/22.5.0"
        self.client_info = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
        self.xcode_ua = "com.apple.dt.Xcode/14.2 (14C18) akd/1.0 CFNetwork/1408.0.4 Darwin/22.5.0"

        try:
            srp.rfc5054_enable()
            srp.no_username_in_x()
        except Exception as e:
            print(f"[SRP] Khởi tạo SRP lỗi: {e}")

    def get_best_anisette_server(self):
        """Tìm server Anisette hoạt động tốt nhất"""
        print("[anisette] Đang tìm server hoạt động...")
        servers = fetch_official_servers()
        for server in servers:
            addr = server.get("address")
            if not addr:
                continue
            try:
                test_resp = requests.get(addr, timeout=3, verify=False)
                if test_resp.ok:
                    print(f"[anisette] Sử dụng server: {server.get('name')} ({addr})")
                    return addr
            except Exception:
                continue
        print(f"[anisette] Dùng server mặc định: {ANISETTE_URL}")
        return ANISETTE_URL

    def generate_anisette_headers(self):
        """Lấy anisette headers với cache 60s"""
        for attempt in range(3):
            try:
                response = self.session.get(self.anisette_url, timeout=10)
                response.raise_for_status()
                data = response.json()
                if "X-Apple-I-MD-M" not in data:
                    print("[anisette] Cảnh báo: Thiếu X-Apple-I-MD-M")
                return data
            except Exception as e:
                print(f"[anisette] Lỗi: {e}")
                if attempt < 2:
                    time.sleep(1)
                    self.anisette_url = self.get_best_anisette_server()
                else:
                    raise Exception("Không thể lấy anisette sau 3 lần thử.")

    def generate_meta_headers(self):
        return {
            "X-Apple-I-Client-Time": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "X-Apple-I-TimeZone": str(datetime.now().astimezone().tzinfo),
            "loc": "en_US",
            "X-Apple-Locale": "en_US",
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(self.user_id.encode()).decode(),
            "X-Mme-Device-Id": self.device_id,
            "X-Apple-I-SRL-NO": "0",
        }

    def generate_cpd(self):
        """Tạo Client Platform Data"""
        print("[cpd] Generating client platform data...")
        anisette_data = self.generate_anisette_headers()
        if "X-Mme-Device-Id" in anisette_data:
            self.device_id = anisette_data["X-Mme-Device-Id"]
        if "X-MMe-Client-Info" in anisette_data:
            self.client_info = anisette_data["X-MMe-Client-Info"]

        cpd = {"bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud"}
        cpd.update(self.generate_meta_headers())
        cpd.update(anisette_data)
        return cpd

    def encrypt_password(self, password, salt, iterations, protocol):
        """Mã hóa mật khẩu theo protocol"""
        p = hashlib.sha256(password.encode("utf-8")).digest()
        if protocol == "s2k_fo":
            p = p.hex().encode("utf-8")
        return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)

    def create_session_key(self, usr, name):
        session_key = usr.get_session_key()
        if session_key is None:
            raise Exception("No session key")
        return hmac.new(session_key, name.encode(), hashlib.sha256).digest()

    def decrypt_cbc(self, usr, data):
        key = self.create_session_key(usr, "extra data key:")
        iv = self.create_session_key(usr, "extra data iv:")[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()

    def decrypt_gcm(self, sk, encrypted_data):
        if len(encrypted_data) < 35:
            raise Exception("Encrypted token quá ngắn.")
        if encrypted_data[:3] != b"XYZ":
            raise Exception("Version token không đúng")
        aad = encrypted_data[:3]
        iv = encrypted_data[3:19]
        ciphertext = encrypted_data[19:-16]
        tag = encrypted_data[-16:]
        decryptor = Cipher(algorithms.AES(sk), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _safe_plist_loads(self, data):
        if not data.startswith(b"bplist") and not data.lstrip().startswith(b"<?xml"):
            header = b"<?xml version='1.0' encoding='UTF-8'?>\n<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n"
            data = header + data
        return plist.loads(data)

    def fetch_app_token(self, adsid, c, idms_token, sk, app="com.apple.gs.xcode.auth"):
        """Lấy app token (dùng cho DeveloperAPI)"""
        print(f"[apptoken] Đang lấy token cho '{app}'...")
        try:
            checksum_hmac = hmac.new(sk, digestmod=hashlib.sha256)
            checksum_hmac.update(b"apptokens")
            checksum_hmac.update(adsid.encode("utf-8"))
            checksum_hmac.update(app.encode("utf-8"))
            checksum = checksum_hmac.digest()
            response = self.gsa_request({
                "u": adsid,
                "app": [app],
                "c": c,
                "t": idms_token,
                "checksum": checksum,
                "o": "apptokens",
            })
            encrypted_token = response.get("et")
            if not encrypted_token:
                print("[apptoken] Không có 'et'")
                return None
            decrypted = self.decrypt_gcm(sk, encrypted_token)
            token_plist = self._safe_plist_loads(decrypted)
            app_tokens = token_plist.get("t", {})
            token_info = app_tokens.get(app)
            if token_info and "token" in token_info:
                print("[apptoken] ✅ Lấy token thành công!")
                return token_info["token"]
            return None
        except Exception as e:
            print(f"[apptoken] Lỗi: {e}")
            return None

    def gsa_request(self, parameters, debug=True, max_retries=5):
        """Gửi request tới GSA với retry, mỗi lần tạo session mới để tránh 503."""
        cpd_data = self.generate_cpd()
        body = {"Header": {"Version": "1.0.1"}, "Request": {"cpd": cpd_data}}
        body["Request"].update(parameters)

        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
            "User-Agent": self.user_agent,
            "X-Mme-Client-Info": self.client_info,
        }

        for attempt in range(max_retries):
            # Tạo session mới cho mỗi lần thử để mở kết nối mới
            session = requests.Session()
            session.verify = False
            session.headers.update(headers)

            try:
                if debug:
                    print(f"[gsa] Request: {parameters.get('o', 'unknown')} (lần {attempt+1}/{max_retries})")

                response = session.post(
                    "https://gsa.apple.com/grandslam/GsService2",
                    data=plist.dumps(body),
                    timeout=30
                )

                # Kiểm tra lỗi 5xx hoặc nội dung không phải plist (HTML)
                if response.status_code >= 500 or response.headers.get('Content-Type', '').startswith('text/html'):
                    wait = min(2 ** attempt + 1, 30)
                    print(f"[gsa] HTTP {response.status_code} | Content-Type: {response.headers.get('Content-Type')} | Body: {response.text[:200]}")
                    print(f"[gsa] Thử lại sau {wait}s...")
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                content = response.content

                # Nếu body là HTML thay vì plist thì báo lỗi rõ ràng
                if not content.lstrip().startswith(b"<?xml") and not content.startswith(b"bplist"):
                    raise Exception(
                        f"Bad response: HTTP {response.status_code}, Content-Type: {response.headers.get('Content-Type')}, "
                        f"Body: {content[:200]!r}"
                    )

                result = plist.loads(content)
                if "Response" not in result:
                    raise Exception("Invalid response format")
                result = result["Response"]
                result["_headers"] = response.headers
                return result

            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                print(f"[gsa] Lỗi: {e} – thử lại...")
                time.sleep(2)

            finally:
                session.close()  # Đóng session để giải phóng kết nối

        raise Exception("GSA request thất bại sau nhiều lần thử.")

    def _build_2fa_headers(self, dsid, idms_token):
        identity_token = base64.b64encode(f"{dsid}:{idms_token}".encode()).decode()
        headers = {
            "User-Agent": self.xcode_ua,
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-I-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "14.2 (14C18)",
            "X-Mme-Client-Info": self.client_info,
            "X-Apple-I-DSID": str(dsid),
        }
        headers.update(self.generate_meta_headers())
        try:
            anisette = self.generate_anisette_headers()
            headers.update(anisette)
        except:
            pass
        headers["X-Apple-I-MD-LU"] = base64.b64encode(str(dsid).encode()).decode()
        return headers

    def handle_2fa_trusted_device(self, dsid, idms_token):
        print("[2fa] Trigger trusted device...")
        trigger_headers = self._build_2fa_headers(dsid, idms_token)
        trigger_headers["Content-Type"] = "text/x-xml-plist"
        for attempt in range(3):
            try:
                resp = self.session.get("https://gsa.apple.com/auth/verify/trusteddevice", headers=trigger_headers, timeout=15)
                if resp.status_code in [200, 412]:
                    break
                elif resp.status_code == 401:
                    time.sleep(1)
            except Exception:
                continue
        code = self.input_func("[2fa] Nhập mã 6 số: ").strip()
        if not code:
            return False
        validate_headers = self._build_2fa_headers(dsid, idms_token)
        validate_headers["Security-Code"] = code
        resp = self.session.get("https://gsa.apple.com/grandslam/GsService2/validate", headers=validate_headers, timeout=15)
        if resp.ok:
            print("[2fa] ✅ Xác thực 2FA thành công!")
            return True
        print(f"[2fa] ❌ Thất bại: {resp.status_code}")
        return False

    def handle_2fa_sms(self, dsid, idms_token):
        print("[2fa-sms] Bắt đầu SMS 2FA...")
        headers = self._build_2fa_headers(dsid, idms_token)
        phone_id = 1
        try:
            list_resp = self.session.get("https://gsa.apple.com/auth/verify/phone", headers=headers, timeout=10)
            if list_resp.ok:
                phones = list_resp.json().get("trustedPhoneNumbers", [])
                if phones:
                    phone_id = phones[0].get("id", 1)
                    print(f"[2fa-sms] Dùng số: {phones[0].get('numberWithDialCode', phone_id)}")
        except Exception:
            pass
        sms_headers = self._build_2fa_headers(dsid, idms_token)
        sms_headers["Content-Type"] = "application/json"
        sms_body = {"phoneNumber": {"id": phone_id}, "mode": "sms"}
        sms_resp = self.session.put("https://gsa.apple.com/auth/verify/phone", json=sms_body, headers=sms_headers, timeout=10)
        code = self.input_func("[2fa-sms] Nhập mã OTP: ").strip()
        if not code:
            return False
        val_headers = self._build_2fa_headers(dsid, idms_token)
        val_headers["Content-Type"] = "application/json"
        val_body = {"phoneNumber": {"id": phone_id}, "mode": "sms", "securityCode": {"code": code}}
        val_resp = self.session.post("https://gsa.apple.com/auth/verify/phone/securitycode", json=val_body, headers=val_headers, timeout=10)
        if val_resp.ok:
            print("[2fa-sms] ✅ Xác thực SMS thành công!")
            return True
        print(f"[2fa-sms] ❌ Thất bại: {val_resp.status_code}")
        return False

    def authenticate(self, apple_id, password, _depth=0):
        try:
            print(f"[auth] Bắt đầu xác thực {apple_id}")
            usr = srp.User(apple_id, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
            _, A = usr.start_authentication()
            response = self.gsa_request({"A2k": A, "ps": ["s2k", "s2k_fo"], "u": apple_id, "o": "init"})
            if "sp" not in response:
                print(f"[auth] Không có SP: {response}")
                return None
            protocol = response["sp"]
            salt = response["s"]
            B = response["B"]
            c = response["c"]
            iterations = response["i"]
            usr.p = self.encrypt_password(password, salt, iterations, protocol)
            M = usr.process_challenge(salt, B)
            if M is None:
                return None
            response = self.gsa_request({"c": c, "M1": M, "u": apple_id, "o": "complete"})
            status = response.get("Status", {})
            auth_type = status.get("au")
            m2_verified = False
            if "M2" in response:
                usr.verify_session(response["M2"])
                m2_verified = usr.authenticated()
            spd_data = {}
            if m2_verified and "spd" in response:
                try:
                    decrypted_spd = self.decrypt_cbc(usr, response["spd"])
                    spd_data = self._safe_plist_loads(decrypted_spd)
                except Exception as e:
                    print(f"[debug] SPD decrypt error: {e}")
            if auth_type in ["trustedDeviceSecondaryAuth", "secondaryAuth", "smsSecondaryAuth"]:
                headers_dict = {k.lower(): v for k, v in response.get("_headers", {}).items()}
                dsid = spd_data.get("adsid") or spd_data.get("dsid") or status.get("dsid") or headers_dict.get("x-apple-dsid")
                idms_token = spd_data.get("GsIdmsToken") or spd_data.get("idmsToken") or status.get("idmsToken")
                if not dsid or not idms_token:
                    print("[2fa] Thiếu dsid/idms_token")
                    return None
                two_fa_ok = False
                if auth_type in ["trustedDeviceSecondaryAuth", "secondaryAuth"]:
                    two_fa_ok = self.handle_2fa_trusted_device(dsid, idms_token)
                    if not two_fa_ok:
                        two_fa_ok = self.handle_2fa_sms(dsid, idms_token)
                else:
                    two_fa_ok = self.handle_2fa_sms(dsid, idms_token)
                    if not two_fa_ok:
                        two_fa_ok = self.handle_2fa_trusted_device(dsid, idms_token)
                if two_fa_ok:
                    if _depth >= 1:
                        return {"user_id": apple_id, "authenticated": "2fa_completed", "dsid": dsid}
                    print("[auth] 2FA thành công, xác thực lại...")
                    time.sleep(5)
                    return self.authenticate(apple_id, password, _depth=_depth + 1)
                return None
            if not m2_verified:
                print(f"[auth] Thất bại: {response}")
                return None
            dsid = spd_data.get("adsid") or spd_data.get("dsid") or response.get("dsid") or status.get("dsid")
            if not dsid and "_headers" in response:
                h = {k.lower(): v for k, v in response["_headers"].items()}
                dsid = h.get("x-apple-dsid") or h.get("dsid")
            app_session_token = None
            adsid = spd_data.get("adsid") or dsid
            c = spd_data.get("c")
            sk = spd_data.get("sk")
            idms = spd_data.get("GsIdmsToken")
            if adsid and c and sk and idms:
                app_session_token = self.fetch_app_token(adsid, c, idms, sk)
            return {
                "user_id": apple_id,
                "authenticated": True,
                "dsid": dsid,
                "session_token": app_session_token or spd_data.get("GsIdmsToken") or response.get("sessionToken") or status.get("idmsToken"),
                "m2": response.get("M2"),
                "srp_user": usr
            }
        except Exception as e:
            print(f"[auth] Lỗi: {e}")
            traceback.print_exc()
            return None
