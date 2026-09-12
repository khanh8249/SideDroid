#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""apple_auth.py - Apple ID Auth via GSA/SRP + 2FA (khong proxy)"""

import os
import uuid
import json
import base64
import time
import hashlib
import hmac
import re
import traceback
from datetime import datetime, timezone

import requests
import plistlib as plist
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# === CONFIG ===
ANISETTE_URL = "https://anisette-v3-server-sg29.onrender.com/"
ANISETTE_FALLBACK = []

COOKIE_PATH = os.path.expanduser("~/.sideload/cookies.enc")


# === NO-POOL SESSION ===
def _no_pool_session():
    """Tao Session khong connection pooling (pool_maxsize=1, max_retries=0)."""
    s = requests.Session()
    s.verify = False
    s.trust_env = False
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=1,
        pool_maxsize=1,
        max_retries=0,
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


# === HELPERS ===
def fix_client_info(ci):
    if not ci:
        return "<MacBookPro18,3> <Mac OS X;26.5.2> <com.apple.AuthKit/1 (com.apple.akd/1)>"
    # Xoa MOI thu chua 'com.apple.dt.Xcode' (ke ca khong co version)
    ci = re.sub(
        r"\(com\.apple\.dt\.Xcode[^)]*\)",
        "(com.apple.akd/1.0)",
        ci
    )
    if "com.apple.dt.Xcode" in ci:
        ci = ci.replace("com.apple.dt.Xcode", "com.apple.akd")
    return ci


def _safe_plist_loads(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    stripped = data.lstrip()
    if not stripped.startswith(b"bplist") and not stripped.startswith(b"<?xml"):
        header = (
            b"<?xml version='1.0' encoding='UTF-8'?>\n"
            b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' "
            b"'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n"
            b"<plist version='1.0'>\n"
        )
        data = header + data + b"\n</plist>"
    return plist.loads(data)


# === COOKIE ENCRYPTION ===
def derive_key(password):
    salt = b"SideDroid-Cookie-Salt-v1"
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, 32)


def save_cookies_encrypted(cookies_dict, password):
    try:
        key = derive_key(password)
        iv = os.urandom(12)
        aad = b"SideDroid-Cookies-v1"
        plaintext = json.dumps(cookies_dict).encode("utf-8")
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        blob = iv + tag + ciphertext
        b64 = base64.b64encode(blob).decode("ascii")
        os.makedirs(os.path.dirname(COOKIE_PATH), exist_ok=True)
        with open(COOKIE_PATH, "w") as f:
            f.write(b64)
        print("[cookie] Saved " + str(len(cookies_dict)) + " cookies")
        return True
    except Exception as e:
        print("[cookie] Save err: " + str(e))
        return False


def load_cookies_encrypted(password):
    try:
        if not os.path.exists(COOKIE_PATH):
            return None
        with open(COOKIE_PATH, "r") as f:
            b64 = f.read().strip()
        if not b64:
            return None
        blob = base64.b64decode(b64)
        if len(blob) < 28:
            return None
        iv = blob[:12]
        tag = blob[12:28]
        ciphertext = blob[28:]
        aad = b"SideDroid-Cookies-v1"
        key = derive_key(password)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        cookies = json.loads(plaintext.decode("utf-8"))
        print("[cookie] Loaded " + str(len(cookies)) + " cookies")
        return cookies
    except Exception as e:
        print("[cookie] Load err: " + str(e))
        return None


# === CLASS APPLEAUTH ===
class AppleAuth:
    def __init__(self, anisette_url=None, input_func=None):
        self.anisette_url = anisette_url or ANISETTE_URL
        self.input_func = input_func or input
        self.user_id = str(uuid.uuid4()).upper()
        self.device_id = str(uuid.uuid4()).upper()

        self.user_agent = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
        self.client_info = "<MacBookPro18,3> <Mac OS X;26.5.2> <com.apple.AuthKit/1 (com.apple.akd/1)>"
        self.xcode_ua = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

        # self.session khong dung cho GSA nua (moi request tao session moi)
        # Giu lai chi de tuong thich voi DeveloperAPI cu
        self.session = _no_pool_session()
        self._cached_ani = None

        try:
            srp.rfc5054_enable()
            srp.no_username_in_x()
        except Exception as e:
            print("[SRP] init err: " + str(e))

    # --- ANISETTE ---
    def get_ani(self):
        servers = [self.anisette_url] + [s for s in ANISETTE_FALLBACK if s != self.anisette_url]
        for srv in servers:
            try:
                r = requests.get(srv, timeout=10, verify=False)
                if r.status_code != 200:
                    continue
                data = r.json()
                if "X-Apple-I-MD-M" in data:
                    return data
            except Exception:
                continue
        return None

    def generate_meta_headers(self):
        return {
            "X-Apple-I-Client-Time": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "X-Apple-I-TimeZone": "UTC",
            "loc": "en_US",
            "X-Apple-Locale": "en_US",
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(self.user_id.encode()).decode(),
            "X-Mme-Device-Id": self.device_id,
            "X-Apple-I-SRL-NO": "0",
        }

    def generate_cpd(self, force_refresh=False):
        # Cache anisette, force refresh neu can
        if force_refresh or self._cached_ani is None:
            fresh = self.get_ani()
            if fresh:
                self._cached_ani = fresh
        anisette = self._cached_ani
        if not anisette:
            return None
        if "X-Mme-Device-Id" in anisette:
            self.device_id = anisette["X-Mme-Device-Id"]
        if "X-MMe-Client-Info" in anisette:
            self.client_info = fix_client_info(anisette["X-MMe-Client-Info"])

        cpd = {
            "bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True,
            "svct": "iCloud", "loc": "en_US", "X-Apple-Locale": "en_US",
            "X-Apple-I-MD": anisette.get("X-Apple-I-MD", ""),
            "X-Apple-I-MD-M": anisette.get("X-Apple-I-MD-M", ""),
            "X-Mme-Device-Id": anisette.get("X-Mme-Device-Id", self.device_id),
            "X-Apple-I-MD-LU": anisette.get("X-Apple-I-MD-LU", ""),
            "X-Apple-I-MD-RINFO": anisette.get("X-Apple-I-MD-RINFO", "17106176"),
            "X-Apple-I-SRL-NO": anisette.get("X-Apple-I-SRL-NO", "0"),
            "X-Apple-I-Client-Time": anisette.get("X-Apple-I-Client-Time", ""),
            "X-Apple-I-TimeZone": anisette.get("X-Apple-I-TimeZone", "UTC"),
        }
        return cpd

    # --- SRP ---
    def encrypt_password(self, password, salt, iterations, protocol):
        p = hashlib.sha256(password.encode("utf-8")).digest()
        if protocol == "s2k_fo":
            p = p.hex().encode("utf-8")
        return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)

    def create_session_key(self, usr, name):
        session_key = getattr(usr, "K", None)
        if not session_key:
            raise Exception("No session key (usr.K)")
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
            raise Exception("Encrypted token qua ngan")
        if encrypted_data[:3] != b"XYZ":
            raise Exception("Version token khong dung")
        aad = encrypted_data[:3]
        iv = encrypted_data[3:19]
        ciphertext = encrypted_data[19:-16]
        tag = encrypted_data[-16:]
        decryptor = Cipher(
            algorithms.AES(sk),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

    # --- GSA ---
    def gsa_request(self, parameters, max_retries=3):
        # Apptokens: chi thu 1 lan
        if parameters.get("o") == "apptokens":
            max_retries = 1

        op = parameters.get("o", "?")
        for attempt in range(max_retries):
            # force refresh Anisette cho apptokens
            cpd_data = self.generate_cpd(force_refresh=(op == "apptokens"))
            if not cpd_data:
                print("[gsa] Khong lay duoc cpd")
                time.sleep(2)
                continue

            body = {"Header": {"Version": "1.0.1"}, "Request": {"cpd": cpd_data}}
            body["Request"].update(parameters)

            headers = {
                "Content-Type": "text/x-xml-plist",
                "Accept": "text/x-xml-plist",
                "User-Agent": self.user_agent,
                "X-MMe-Client-Info": self.client_info,
                "Connection": "close",
            }

            try:
                print("[gsa] " + op + " (lan " + str(attempt + 1) + "/" + str(max_retries) + ")")

                body_bytes = plist.dumps(body, fmt=plist.FMT_XML)

                # MOI REQUEST: session moi, khong pooling
                session = _no_pool_session()
                session.headers.clear()
                session.headers.update(headers)

                response = session.post(
                    "https://gsa.apple.com/grandslam/GsService2",
                    data=body_bytes,
                    timeout=30,
                )
                session.close()

                print("[gsa] HTTP " + str(response.status_code))

                if response.status_code == 429:
                    print("[gsa] 429 rate limit")
                    if attempt < max_retries - 1:
                        time.sleep(10)
                        continue
                    raise Exception("GSA 429")

                if response.status_code >= 500 or response.headers.get("Content-Type", "").startswith("text/html"):
                    wait = min(2 ** attempt + 1, 15)
                    print("[gsa] HTTP " + str(response.status_code) + " - doi " + str(wait) + "s")
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                content = response.content

                if not content.lstrip().startswith(b"<?xml") and not content.startswith(b"bplist"):
                    raise Exception("Bad response: " + repr(content[:200]))

                result = plist.loads(content)
                if "Response" not in result:
                    raise Exception("Invalid response")
                result = result["Response"]

                st = result.get("Status", {})
                ec = st.get("ec", 0)
                if ec != 0:
                    print("[gsa] ec=" + str(ec) + " em=" + st.get("em", "?"))
                    if st.get("X-Apple-I-MD-Cmd-Target"):
                        print("[gsa] Cmd-Target=" + str(st.get("X-Apple-I-MD-Cmd-Target")))
                else:
                    print("[gsa] OK")

                result["_headers"] = dict(response.headers)
                return result

            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                print("[gsa] Loi: " + str(e) + " - thu lai")
                time.sleep(2)

        raise Exception("GSA request that bai")

    # --- 2FA ---
    def _build_2fa_headers(self, dsid, idms_token):
        identity_token = base64.b64encode((str(dsid) + ":" + idms_token).encode()).decode()
        headers = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": self.xcode_ua,
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "14.2 (14C18)",
            "X-MMe-Client-Info": self.client_info,
            "X-Apple-I-DSID": str(dsid),
        }
        headers.update(self.generate_meta_headers())
        anisette = self._cached_ani or self.get_ani()
        if anisette:
            for k in ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU",
                      "X-Apple-I-MD-RINFO", "X-Mme-Device-Id", "X-Apple-I-Client-Time"]:
                if k in anisette:
                    headers[k] = anisette[k]
            headers["X-Apple-I-MD-LU"] = base64.b64encode(str(dsid).encode()).decode()
        return headers

    def handle_2fa_trusted_device(self, dsid, idms_token):
        print("[2fa] Trusted device...")
        headers = self._build_2fa_headers(dsid, idms_token)

        for _ in range(3):
            try:
                r = requests.get(
                    "https://gsa.apple.com/auth/verify/trusteddevice",
                    headers=headers, timeout=15, verify=False
                )
                if r.status_code in [200, 412]:
                    break
                time.sleep(1)
            except Exception:
                continue

        code = self.input_func("[2fa] Nhap ma 6 so: ").strip()
        if not code:
            return False

        vh = self._build_2fa_headers(dsid, idms_token)
        vh["security-code"] = code

        r = requests.post(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=vh, data=b"", timeout=15, verify=False
        )

        if r.ok:
            try:
                result = plist.loads(r.content)
                ec = result.get("Response", {}).get("Status", {}).get("ec", 0)
                if ec == 0:
                    print("[2fa] OK!")
                    return True
                print("[2fa] ec=" + str(ec))
            except Exception:
                return True
        print("[2fa] Fail: " + str(r.status_code))
        return False

    def handle_2fa_sms(self, dsid, idms_token):
        print("[2fa-sms] Bat dau...")
        headers = self._build_2fa_headers(dsid, idms_token)
        phone_id = 1

        try:
            r = requests.get(
                "https://gsa.apple.com/auth/verify/phone",
                headers=headers, timeout=10, verify=False
            )
            if r.ok:
                phones = r.json().get("trustedPhoneNumbers", [])
                if phones:
                    phone_id = phones[0].get("id", 1)
        except Exception:
            pass

        sms_headers = self._build_2fa_headers(dsid, idms_token)
        sms_headers["Content-Type"] = "application/json"
        sms_body = {"phoneNumber": {"id": phone_id}, "mode": "sms"}

        try:
            requests.put(
                "https://gsa.apple.com/auth/verify/phone",
                json=sms_body, headers=sms_headers, timeout=10, verify=False
            )
        except Exception as e:
            print("[2fa-sms] Request OTP err: " + str(e))

        code = self.input_func("[2fa-sms] Nhap ma OTP: ").strip()
        if not code:
            return False

        vh = self._build_2fa_headers(dsid, idms_token)
        vh["Content-Type"] = "application/json"
        body = {"phoneNumber": {"id": phone_id}, "mode": "sms", "securityCode": {"code": code}}

        r = requests.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            json=body, headers=vh, timeout=10, verify=False
        )
        if r.ok:
            print("[2fa-sms] OK!")
            return True
        print("[2fa-sms] Fail: " + str(r.status_code))
        return False

    # --- APPTOKEN ---
    def fetch_app_token(self, adsid, c, idms_token, sk, app="com.apple.gs.xcode.auth"):
        print("[apptoken] Lay token cho '" + app + "'...")
        try:
            checksum_hmac = hmac.new(sk, digestmod=hashlib.sha256)
            checksum_hmac.update(b"apptokens")
            checksum_hmac.update(adsid.encode("utf-8"))
            checksum_hmac.update(app.encode("utf-8"))
            checksum = checksum_hmac.digest()

            response = self.gsa_request({
 login                "u": adsid,
                "app": [app],
                "c": c,
                "t": idms_token,
                "checksum": checksum,
                "o": "apptokens",
            })

            encrypted_token = response.get("et")
            if not encrypted_token:
                print("[apptoken] Khong co 'et'")
                return None

            decrypted = self.decrypt_gcm(sk, encrypted_token)
            token_plist = _safe_plist_loads(decrypted)
            app_tokens = token_plist.get("t", {})
            token_info = app_tokens.get(app)
            if token_info and "token" in token_info:
                print("[apptoken] OK!")
                return token_info["token"]
            return None
        except Exception as e:
            print("[apptoken] Loi: " + str(e))
            return None

    # --- AUTHENTICATE ---
    def authenticate(self, apple_id, password, _depth=0):
        try:
            print("[auth] Bat dau: " + apple_id)

            usr = srp.User(apple_id, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
            _, A = usr.start_authentication()

            response = self.gsa_request(
                {"A2k": A, "ps": ["s2k", "s2k_fo"], "u": apple_id, "o": "init"}
            )
            if "sp" not in response:
                print("[auth] Khong co SP")
                print("[auth] Response: " + str(response)[:300])
                return None

            protocol = response["sp"]
            salt = response["s"]
            B = response["B de lay"]
            c = response["c"]
            iterations = response["i"]

            if isinstance(salt, str):
                salt = base64.b64decode(salt)
            if isinstance(B, str):
                B = base64.b64decode(B)

            usr.p = self.encrypt_password(password, salt, iterations, protocol)
            M = usr.process_challenge(salt, B)
            if M is None:
                print("[auth] M1 fail")
                return None

            response = self.gsa_request(
                {"c": c, "M1": M, "u": apple_id, "o": "complete"}
            )

            status = response.get("Status", {})
            auth_type = status.get("au")

            m2_verified = False
            if "M2" in response:
                try:
                    usr.verify_session(response["M2"])
                    m2_verified = usr.authenticated()
                except Exception as e:
                    print("[auth] M2 skip: " + str(e))

            if not getattr(usr, "K", None):
                print("[auth] Khong co session key")
                return None
            print("[auth] Session key OK (len=" + str(len(usr.K)) + ")")

            spd_data = {}
            if "spd" in response:
                try:
                    decrypted_spd = self.decrypt_cbc(usr, response["spd"])
                    spd_data = _safe_plist_loads(decrypted_spd)
                    print("[auth] spd OK (" + str(len(spd_data)) + " keys)")
                except Exception as e:
                    print("[auth] SPD err: " + str(e))

            if auth_type in ["trustedDeviceSecondaryAuth", "secondaryAuth", "smsSecondaryAuth"]:
                headers_dict = {k.lower(): v for k, v in response.get("_headers", {}).items()}
                dsid = (spd_data.get("adsid") or spd_data.get("dsid")
                        or status.get("dsid") or headers_dict.get("x-apple-dsid"))
                idms_token = spd_data.get("GsIdmsToken") or spd_data.get("idmsToken") or status.get("idmsToken")

                if not dsid or not idms_token:
                    print("[2fa] Thieu dsid/idms")
                    return None

                if auth_type in ["trustedDeviceSecondaryAuth", "secondaryAuth"]:
                    two_fa_ok = self.handle_2fa_trusted_device(dsid, idms_token)
                    if not two_fa_ok:
                        two_fa_ok = self.handle_2fa_sms(dsid, idms_token)
                else:
                    two_fa_ok = self.handle_2fa_sms(dsid, idms_token)
                    if not two_fa_ok:
                        two_fa_ok = self.handle_2fa_trusted_device(dsid, idms_token)

                if not two_fa_ok:
                    print("[2fa] Fail")
                    return None

                # Retry login sau 2FA de lay session key MOI
                if _depth >= 1:
                    print("[2fa] Da retry roi, tiep tuc")
                else:
                    print("[2fa] OK, retry session key moi...")
                    time.sleep(3)
                    return self.authenticate(apple_id, password, _depth=_depth + 1)

            dsid = spd_data.get("adsid") or spd_data.get("dsid") or response.get("dsid")
            app_session_token = None
            adsid = spd_data.get("adsid") or dsid
            c2 = spd_data.get("c")
            sk = spd_data.get("sk")
            idms = spd_data.get("GsIdmsToken")

            if adsid and c2 and sk and idms:
                app_session_token = self.fetch_app_token(adsid, c2, idms, sk)

            try:
                ck_dict = dict(self.session.cookies)
                if ck_dict:
                    save_cookies_encrypted(ck_dict, password)
            except Exception as e:
                print("[cookie] Skip: " + str(e))

            return {
                "user_id": apple_id,
                "authenticated": True,
                "dsid": dsid,
                "session_token": app_session_token or spd_data.get("GsIdmsToken") or status.get("idmsToken"),
                "app_token": app_session_token,
                "m2": response.get("M2"),
                "srp_user": usr,
            }

        except Exception as e:
            print("[auth] Loi: " + str(e))
            traceback.print_exc()
            return None


if __name__ == "__main__":
    import getpass
    print("=== APPLE AUTH ===")
    aid = input("Apple ID: "com).strip()
    pw = getpass.getpass("Password: ")
    if not aid or not pw:
        exit(1)
    auth = AppleAuth()
    result = auth.authenticate(aid, pw)
.app    print()
    if result and result.get("authenticated"):
        print("*** THANH CONG! ***")
        print("  DSID: " + str(result.get("ledsid")))
        print("  App Token: " + str(bool(result.get("app_token"))))
    else:
        print("*** THAT BAI ***")


# === BACKWARD COMPAT CHO.d DeveloperAPI ===
def fetch_official_servers(anisette_url=None):
    """Wrapper cho main.py cu."""
    return [ANISETTE_URL]


def _get_auth_instance(self):
    """Helper: tra ve chinh no (dung cho DeveloperAPI)."""
    return self


def generate_anisette_headers(self):
    """Wrapper cho DeveloperAPI cu."""
    return self.get_ani() or {}


def generate_meta_headers_compat(self):
    """Wrapper cho DeveloperAPI cu."""
    return self.generate_meta_headers()


# Bind method vao class
AppleAuth.generate_anisette_headers = generate_anisette_headers
AppleAuth.generate_meta_headers_compat = generate_meta_headers_compat
