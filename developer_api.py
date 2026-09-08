#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import plistlib
import requests
import json
import base64
import time
import uuid
import re
import os

ANISETTE_URL = "https://anisette-v3-server-8re5.onrender.com/"

_QUOTA_MARKERS = (
    "maximum number of app ids",
    "you may create up to",
    "app id limit",
    "every 7 days",
    "created too many app ids",
    "reached the maximum",
)

def classify_app_id_error(last_error):
    if not last_error:
        return "other"
    result_code = last_error.get("resultCode")
    user_string = str(last_error.get("userString", "") or "")
    lower = user_string.lower()
    if result_code == 9401 or "is not available" in lower or "enter a different string" in lower:
        return "unavailable"
    if any(marker in lower for marker in _QUOTA_MARKERS) or "limit" in lower:
        return "quota"
    return "other"

class DeveloperAPI:
    def __init__(self, apple_auth_instance, dsid, session_token):
        self.auth = apple_auth_instance
        self.dsid = dsid
        self.session_token = session_token
        self.session = self.auth.session
        self.base_url = "https://developerservices2.apple.com/services/QH65B2"
        self.services_base_url = "https://developerservices2.apple.com/services/v1"
        self.client_id = "XABBG36SBA"
        self.protocol_version = "QH65B2"
        self.xcode_version = "11.2 (11B41)"
        self.team_id = None
        self.last_error = None
        self._cached_anisette = None
        self._last_anisette_time = 0

    def _get_anisette(self, force=False):
        if force or self._cached_anisette is None or (time.time() - self._last_anisette_time > 60):
            self._cached_anisette = self.auth.generate_anisette_headers()
            self._last_anisette_time = time.time()
        return self._cached_anisette

    def _auth_headers(self, content_type, accept):
        headers = {
            "Content-Type": content_type,
            "User-Agent": "Xcode",
            "Accept": accept,
            "Accept-Language": "en-us",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": self.xcode_version,
            "X-Apple-I-Identity-Id": str(self.dsid) if self.dsid else "",
            "X-Apple-GS-Token": str(self.session_token) if self.session_token else "",
        }
        headers.update(self._get_anisette())
        return headers

    def _make_developer_request(self, action_path, extra_params=None, require_team=True):
        for attempt in range(2):
            headers = self._auth_headers("text/x-xml-plist", "text/x-xml-plist")
            params = {
                "clientId": self.client_id,
                "protocolVersion": self.protocol_version,
                "requestId": str(uuid.uuid4()).upper(),
            }
            if require_team:
                if not self.team_id:
                    raise Exception("Chưa có team_id")
                params["teamId"] = self.team_id
            if extra_params:
                params.update(extra_params)
            url = f"{self.base_url}/{action_path}?clientId={self.client_id}"
            payload = plistlib.dumps(params, fmt=plistlib.FMT_XML)
            try:
                response = self.session.post(url, headers=headers, data=payload, timeout=30)
                if response.status_code >= 500:
                    print(f"[DeveloperAPI] Lỗi {response.status_code} - thử lại...")
                    time.sleep(2)
                    continue
                response.raise_for_status()
                result = plistlib.loads(response.content)
                result_code = result.get("resultCode") or result.get("resultcode")
                if result_code == 1100 and attempt == 0:
                    self._get_anisette(force=True)
                    continue
                return result
            except Exception as e:
                if attempt == 0:
                    print(f"[DeveloperAPI] Lỗi lần 1: {e} - thử lại...")
                    self._get_anisette(force=True)
                    continue
                raise
        raise Exception(f"Request {action_path} thất bại.")

    def list_teams(self):
        try:
            response = self._make_developer_request("listTeams.action", require_team=False)
            return response.get("teams", [])
        except Exception as e:
            print(f"[DeveloperAPI] Lỗi list teams: {e}")
            return []

    def set_team(self, team_id):
        self.team_id = team_id

    def list_devices(self):
        try:
            response = self._make_developer_request("ios/listDevices.action")
            return response.get("devices", [])
        except Exception as e:
            print(f"[DeveloperAPI] Lỗi list devices: {e}")
            return []

    def register_device(self, device_name, device_udid):
        self.last_error = None
        try:
            response = self._make_developer_request("ios/addDevice.action", extra_params={
                "deviceNumber": device_udid,
                "name": device_name,
            })
            device = response.get("device")
            if device:
                return device
            self.last_error = {
                "resultCode": response.get("resultCode"),
                "userString": response.get("userString") or response.get("resultString") or "",
            }
            return None
        except Exception as e:
            self.last_error = {"resultCode": -1, "userString": str(e)}
            return None

    def list_app_ids(self):
        try:
            response = self._make_developer_request("ios/listAppIds.action")
            return response.get("appIds", [])
        except Exception as e:
            print(f"[DeveloperAPI] Lỗi list app ids: {e}")
            return []

    def create_app_id(self, bundle_id, name):
        sanitized = re.sub(r"[^A-Za-z0-9 ]", "", name) or "App"
        self.last_error = None
        try:
            response = self._make_developer_request("ios/addAppId.action", extra_params={
                "identifier": bundle_id,
                "name": sanitized,
            })
            app_id = response.get("appId")
            if app_id:
                return app_id
            self.last_error = {
                "resultCode": response.get("resultCode"),
                "userString": response.get("userString") or response.get("resultString") or "",
            }
            return None
        except Exception as e:
            self.last_error = {"resultCode": -1, "userString": str(e)}
            return None

    def delete_app_id(self, app_id_id):
        try:
            response = self._make_developer_request("ios/deleteAppId.action", extra_params={
                "appIdId": app_id_id,
            })
            return response.get("resultCode") in (0, None)
        except:
            return False

    def list_certificates(self):
        if not self.team_id:
            return []
        url = f"{self.services_base_url}/certificates"
        query = f"teamId={self.team_id}&filter[certificateType]=IOS_DEVELOPMENT"
        self._get_anisette(force=True)
        headers = self._auth_headers("application/vnd.api+json", "application/vnd.api+json")
        headers["X-HTTP-Method-Override"] = "GET"
        try:
            response = self.session.post(url, headers=headers, json={"urlEncodedQueryParams": query}, timeout=30)
            response.raise_for_status()
            return response.json().get("data", [])
        except Exception as e:
            print(f"[DeveloperAPI] Lỗi list certs: {e}")
            return []

    def revoke_certificate(self, certificate_id):
        if not self.team_id:
            return False
        url = f"{self.services_base_url}/certificates/{certificate_id}"
        query = f"teamId={self.team_id}"
        self._get_anisette(force=True)
        headers = self._auth_headers("application/vnd.api+json", "application/vnd.api+json")
        headers["X-HTTP-Method-Override"] = "DELETE"
        try:
            response = self.session.post(url, headers=headers, json={"urlEncodedQueryParams": query}, timeout=30)
            if response.status_code in [200, 204]:
                return True
            print(f"[DeveloperAPI] Revoke thất bại: {response.status_code}")
            return False
        except:
            return False

    def create_certificate(self, machine_name="ios-sideload-tool"):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        print("[DeveloperAPI] Tạo certificate mới...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, machine_name)]))
            .sign(private_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        machine_id = str(uuid.uuid4()).upper()
        try:
            response = self._make_developer_request("ios/submitDevelopmentCSR.action", extra_params={
                "csrContent": csr_pem,
                "machineId": machine_id,
                "machineName": machine_name,
            })
            cert_request = response.get("certRequest")
            if not cert_request:
                return None
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
            cert_request["_private_key_pem"] = key_pem
            cert_id = cert_request.get("certificateId")
            if cert_id:
                cert_content = self._fetch_certificate_content(cert_id)
                if cert_content:
                    cert_request["certContent"] = cert_content
            return cert_request
        except Exception as e:
            print(f"[DeveloperAPI] Lỗi tạo cert: {e}")
            return None

    def _fetch_certificate_content(self, certificate_id):
        delays = [2, 4, 6, 8, 10]
        for attempt, delay in enumerate(delays):
            certs = self.list_certificates()
            for cert in certs:
                if str(cert.get("id")) == str(certificate_id):
                    content = cert.get("attributes", {}).get("certificateContent")
                    if content:
                        return content
            if attempt < len(delays) - 1:
                time.sleep(delay)
        return None

    def download_provisioning_profile(self, app_id_id, retries=3):
        """
        Tải Team Provisioning Profile cho một App ID.

        LƯU Ý: Apple có thể trả về HTTP 200 hợp lệ nhưng KHÔNG kèm
        theo "provisioningProfile" trong response (ví dụ App ID có
        vấn đề, thiếu quyền, hoặc lỗi nghiệp vụ khác từ phía Apple).
        Trường hợp đó KHÔNG ném exception, nên nếu chỉ bắt except thì
        sẽ thất bại trong im lặng. Vì vậy ta luôn ghi lại self.last_error
        và log rõ resultCode/userString mỗi lần thất bại, dù có
        exception hay không.
        """
        delay = 3
        self.last_error = None

        for attempt in range(retries):
            try:
                response = self._make_developer_request(
                    "ios/downloadTeamProvisioningProfile.action",
                    extra_params={"appIdId": app_id_id},
                )
                profile = response.get("provisioningProfile")
                if profile:
                    return profile

                # Response hợp lệ (không exception) nhưng thiếu profile
                # -> Apple trả lỗi nghiệp vụ trong resultCode/userString.
                self.last_error = {
                    "resultCode": response.get("resultCode") or response.get("resultcode"),
                    "userString": response.get("userString") or response.get("resultString") or "",
                }
                print(
                    f"[DeveloperAPI] downloadTeamProvisioningProfile thất bại "
                    f"(attempt {attempt + 1}/{retries}): {self.last_error}"
                )

            except Exception as e:
                self.last_error = {"resultCode": -1, "userString": str(e)}
                print(f"[DeveloperAPI] Lỗi download profile: {e}")

            if attempt < retries - 1:
                time.sleep(delay)
                delay += 2

        return None
