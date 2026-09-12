#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import getpass
import time
import uuid
import shutil
import subprocess
import plistlib
import zipfile
import random
import string
import signal
import config
import utils
import device_link
from apple_auth import AppleAuth, fetch_official_servers
from developer_api import DeveloperAPI, classify_app_id_error
from cryptography import x509

WORK_DIR = os.path.expanduser("~/.sideload")
os.makedirs(WORK_DIR, exist_ok=True)

# === MÀU ANSI ===
class C:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg): print(f"{C.OKCYAN}[INFO]{C.ENDC} {msg}")
def log_ok(msg): print(f"{C.OKGREEN}[OK]{C.ENDC} {msg}")
def log_warn(msg): print(f"{C.WARNING}[WARN]{C.ENDC} {msg}")
def log_error(msg): print(f"{C.FAIL}[ERROR]{C.ENDC} {msg}")
def log_step(step, msg): print(f"\n{C.BOLD}{C.HEADER}── Bước {step} ──{C.ENDC} {msg}")

# === HELPER: LÀM SẠCH STRING ===
def clean_string(s):
    """Loại bỏ ký tự điều khiển và đảm bảo là string hợp lệ"""
    if s is None:
        return ""
    if isinstance(s, bytes):
        s = s.decode('utf-8', errors='ignore')
    if not isinstance(s, str):
        s = str(s)
    return ''.join(c for c in s if c.isprintable())

# === KILL USBMUXD ===
def kill_usbmuxd():
    """Kill tất cả tiến trình usbmuxd đang chạy"""
    try:
        result = subprocess.run(["pgrep", "-f", "usbmuxd"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid:
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                        log_info(f"Đã kill usbmuxd PID {pid}")
                    except:
                        pass
            time.sleep(1)
            return True
        return False
    except Exception as e:
        log_warn(f"Lỗi kill usbmuxd: {e}")
        return False

def check_usbmuxd():
    """Kiểm tra usbmuxd có đang chạy không"""
    try:
        result = subprocess.run(["pgrep", "-f", "usbmuxd"], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False

# === ZSIGN ===
def find_zsign():
    if shutil.which("zsign"):
        return shutil.which("zsign")
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zsign")
    if os.path.exists(local):
        return local
    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    prefix_bin = os.path.join(prefix, "bin", "zsign")
    if os.path.exists(prefix_bin):
        return prefix_bin
    home = os.path.expanduser("~/zsign/zsign")
    if os.path.exists(home):
        return home
    work = os.path.expanduser("~/.sideload/zsign")
    if os.path.exists(work):
        return work
    return None

def check_zsign():
    zsign = find_zsign()
    if not zsign:
        print("[zsign] ❌ Không tìm thấy zsign!")
        print("[zsign] Cài bằng: pkg install zsign")
        print("[zsign] Hoặc: https://github.com/zhlynn/zsign")
        return False
    try:
        result = subprocess.run([zsign, "-v"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[zsign] ✅ Tìm thấy: {zsign}")
            return True
    except:
        pass
    print(f"[zsign] ⚠️ Tìm thấy nhưng không hoạt động: {zsign}")
    return False

# === IPHONE STATUS ===
def check_iphone_status():
    try:
        udid = device_link.get_udid_from_usb()
        if not udid:
            return "🔴 DISCONNECTED (hoặc usbmuxd chưa chạy)"
        try:
            result = subprocess.run(["idevicepair", "validate"], capture_output=True, text=True, timeout=10)
            if "SUCCESS" in result.stdout.upper() or result.returncode == 0:
                return f"🟢 CONNECTED & TRUSTED (UDID: {udid[:8]}...)"
            else:
                return f"🟠 CONNECTED - UNTRUSTED / UNPAIRED (UDID: {udid[:8]}...)"
        except:
            return f"🟡 CONNECTED - Không xác định pairing (UDID: {udid[:8]}...)"
    except:
        return "🔴 DISCONNECTED"

# === USB DEVICES ===
def list_usb_devices():
    """Liệt kê tất cả thiết bị USB đang kết nối"""
    log_info("Đang quét tất cả thiết bị USB...")
    try:
        result = subprocess.run(["termux-usb", "-l"], capture_output=True, text=True, timeout=10)
        usb_devices = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if '/dev/bus/usb/' in line:
                line = line.strip('"').strip("'")
                parts = line.split()
                if parts:
                    path = parts[-1].strip('"').strip("'")
                    usb_devices.append({
                        "path": path,
                        "info": line
                    })
        return usb_devices
    except Exception as e:
        log_error(f"Lỗi quét USB: {e}")
        return []

def show_usb_selection_menu():
    """Hiển thị menu chọn thiết bị USB"""
    log_step(0, "Chọn thiết bị USB")
    usb_devices = list_usb_devices()
    if not usb_devices:
        log_error("Không tìm thấy thiết bị USB nào!")
        log_warn("👉 Cắm iPhone qua cáp USB và mở khoá màn hình.")
        return None
    log_info(f"Tìm thấy {len(usb_devices)} thiết bị USB:")
    print()
    for i, usb in enumerate(usb_devices, 1):
        path = usb["path"].strip('"').strip("'")
        usb["path"] = path
        parts = path.split('/')
        bus = parts[-2] if len(parts) >= 2 else "?"
        dev = parts[-1] if len(parts) >= 1 else "?"
        print(f"  {C.BOLD}[{i}]{C.ENDC} {C.OKCYAN}{path}{C.ENDC}")
        print(f"      {C.OKBLUE}Bus:{C.ENDC} {bus} | {C.OKBLUE}Device:{C.ENDC} {dev}")
        print(f"      {C.OKBLUE}Info:{C.ENDC} {usb['info']}")
        print()
    choice = input(f"Chọn thiết bị (1-{len(usb_devices)}, Enter để chọn đầu tiên): ").strip()
    if choice:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(usb_devices):
                selected = usb_devices[idx]
                path = selected["path"].strip('"').strip("'")
                log_ok(f"Đã chọn: {path}")
                return {"path": path, "info": selected.get("info", "")}
            else:
                log_error("Số không hợp lệ. Chọn thiết bị đầu tiên.")
                path = usb_devices[0]["path"].strip('"').strip("'")
                return {"path": path, "info": usb_devices[0].get("info", "")}
        except:
            log_error("Lựa chọn không hợp lệ. Chọn thiết bị đầu tiên.")
            path = usb_devices[0]["path"].strip('"').strip("'")
            return {"path": path, "info": usb_devices[0].get("info", "")}
    else:
        path = usb_devices[0]["path"].strip('"').strip("'")
        log_ok(f"Đã chọn mặc định: {path}")
        return {"path": path, "info": usb_devices[0].get("info", "")}

# === SETUP USB ===
def setup_usb_connection():
    """Chỉ chạy khi người dùng chọn mục Setup USB"""
    log_step(0, "Thiết lập USB & USBMUXD")
    
    if not shutil.which("termux-usb"):
        log_error("termux-usb không tìm thấy! Cài Termux:API")
        log_info("Cài: pkg install termux-api")
        return False
    
    kill_usbmuxd()
    
    selected_usb = show_usb_selection_menu()
    if not selected_usb:
        return False
    
    usb_path = selected_usb["path"].strip('"').strip("'")
    
    log_info(f"Sử dụng thiết bị: {usb_path}")
    log_info("Đang xin quyền truy cập USB...")
    subprocess.run(["termux-usb", "-r", usb_path], timeout=10)
    log_ok("Đã gửi yêu cầu quyền. Bấm OK trên popup Android.")
    
    log_info("Đang chờ 5 giây để kiểm tra thiết bị...")
    time.sleep(5)
    
    log_info("Đang khởi động usbmuxd...")
    cmd = f'termux-usb -r -E -e "usbmuxd -f -p" "{usb_path}"'
    log_info(f"Command: {cmd}")
    
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
    except Exception as e:
        log_error(f"Lỗi khởi động usbmuxd: {e}")
        return False
    
    log_info("Đang chờ usbmuxd khởi động...")
    time.sleep(8)
    
    if check_usbmuxd():
        log_ok("✅ usbmuxd đang chạy!")
    else:
        log_warn("⚠️ usbmuxd chưa chạy.")
        log_info("👉 Thử chạy thủ công:")
        log_info(f'   termux-usb -r -E -e "usbmuxd -f -p" "{usb_path}"')
        kill_usbmuxd()
        return False
    
    try:
        udid = device_link.get_udid_from_usb()
        if udid:
            log_ok(f"✅ Thiết bị tìm thấy: {udid}")
            return True
    except:
        pass
    
    log_warn("⚠️ Không thể kết nối tự động.")
    log_info("Đang kill usbmuxd do kết nối thất bại...")
    kill_usbmuxd()
    log_info("👉 Chạy thủ công trong terminal khác:")
    log_info(f'   termux-usb -r -E -e "usbmuxd -f -p" "{usb_path}"')
    return False

# === TEST PAIRING ===
def test_pairing():
    """Test pairing với thiết bị"""
    log_step(0, "Test Pairing")
    udid = device_link.get_udid_from_usb()
    if not udid:
        log_error("Không tìm thấy thiết bị!")
        log_warn("👉 Chạy 'Setup USB' trước.")
        return False
    log_info(f"UDID: {udid}")
    log_info("STEP 1: Gửi yêu cầu pair...")
    log_warn("👉 Kiểm tra iPhone: Bấm 'Trust' và nhập passcode nếu có.")
    try:
        output = subprocess.run(["idevicepair", "pair", udid], capture_output=True, text=True, timeout=60)
        print(output.stdout)
        print(output.stderr)
    except subprocess.TimeoutExpired:
        log_warn("Timeout khi pair.")
        log_info("Đang kill usbmuxd do pair thất bại...")
        kill_usbmuxd()
        return False
    except Exception as e:
        log_error(f"Lỗi pair: {e}")
        kill_usbmuxd()
        return False
    log_info("Waiting 5 giây...")
    time.sleep(5)
    log_info("STEP 2: Xác nhận pairing...")
    try:
        output2 = subprocess.run(["idevicepair", "pair", udid], capture_output=True, text=True, timeout=30)
        print(output2.stdout)
        print(output2.stderr)
        if "SUCCESS" in output2.stdout.upper() or "paired" in output2.stdout.lower():
            log_ok("🎉 Pairing thành công!")
            return True
        else:
            log_warn("⚠️ Pairing chưa hoàn tất.")
            log_info("Đang kill usbmuxd do pair thất bại...")
            kill_usbmuxd()
            return False
    except Exception as e:
        log_error(f"Lỗi confirm: {e}")
        kill_usbmuxd()
        return False

# === PATCH BUNDLE ID ===
def patch_bundle_ids(app_bundle_path, team_id):
    """Đổi bundle ID: com.app.name.{teamid} và com.app.name.{teamid}.widget"""
    original_bundle_id = utils.get_bundle_id(app_bundle_path)
    original_bundle_id = clean_string(original_bundle_id)
    
    if not original_bundle_id:
        raise Exception("Bundle ID gốc rỗng sau khi clean")
    
    new_bundle_id = f"{original_bundle_id}.{team_id}"
    utils.set_bundle_id(app_bundle_path, new_bundle_id)
    log_ok(f"[PATCH] App: {original_bundle_id} -> {new_bundle_id}")
    
    plugins_dir = os.path.join(app_bundle_path, "PlugIns")
    if os.path.isdir(plugins_dir):
        for item in os.listdir(plugins_dir):
            if item.endswith(".appex"):
                ext_plist = os.path.join(plugins_dir, item, "Info.plist")
                if os.path.exists(ext_plist):
                    with open(ext_plist, 'rb') as f:
                        ext_data = plistlib.load(f)
                    ext_original_id = clean_string(ext_data.get("CFBundleIdentifier", ""))
                    
                    if ext_original_id.startswith(original_bundle_id):
                        ext_suffix = ext_original_id[len(original_bundle_id):]
                        ext_new_id = f"{original_bundle_id}.{team_id}{ext_suffix}"
                        ext_data["CFBundleIdentifier"] = ext_new_id
                        with open(ext_plist, 'wb') as f:
                            plistlib.dump(ext_data, f, fmt=plistlib.FMT_BINARY)
                        log_ok(f"[PATCH] Extension: {ext_original_id} -> {ext_new_id}")
    
    return new_bundle_id

# === APP ID / PROVISIONING HELPERS ===
def find_app_id(dev_api, bundle_id):
    """Tìm Exact App ID theo bundle identifier."""
    bundle_id = clean_string(bundle_id)
    for app_id in dev_api.list_app_ids() or []:
        identifier = clean_string(
            app_id.get("identifier")
            or app_id.get("bundleId")
            or app_id.get("bundleID")
            or ""
        )
        if identifier == bundle_id:
            return app_id
    return None


def get_app_id_identifier(app_id):
    return clean_string(
        app_id.get("identifier")
        or app_id.get("bundleId")
        or app_id.get("bundleID")
        or ""
    )


def get_app_id_id(app_id):
    return app_id.get("appIdId") or app_id.get("id")


def create_or_get_app_id(dev_api, bundle_id, name):
    """Tạo Exact App ID nếu chưa có, không tạo wildcard."""
    existing = find_app_id(dev_api, bundle_id)
    if existing:
        log_ok(f"Dùng App ID có sẵn: {bundle_id}")
        return existing

    created = dev_api.create_app_id(bundle_id, name)
    if not created:
        log_error(f"Không tạo được App ID {bundle_id}: {dev_api.last_error}")
        return None

    log_ok(f"Đã tạo App ID: {bundle_id}")
    return created


def decode_provisioning_profile(profile):
    if not profile:
        return None

    encoded = (
        profile.get("encodedProfile")
        or profile.get("content")
        or profile.get("profileContent")
    )
    if not encoded:
        return None

    try:
        data = utils.decode_apple_data_field(encoded)
        return data if data else None
    except Exception as e:
        log_error(f"Không decode được provisioning profile: {e}")
        return None


def download_profile_for_app(dev_api, app_id, bundle_id):
    """Tải profile riêng cho đúng App ID."""
    app_id_id = get_app_id_id(app_id)
    if not app_id_id:
        log_error(f"App ID {bundle_id} không có ID nội bộ.")
        return None

    profile = dev_api.download_provisioning_profile(app_id_id)
    content = decode_provisioning_profile(profile)

    if not content:
        log_error(f"Không tải được provisioning profile cho {bundle_id}.")
        return None

    return content


def write_embedded_profile(bundle_path, profile_content):
    profile_path = os.path.join(bundle_path, "embedded.mobileprovision")
    with open(profile_path, "wb") as f:
        f.write(profile_content)
    return profile_path


def get_extension_bundles(app_bundle):
    """Trả về [(appex_path, bundle_id)] sau khi Bundle ID đã được patch."""
    result = []
    plugins_dir = os.path.join(app_bundle, "PlugIns")

    if not os.path.isdir(plugins_dir):
        return result

    for item in sorted(os.listdir(plugins_dir)):
        if not item.endswith(".appex"):
            continue

        appex_path = os.path.join(plugins_dir, item)
        plist_path = os.path.join(appex_path, "Info.plist")

        if not os.path.isfile(plist_path):
            continue

        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
            bundle_id = clean_string(data.get("CFBundleIdentifier", ""))
            if bundle_id:
                result.append((appex_path, bundle_id))
        except Exception as e:
            log_warn(f"Không đọc được Info.plist của {item}: {e}")

    return result


def get_certificate_team_id(cert_path):
    """Lấy Team ID thật từ OU trong certificate PEM."""
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        from cryptography.x509.oid import NameOID

        values = cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATIONAL_UNIT_NAME
        )
        for attr in values:
            value = clean_string(attr.value)
            if re.fullmatch(r"[A-Z0-9]{10}", value):
                return value

        # Một số certificate có thể có nhiều trường subject khác nhau.
        for attr in cert.subject:
            value = clean_string(attr.value)
            if re.fullmatch(r"[A-Z0-9]{10}", value):
                return value

    except Exception as e:
        log_warn(f"Không đọc được Team ID từ certificate: {e}")

    return None


def prepare_provisioning(dev_api, app_bundle, app_name, team_id):
    """
    Mỗi bundle (app + từng .appex) có:
      1. Exact App ID riêng
      2. provisioning profile riêng
      3. embedded.mobileprovision riêng

    Trả về danh sách profile theo thứ tự main app -> extensions.
    """
    profiles = []

    # Main app
    main_bundle_id = clean_string(utils.get_bundle_id(app_bundle))
    if not main_bundle_id:
        log_error("Main Bundle ID rỗng.")
        return None

    main_app_id = create_or_get_app_id(
        dev_api, main_bundle_id, app_name
    )
    if not main_app_id:
        return None

    main_profile = download_profile_for_app(
        dev_api, main_app_id, main_bundle_id
    )
    if not main_profile:
        return None

    main_profile_path = write_embedded_profile(app_bundle, main_profile)
    profiles.append((app_bundle, main_bundle_id, main_profile_path))
    log_ok(f"Profile riêng cho App: {main_bundle_id}")

    # Extensions
    for appex_path, ext_bundle_id in get_extension_bundles(app_bundle):
        ext_name = clean_string(
            os.path.basename(appex_path).removesuffix(".appex")
        ) or f"{app_name} Extension"

        log_info(f"Xử lý Extension: {ext_bundle_id}")

        ext_app_id = create_or_get_app_id(
            dev_api, ext_bundle_id, ext_name
        )
        if not ext_app_id:
            return None

        ext_profile = download_profile_for_app(
            dev_api, ext_app_id, ext_bundle_id
        )
        if not ext_profile:
            return None

        ext_profile_path = write_embedded_profile(
            appex_path, ext_profile
        )
        profiles.append(
            (appex_path, ext_bundle_id, ext_profile_path)
        )
        log_ok(f"Profile riêng cho Extension: {ext_bundle_id}")

    return profiles


# === DO SIDELOAD ===
def do_sideload(ipa_path, apple_id, password):
    """Sideload với Team ID thật + profile riêng cho từng bundle."""
    log_step(1, "Xác thực Apple ID")

    if not check_usbmuxd():
        log_error("usbmuxd chưa chạy! Chạy 'Setup USB' trước.")
        return False

    udid = device_link.get_udid_from_usb()
    if not udid:
        log_error("Không tìm thấy thiết bị! Chạy 'Setup USB' trước.")
        kill_usbmuxd()
        return False
    log_ok(f"UDID: {udid}")

    try:
        import requests
        requests.get("https://www.apple.com", timeout=5)
        log_ok("Có kết nối internet")
    except Exception:
        log_error("Không có kết nối internet!")
        return False

    auth = AppleAuth(input_func=input)
    auth_result = auth.authenticate(apple_id, password)

    if not auth_result or not auth_result.get("authenticated"):
        log_error("Xác thực thất bại.")
        return False

    if auth_result.get("authenticated") == "2fa_completed":
        log_warn("2FA hoàn tất. Hãy chạy lại.")
        return False

    config.set_apple_id(apple_id)
    if config.get_password() != password:
        config.save_password(password)
    log_ok("Đã lưu thông tin đăng nhập.")

    dsid = auth_result["dsid"]
    session_token = auth_result["session_token"]
    dev_api = DeveloperAPI(auth, dsid, session_token)

    log_step(2, "Lấy Team ID thật từ Apple Developer")
    teams = dev_api.list_teams()
    if not teams:
        log_error("Không lấy được Team ID. Kiểm tra tài khoản Developer.")
        return False

    team_id = clean_string(
        teams[0].get("teamId")
        or teams[0].get("teamID")
        or teams[0].get("id")
        or ""
    )

    if not re.fullmatch(r"[A-Z0-9]{10}", team_id):
        log_error(f"Team ID Apple trả về không hợp lệ: {team_id!r}")
        return False

    dev_api.set_team(team_id)
    log_ok(f"Team ID thật: {team_id}")

    log_step(3, "Kiểm tra thiết bị trên Apple")
    devices = dev_api.list_devices() or []

    if not any(
        clean_string(d.get("deviceNumber") or d.get("udid") or "") == udid
        for d in devices
    ):
        log_info("Thiết bị chưa đăng ký. Đang đăng ký...")
        if not dev_api.register_device(f"iPhone-{udid[:8]}", udid):
            log_error(f"Đăng ký thiết bị thất bại: {dev_api.last_error}")
            return False
        log_ok("Đã đăng ký thiết bị.")

    log_step(4, "Chuẩn bị Certificate")
    cert_pem_path = os.path.join(WORK_DIR, "cert.pem")
    key_pem_path = os.path.join(WORK_DIR, "key.pem")

    cert_exists = os.path.isfile(cert_pem_path)
    key_exists = os.path.isfile(key_pem_path)

    if cert_exists != key_exists:
        log_error(
            "cert.pem và key.pem không đồng bộ. "
            "Xoá/copy lại đúng cặp certificate + private key."
        )
        return False

    if not cert_exists:
        log_info("Chưa có certificate local. Đang tạo certificate mới...")
        cert_data = dev_api.create_certificate(
            f"sideload-{uuid.uuid4().hex[:8]}"
        )

        if not cert_data:
            log_error(
                f"Không tạo được certificate: {dev_api.last_error}"
            )
            return False

        cert_content = (
            cert_data.get("attributes", {}).get("certificateContent")
            or cert_data.get("certContent")
        )
        key_pem = cert_data.get("_private_key_pem")

        if not cert_content or not key_pem:
            log_error("Apple không trả đủ certificate/private key.")
            return False

        utils.save_certificate_as_pem(
            cert_content, cert_pem_path
        )

        with open(key_pem_path, "w", encoding="utf-8") as f:
            f.write(key_pem)

        log_ok("Đã tạo certificate mới.")
    else:
        log_ok("Dùng certificate + private key có sẵn.")

    # Tuyệt đối không tự revoke certificate cũ.
    cert_team_id = get_certificate_team_id(cert_pem_path)

    if not cert_team_id:
        log_error(
            "Không xác định được Team ID trong cert.pem. "
            "Không tiếp tục ký để tránh ký sai team."
        )
        return False

    log_info(f"Team ID trong certificate: {cert_team_id}")

    if cert_team_id != team_id:
        log_error(
            f"Certificate Team ID ({cert_team_id}) khác "
            f"Developer Team ID ({team_id})."
        )
        log_error(
            "Hãy dùng đúng cặp cert.pem + key.pem của Team này."
        )
        return False

    log_ok("Certificate Team ID khớp Developer Team.")

    log_step(5, "Extract IPA & đổi Bundle ID")
    work_dir = os.path.join(WORK_DIR, "extract")
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir, exist_ok=True)

    utils.extract_ipa(ipa_path, work_dir)

    app_bundle = utils.find_app_bundle(work_dir)
    if not app_bundle:
        log_error("Không tìm thấy .app trong IPA.")
        return False

    original_bundle_id = clean_string(
        utils.get_bundle_id(app_bundle)
    )
    app_name = clean_string(utils.get_app_name(app_bundle))

    if not original_bundle_id:
        log_error("IPA không có CFBundleIdentifier.")
        return False

    log_info(
        f"App: {app_name} | Bundle ID gốc: {original_bundle_id}"
    )

    bundle_id = patch_bundle_ids(app_bundle, team_id)
    log_ok(f"Bundle ID mới: {bundle_id}")

    log_step(6, "Tạo App ID & Provisioning Profile riêng")

    profiles = prepare_provisioning(
        dev_api,
        app_bundle,
        app_name,
        team_id
    )

    if not profiles:
        log_error("Chuẩn bị provisioning profile thất bại.")
        return False

    log_ok(
        f"Đã chuẩn bị {len(profiles)} provisioning profile "
        f"(App + Extension)."
    )

    log_step(7, "Ký IPA bằng zsign")

    if not check_zsign():
        return False

    zsign_path = find_zsign()
    if not zsign_path:
        return False

    signed_ipa = os.path.join(
        WORK_DIR, f"{app_name}_signed.ipa"
    )
    tmp_dir = os.path.join(WORK_DIR, "zsign_tmp")

    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    os.makedirs(tmp_dir, exist_ok=True)

    # zsign hỗ trợ nhiều -m: main app + từng extension.
    zsign_cmd = [
        zsign_path,
        "-f",
        "-t", tmp_dir,
        "-c", cert_pem_path,
        "-k", key_pem_path,
    ]

    for bundle_path, bundle_id, profile_path in profiles:
        if not os.path.isfile(profile_path):
            log_error(
                f"Thiếu provisioning profile: {profile_path}"
            )
            return False
        zsign_cmd.extend(["-m", profile_path])
        log_info(f"[ZSIGN] -m {bundle_id}")

    zsign_cmd.extend([
        "-o", signed_ipa,
        app_bundle
    ])

    try:
        utils.run_command(zsign_cmd)
    except Exception as e:
        log_error(f"Ký IPA thất bại: {e}")
        return False

    if not os.path.isfile(signed_ipa):
        log_error("zsign không tạo ra IPA đầu ra.")
        return False

    log_ok(f"Đã ký IPA: {signed_ipa}")

    log_step(8, "Pairing & Cài đặt")

    pair = device_link.pair_device(udid)
    if not pair:
        log_error("Pairing thất bại.")
        log_info("Đang kill usbmuxd do pairing thất bại...")
        kill_usbmuxd()
        return False

    log_ok("Pairing thành công.")

    try:
        installed = device_link.install_ipa(pair, signed_ipa)
        if not installed:
            raise RuntimeError("ideviceinstaller trả về thất bại")

        log_ok("🎉 Cài đặt thành công!")
        return True

    except Exception as e:
        log_error(f"Cài đặt thất bại: {e}")
        log_info("Đang kill usbmuxd do cài đặt thất bại...")
        kill_usbmuxd()
        return False


# === REVOKE CERTS ===
def do_revoke_certs(apple_id, password):
    log_step(1, "Xác thực")
    auth = AppleAuth(input_func=input)
    auth_result = auth.authenticate(apple_id, password)
    
    if not auth_result or not auth_result.get("authenticated"):
        log_error("Xác thực thất bại.")
        return False
    if auth_result.get("authenticated") == "2fa_completed":
        log_warn("2FA hoàn tất. Chạy lại.")
        return False
    
    dsid = auth_result["dsid"]
    session_token = auth_result["session_token"]
    dev_api = DeveloperAPI(auth, dsid, session_token)
    
    teams = dev_api.list_teams()
    if not teams:
        log_error("Không có team.")
        return False
    team_id = teams[0].get("teamId") or teams[0].get("teamID") or teams[0].get("id")
    dev_api.set_team(team_id)
    
    certs = dev_api.list_certificates()
    if not certs:
        log_info("Không có certificate nào.")
        return True
    
    log_info(f"Có {len(certs)} certificate:")
    for i, cert in enumerate(certs, 1):
        attrs = cert.get("attributes", {})
        print(f"  [{i}] id={cert.get('id')} name={attrs.get('name')} exp={attrs.get('expirationDate')}")
    
    selector = input("Chọn certificate cần thu hồi (số hoặc 'all'): ").strip().lower()
    if selector == "all":
        targets = certs
    else:
        try:
            idx = int(selector) - 1
            targets = [certs[idx]] if 0 <= idx < len(certs) else []
        except:
            targets = []
        if not targets:
            log_error("Chọn không hợp lệ.")
            return False
    
    for cert in targets:
        ok = dev_api.revoke_certificate(cert.get("id"))
        log_ok(f"Revoke {cert.get('id')} {'thành công' if ok else 'thất bại'}")
    return True

# === MAIN ===
def main():
    print(f"{C.BOLD}{C.HEADER}╔══════════════════════════════════════════╗{C.ENDC}")
    print(f"{C.BOLD}{C.HEADER}║     iOS Sideload Tool for Termux        ║{C.ENDC}")
    print(f"{C.BOLD}{C.HEADER}╚══════════════════════════════════════════╝{C.ENDC}")
    print()
    print(f"{C.OKCYAN}📱 iPhone Status:{C.ENDC} {check_iphone_status()}")
    
    print()
    
    saved_id = config.get_apple_id()
    saved_pass = config.get_password()
    
    print("1. Sideload IPA")
    print("2. Thu hồi cert")
    print("3. Setup USB & USBMUXD")
    print("4. Test Pairing")
    print("5. Thoát")
    choice = input("Chọn (1-5): ").strip()
    
    if choice == "1":
        if not check_usbmuxd():
            log_error("usbmuxd chưa chạy! Chạy 'Setup USB' (mục 3) trước.")
            main()
            return
        
        udid = device_link.get_udid_from_usb()
        if not udid:
            log_error("Không tìm thấy thiết bị! Chạy 'Setup USB' (mục 3) trước.")
            main()
            return
        
        ipa = input("Đường dẫn IPA: ").strip()
        ipa = os.path.expanduser(ipa)
        ipa = os.path.abspath(ipa)
        
        if not os.path.exists(ipa):
            log_error(f"File IPA không tồn tại: {ipa}")
            return
        
        if saved_id:
            print(f"{C.OKCYAN}Apple ID đã lưu:{C.ENDC} {saved_id}")
            if input("Dùng? (y/n): ").lower() == "y":
                apple_id = saved_id
            else:
                apple_id = input("Apple ID: ").strip()
                config.set_apple_id(apple_id)
        else:
            apple_id = input("Apple ID: ").strip()
            config.set_apple_id(apple_id)
        
        if saved_pass and apple_id == saved_id:
            if input("Dùng mật khẩu đã lưu? (y/n): ").lower() == "y":
                password = saved_pass
            else:
                password = getpass.getpass("Mật khẩu: ")
                config.save_password(password)
        else:
            password = getpass.getpass("Mật khẩu: ")
            config.save_password(password)
        
        do_sideload(ipa, apple_id, password)
    
    elif choice == "2":
        if saved_id:
            print(f"{C.OKCYAN}Apple ID đã lưu:{C.ENDC} {saved_id}")
            if input("Dùng? (y/n): ").lower() == "y":
                apple_id = saved_id
            else:
                apple_id = input("Apple ID: ").strip()
                config.set_apple_id(apple_id)
        else:
            apple_id = input("Apple ID: ").strip()
            config.set_apple_id(apple_id)
        
        if saved_pass and apple_id == saved_id:
            if input("Dùng mật khẩu đã lưu? (y/n): ").lower() == "y":
                password = saved_pass
            else:
                password = getpass.getpass("Mật khẩu: ")
                config.save_password(password)
        else:
            password = getpass.getpass("Mật khẩu: ")
            config.save_password(password)
        
        do_revoke_certs(apple_id, password)
    
    elif choice == "3":
        setup_usb_connection()
        main()
    
    elif choice == "4":
        test_pairing()
        main()
    
    elif choice == "5":
        print("Đã thoát.")
        sys.exit(0)

    else:
        print("Lựa chọn không hợp lệ.")
        main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nĐã hủy.")
        kill_usbmuxd()
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Lỗi: {e}")
        kill_usbmuxd()
        sys.exit(1)
