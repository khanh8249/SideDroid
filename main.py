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

def list_usb_devices():
    """Liệt kê tất cả thiết bị USB đang kết nối"""
    log_info("Đang quét tất cả thiết bị USB...")
    try:
        result = subprocess.run(["termux-usb", "-l"], capture_output=True, text=True, timeout=10)
        usb_devices = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if '/dev/bus/usb/' in line:
                parts = line.split()
                if parts:
                    path = parts[-1]
                    if isinstance(path, dict):
                        path = str(path)
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
        path = usb["path"]
        if isinstance(path, dict):
            path = str(path)
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
                path = selected["path"]
                if isinstance(path, dict):
                    path = str(path)
                log_ok(f"Đã chọn: {path}")
                return {"path": path, "info": selected.get("info", "")}
            else:
                log_error("Số không hợp lệ. Chọn thiết bị đầu tiên.")
                return {"path": str(usb_devices[0]["path"]), "info": usb_devices[0].get("info", "")}
        except:
            log_error("Lựa chọn không hợp lệ. Chọn thiết bị đầu tiên.")
            return {"path": str(usb_devices[0]["path"]), "info": usb_devices[0].get("info", "")}
    else:
        log_ok(f"Đã chọn mặc định: {usb_devices[0]['path']}")
        return {"path": str(usb_devices[0]["path"]), "info": usb_devices[0].get("info", "")}

def setup_usb_connection():
    log_step(0, "Thiết lập USB & USBMUXD")
    if not shutil.which("termux-usb"):
        log_error("termux-usb không tìm thấy! Cài Termux:API")
        log_info("Cài: pkg install termux-api")
        return False
    selected_usb = show_usb_selection_menu()
    if not selected_usb:
        return False
    usb_path = selected_usb["path"]
    if isinstance(usb_path, dict):
        usb_path = str(usb_path)
    log_info(f"Sử dụng thiết bị: {usb_path}")
    log_info("Đang xin quyền truy cập USB...")
    subprocess.run(["termux-usb", "-r", usb_path], timeout=10)
    log_ok("Đã gửi yêu cầu quyền. Bấm OK trên popup Android.")
    
    # === TIMEOUT 5S KIỂM TRA THIẾT BỊ ===
    log_info("Đang chờ 5 giây để kiểm tra thiết bị...")
    time.sleep(5)
    
    log_info("Đang khởi động usbmuxd...")
    cmd = f"termux-usb -r -E -e \"usbmuxd -f -p\" {usb_path}"
    log_info(f"Command: {cmd}")
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)
    try:
        if subprocess.run(["pgrep", "usbmuxd"], capture_output=True).returncode == 0:
            log_ok("usbmuxd đang chạy!")
        else:
            log_warn("⚠️ usbmuxd chưa chạy. Kiểm tra lại.")
    except:
        pass
    try:
        udid = device_link.get_udid_from_usb()
        if udid:
            log_ok(f"✅ Thiết bị tìm thấy: {udid}")
            return True
    except:
        pass
    log_warn("⚠️ Không thể kết nối tự động. Hãy thử chạy lại.")
    return False

def test_pairing():
    """Test pairing với thiết bị"""
    log_step(0, "Test Pairing")
    udid = device_link.get_udid_from_usb()
    if not udid:
        log_error("Không tìm thấy thiết bị!")
        return False
    log_info(f"UDID: {udid}")
    log_info("STEP 1: Gửi yêu cầu pair...")
    log_warn("👉 Kiểm tra iPhone: Bấm 'Trust' và nhập passcode nếu có.")
    try:
        output = subprocess.run(["idevicepair", "pair", udid], capture_output=True, text=True, timeout=60)
        print(output.stdout)
        print(output.stderr)
    except subprocess.TimeoutExpired:
        log_warn("Timeout khi pair. Kiểm tra kết nối.")
        return False
    except Exception as e:
        log_error(f"Lỗi pair: {e}")
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
            log_warn("⚠️ Pairing chưa hoàn tất. Đảm bảo đã Trust trên iPhone.")
            return False
    except Exception as e:
        log_error(f"Lỗi confirm: {e}")
        return False

def extract_team_id_from_cert(cert_pem_path):
    """Lấy Team ID từ certificate"""
    try:
        with open(cert_pem_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        for ext in cert.extensions:
            if ext.oid.dotted_string == "1.2.840.113635.100.6.1.2":
                return ext.value.value.decode()
        for attr in cert.subject:
            if attr.oid._name == "organizationalUnitName":
                return attr.value
        return None
    except Exception as e:
        print(f"[cert] Lỗi lấy Team ID: {e}")
        return None

def generate_random_team_id():
    """Gen Team ID ngẫu nhiên"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

def patch_bundle_ids(app_bundle_path, team_id):
    """Đổi bundle ID cho app và extension thành .teamid"""
    # Đổi app
    original_bundle_id = utils.get_bundle_id(app_bundle_path)
    new_bundle_id = f"{original_bundle_id}.{team_id}"
    utils.set_bundle_id(app_bundle_path, new_bundle_id)
    log_ok(f"[PATCH] App: {original_bundle_id} -> {new_bundle_id}")
    
    # Đổi extensions - TỰ ĐỘNG THEO team_id
    plugins_dir = os.path.join(app_bundle_path, "PlugIns")
    if os.path.isdir(plugins_dir):
        for item in os.listdir(plugins_dir):
            if item.endswith(".appex"):
                ext_plist = os.path.join(plugins_dir, item, "Info.plist")
                if os.path.exists(ext_plist):
                    with open(ext_plist, 'rb') as f:
                        ext_data = plistlib.load(f)
                    ext_original_id = ext_data.get("CFBundleIdentifier", "")
                    if ext_original_id.startswith(original_bundle_id):
                        ext_new_id = f"{new_bundle_id}.{ext_original_id.split('.')[-1]}"
                        ext_data["CFBundleIdentifier"] = ext_new_id
                        with open(ext_plist, 'wb') as f:
                            plistlib.dump(ext_data, f)
                        log_ok(f"[PATCH] Extension: {ext_original_id} -> {ext_new_id}")
    return new_bundle_id

def do_sideload(ipa_path, apple_id, password):
    log_step(1, "Xác thực Apple ID")
    try:
        import requests
        requests.get("https://www.apple.com", timeout=5)
        log_ok("Có kết nối internet")
    except:
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
    
    log_step(2, "Lấy Team ID")
    teams = dev_api.list_teams()
    if not teams:
        log_error("Không có Team ID. Kiểm tra tài khoản developer.")
        return False
    team_id = teams[0].get("teamId") or teams[0].get("teamID") or teams[0].get("id")
    dev_api.set_team(team_id)
    log_ok(f"Team ID: {team_id}")
    
    log_step(3, "Kiểm tra thiết bị")
    udid = device_link.get_udid_from_usb()
    if not udid:
        log_error("Không tìm thấy thiết bị. Chạy 'Thiết lập USB' trước.")
        return False
    log_ok(f"UDID: {udid}")
    
    devices = dev_api.list_devices()
    if not any(d.get("deviceNumber") == udid or d.get("udid") == udid for d in devices):
        log_info("Đăng ký thiết bị mới...")
        if not dev_api.register_device(f"iPhone-{udid[:8]}", udid):
            log_error("Đăng ký thiết bị thất bại.")
            return False
        log_ok("Đã đăng ký thiết bị.")
    
    log_step(4, "Chuẩn bị Certificate")
    cert_pem_path = os.path.join(WORK_DIR, "cert.pem")
    key_pem_path = os.path.join(WORK_DIR, "key.pem")
    
    if not os.path.exists(cert_pem_path):
        existing = dev_api.list_certificates()
        if existing:
            oldest = existing[0]
            log_info(f"Thu hồi cert cũ: {oldest.get('id')}")
            dev_api.revoke_certificate(oldest.get("id"))
            time.sleep(2)
        
        cert_data = dev_api.create_certificate(f"sideload-{uuid.uuid4().hex[:8]}")
        if not cert_data:
            log_error("Không tạo được certificate.")
            return False
        cert_content = cert_data.get("attributes", {}).get("certificateContent") or cert_data.get("certContent")
        if not cert_content:
            log_error("Không có nội dung cert.")
            return False
        utils.save_certificate_as_pem(cert_content, cert_pem_path)
        key_pem = cert_data.get("_private_key_pem")
        if not key_pem:
            log_error("Không có private key.")
            return False
        with open(key_pem_path, "w") as f:
            f.write(key_pem)
        log_ok("Đã tạo certificate mới.")
    else:
        log_ok("Dùng certificate có sẵn.")
    
    # === LẤY TEAM ID (từ cert hoặc gen ngẫu nhiên) ===
    cert_team_id = extract_team_id_from_cert(cert_pem_path)
    if cert_team_id:
        team_id = cert_team_id
        log_ok(f"Team ID từ cert: {team_id}")
    else:
        team_id = generate_random_team_id()
        log_warn(f"Không lấy được Team ID từ cert - dùng Team ID ngẫu nhiên: {team_id}")
    
    log_step(5, "Xử lý App ID & Provisioning Profile")
    work_dir = os.path.join(WORK_DIR, "extract")
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)
    
    utils.extract_ipa(ipa_path, work_dir)
    app_bundle = utils.find_app_bundle(work_dir)
    bundle_id = utils.get_bundle_id(app_bundle)
    app_name = utils.get_app_name(app_bundle)
    log_info(f"App: {app_name} | Bundle ID: {bundle_id}")
    
    # === ĐỔI BUNDLE ID (app + extension) ===
    bundle_id = patch_bundle_ids(app_bundle, team_id)
    log_ok(f"✅ Đã đổi bundle ID thành: {bundle_id}")
    
    # === TẠO APP ID ===
    app_ids = dev_api.list_app_ids()
    app_id_obj = None
    for a in app_ids:
        if a.get("identifier") == bundle_id:
            app_id_obj = a
            break
    
    if not app_id_obj:
        app_id_obj = dev_api.create_app_id(bundle_id, app_name)
        if not app_id_obj:
            log_error(f"Không tạo được App ID: {dev_api.last_error}")
            return False
        log_ok(f"✅ Đã tạo App ID: {bundle_id}")
    else:
        log_ok(f"✅ Dùng App ID có sẵn: {bundle_id}")
    
    # === TẢI PROVISIONING PROFILE ===
    app_id_id = app_id_obj.get("appIdId") or app_id_obj.get("id")
    profile = dev_api.download_provisioning_profile(app_id_id)
    if not profile:
        log_error("Không tải được Provisioning Profile.")
        return False
    
    profile_content = utils.decode_apple_data_field(
        profile.get("encodedProfile") or profile.get("content") or profile.get("profileContent")
    )
    # Ghi profile vào app
    app_prov_path = os.path.join(app_bundle, "embedded.mobileprovision")
    with open(app_prov_path, "wb") as f:
        f.write(profile_content)
    log_ok("Đã thêm mobileprovision vào app")
    
    # Ghi profile vào extension (nếu có)
    plugins_dir = os.path.join(app_bundle, "PlugIns")
    if os.path.isdir(plugins_dir):
        for item in os.listdir(plugins_dir):
            if item.endswith(".appex"):
                ext_prov_path = os.path.join(plugins_dir, item, "embedded.mobileprovision")
                with open(ext_prov_path, "wb") as f:
                    f.write(profile_content)
                log_ok(f"Đã thêm mobileprovision vào extension: {item}")
    
    log_step(6, "Ký IPA bằng zsign")
    if not check_zsign():
        return False
    
    zsign_path = find_zsign()
    if not zsign_path:
        return False
    
    signed_ipa = os.path.join(WORK_DIR, f"{app_name}_signed.ipa")
    tmp_dir = os.path.join(WORK_DIR, "zsign_tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    
    # Xây dựng lệnh zsign (KHÔNG có -E)
    zsign_cmd = [
        zsign_path,
        "-f",
        "-t", tmp_dir,
        "-c", cert_pem_path,
        "-k", key_pem_path,
        "-m", app_prov_path,
    ]
    
    # Thêm -m cho extension nếu có
    plugins_dir = os.path.join(app_bundle, "PlugIns")
    if os.path.isdir(plugins_dir):
        for item in os.listdir(plugins_dir):
            if item.endswith(".appex"):
                ext_prov_path = os.path.join(plugins_dir, item, "embedded.mobileprovision")
                if os.path.exists(ext_prov_path):
                    zsign_cmd.extend(["-m", ext_prov_path])
    
    # Thêm output và input
    zsign_cmd.extend(["-o", signed_ipa, app_bundle])
    
    try:
        utils.run_command(zsign_cmd)
        log_ok(f"Đã ký IPA: {signed_ipa}")
    except Exception as e:
        log_error(f"Ký IPA thất bại: {e}")
        return False
    
    log_step(7, "Pairing & Cài đặt")
    pair = device_link.pair_device(udid)
    if not pair:
        log_error("Pairing thất bại.")
        return False
    log_ok("Pairing thành công.")
    
    device_link.install_ipa(pair, signed_ipa)
    log_ok("Cài đặt thành công!")
    return True

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
    print("3. Thiết lập USB & USBMUXD")
    print("4. Test Pairing")
    print("5. Thoát")
    choice = input("Chọn (1-5): ").strip()
    
    if choice == "1":
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
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Lỗi: {e}")
        sys.exit(1)
