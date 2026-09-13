#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess
import os
import sys

def check_tidevice():
    """Kiểm tra tidevice đã cài chưa"""
    try:
        result = subprocess.run(["tidevice", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True
    except:
        pass
    print("[device_link] ❌ tidevice chưa cài!")
    print("[device_link] Cài bằng: pip install tidevice")
    return False

def check_libimobiledevice():
    """Kiểm tra libimobiledevice đã cài chưa"""
    required = ["idevice_id", "idevicepair"]
    missing = []
    for tool in required:
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing.append(tool)
    if missing:
        print("[device_link] ❌ Thiếu libimobiledevice:")
        for t in missing:
            print(f"  - {t}")
        print("Cài bằng: pkg install libimobiledevice")
        return False
    return True

def _run(cmd, timeout=30):
    """Chạy lệnh và trả về output"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[device_link] Lỗi {cmd}: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        print(f"[device_link] Timeout {cmd}")
        raise

def get_udid_from_usb():
    """Lấy UDID thiết bị đang kết nối"""
    if not check_libimobiledevice():
        return None
    try:
        output = _run(["idevice_id", "-l"], timeout=10)
        if output:
            udid = output.split('\n')[0].strip()
            # Kiểm tra UDID hợp lệ
            if len(udid) == 40 and all(c in "0123456789abcdefABCDEF" for c in udid):
                print(f"[device_link] UDID: {udid}")
                return udid
    except Exception as e:
        print(f"[device_link] Lỗi UDID: {e}")
    return None

def pair_device(udid=None):
    """Pairing với thiết bị - dùng idevicepair"""
    if not check_libimobiledevice():
        return None
    if not udid:
        udid = get_udid_from_usb()
        if not udid:
            return None
    print("[device_link] Bắt đầu pairing...")
    print("[device_link] 👉 Hãy bấm 'Tin cậy' trên iPhone nếu có popup.")
    try:
        output = _run(["idevicepair", "pair", udid], timeout=60)
        print(f"[device_link] Pairing: {output}")
        if "success" in output.lower() or "paired" in output.lower():
            return {"UDID": udid, "paired": True}
    except Exception as e:
        print(f"[device_link] Lỗi pairing: {e}")
    return None

def install_ipa(pair_record, ipa_path, progress_cb=None):
    """Cài đặt IPA bằng tidevice install"""
    if not check_tidevice():
        return False
    if not os.path.exists(ipa_path):
        print(f"[device_link] File IPA không tồn tại: {ipa_path}")
        return False
    
    # Kiểm tra kết nối USB
    udid = get_udid_from_usb()
    if not udid:
        print(f"[device_link] ❌ Không tìm thấy thiết bị!")
        return False
    
    # Kiểm tra pairing - BẮT BUỘC
    if not pair_record or not pair_record.get("paired"):
        print(f"[device_link] ❌ Chưa pairing với thiết bị!")
        return False
    
    # Cài đặt IPA - dùng tidevice install
    print(f"[device_link] Cài đặt {ipa_path}...")
    try:
        cmd = ["tidevice", "install", ipa_path]
        
        if progress_cb:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                if "%" in line:
                    try:
                        pct = int(line.split("%")[0].split()[-1])
                        progress_cb(pct, line.strip())
                    except:
                        pass
                print(line.strip())
            process.wait()
            return process.returncode == 0
        else:
            output = _run(cmd, timeout=300)
            print(output)
            return True
    except Exception as e:
        print(f"[device_link] Lỗi cài đặt: {e}")
        return False

def list_installed_apps(pair_record=None):
    """Liệt kê các app đã cài"""
    if not check_tidevice():
        return []
    try:
        output = _run(["tidevice", "applist"], timeout=30)
        apps = []
        for line in output.split('\n'):
            line = line.strip()
            if line and not line.startswith("Total"):
                apps.append(line.split()[0])
        return apps
    except:
        return []

def validate_pair_record(pair_record):
    """Kiểm tra pair_record"""
    return bool(pair_record and pair_record.get("paired"))

def reset_mux_device():
    """Không cần reset vì tidevice tự xử lý"""
    pass
