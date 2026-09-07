#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess
import os
import shutil
import zipfile
import plistlib
import base64
import binascii

def run_command(command, cwd=None, extra_env=None):
    env = None
    if extra_env:
        env = dict(os.environ)
        env.update(extra_env)
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, check=True)
        print(f"[CMD] {command}\n{result.stdout}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[CMD ERROR] {command}")
        if e.stdout:
            print(f"--- stdout ---\n{e.stdout}")
        if e.stderr:
            print(f"--- stderr ---\n{e.stderr}")
        raise

def extract_ipa(ipa_path, output_dir):
    print(f"[IPA] Giải nén {ipa_path} vào {output_dir}...")
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(output_dir)
    print("[IPA] Giải nén xong.")
    return output_dir

def find_app_bundle(extracted_ipa_path):
    payload_path = os.path.join(extracted_ipa_path, "Payload")
    if not os.path.exists(payload_path):
        raise Exception(f"Không có Payload trong {extracted_ipa_path}")
    for item in os.listdir(payload_path):
        if item.endswith(".app"):
            return os.path.join(payload_path, item)
    raise Exception("Không tìm thấy .app")

def get_bundle_id(app_bundle_path):
    info_plist = os.path.join(app_bundle_path, "Info.plist")
    with open(info_plist, 'rb') as f:
        plist_data = plistlib.load(f)
    return plist_data.get("CFBundleIdentifier")

def get_app_name(app_bundle_path):
    info_plist = os.path.join(app_bundle_path, "Info.plist")
    with open(info_plist, 'rb') as f:
        plist_data = plistlib.load(f)
    return plist_data.get("CFBundleDisplayName") or plist_data.get("CFBundleName") or "App"

def set_bundle_id(app_bundle_path, new_bundle_id):
    info_plist = os.path.join(app_bundle_path, "Info.plist")
    with open(info_plist, 'rb') as f:
        plist_data = plistlib.load(f)
    plist_data["CFBundleIdentifier"] = new_bundle_id
    with open(info_plist, 'wb') as f:
        plistlib.dump(plist_data, f)
    return new_bundle_id

def save_certificate_as_pem(cert_content_raw, output_path):
    if isinstance(cert_content_raw, bytes) and cert_content_raw[:1] == b"\x30":
        with open(output_path, "wb") as f:
            f.write(b"-----BEGIN CERTIFICATE-----\n")
            f.write(base64.encodebytes(cert_content_raw))
            f.write(b"-----END CERTIFICATE-----\n")
        return

    if isinstance(cert_content_raw, bytes):
        raw_str = cert_content_raw.decode("utf-8", "ignore")
    else:
        raw_str = cert_content_raw

    if "-----BEGIN CERTIFICATE-----" in raw_str:
        with open(output_path, "w") as f:
            f.write(raw_str)
        return

    try:
        decoded = base64.b64decode(raw_str, validate=False)
    except Exception:
        decoded = None

    if decoded and b"-----BEGIN CERTIFICATE-----" in decoded[:60]:
        with open(output_path, "wb") as f:
            f.write(decoded)
        return

    if decoded:
        with open(output_path, "wb") as f:
            f.write(b"-----BEGIN CERTIFICATE-----\n")
            f.write(base64.encodebytes(decoded))
            f.write(b"-----END CERTIFICATE-----\n")
        return

    raise Exception("Không thể nhận diện định dạng cert")

def decode_apple_data_field(raw):
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw)
        except (binascii.Error, ValueError):
            return raw.encode("utf-8")
    return b""
