#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import os
from cryptography.fernet import Fernet

TERMUX_HOME = os.environ.get("HOME", "/data/data/com.termux/files/home")
CONFIG_DIR = os.path.join(TERMUX_HOME, ".config", "sideload")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
SECRET_KEY_PATH = os.path.join(CONFIG_DIR, ".secret.key")
CRED_FILE = os.path.join(CONFIG_DIR, "credentials.enc")

def _ensure_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)

def _get_fernet():
    _ensure_dir()
    if not os.path.exists(SECRET_KEY_PATH):
        key = Fernet.generate_key()
        with open(SECRET_KEY_PATH, "wb") as f:
            f.write(key)
        os.chmod(SECRET_KEY_PATH, 0o600)
    with open(SECRET_KEY_PATH, "rb") as f:
        key = f.read()
    return Fernet(key)

def _encrypt_password(password):
    f = _get_fernet()
    return f.encrypt(password.encode()).decode()

def _decrypt_password(encrypted):
    f = _get_fernet()
    return f.decrypt(encrypted.encode()).decode()

def load_config():
    _ensure_dir()
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_config(config):
    _ensure_dir()
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

def get_apple_id():
    return load_config().get("apple_id", "")

def set_apple_id(apple_id):
    config = load_config()
    if apple_id:
        config["apple_id"] = apple_id
    else:
        config.pop("apple_id", None)
    save_config(config)

def get_anisette_url():
    return load_config().get("anisette_url", "")

def set_anisette_url(url):
    config = load_config()
    if url:
        config["anisette_url"] = url
    else:
        config.pop("anisette_url", None)
    save_config(config)

def save_password(password):
    if not password:
        return
    enc = _encrypt_password(password)
    with open(CRED_FILE, "w") as f:
        f.write(enc)
    os.chmod(CRED_FILE, 0o600)
    print("[config] Đã lưu mật khẩu (mã hoá).")

def get_password():
    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE, "r") as f:
                enc = f.read().strip()
            return _decrypt_password(enc)
        except Exception as e:
            print(f"[config] Không đọc được mật khẩu: {e}")
    return ""

def clear_credentials():
    if os.path.exists(CRED_FILE):
        os.remove(CRED_FILE)
    print("[config] Đã xoá thông tin đăng nhập.")
