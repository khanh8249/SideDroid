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
    os.makedirs(output_dir, exist_ok=True)

    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        for info in zip_ref.infolist():
            extracted_path = os.path.join(output_dir, info.filename)
            os.makedirs(os.path.dirname(extracted_path), exist_ok=True)

            if info.is_dir():
                os.makedirs(extracted_path, exist_ok=True)
                continue

            if (info.external_attr >> 28) == 0xA:
                link_target = zip_ref.read(info).decode('utf-8').strip()
                if os.path.exists(extracted_path) or os.path.islink(extracted_path):
                    os.unlink(extracted_path)
                os.symlink(link_target, extracted_path)
            else:
                with zip_ref.open(info) as source, open(extracted_path, 'wb') as target:
                    shutil.copyfileobj(source, target)

                unix_attributes = info.external_attr >> 16
                if unix_attributes != 0:
                    os.chmod(extracted_path, unix_attributes & 0o777)

    print("[IPA] Giải nén xong và giữ nguyên cấu trúc iOS.")
    return output_dir
    p
def package_ipa(source_dir, output_ipa, prefer_ditto=True):
    """
    Đóng gói thư mục thành IPA, giữ nguyên symlink + quyền POSIX.
    
    - Nếu có `ditto` (macOS), dùng nó (chuẩn nhất).
    - Fallback: tự viết bằng zipfile, set external_attr đúng.
    
    source_dir: thư mục chứa Payload/ (ví dụ work_dir)
    output_ipa: đường dẫn file .ipa đầu ra
    """
    payload = os.path.join(source_dir, "Payload")
    if not os.path.isdir(payload):
        raise Exception(f"Không tìm thấy Payload/ trong {source_dir}")

    if os.path.exists(output_ipa):
        os.remove(output_ipa)

    # === Ưu tiên ditto (chuẩn Apple, không sinh __MACOSX) ===
    if prefer_ditto and shutil.which("ditto"):
        try:
            subprocess.run(
                ["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                 payload, output_ipa],
                check=True, capture_output=True, text=True,
            )
            print(f"[IPA] Đóng gói bằng ditto: {output_ipa}")
            return output_ipa
        except subprocess.CalledProcessError as e:
            print(f"[IPA] ditto thất bại, fallback sang zipfile: {e.stderr}")
            if os.path.exists(output_ipa):
                os.remove(output_ipa)

    # === Fallback: zipfile thuần, giữ symlink ===
    print(f"[IPA] Đóng gói bằng zipfile: {output_ipa}")

    def _add_tree(zf, base_real):
        """Duyệt cây thư mục, thêm từng entry vào zip với attr đúng."""
        # Duyệt thủ công để kiểm soát thứ tự: file trước, symlink sau
        files_to_add = []
        symlinks_to_add = []
        dirs_to_add = []

        for root, dirs, files in os.walk(base_real):
            # Sắp xếp để output ổn định
            dirs.sort()
            files.sort()

            for name in dirs:
                full = os.path.join(root, name)
                if os.path.islink(full):
                    symlinks_to_add.append(full)
                else:
                    dirs_to_add.append(full)

            for name in files:
                full = os.path.join(root, name)
                if os.path.islink(full):
                    symlinks_to_add.append(full)
                else:
                    files_to_add.append(full)

        # 1. Thư mục
        for full in dirs_to_add:
            rel = os.path.relpath(full, base_real).replace(os.sep, "/") + "/"
            zi = zipfile.ZipInfo(rel)
            zi.create_system = 3
            try:
                st = os.stat(full)
                zi.external_attr = ((st.st_mode & 0xFFFF) | 0o040000) << 16
            except OSError:
                zi.external_attr = (0o40755) << 16
            zi.compress_type = zipfile.ZIP_STORED
            zf.writestr(zi, b"")

        # 2. File thường
        for full in files_to_add:
            rel = os.path.relpath(full, base_real).replace(os.sep, "/")
            zi = zipfile.ZipInfo(rel)
            zi.create_system = 3
            try:
                st = os.stat(full)
                zi.external_attr = (st.st_mode & 0xFFFF) << 16
                zi.date_time = time.localtime(st.st_mtime)[:6]
            except OSError:
                zi.external_attr = (0o100644) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED

            # Ghi theo chunk để không tốn RAM với IPA lớn
            with open(full, "rb") as src, zf.open(zi, "w") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)

        # 3. Symlink (thêm sau cùng, để không bị ghi đè)
        for full in symlinks_to_add:
            rel = os.path.relpath(full, base_real).replace(os.sep, "/")
            target = os.readlink(full)

            zi = zipfile.ZipInfo(rel)
            zi.create_system = 3
            # S_IFLNK = 0o120000, quyền 0o777
            zi.external_attr = (0o120777) << 16
            zi.compress_type = zipfile.ZIP_STORED
            zf.writestr(zi, target.encode("utf-8"))

        return len(files_to_add), len(symlinks_to_add), len(dirs_to_add)

    base_real = os.path.realpath(payload)

    with zipfile.ZipFile(output_ipa, "w", zipfile.ZIP_DEFLATED) as zf:
        n_files, n_links, n_dirs = _add_tree(zf, base_real)

    print(f"[IPA] Đã đóng gói: {n_files} file, {n_links} symlink, {n_dirs} thư mục")
    return output_ipa


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
