#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess
import os


def check_libimobiledevice():
    """Kiểm tra các công cụ libimobiledevice cần thiết."""
    required = [
        "idevice_id",
        "idevicepair",
        "ideviceinstaller",
    ]

    missing = []

    for tool in required:
        try:
            result = subprocess.run(
                ["which", tool],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                missing.append(tool)
        except Exception:
            missing.append(tool)

    if missing:
        print("[device_link] ❌ Thiếu công cụ:")
        for tool in missing:
            print(f"  - {tool}")
        print("[device_link] Cài bằng:")
        print("  pkg install libimobiledevice")
        return False

    return True


def _run(cmd, timeout=30):
    """Chạy command và trả về stdout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )

        stdout = result.stdout.strip()

        if result.stderr.strip():
            print(result.stderr.strip())

        return stdout

    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        print(f"[device_link] Lệnh thất bại: {' '.join(cmd)}")
        if stderr:
            print(f"[device_link] {stderr}")
        raise

    except subprocess.TimeoutExpired:
        print(
            f"[device_link] Timeout sau {timeout}s: "
            f"{' '.join(cmd)}"
        )
        raise


def get_udid_from_usb():
    """Lấy UDID của thiết bị iOS đang kết nối qua USB."""

    if not check_libimobiledevice():
        return None

    try:
        output = _run(
            ["idevice_id", "-l"],
            timeout=10,
        )

        if not output:
            print("[device_link] Không tìm thấy thiết bị iOS.")
            return None

        for line in output.splitlines():
            udid = line.strip()
            if (
                len(udid) == 40
                and all(
                    c in "0123456789abcdefABCDEF"
                    for c in udid
                )
            ):
                print(f"[device_link] UDID: {udid}")
                return udid

        print("[device_link] Không tìm thấy UDID hợp lệ.")
        return None

    except Exception as e:
        print(f"[device_link] Lỗi lấy UDID: {e}")
        return None


def pair_device(udid=None):
    """Pair thiết bị bằng idevicepair."""

    if not check_libimobiledevice():
        return None

    if not udid:
        udid = get_udid_from_usb()
        if not udid:
            return None

    print("[device_link] Bắt đầu pairing...")
    print(
        "[device_link] 👉 Nếu iPhone hỏi Trust, "
        "hãy bấm 'Tin cậy'."
    )

    try:
        output = _run(
            ["idevicepair", "-u", udid, "pair"],
            timeout=60,
        )

        if output:
            print(f"[device_link] Pairing: {output}")

        lower = output.lower()

        if (
            "success" in lower
            or "successfully" in lower
            or "paired" in lower
        ):
            return {
                "UDID": udid,
                "paired": True,
            }

        print("[device_link] Pairing hoàn tất.")
        return {
            "UDID": udid,
            "paired": True,
        }

    except Exception as e:
        print(f"[device_link] Lỗi pairing: {e}")
        return None


def validate_pair_record(pair_record):
    """Kiểm tra pair_record."""
    return bool(pair_record and pair_record.get("paired"))


def reset_mux_device():
    """Placeholder cho tương lai. Không cần reset vì idevicepair tự xử lý."""
    pass


def install_ipa(pair_record, ipa_path, progress_cb=None):
    """Cài IPA bằng ideviceinstaller."""

    if not check_libimobiledevice():
        return False

    if not ipa_path:
        print("[device_link] ❌ Đường dẫn IPA rỗng.")
        return False

    if not os.path.isfile(ipa_path):
        print(
            f"[device_link] ❌ File IPA không tồn tại: "
            f"{ipa_path}"
        )
        return False

    udid = get_udid_from_usb()
    if not udid:
        print("[device_link] ❌ Không tìm thấy thiết bị!")
        return False

    if not pair_record:
        print("[device_link] ❌ Không có pair record.")
        return False

    if not pair_record.get("paired"):
        print("[device_link] ❌ Thiết bị chưa được pairing!")
        return False

    paired_udid = pair_record.get("UDID")
    if paired_udid and paired_udid != udid:
        print("[device_link] ❌ UDID trong pair record không khớp.")
        print(f"[device_link] Pair record: {paired_udid}")
        print(f"[device_link] Thiết bị:      {udid}")
        return False

    print(f"[device_link] Cài đặt {ipa_path}...")
    print(f"[device_link] UDID: {udid}")

    cmd = [
        "ideviceinstaller",
        "-u", udid,
        "install", ipa_path,
    ]

    try:
        if progress_cb:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            if process.stdout:
                for line in process.stdout:
                    line = line.rstrip()
                    if not line:
                        continue
                    print(line)

                    if "%" in line:
                        try:
                            before_percent = line.split("%", 1)[0]
                            number = before_percent.split()[-1]
                            pct = int(float(number))
                            pct = max(0, min(100, pct))
                            progress_cb(pct, line)
                        except (ValueError, IndexError):
                            pass

            process.wait()

            if process.returncode != 0:
                print(
                    f"[device_link] ❌ ideviceinstaller "
                    f"exit code: {process.returncode}"
                )
                return False

            return True

        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.stdout.strip():
                print(result.stdout.strip())
            if result.stderr.strip():
                print(result.stderr.strip())

            if result.returncode != 0:
                print(
                    f"[device_link] ❌ ideviceinstaller "
                    f"exit code: {result.returncode}"
                )
                return False

            return True

    except subprocess.TimeoutExpired:
        print("[device_link] ❌ Timeout khi cài đặt.")
        return False

    except Exception as e:
        print(f"[device_link] ❌ Lỗi cài đặt: {e}")
        return False
