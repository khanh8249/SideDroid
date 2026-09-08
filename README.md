# 📱 SideDroid

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Platform-Termux-orange.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
</p>

<p align="center">
  <b>🛠 Công cụ Sideload IPA trên Termux dành cho Android</b><br>
  Hỗ trợ ký và cài ứng dụng iOS trực tiếp từ điện thoại Android
</p>

---

## ✨ Tính năng nổi bật

- 🔐 **Xác thực Apple ID** - Hỗ trợ đăng nhập và xử lý 2FA
- 📱 **Ký IPA** - Sử dụng zsign để ký ứng dụng iOS
- 🔌 **Hỗ trợ USB** - Kết nối iPhone qua cáp USB trên Android
- 🧩 **Hỗ trợ Extension** - Tự động xử lý App ID cho Widget, Keyboard, Notification
- 🚀 **Tự động cài đặt** - Cài IPA trực tiếp lên iPhone sau khi ký
- 🔄 **Quản lý Certificate** - Tạo và thu hồi certificate tự động
- 💾 **Lưu thông tin** - Lưu Apple ID và mật khẩu để sử dụng sau

---

## 📋 Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|-----------|---------|
| **Android** | 7.0+ (API 24+) |
| **Termux** | Phiên bản mới nhất |
| **iPhone** | iOS 12.0+ (đã jailbreak hoặc SideStore/AltStore) |
| **Python** | 3.7+ |
| **zsign** | Đã cài đặt |
| **libimobiledevice** | Đã cài đặt |

---

## 🔧 Cài đặt

### 1. Cài đặt Termux và các gói cần thiết

```bash
pkg update && pkg upgrade -y
pkg install -y python git unzip wget
pkg install -y libimobiledevice usbmuxd ideviceinstaller
pkg install -y zsign
```

2. Clone repository

```bash
git clone https://github.com/khanh8249/SideDroid.git
cd SideDroid
```

3. Cài đặt Python dependencies

```bash
pip install -r requirements.txt
```

4. Cấp quyền thực thi

```bash
chmod +x main.py
```

---

🚀 Hướng dẫn sử dụng

Chạy chương trình

```bash
python main.py
```

Menu chính

```
╔══════════════════════════════════════════╗
║     iOS Sideload Tool for Termux        ║
╚══════════════════════════════════════════╝

📱 iPhone Status: 🟢 CONNECTED & TRUSTED (UDID: ABC123...)

1. Sideload IPA
2. Thu hồi cert
3. Thiết lập USB & USBMUXD
4. Test Pairing
5. Thoát
```

---

📖 Quy trình Sideload IPA

Bước 1: Thiết lập USB (lần đầu)

```
📌 Chọn menu 3: Thiết lập USB & USBMUXD
👉 Kết nối iPhone qua cáp USB
👉 `hiện cho phép kết nốt với iphone trên termux thì hãy nhanh tay bấm vào đồng ý nếu không được thì hãy kill usbmuxd rồi vào bước 3 của menu`
👉 `Cắm iPhone và mở khóa màn hình`
👉 `Bấm "Trust" trên iPhone khi được hỏi
```

Bước 2: Sideload IPA

```
📌 Chọn menu 1: Sideload IPA
📂 Nhập đường dẫn IPA
📱 Nhập Apple ID và mật khẩu
🔐 Xác thực 2FA (nếu cần)
✅ Tự động ký và cài lên iPhone
```

Bước 3: Hoàn tất

```
🎉 Ứng dụng đã được cài thành công trên iPhone!
```

---

🛠 Cấu trúc dự án

```
SideDroid/
├── main.py              # File chính
├── apple_auth.py        # Xác thực Apple ID
├── developer_api.py     # API Apple Developer
├── device_link.py       # Kết nối thiết bị
├── config.py            # Quản lý cấu hình
├── utils.py             # Hàm tiện ích
├── zsign                # Binary zsign (tùy chọn)
├── requirements.txt     # Python dependencies
└── README.md            # Tài liệu
```

---

🔑 Hỗ trợ Apple ID

`Loại tài khoản App ID Extension Giới hạn
Free 1-2 ⚠️ Giới hạn 3 app / 7 ngày
Paid ($99/năm) Không giới hạn ✅ Đầy đủ Không giới hạn`

---

❓ Xử lý lỗi thường gặp

1. Lỗi "zsign không tìm thấy"

```bash
pkg install zsign
# Hoặc build từ source:
git clone https://github.com/zhlynn/zsign.git
cd zsign
make
cp zsign $PREFIX/bin/
```

2. Lỗi "Không tìm thấy thiết bị"

```bash
# Kiểm tra kết nối
idevice_id -l

# Nếu không thấy, kiểm tra:
# - Cáp USB
# - iPhone đã mở khóa
# - Đã bấm "Trust" chưa
```

3. Lỗi "Pairing thất bại"

```bash
# Xóa pairing cũ
idevicepair unpair
# Pair lại
idevicepair pair
# Xác nhận
idevicepair validate
```

---

📝 Lưu ý

· ⚠️ Tài khoản Free: Chỉ hỗ trợ tối đa 2 App ID (1 app + 1 extension)
· 🔄 Làm mới: Ứng dụng cần được refresh mỗi 7 ngày (tài khoản Free)
· 📱 iPhone: Cần jailbreak hoặc cài SideStore/AltStore để cài IPA
· 🔌 USB: Cần cấp quyền USB trên Android (popup "Termux-usb")

---

🤝 Đóng góp

Mọi đóng góp đều được chào đón! Vui lòng:

1. Fork repository
2. Tạo branch mới (git checkout -b feature/AmazingFeature)
3. Commit changes (git commit -m 'Add some AmazingFeature')
4. Push lên branch (git push origin feature/AmazingFeature)
5. Mở Pull Request

---

📄 Giấy phép

Dự án được phân phối dưới giấy phép MIT. Xem LICENSE để biết thêm chi tiết.

---

⚠️ Tuyên bố từ chối trách nhiệm

Công cụ này chỉ dành cho mục đích học tập và nghiên cứu. Người dùng chịu hoàn toàn trách nhiệm về việc sử dụng công cụ này. Tác giả không chịu trách nhiệm cho bất kỳ vi phạm bản quyền hoặc điều khoản sử dụng nào của Apple.

---

📞 Liên hệ

· Tác giả: @khanh8249
· Issue: GitHub Issues

---

<p align="center">
  Made with ❤️ by khanh8249
</p>
```---

📦 File requirements.txt (nếu cần)

```txt
requests>=2.28.0
pycryptodome>=3.15.0
plistlib>=1.0
typing-extensions>=4.0.0
```

---

🎯 Bonus: Thêm badge cho README

Bạn có thể thêm các badge sau vào đầu file:

```markdown
<p align="center">
  <img src="https://img.shields.io/github/stars/khanh8249/SideDroid?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/khanh8249/SideDroid?style=social" alt="Forks">
  <img src="https://img.shields.io/github/watchers/khanh8249/SideDroid?style=social" alt="Watchers">
  <img src="https://img.shields.io/github/last-commit/khanh8249/SideDroid" alt="Last Commit">
  <img src="https://img.shields.io/github/issues/khanh8249/SideDroid" alt="Issues">
</p>
```

---
