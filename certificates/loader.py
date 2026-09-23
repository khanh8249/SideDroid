# certificates/loader.py
from importlib.resources import files
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def _load_der(filename: str):
    data = files("certificates.assets").joinpath(filename).read_bytes()
    return x509.load_der_x509_certificate(data, default_backend())


def load_apple_root():
    return _load_der("AppleRootCA-G3.cer")


def load_apple_wwdr_g3():
    return _load_der("AppleWWDRCAG3.cer")


def load_user_cert(pem_path: str):
    with open(pem_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())
