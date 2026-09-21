# certificates/chain.py
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from .loader import load_apple_root, load_apple_wwdr_g3


def build_full_chain(user_cert_pem: str):
    """
    Ghép chuỗi: user cert → WWDR G3 → Apple Root.
    Trả về list x509.Certificate theo đúng thứ tự.
    """
    user = x509.load_pem_x509_certificate(user_cert_pem.encode())
    return [user, load_apple_wwdr_g3(), load_apple_root()]


def chain_to_pem_bundle(chain) -> str:
    """Chuyển list cert thành một PEM bundle nhiều cert."""
    return "".join(
        c.public_bytes(serialization.Encoding.PEM).decode()
        for c in chain
    )


def write_chain_file(user_cert_pem: str, output_path: str) -> str:
    """Ghi chain.pem ra file, trả về đường dẫn."""
    bundle = chain_to_pem_bundle(build_full_chain(user_cert_pem))
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(bundle)
    return output_path
