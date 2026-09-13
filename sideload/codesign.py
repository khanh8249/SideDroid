# sideload/codesign.py
"""
Port từ sideload/macho.d (phần Blob/CodeDirectory/Signature/EmbeddedSignature).
"""

import struct
import time
import plistlib
from abc import ABC, abstractmethod
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


# ===========================================================================
# Constants
# ===========================================================================
PAGE_SIZE_LOG2               = 14
PAGE_SIZE_CODEDIRECTORY_LOG2 = 12
PAGE_SIZE_CODEDIRECTORY      = 1 << PAGE_SIZE_CODEDIRECTORY_LOG2

CSSLOT_CODEDIRECTORY             = 0
CSSLOT_REQUIREMENTS              = 2
CSSLOT_ENTITLEMENTS              = 5
CSSLOT_DER_ENTITLEMENTS          = 7
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_SIGNATURESLOT             = 0x10000

CSMAGIC_BLOBWRAPPER               = 0xfade0b01
CSMAGIC_REQUIREMENT               = 0xfade0c00
CSMAGIC_REQUIREMENTS              = 0xfade0c01
CSMAGIC_CODEDIRECTORY             = 0xfade0c02
CSMAGIC_EMBEDDED_SIGNATURE        = 0xfade0cc0
CSMAGIC_EMBEDDED_SIGNATURE_OLD    = 0xfade0b02
CSMAGIC_EMBEDDED_ENTITLEMENTS     = 0xfade7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172

CODEDIRECTORY_VERSION = 0x20400

OID_CMS_SIGNED_DATA    = "1.2.840.113549.1.7.2"
OID_CMS_DATA_CONTENT   = "1.2.840.113549.1.7.1"
OID_PKCS9_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_PKCS9_MSG_DIGEST   = "1.2.840.113549.1.9.4"
OID_PKCS9_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SHA_256            = "2.16.840.1.101.3.4.2.1"
OID_RSA_SHA256         = "1.2.840.113549.1.1.11"
OID_APPLE_CDHASH_SET   = "1.2.840.113635.100.9.2"
OID_APPLE_CDHASHES     = "1.2.840.113635.100.9.1"


# ===========================================================================
# Exceptions
# ===========================================================================
class UnknownHashFunction(Exception):
    pass


class UnsupportedEntitlementsException(Exception):
    pass


# ===========================================================================
# Minimal DER encoder
# ===========================================================================
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, (n >> 8) & 0xff, n & 0xff])
    if n < 0x1000000:
        return bytes([0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
    return bytes([0x84, (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def der_seq(items):
    return _der(0x30, b"".join(items))


def der_set(items):
    return _der(0x31, b"".join(items))


def der_bool(v: bool) -> bytes:
    return _der(0x01, b"\xff" if v else b"\x00")


def der_int(n: int) -> bytes:
    if n == 0:
        return _der(0x02, b"\x00")
    if n > 0:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
    else:
        length = ((n + 1).bit_length() + 8) // 8
        b = n.to_bytes(length, "big", signed=True)
    return _der(0x02, b)


def der_octet_string(b: bytes) -> bytes:
    return _der(0x04, b)


def der_utf8_string(s: str) -> bytes:
    return _der(0x0c, s.encode("utf-8"))


def der_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    enc = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            enc += bytes([p])
        else:
            bs = []
            while p > 0:
                bs.insert(0, p & 0x7f)
                p >>= 7
            for i in range(len(bs) - 1):
                bs[i] |= 0x80
            enc += bytes(bs)
    return _der(0x06, enc)


def der_utc_time(t) -> bytes:
    s = time.strftime("%y%m%d%H%M%SZ", t)
    return _der(0x17, s.encode("ascii"))


def der_context_explicit(tag: int, content: bytes) -> bytes:
    return _der(0xA0 + tag, content)


# ===========================================================================
# Blob base
# ===========================================================================
class Blob(ABC):
    @abstractmethod
    def type(self) -> int: ...
    @abstractmethod
    def length(self) -> int: ...
    @abstractmethod
    def encode(self, previous_encoded_blobs: List[bytes]) -> bytes: ...


# ===========================================================================
# RawBlob
# ===========================================================================
class RawBlob(Blob):
    def __init__(self, type_: int, data: bytes):
        self._type = type_
        length = struct.unpack_from(">I", data, 4)[0]
        self._data = data[:length]

    def type(self) -> int:
        return self._type

    def length(self) -> int:
        return len(self._data)

    def encode(self, previous_encoded_blobs: List[bytes]) -> bytes:
        return self._data


# ===========================================================================
# CodeDirectoryBlob
# ===========================================================================
class CodeDirectoryBlob(Blob):
    _FMT = ">9IBBBB4I4Q"
    SIZE = struct.calcsize(_FMT)  # 88 bytes

    def __init__(self, hash_function, bundle_identifier, team_identifier,
                 macho, entitlements, info_plist, code_resources,
                 is_alternate=False):
        self.hash_function = hash_function
        self.bundle_id = bundle_identifier
        self.team_id = team_identifier
        self.macho = macho
        self.entitlements = entitlements
        self.info_plist = info_plist
        self.code_resources = code_resources
        self.is_alternate = is_alternate

    def type(self) -> int:
        return (CSSLOT_ALTERNATE_CODEDIRECTORIES
                if self.is_alternate else CSSLOT_CODEDIRECTORY)

    def _hash_size(self) -> int:
        return self.hash_function().digest_size

    def _hash_type(self) -> int:
        size = self._hash_size()
        if size == 20:
            return 1
        if size == 32:
            return 2
        raise UnknownHashFunction()

    def length(self) -> int:
        hash_len = self._hash_size()
        code_limit = self.macho.code_signature_offset()
        n_code_slots = (code_limit + 4095) // 4096
        return (self.SIZE
                + len(self.bundle_id) + 1
                + len(self.team_id) + 1
                + ((2 if self.macho.filetype == 0x2 else 0)
                   + 5 + n_code_slots) * hash_len)

    def encode(self, previous_encoded_blobs: List[bytes]) -> bytes:
        exec_seg_base  = self.macho.exec_seg_base
        exec_seg_limit = self.macho.exec_seg_limit
        exec_flags     = self.macho.exec_flags(self.entitlements)

        if self.entitlements.get("get-task-allow") is True:
            exec_flags |= 0x10

        code_limit = self.macho.code_signature_offset()
        code_data  = bytes(self.macho.data[:code_limit])
        code_slots = [code_data[i:i + 4096]
                      for i in range(0, len(code_data), 4096)]

        is_execute = self.macho.filetype == 0x2

        req_data = None
        ent_data = None
        der_ent_data = None
        for blob in previous_encoded_blobs:
            if len(blob) < 8:
                continue
            magic = struct.unpack_from(">I", blob, 0)[0]
            if magic == CSMAGIC_REQUIREMENTS:
                req_data = blob
            elif magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
                ent_data = blob
            elif magic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
                der_ent_data = blob

        if req_data is None:
            raise ValueError("Requirements have not been computed before CodeDir!")
        if ent_data is None:
            raise ValueError("Entitlements have not been computed before CodeDir!")
        if is_execute and der_ent_data is None:
            raise ValueError("DerEntitlements have not been computed before CodeDir!")

        hash_len = self._hash_size()
        h = self.hash_function

        def H(data: bytes) -> bytes:
            return h(data).digest()

        body = bytearray()

        ident_offset = self.SIZE
        body += self.bundle_id.encode("utf-8") + b"\x00"

        team_offset = self.SIZE + len(body)
        body += self.team_id.encode("utf-8") + b"\x00"

        empty_hash = b"\x00" * hash_len
        special_slots: List[bytes] = []

        if is_execute:
            special_slots.append(H(der_ent_data))
            special_slots.append(empty_hash)
        special_slots.append(H(ent_data))
        special_slots.append(empty_hash)
        special_slots.append(H(self.code_resources) if self.code_resources else empty_hash)
        special_slots.append(H(req_data))
        special_slots.append(H(self.info_plist) if self.info_plist else empty_hash)

        n_special = len(special_slots)
        for s in special_slots:
            body += s

        hash_offset = self.SIZE + len(body)
        n_code_slots = len(code_slots)

        for slot in code_slots:
            body += H(slot)

        code_limit32 = code_limit if code_limit <= 0xFFFFFFFF else 0
        code_limit64 = code_limit if code_limit > 0xFFFFFFFF else 0

        header = struct.pack(
            self._FMT,
            CSMAGIC_CODEDIRECTORY,
            self.SIZE + len(body),
            CODEDIRECTORY_VERSION,
            0,
            hash_offset,
            ident_offset,
            n_special,
            n_code_slots,
            code_limit32,
            hash_len,
            self._hash_type(),
            0,
            PAGE_SIZE_CODEDIRECTORY_LOG2,
            0,
            0,
            team_offset,
            0,
            code_limit64,
            exec_seg_base,
            exec_seg_limit,
            exec_flags,
        )

        return header + bytes(body)


# ===========================================================================
# Requirement
# ===========================================================================
class Requirement(Blob):
    def type(self) -> int:
        return CSMAGIC_REQUIREMENT

    def length(self) -> int:
        return 0

    def encode(self, previous_encoded_blobs):
        return b""


# ===========================================================================
# RequirementsBlob
# ===========================================================================
class RequirementsBlob(Blob):
    def type(self) -> int:
        return CSSLOT_REQUIREMENTS

    def length(self) -> int:
        return 4 + 4 + 4

    def encode(self, previous_encoded_blobs):
        return (struct.pack(">I", CSMAGIC_REQUIREMENTS)
                + struct.pack(">I", self.length())
                + struct.pack(">I", 0))


# ===========================================================================
# EntitlementsBlob
# ===========================================================================
class EntitlementsBlob(Blob):
    def __init__(self, xml_entitlements: str):
        if isinstance(xml_entitlements, bytes):
            xml_entitlements = xml_entitlements.decode("utf-8", "ignore")
        self.entitlements = xml_entitlements

    def type(self) -> int:
        return CSSLOT_ENTITLEMENTS

    def length(self) -> int:
        return 4 + 4 + len(self.entitlements.encode("utf-8"))

    def encode(self, previous_encoded_blobs):
        return (struct.pack(">I", CSMAGIC_EMBEDDED_ENTITLEMENTS)
                + struct.pack(">I", self.length())
                + self.entitlements.encode("utf-8"))


# ===========================================================================
# DerEntitlementsBlob
# ===========================================================================
class DerEntitlementsBlob(Blob):
    def __init__(self, entitlements: dict):
        self.entitlements_der = _encode_entitlements(entitlements)

    def type(self) -> int:
        return CSSLOT_DER_ENTITLEMENTS

    def length(self) -> int:
        return 4 + 4 + len(self.entitlements_der)

    def encode(self, previous_encoded_blobs):
        return (struct.pack(">I", CSMAGIC_EMBEDDED_DER_ENTITLEMENTS)
                + struct.pack(">I", self.length())
                + self.entitlements_der)


def _encode_entitlements(value) -> bytes:
    if isinstance(value, bool):
        return der_bool(value)
    if isinstance(value, int):
        return der_int(value)
    if isinstance(value, str):
        return der_utf8_string(value)
    if isinstance(value, (list, tuple)):
        return der_seq([_encode_entitlements(v) for v in value])
    if isinstance(value, dict):
        entries = [der_seq([der_utf8_string(k), _encode_entitlements(v)])
                   for k, v in value.items()]
        return der_set(entries)
    raise UnsupportedEntitlementsException(f"Unsupported: {type(value)}")


# ===========================================================================
# DebugBlob
# ===========================================================================
class DebugBlob(Blob):
    def __init__(self, type_: int, data: bytes):
        self._type = type_
        self._data = data

    def type(self) -> int:
        return self._type

    def length(self) -> int:
        return len(self._data)

    def encode(self, previous_encoded_blobs):
        return self._data


# ===========================================================================
# SignatureBlob
# ===========================================================================
class SignatureBlob(Blob):
    def __init__(self, identity, hashers: List):
        self.identity = identity
        self.hashers = hashers  # [None, sha1_ctor, sha256_ctor]

    def type(self) -> int:
        return CSSLOT_SIGNATURESLOT

    def length(self) -> int:
        return 5000

    def encode(self, previous_encoded_blobs: List[bytes]) -> bytes:
        code_dirs = [
            b for b in previous_encoded_blobs
            if len(b) >= 4 and struct.unpack_from(">I", b, 0)[0] == CSMAGIC_CODEDIRECTORY
        ]

        signature = self._encode_cms(code_dirs)

        body = (struct.pack(">I", CSMAGIC_BLOBWRAPPER)
                + struct.pack(">I", 4 + 4 + len(signature))
                + signature)

        target = self.length()
        if len(body) < target:
            body += b"\x00" * (target - len(body))
        return body

    def _code_dir_hash_type(self, code_dir: bytes) -> int:
        return code_dir[36]

    def _encode_cms(self, code_dirs: List[bytes]) -> bytes:
        from sideload.applecert import apple_wwdr_g3, apple_root

        sha256 = self.hashers[2]
        h256 = sha256().digest

        cd_hashes_entries = []
        for cd in code_dirs:
            ht = self._code_dir_hash_type(cd)
            if ht == 1:
                digest = self.hashers[1]().digest(cd)
            elif ht == 2:
                digest = self.hashers[2]().digest(cd)
            else:
                digest = sha256(cd).digest()
            cd_hashes_entries.append(digest[:20])

        cdhashes_plist = {"cdhashes": cd_hashes_entries}
        cdhashes_xml = plistlib.dumps(cdhashes_plist, fmt=plistlib.FMT_XML)[:-1]

        now = time.gmtime()

        signed_attrs = b"".join([
            der_seq([
                der_oid(OID_PKCS9_CONTENT_TYPE),
                der_set([der_oid(OID_CMS_DATA_CONTENT)]),
            ]),
            der_seq([
                der_oid(OID_PKCS9_SIGNING_TIME),
                der_set([der_utc_time(now)]),
            ]),
            der_seq([
                der_oid(OID_PKCS9_MSG_DIGEST),
                der_set([der_octet_string(h256(code_dirs[0]))]),
            ]),
            der_seq([
                der_oid(OID_APPLE_CDHASH_SET),
                der_set([
                    der_seq([
                        der_oid(OID_SHA_256),
                        der_octet_string(h256(code_dirs[0])),
                    ]),
                ]),
            ]),
            der_seq([
                der_oid(OID_APPLE_CDHASHES),
                der_set([der_octet_string(cdhashes_xml)]),
            ]),
        ])

        attr_to_sign = der_set([signed_attrs])

        signature_value = self.identity.private_key.sign(
            attr_to_sign,
            asym_padding.PKCS1v15(),
            hashes.SHA256(),
        )

        wwdr = x509.load_der_x509_certificate(apple_wwdr_g3)
        root = x509.load_der_x509_certificate(apple_root)
        signer_cert = self.identity.certificate

        issuer_dn = signer_cert.issuer.public_bytes()
        serial = signer_cert.serial_number

        signer_info = der_seq([
            der_int(1),
            der_seq([issuer_dn, der_int(serial)]),
            der_seq([der_oid(OID_SHA_256)]),
            der_context_explicit(0, signed_attrs),
            der_seq([der_oid(OID_RSA_SHA256), der_octet_string(b"\x05\x00")]),
            der_octet_string(signature_value),
        ])

        signed_data_content = der_seq([
            der_int(1),
            der_set([der_seq([der_oid(OID_SHA_256)])]),
            der_seq([der_oid(OID_CMS_DATA_CONTENT)]),
            der_context_explicit(0,
                signer_cert.public_bytes(serialization.Encoding.DER)
                + wwdr.public_bytes(serialization.Encoding.DER)
                + root.public_bytes(serialization.Encoding.DER)
            ),
            der_set([signer_info]),
        ])

        return der_seq([
            der_oid(OID_CMS_SIGNED_DATA),
            der_context_explicit(0, signed_data_content),
        ])


# ===========================================================================
# EmbeddedSignature
# ===========================================================================
class EmbeddedSignature:
    def __init__(self):
        self.blobs: List[Blob] = []

    def length(self) -> int:
        return 12 + 8 * len(self.blobs) + sum(b.length() for b in self.blobs)

    @staticmethod
    def decode(data: bytes) -> "EmbeddedSignature":
        magic, length, count = struct.unpack_from(">III", data, 0)
        if magic != CSMAGIC_EMBEDDED_SIGNATURE:
            raise ValueError(f"Not an embedded signature: {magic:#x}")

        blob_indexes = []
        for i in range(count):
            t, off = struct.unpack_from(">II", data, 12 + i * 8)
            blob_indexes.append((t, off))

        sig = EmbeddedSignature()
        sig.blobs = [RawBlob(t, data[off:]) for t, off in blob_indexes]
        return sig

    def encode(self) -> bytes:
        offset = 12 + len(self.blobs) * 8

        blobs_data: List[bytes] = []
        for blob in self.blobs:
            d = blob.encode(blobs_data)
            announced = blob.length()
            real = len(d)
            if announced != real:
                raise ValueError(
                    f"Blob announced {announced} bytes but encoded {real}"
                )
            blobs_data.append(d)

        for i, b in enumerate(self.blobs):
            if b.type() == CSSLOT_CODEDIRECTORY:
                if i != 0:
                    self.blobs[0], self.blobs[i] = self.blobs[i], self.blobs[0]
                    blobs_data[0], blobs_data[i] = blobs_data[i], blobs_data[0]
                break

        blob_indexes = bytearray()
        for b, d in zip(self.blobs, blobs_data):
            blob_indexes += struct.pack(">II", b.type(), offset)
            offset += len(d)

        data = b"".join(blobs_data)

        return (struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE,
                            12 + len(self.blobs) * 8 + len(data),
                            len(self.blobs))
                + bytes(blob_indexes)
                + data)
