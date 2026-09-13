def length(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, value):
    return bytes([tag]) + length(len(value)) + value


def seq(*items):
    return tlv(0x30, b"".join(items))


def setof(*items):
    return tlv(0x31, b"".join(items))


def oid(value):
    parts = [int(x) for x in value.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        chunks = [n & 0x7F]
        n >>= 7
        while n:
            chunks.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(chunks))
    return tlv(0x06, out)


def octet(value):
    return tlv(0x04, value)


def integer(value):
    if value == 0:
        raw = b"\0"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\0" + raw
    return tlv(0x02, raw)


def null():
    return b"\x05\x00"


def context0(value):
    return tlv(0xA0, value)


def utf8(value):
    return tlv(0x0C, value.encode())


def utc_time(value):
    return tlv(0x17, value.encode())
