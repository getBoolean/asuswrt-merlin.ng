# UniFi "inform" (TNBU) wire-format reference — clean-room
#
# Encode/decode of the documented TNBU packet framing ONLY, written from the
# protocol facts in ../RESEARCH.md for interoperability research (DMCA 1201(f) /
# EU 2009/24/EC Art. 6). It contains no device-impersonation, discovery, or
# adoption logic and bundles none of Ubiquiti's code. See RESEARCH.md section 3.1.
#
# Requires: cryptography (PyCA). Python 3.
"""TNBU inform packet framing.

Wire format (all integers big-endian): a 40-byte header followed by the body.

    0   4  magic       b"TNBU"
    4   4  version     packet version (currently 0)
    8   6  hwaddr      device MAC
    14  2  flags       0x1 encrypted, 0x2 zlib, 0x4 snappy, 0x8 AES-GCM
    16  16 iv          AES IV / GCM nonce
    32  4  dataversion payload version (must be 1 = JSON)
    36  4  datalen     length of the payload that follows

Encryption: AES-128 with the 16-byte device authkey (hex string). CBC uses
PKCS#7 padding. GCM uses the 16-byte header IV as the nonce, a 128-bit tag
appended to the ciphertext, and the full 40-byte header (with datalen already
set) as AAD. Factory-default devices use authkey
ba86f2bbe107c7c57eb5f2690775c712 (= MD5("ubnt")).
"""

import os
import struct
import zlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"TNBU"
HEADER = struct.Struct(">4sI6sH16sII")
DEFAULT_AUTHKEY = "ba86f2bbe107c7c57eb5f2690775c712"

FLAG_ENCRYPTED = 0x1
FLAG_ZLIB = 0x2
FLAG_SNAPPY = 0x4
FLAG_GCM = 0x8


def mac_bytes(mac):
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def pack(mac, payload, authkey=DEFAULT_AUTHKEY, gcm=True, compress=True):
    """Build an inform packet from a JSON payload (bytes)."""
    key = bytes.fromhex(authkey)
    flags = FLAG_ENCRYPTED
    data = payload
    if compress:
        data = zlib.compress(data)
        flags |= FLAG_ZLIB
    iv = os.urandom(16)
    if gcm:
        flags |= FLAG_GCM
        header = HEADER.pack(MAGIC, 0, mac_bytes(mac), flags, iv, 1, len(data) + 16)
        body = AESGCM(key).encrypt(iv, data, header)
    else:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        body = enc.update(padded) + enc.finalize()
        header = HEADER.pack(MAGIC, 0, mac_bytes(mac), flags, iv, 1, len(body))
    return header + body


def unpack(packet, authkey=DEFAULT_AUTHKEY):
    """Decode an inform packet, returning (header dict, payload bytes)."""
    magic, version, hwaddr, flags, iv, dataversion, datalen = HEADER.unpack_from(packet)
    if magic != MAGIC:
        raise ValueError("bad magic %r" % magic)
    body = packet[HEADER.size:HEADER.size + datalen]
    key = bytes.fromhex(authkey)
    if flags & FLAG_ENCRYPTED:
        if flags & FLAG_GCM:
            data = AESGCM(key).decrypt(iv, body, packet[:HEADER.size])
        else:
            dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            padded = dec.update(body) + dec.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded) + unpadder.finalize()
    else:
        data = body
    if flags & FLAG_ZLIB:
        data = zlib.decompress(data)
    if flags & FLAG_SNAPPY:
        raise NotImplementedError("snappy payloads are not supported")
    hdr = {
        "version": version,
        "mac": ":".join("%02x" % b for b in hwaddr),
        "flags": flags,
        "dataversion": dataversion,
        "datalen": datalen,
    }
    return hdr, data


if __name__ == "__main__":
    # Round-trip self-test (no network, no controller): proves the framing + both
    # cipher modes + zlib are internally consistent.
    import json
    sample = json.dumps({"model": "U6IW", "mac": "02:aa:bb:cc:dd:01"}).encode()
    for gcm in (True, False):
        for comp in (True, False):
            pkt = pack("02:aa:bb:cc:dd:01", sample, gcm=gcm, compress=comp)
            hdr, out = unpack(pkt)
            assert out == sample, (gcm, comp)
    print("framing round-trip OK (gcm/cbc x zlib/plain)")
