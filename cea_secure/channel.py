"""Per-message protection with Ascon-AEAD128, following OSCORE (RFC 8613).

The security context is derived exactly as in RFC 8613, Section 3.2.1 (HKDF
with SHA-256 and the CBOR `info` structure), the nonce is built as in Section
5.2, the AAD is the COSE Enc_structure of Section 5.4, and replays are caught
with the sliding window of Section 7.4. The AEAD is Ascon-AEAD128 from NIST
SP 800-232 instead of AES-CCM.

To keep the demo free of a CoAP stack, protected readings travel in a compact
frame instead of a CoAP message with an OSCORE option:

    n (1 byte) | Partial IV (n bytes) | len(kid) (1 byte) | kid | ciphertext || tag (16 bytes)
"""

import hashlib
import hmac

import cbor2

from . import ascon

# COSE algorithm value requested for Ascon-AEAD128 in draft-ochkas-cose-ascon-04.
# It is not yet registered with IANA, which is fine for a closed deployment
# where both ends are pre-configured.
ALG_ASCON_AEAD128 = 35
KEY_LEN = 16
NONCE_LEN = 16
TAG_LEN = 16
REPLAY_WINDOW = 32
MAX_SEQ = 2**40 - 1  # Partial IV is at most 5 bytes


class IntegrityError(Exception):
    """The frame was forged or modified in transit."""


class ReplayError(Exception):
    """The frame is a copy of one already accepted (or too old)."""


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) with SHA-256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive(master_secret: bytes, master_salt: bytes, id_: bytes, kind: str, length: int,
           alg: int = ALG_ASCON_AEAD128, id_context: bytes = None) -> bytes:
    """One RFC 8613 key derivation: info = [id, id_context, alg_aead, type, L]."""
    info = cbor2.dumps([id_, id_context, alg, kind, length])
    return hkdf_sha256(master_salt, master_secret, info, length)


def piv_bytes(seq: int) -> bytes:
    """Partial IV: the sequence number in the fewest bytes (0 is encoded as 0x00)."""
    return seq.to_bytes(max(1, (seq.bit_length() + 7) // 8), "big")


def build_nonce(common_iv: bytes, id_piv: bytes, piv: bytes) -> bytes:
    """RFC 8613, Section 5.2: size of ID_PIV | padded ID_PIV | padded PIV, XOR Common IV."""
    if len(id_piv) > NONCE_LEN - 6:
        raise ValueError("sender ID too long for this nonce length")
    raw = bytes([len(id_piv)]) + id_piv.rjust(NONCE_LEN - 6, b"\x00") + piv.rjust(5, b"\x00")
    return bytes(a ^ b for a, b in zip(raw, common_iv))


def build_aad(kid: bytes, piv: bytes, alg: int = ALG_ASCON_AEAD128) -> bytes:
    """RFC 8613, Section 5.4: Enc_structure over external_aad = [ver, [alg], kid, piv, options]."""
    external_aad = cbor2.dumps([1, [alg], kid, piv, b""])
    return cbor2.dumps(["Encrypt0", b"", external_aad])


class ReplayWindow:
    """RFC 8613, Section 7.4: accept each sequence number once, within a sliding window."""

    def __init__(self, size: int = REPLAY_WINDOW):
        self.size = size
        self.highest = -1
        self.seen = 0  # bit i set = (highest - i) already accepted

    def check(self, seq: int) -> None:
        if seq > self.highest:
            return
        offset = self.highest - seq
        if offset >= self.size:
            raise ReplayError(f"sequence number {seq} is older than the replay window")
        if self.seen & (1 << offset):
            raise ReplayError(f"sequence number {seq} was already accepted")

    def accept(self, seq: int) -> None:
        if seq > self.highest:
            shift = seq - self.highest
            self.seen = ((self.seen << shift) | 1) & ((1 << self.size) - 1)
            self.highest = seq
        else:
            self.seen |= 1 << (self.highest - seq)


class SecureChannel:
    """One direction pair of an OSCORE-style security context."""

    def __init__(self, master_secret: bytes, master_salt: bytes, sender_id: bytes, recipient_id: bytes):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.sender_key = derive(master_secret, master_salt, sender_id, "Key", KEY_LEN)
        self.recipient_key = derive(master_secret, master_salt, recipient_id, "Key", KEY_LEN)
        self.common_iv = derive(master_secret, master_salt, b"", "IV", NONCE_LEN)
        self.seq = 0
        self.window = ReplayWindow()

    @classmethod
    def from_keys(cls, keys) -> "SecureChannel":
        return cls(keys.master_secret, keys.master_salt, keys.sender_id, keys.recipient_id)

    def protect(self, plaintext: bytes) -> bytes:
        if self.seq > MAX_SEQ:
            raise OverflowError("sequence numbers exhausted: run EDHOC again")
        piv = piv_bytes(self.seq)
        self.seq += 1
        kid = self.sender_id
        nonce = build_nonce(self.common_iv, kid, piv)
        sealed = ascon.ascon_encrypt(self.sender_key, nonce, build_aad(kid, piv), plaintext)
        return bytes([len(piv)]) + piv + bytes([len(kid)]) + kid + sealed

    @staticmethod
    def frame_kid(frame: bytes) -> bytes:
        """Read the sender ID from a frame without decrypting it."""
        n = frame[0]
        k = frame[1 + n]
        return bytes(frame[2 + n:2 + n + k])

    def unprotect(self, frame: bytes) -> bytes:
        try:
            n = frame[0]
            piv = bytes(frame[1:1 + n])
            k = frame[1 + n]
            kid = bytes(frame[2 + n:2 + n + k])
            sealed = bytes(frame[2 + n + k:])
        except IndexError as err:
            raise IntegrityError("truncated frame") from err
        if not 1 <= n <= 5 or len(sealed) < TAG_LEN or kid != self.recipient_id:
            raise IntegrityError("malformed frame")
        seq = int.from_bytes(piv, "big")
        self.window.check(seq)
        nonce = build_nonce(self.common_iv, kid, piv)
        plaintext = ascon.ascon_decrypt(self.recipient_key, nonce, build_aad(kid, piv), sealed)
        if plaintext is None:
            raise IntegrityError("authentication tag does not match: frame was forged or modified")
        self.window.accept(seq)
        return plaintext
