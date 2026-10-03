"""OSCORE-style context (RFC 8613) with Ascon-AEAD128."""

import pytest

from cea_secure.channel import (NONCE_LEN, IntegrityError, ReplayError, SecureChannel, build_nonce, derive,
                                piv_bytes)


def test_key_derivation_matches_rfc8613_appendix_c1_1():
    """RFC 8613 test vector 1 (client), with its own algorithm (AES-CCM-16-64-128 = 10)."""
    secret = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    salt = bytes.fromhex("9e7ca92223786340")
    assert derive(secret, salt, b"", "Key", 16, alg=10).hex() == "f0910ed7295e6ad4b54fc793154302ff"
    assert derive(secret, salt, b"\x01", "Key", 16, alg=10).hex() == "ffb14e093c94c9cac9471648b4f98710"
    assert derive(secret, salt, b"", "IV", 13, alg=10).hex() == "4622d4dd6d944168eefb54987c"


def _pair():
    secret, salt = bytes(16), bytes(8)
    sensor = SecureChannel(secret, salt, sender_id=b"\x27", recipient_id=b"\x37")
    gateway = SecureChannel(secret, salt, sender_id=b"\x37", recipient_id=b"\x27")
    return sensor, gateway


def test_roundtrip_and_keys_mirror():
    sensor, gateway = _pair()
    assert sensor.sender_key == gateway.recipient_key and sensor.common_iv == gateway.common_iv
    assert gateway.unprotect(sensor.protect(b"0+24.1+68.0+4800\r\n")) == b"0+24.1+68.0+4800\r\n"


def test_tampered_frame_rejected():
    sensor, gateway = _pair()
    frame = bytearray(sensor.protect(b"reading"))
    frame[-1] ^= 0x80
    with pytest.raises(IntegrityError):
        gateway.unprotect(bytes(frame))


def test_replay_rejected_but_reordering_allowed():
    sensor, gateway = _pair()
    frames = [sensor.protect(f"r{i}".encode()) for i in range(4)]
    gateway.unprotect(frames[0])
    gateway.unprotect(frames[2])
    gateway.unprotect(frames[1])  # late but new: accepted
    with pytest.raises(ReplayError):
        gateway.unprotect(frames[2])


def test_frames_older_than_window_rejected():
    sensor, gateway = _pair()
    old = sensor.protect(b"old")
    sensor.seq = 100
    gateway.unprotect(sensor.protect(b"new"))
    with pytest.raises(ReplayError):
        gateway.unprotect(old)


def test_failed_frame_does_not_advance_window():
    sensor, gateway = _pair()
    good = sensor.protect(b"x")
    bad = bytearray(good)
    bad[-1] ^= 1
    with pytest.raises(IntegrityError):
        gateway.unprotect(bytes(bad))
    assert gateway.unprotect(good) == b"x"


def test_nonce_layout():
    nonce = build_nonce(bytes(NONCE_LEN), b"\x27", piv_bytes(5))
    assert nonce == bytes([1]) + bytes(9) + b"\x27" + bytes(4) + b"\x05"
    assert piv_bytes(0) == b"\x00" and piv_bytes(256) == b"\x01\x00"
