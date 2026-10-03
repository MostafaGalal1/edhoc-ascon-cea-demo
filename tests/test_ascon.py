"""Ascon-AEAD128 (NIST SP 800-232) against published test vectors."""

import json
from pathlib import Path

from cea_secure import ascon

VECTORS = Path(__file__).parent / "vectors"


def _kat_entries():
    for block in (VECTORS / "ascon_aead128_kat.txt").read_text().strip().split("\n\n"):
        fields = {}
        for line in block.splitlines():
            key, _, value = line.partition(" =")
            fields[key.strip()] = value.strip()
        yield {k: bytes.fromhex(fields[k]) for k in ("Key", "Nonce", "PT", "AD", "CT")}


def test_designers_kat_all_1089_vectors():
    count = 0
    for v in _kat_entries():
        assert ascon.ascon_encrypt(v["Key"], v["Nonce"], v["AD"], v["PT"]) == v["CT"]
        assert ascon.ascon_decrypt(v["Key"], v["Nonce"], v["AD"], v["CT"]) == v["PT"]
        count += 1
    assert count == 1089


def test_nist_acvp_vector_197():
    """The one byte-aligned vector in NIST's ACVP sample set (120-bit truncated tag)."""
    data = json.loads((VECTORS / "nist_acvp_ascon_aead128_tc197.json").read_text())
    t, expected = data["prompt"], data["expected"]
    key, nonce, ad, ct, tag = (bytes.fromhex(t[k]) for k in ("key", "nonce", "ad", "ct", "tag"))
    assert t["tagLen"] == 120 and expected["testPassed"] is True
    # Decrypt as SP 800-232 does, then compare the leftmost 120 bits of the tag.
    state = [0, 0, 0, 0, 0]
    ascon.ascon_initialize(state, 128, 16, 12, 8, 1, key, nonce)
    ascon.ascon_process_associated_data(state, 8, 16, ad)
    plaintext = ascon.ascon_process_ciphertext(state, 8, 16, ct)
    full_tag = ascon.ascon_finalize(state, 16, 12, key)
    assert plaintext == bytes.fromhex(expected["pt"])
    assert full_tag[:15] == tag


def test_any_modification_is_rejected():
    key, nonce = bytes(range(16)), bytes(range(16, 32))
    sealed = ascon.ascon_encrypt(key, nonce, b"hdr", b"0+24.1+68.0+4800\r\n")
    for i in range(len(sealed)):
        tampered = bytearray(sealed)
        tampered[i] ^= 0x01
        assert ascon.ascon_decrypt(key, nonce, b"hdr", bytes(tampered)) is None
    assert ascon.ascon_decrypt(key, nonce, b"other", sealed) is None
