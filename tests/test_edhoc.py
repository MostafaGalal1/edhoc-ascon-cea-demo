"""EDHOC (RFC 9528) handshake sizes and authentication failures."""

import pytest

from cea_secure.credentials import new_identity
from cea_secure.edhoc import GatewayHandshake, HandshakeError, SensorHandshake


@pytest.fixture(scope="module")
def ids():
    return new_identity("sensor-07", 0x07), new_identity("gateway-1", 0x0A)


def _run(sensor, gateway_cred, gateway, registry, tamper=None):
    s = SensorHandshake(sensor, gateway_cred)
    g = GatewayHandshake(gateway, registry, c_r=b"\x27")
    m1 = s.message_1()
    if tamper:
        m1 = tamper(m1)
    m2 = g.process_message_1(m1)
    m3 = s.process_message_2(m2)
    g.process_message_3(m3)
    return (m1, m2, m3), s, g


def test_sizes_match_table_1_and_keys_agree(ids):
    sensor, gateway = ids
    (m1, m2, m3), s, g = _run(sensor, gateway.credential, gateway, {sensor.kid_bytes: sensor.credential})
    assert (len(m1), len(m2), len(m3)) == (37, 45, 19)
    ks, kg = s.keys(), g.keys()
    assert ks.master_secret == kg.master_secret and ks.master_salt == kg.master_salt
    assert ks.sender_id == kg.recipient_id == b"\x27" and ks.recipient_id == kg.sender_id == b"\x37"


def test_impersonator_with_same_kid_rejected(ids):
    sensor, gateway = ids
    mallory = new_identity("sensor-07", 0x07)
    with pytest.raises(HandshakeError, match="failed authentication"):
        _run(mallory, gateway.credential, gateway, {sensor.kid_bytes: sensor.credential})


def test_unknown_kid_rejected(ids):
    sensor, gateway = ids
    with pytest.raises(HandshakeError, match="unknown sensor kid 0x55"):
        _run(new_identity("x", 0x55), gateway.credential, gateway, {sensor.kid_bytes: sensor.credential})


def test_rogue_gateway_rejected(ids):
    sensor, gateway = ids
    impostor = new_identity("gateway-1", 0x0A)
    with pytest.raises(HandshakeError, match="message_2 did not verify"):
        _run(sensor, gateway.credential, impostor, {sensor.kid_bytes: sensor.credential})


def test_tampered_message_1_rejected(ids):
    sensor, gateway = ids

    def flip(m1):
        return m1[:6] + bytes([m1[6] ^ 1]) + m1[7:]

    with pytest.raises(HandshakeError):
        _run(sensor, gateway.credential, gateway, {sensor.kid_bytes: sensor.credential}, tamper=flip)


def test_every_bit_flip_in_g_x_is_rejected_without_crashing(ids):
    """lakers 0.6.2 panics on an invalid curve point; the wrapper must turn that into a rejection."""
    sensor, gateway = ids
    registry = {sensor.kid_bytes: sensor.credential}
    m1 = SensorHandshake(sensor, gateway.credential).message_1()
    for byte in range(4, 36):  # G_X occupies bytes 4..35 (after 03 02 58 20)
        for bit in (0x01, 0x80):
            tampered = m1[:byte] + bytes([m1[byte] ^ bit]) + m1[byte + 1:]
            s = SensorHandshake(sensor, gateway.credential)
            s.message_1()
            g = GatewayHandshake(gateway, registry, c_r=b"\x27")
            with pytest.raises(HandshakeError):
                s.process_message_2(g.process_message_1(tampered))
