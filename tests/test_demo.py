"""The full narrated demo, over real UDP sockets, must pass every check."""

from cea_secure.demo import Demo


def test_demo_passes_all_checks(capsys):
    assert Demo(color=False, step=False).run()
    out = capsys.readouterr().out
    assert "37 + 45 + 19 = 101 bytes" in out
    assert "12/12 checks passed" in out


def test_gateway_survives_invalid_curve_point():
    import time

    from cea_secure.credentials import new_identity
    from cea_secure.nodes import EDHOC_1, Gateway, Sensor

    sensor_id, gateway_id = new_identity("s", 0x07), new_identity("g", 0x0A)
    gateway = Gateway(gateway_id, {sensor_id.kid_bytes: sensor_id.credential}).start()
    try:
        x = 0
        from cea_secure.edhoc import _on_p256
        while _on_p256(x.to_bytes(32, "big")):
            x += 1
        forged = bytes([EDHOC_1]) + bytes.fromhex("03025820") + x.to_bytes(32, "big") + b"\x37"
        attacker = Sensor(sensor_id, gateway_id.credential, gateway.address)
        attacker.sock.sendto(forged, gateway.address)
        assert "invalid ephemeral key" in gateway.events.get(timeout=3)["reason"]
        time.sleep(0.1)
        sensor = Sensor(sensor_id, gateway_id.credential, gateway.address)
        assert sensor.handshake() == (37, 45, 19)  # still serving
        sensor.close()
        attacker.close()
    finally:
        gateway.stop()
