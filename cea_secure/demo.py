"""Narrated demo: a greenhouse CO2 sensor, its edge gateway, and an attacker on the path.

Act 1  Today: SDI-12 readings in clear text. The attacker reads and rewrites them.
Act 2  The proposed scheme: EDHOC handshake (measured on the wire), then Ascon-AEAD128.
Act 3  Seven attacks against the scheme, each of which must be rejected.
Act 4  Cost: handshake bytes, LoRaWAN frames and airtime, per-reading overhead.

Every check is asserted; the run ends with a pass/fail summary and a non-zero
exit code if anything did not behave as expected.
"""

import argparse
import os
import queue
import sys

from . import lora, sdi12
from .channel import SecureChannel
from .credentials import new_identity
from .edhoc import GatewayHandshake, HandshakeError
from .nodes import EDHOC_1, EDHOC_2, EDHOC_3, PLAIN, SECURE, TIMEOUT, Attacker, Gateway, Sensor

# Table 1 of the paper: draft-ietf-iotops-security-protocol-comparison-09,
# CCM_8, P-256, ECDSA, with Connection ID (TLS 1.3 row: no Connection ID).
TABLE_1 = [
    ("DTLS 1.3, raw public keys, ECDHE", (185, 454, 255)),
    ("DTLS 1.3, pre-shared key, ECDHE", (219, 226, 56)),
    ("DTLS 1.3, pre-shared key only", (136, 153, 56)),
    ("TLS 1.3, raw public keys, ECDHE", (162, 394, 233)),
    ("EDHOC, signature keys, kid", (37, 102, 77)),
]
PAPER_EDHOC_STATIC_DH = (37, 45, 19)


class Style:
    def __init__(self, enabled: bool):
        on = enabled
        self.bold = "\033[1m" if on else ""
        self.dim = "\033[2m" if on else ""
        self.red = "\033[31m" if on else ""
        self.green = "\033[32m" if on else ""
        self.yellow = "\033[33m" if on else ""
        self.cyan = "\033[36m" if on else ""
        self.reset = "\033[0m" if on else ""


class Demo:
    def __init__(self, color: bool, step: bool):
        self.s = Style(color)
        self.step = step
        self.results = []

    # ---- output helpers -------------------------------------------------
    def act(self, title: str):
        if self.step:
            input(f"\n{self.s.dim}[press Enter for: {title}]{self.s.reset}")
        bar = "=" * 78
        print(f"\n{self.s.bold}{bar}\n {title}\n{bar}{self.s.reset}")

    def say(self, text: str = ""):
        print(f"  {text}")

    def wire(self, who: str, data: bytes, note: str = ""):
        shown = data.hex(" ") if len(data) <= 24 else data[:24].hex(" ") + " ..."
        extra = f"  {self.s.dim}{note}{self.s.reset}" if note else ""
        print(f"  {self.s.cyan}{who:<10}{self.s.reset} {len(data):>3} B  {shown}{extra}")

    def check(self, name: str, passed: bool, detail: str):
        self.results.append((name, passed))
        mark = f"{self.s.green}PASS{self.s.reset}" if passed else f"{self.s.red}FAIL{self.s.reset}"
        print(f"  [{mark}] {name}: {detail}")

    def expect_event(self, gateway: Gateway) -> dict:
        try:
            return gateway.events.get(timeout=TIMEOUT)
        except queue.Empty:
            return {"kind": "timeout"}

    def gateway_says(self, event: dict):
        kind = event["kind"]
        if kind == "accepted":
            r = event["reading"]
            tag = "authenticated" if event["secure"] else "unauthenticated"
            self.say(f"{self.s.yellow}gateway{self.s.reset}    accepted ({tag}) CO2 = {r['co2_ppm']} ppm"
                     f" -> {event['decision']}")
        elif kind in ("rejected", "handshake_rejected"):
            self.say(f"{self.s.yellow}gateway{self.s.reset}    REJECTED: {event['reason']}")
        elif kind == "handshake":
            self.say(f"{self.s.yellow}gateway{self.s.reset}    sensor kid 0x{event['sensor_kid']} authenticated;"
                     f" security context ready (ID 0x{event['c_r']})")
        else:
            self.say(f"{self.s.yellow}gateway{self.s.reset}    (no response)")

    # ---- the story ------------------------------------------------------
    def run(self) -> bool:
        s = self.s
        sensor_id = new_identity("sensor-07", 0x07)
        gateway_id = new_identity("gateway-1", 0x0A)

        gateway = Gateway(gateway_id, {sensor_id.kid_bytes: sensor_id.credential}).start()
        attacker = Attacker(gateway.address).start()
        sensor = Sensor(sensor_id, gateway_id.credential, attacker.address)

        try:
            self.act("Setup: provisioning at manufacturing")
            self.say(f"sensor-07  static P-256 DH key, credential {len(sensor_id.credential)} B, kid 0x07")
            self.say(f"gateway-1  static P-256 DH key, credential {len(gateway_id.credential)} B, kid 0x0a")
            self.say("Each side stores the other's public key. Only the 1-byte kid is ever sent:")
            self.say("no certificates, no certificate authority, nothing to parse on the sensor.")
            self.say(f"All traffic flows sensor -> {s.red}attacker{s.reset} -> gateway over real UDP sockets.")

            self.act_1(sensor, gateway, attacker)
            self.act_2(sensor, gateway, attacker)
            self.act_3(sensor, sensor_id, gateway_id, gateway, attacker)
            self.act_4(sensor)
        finally:
            sensor.close()
            attacker.stop()
            gateway.stop()

        return self.summary()

    def act_1(self, sensor: Sensor, gateway: Gateway, attacker: Attacker):
        s = self.s
        self.act("Act 1  Today: SDI-12 readings travel in clear text")
        reading = sdi12.format_reading("0", 24.1, 68.0, 4800)
        self.say("The CO2 probe measures 4,800 ppm, close to the OSHA 5,000 ppm limit.")
        self.say("The controller must close the CO2 valve and ventilate.")
        self.say()

        def rewrite(frame):
            if frame[0] == PLAIN:
                seen = frame[1:].decode().strip()
                forged = frame.replace(b"+4800", b"+800")
                self.say(f"{s.red}attacker{s.reset}   reads {seen!r}, rewrites it to {forged[1:].decode().strip()!r}")
                return [forged]
            return [frame]

        attacker.uplink_hook = rewrite
        sensor.send_plain(reading)
        self.wire("sensor", bytes([PLAIN]) + reading, "plain ASCII: '0+24.1+68.0+4800\\r\\n'")
        event = self.expect_event(gateway)
        self.gateway_says(event)
        self.check("clear text can be rewritten", event.get("kind") == "accepted"
                   and event["reading"]["co2_ppm"] == 800,
                   "gateway acted on 800 ppm and keeps injecting CO2 into a room already at 4,800 ppm")

        attacker.uplink_hook = None
        self.say()
        self.say("The attacker can also invent readings from nothing, since nobody is authenticated:")
        attacker.inject(bytes([PLAIN]) + sdi12.format_reading("0", 24.1, 68.0, 450))
        event = self.expect_event(gateway)
        self.gateway_says(event)
        self.check("clear text can be spoofed", event.get("kind") == "accepted"
                   and event["reading"]["co2_ppm"] == 450,
                   "gateway accepted a reading the sensor never sent")

    def act_2(self, sensor: Sensor, gateway: Gateway, attacker: Attacker):
        s = self.s
        self.act("Act 2  The proposed scheme: EDHOC, then Ascon-AEAD128")
        self.say("The attacker stays on the path but only watches. First the EDHOC handshake:")
        attacker.log.clear()
        sizes = sensor.handshake()
        event = self.expect_event(gateway)
        on_wire = {k: len(attacker.captured(t)[0]) - 1 for k, t in
                   (("m1", EDHOC_1), ("m2", EDHOC_2), ("m3", EDHOC_3))}
        self.wire("message_1", attacker.captured(EDHOC_1)[0][1:], "method, suite, ephemeral key G_X, C_I")
        self.wire("message_2", attacker.captured(EDHOC_2)[0][1:], "G_Y + encrypted(C_R, ID_CRED_R, MAC_2)")
        self.wire("message_3", attacker.captured(EDHOC_3)[0][1:], "encrypted(ID_CRED_I, MAC_3)")
        self.gateway_says(event)
        total = sum(sizes)
        self.say(f"{s.bold}Measured on the wire: {sizes[0]} + {sizes[1]} + {sizes[2]} = {total} bytes{s.reset}"
                 f"  (paper, Table 1: 37 + 45 + 19 = 101)")
        self.check("EDHOC handshake completes", event.get("kind") == "handshake", "both sides authenticated")
        self.check("handshake size matches Table 1",
                   sizes == PAPER_EDHOC_STATIC_DH and tuple(on_wire.values()) == PAPER_EDHOC_STATIC_DH,
                   f"{total} bytes, versus 894 for DTLS 1.3 with raw public keys")
        self.say("The identities (ID_CRED_R, ID_CRED_I) and MACs are encrypted: a passive")
        self.say("observer learns neither which sensor this is nor which gateway it talks to.")

        self.say()
        self.say("The EDHOC exporter derives the security context; readings are now sealed with Ascon-AEAD128.")
        attacker.log.clear()
        morning = sdi12.format_reading("0", 18.2, 74.0, 450)
        frame = sensor.send_secure(morning)
        self.wire("sensor", frame, "06:00 reading, 450 ppm (attacker keeps a copy)")
        self.gateway_says(self.expect_event(gateway))

        reading = sdi12.format_reading("0", 24.1, 68.0, 4800)
        frame = sensor.send_secure(reading)
        self.wire("sensor", frame, "14:00 reading, 4,800 ppm")
        self.say(f"{s.red}attacker{s.reset}   sees only ciphertext: '+4800' appears nowhere in the frame")
        event = self.expect_event(gateway)
        self.gateway_says(event)
        self.check("protected reading delivered", event.get("kind") == "accepted" and event["secure"]
                   and event["reading"]["co2_ppm"] == 4800 and b"4800" not in frame,
                   "gateway closes the valve and ventilates")
        overhead = len(frame) - 1 - len(reading)
        self.say(f"Protection overhead per reading: {overhead} bytes "
                 f"(16-byte tag + Partial IV + 1-byte ID + 2 length bytes).")

    def act_3(self, sensor: Sensor, sensor_id, gateway_id, gateway: Gateway, attacker: Attacker):
        s = self.s
        self.act("Act 3  Attacks against the proposed scheme")

        # 1. Tamper with a protected reading.
        self.say(f"{s.bold}1. Tamper:{s.reset} flip one ciphertext bit to change the CO2 value")

        def flip(frame):
            if frame[0] == SECURE:
                tampered = bytearray(frame)
                tampered[-20] ^= 0x01
                return [bytes(tampered)]
            return [frame]

        attacker.uplink_hook = flip
        sensor.send_secure(sdi12.format_reading("0", 24.3, 67.5, 4850))
        event = self.expect_event(gateway)
        self.gateway_says(event)
        self.check("tampering detected", event.get("kind") == "rejected" and "IntegrityError" in event["reason"],
                   "the modified reading never reaches the controller")
        attacker.uplink_hook = None

        # 2. Replay the morning reading.
        self.say(f"{s.bold}2. Replay:{s.reset} resend the genuine 06:00 frame (450 ppm) to make the controller inject CO2")
        morning_frame = [f for f in attacker.log if f[1][0] == SECURE][0][1] if attacker.log else None
        attacker.inject(morning_frame)
        event = self.expect_event(gateway)
        self.gateway_says(event)
        self.check("replay detected", event.get("kind") == "rejected" and "ReplayError" in event["reason"],
                   "a genuine but old frame is refused")

        # 3. Forge a frame without the key.
        self.say(f"{s.bold}3. Forge:{s.reset} build a protected frame with a guessed key")
        guess = SecureChannel(os.urandom(16), os.urandom(8), sensor.channel.sender_id, b"\x00")
        guess.seq = 10_000
        attacker.inject(bytes([SECURE]) + guess.protect(sdi12.format_reading("0", 24.1, 68.0, 450)))
        event = self.expect_event(gateway)
        self.gateway_says(event)
        self.check("forgery detected", event.get("kind") == "rejected" and "IntegrityError" in event["reason"],
                   "without the session key no valid tag can be made")

        # 4. Impersonate the registered sensor.
        self.say(f"{s.bold}4. Fake sensor ID:{s.reset} a rogue device claims kid 0x07 but has its own key")
        mallory = new_identity("sensor-07", 0x07)
        rogue = Sensor(mallory, gateway_id.credential, gateway.address, c_i=b"\x05")
        try:
            rogue.handshake()
        except HandshakeError:
            pass
        event = self.expect_event(gateway)
        self.gateway_says(event)
        self.check("impersonation rejected", event.get("kind") == "handshake_rejected"
                   and "failed authentication" in event["reason"], "MAC_3 cannot be computed without sensor-07's key")
        rogue.close()

        # 5. Unknown device.
        self.say(f"{s.bold}5. Unknown sensor ID:{s.reset} a device that was never provisioned (kid 0x55)")
        stranger = Sensor(new_identity("stranger", 0x55), gateway_id.credential, gateway.address, c_i=b"\x06")
        try:
            stranger.handshake()
        except HandshakeError:
            pass
        event = self.expect_event(gateway)
        self.gateway_says(event)
        self.check("unknown device rejected", event.get("kind") == "handshake_rejected"
                   and "unknown sensor kid" in event["reason"], "no credential, no session")
        stranger.close()

        # 6. Tamper with the handshake itself.
        self.say(f"{s.bold}6. Tampered handshake:{s.reset} change one byte of G_X inside message_1 in transit")

        def corrupt_m1(frame):
            if frame[0] == EDHOC_1:
                tampered = bytearray(frame)
                tampered[1 + 6] ^= 0x01
                return [bytes(tampered)]
            return [frame]

        attacker.uplink_hook = corrupt_m1
        fresh = Sensor(sensor_id, gateway_id.credential, attacker.address, c_i=b"\x08")
        outcome = "completed"
        try:
            fresh.handshake()
        except HandshakeError as err:
            outcome = str(err)
        except OSError:
            outcome = "no answer"
        self.say(f"{s.cyan}sensor{s.reset}     {outcome}")
        self.check("tampered handshake rejected", outcome != "completed",
                   "the transcript no longer matches, so the sensor refuses to derive keys")
        attacker.uplink_hook = None
        fresh.close()
        try:
            while True:
                gateway.events.get_nowait()
        except queue.Empty:
            pass

        # 7. Rogue gateway.
        self.say(f"{s.bold}7. Rogue gateway:{s.reset} the attacker answers message_1 itself, posing as gateway-1")
        fake_gateway = new_identity("gateway-1", 0x0A)

        def hijack(frame):
            if frame[0] == EDHOC_1:
                handshake = GatewayHandshake(fake_gateway, {}, c_r=b"\x27")
                attacker.reply_to_sensor(bytes([EDHOC_2]) + handshake.process_message_1(frame[1:]))
                return []
            return [frame]

        attacker.uplink_hook = hijack
        victim = Sensor(sensor_id, gateway_id.credential, attacker.address, c_i=b"\x09")
        outcome = "completed"
        try:
            victim.handshake()
        except HandshakeError as err:
            outcome = str(err)
        self.say(f"{s.cyan}sensor{s.reset}     {outcome}")
        self.check("rogue gateway rejected", outcome != "completed",
                   "the sensor only accepts the gateway key it was provisioned with")
        attacker.uplink_hook = None
        victim.close()

        self.say()
        self.say(f"{s.dim}Not covered by cryptography: an attacker can still drop packets (denial of service).{s.reset}")
        self.say(f"{s.dim}The gateway can only notice the silence and alarm on a missed reporting interval.{s.reset}")

    def act_4(self, sensor: Sensor):
        s = self.s
        self.act("Act 4  Cost on a LoRaWAN link (EU868 DR0: SF12, 125 kHz, 51-byte payloads)")
        rows = [("EDHOC, static DH keys, kid (measured)", sensor.handshake_sizes)] + TABLE_1
        print(f"  {'handshake':<40}{'bytes':>7}{'frames':>8}{'airtime':>10}")
        for name, sizes in sorted(rows, key=lambda r: sum(r[1])):
            cost = lora.handshake_cost(list(sizes))
            mark = s.bold if "measured" in name else ""
            print(f"  {mark}{name:<40}{cost['bytes']:>7}{cost['frames']:>8}{cost['airtime_s']:>9.1f}s{s.reset}")
        edhoc = lora.handshake_cost(list(sensor.handshake_sizes))
        dtls = lora.handshake_cost(list(TABLE_1[0][1]))
        self.say()
        self.say(f"EDHOC fits each message in one frame: {edhoc['frames']} frames, {edhoc['airtime_s']:.1f} s on air.")
        self.say(f"DTLS 1.3 with raw public keys needs at least {dtls['frames']} frames and {dtls['airtime_s']:.1f} s,"
                 f" {dtls['airtime_s'] / edhoc['airtime_s']:.1f}x more.")
        self.say("At the EU868 1% duty cycle, every second on air costs 99 s of enforced silence.")
        self.say(f"{s.dim}Airtime from the Semtech SX1276 formula; frames ignore fragmentation headers,{s.reset}")
        self.say(f"{s.dim}so the DTLS and TLS rows are lower bounds. Non-measured rows are Table 1 of the paper.{s.reset}")

    def summary(self) -> bool:
        s = self.s
        self.act("Summary")
        passed = sum(1 for _, ok in self.results if ok)
        for name, ok in self.results:
            mark = f"{s.green}PASS{s.reset}" if ok else f"{s.red}FAIL{s.reset}"
            print(f"  [{mark}] {name}")
        print(f"\n  {s.bold}{passed}/{len(self.results)} checks passed{s.reset}")
        return passed == len(self.results)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--step", action="store_true", help="pause before each act (for presenting live)")
    parser.add_argument("--no-color", action="store_true", help="plain output, e.g. when saving to a file")
    args = parser.parse_args(argv)
    color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    return 0 if Demo(color=color, step=args.step).run() else 1


if __name__ == "__main__":
    sys.exit(main())
