"""The three parties of the demo, talking over real UDP sockets.

    sensor  --UDP-->  attacker (on-path relay)  --UDP-->  gateway

Every datagram starts with a 1-byte type:

    0x20 PLAIN    SDI-12 reading in clear text (today's deployments)
    0x01 EDHOC_1  EDHOC message_1           (sensor  -> gateway)
    0x02 EDHOC_2  EDHOC message_2           (gateway -> sensor)
    0x03 EDHOC_3  EDHOC message_3           (sensor  -> gateway)
    0x10 SECURE   Ascon-AEAD128 protected reading (see channel.py)
    0x0F REJECT   gateway refused a handshake (diagnostic only)

Byte counts reported for EDHOC are the EDHOC messages themselves, as in Table 1;
the 1-byte type tag is demo framing.
"""

import queue
import socket
import threading

from . import sdi12
from .channel import IntegrityError, ReplayError, SecureChannel
from .credentials import Identity
from .edhoc import ONE_BYTE_IDS, GatewayHandshake, HandshakeError, SensorHandshake

PLAIN, EDHOC_1, EDHOC_2, EDHOC_3, SECURE, REJECT = 0x20, 0x01, 0x02, 0x03, 0x10, 0x0F
TYPE_NAMES = {PLAIN: "PLAIN", EDHOC_1: "EDHOC message_1", EDHOC_2: "EDHOC message_2",
              EDHOC_3: "EDHOC message_3", SECURE: "SECURE", REJECT: "REJECT"}
TIMEOUT = 3.0


def _udp_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    return s


class Gateway:
    """Edge gateway: authenticates sensors, decrypts readings, drives the CO2 valve."""

    def __init__(self, identity: Identity, registered_sensors: dict):
        self.identity = identity
        self.registered = dict(registered_sensors)  # kid -> CCS credential
        self.sock = _udp_socket()
        self.address = self.sock.getsockname()
        self.events = queue.Queue()
        self._pending = {}    # peer address -> GatewayHandshake
        self._sessions = {}   # recipient ID (C_R) -> (sensor kid, SecureChannel)
        self._free_ids = list(ONE_BYTE_IDS)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self.sock.close()

    def _emit(self, kind: str, **info):
        self.events.put(dict(kind=kind, **info))

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if not data:
                continue
            try:
                self._handle(data[0], data[1:], peer)
            except Exception as err:  # one bad packet must never stop the gateway
                self._emit("rejected", reason=f"internal error on bad input: {err!r}")

    def _handle(self, kind: int, body: bytes, peer):
        if kind == PLAIN:
            try:
                reading = sdi12.parse_reading(body)
            except ValueError as err:
                return self._emit("rejected", reason=str(err))
            return self._emit("accepted", secure=False, reading=reading,
                              decision=sdi12.co2_decision(reading["co2_ppm"]))

        if kind == EDHOC_1:
            in_use = {h.c_r for h in self._pending.values()}
            c_r = next(i for i in self._free_ids if i not in in_use)
            handshake = GatewayHandshake(self.identity, self.registered, c_r=c_r)
            try:
                message_2 = handshake.process_message_1(body)
            except HandshakeError as err:
                return self._reject(peer, str(err))
            self._pending[peer] = handshake
            self.sock.sendto(bytes([EDHOC_2]) + message_2, peer)
            return

        if kind == EDHOC_3:
            handshake = self._pending.pop(peer, None)
            if handshake is None:
                return self._reject(peer, "message_3 without a pending handshake")
            try:
                kid = handshake.process_message_3(body)
            except HandshakeError as err:
                return self._reject(peer, str(err))
            self._free_ids.remove(handshake.c_r)
            channel = SecureChannel.from_keys(handshake.keys())
            self._sessions[handshake.c_r] = (kid, channel)
            return self._emit("handshake", sensor_kid=kid.hex(), c_r=handshake.c_r.hex())

        if kind == SECURE:
            try:
                kid = SecureChannel.frame_kid(body)
            except IndexError:
                return self._emit("rejected", reason="truncated frame")
            session = self._sessions.get(kid)
            if session is None:
                return self._emit("rejected", reason=f"no security context for ID 0x{kid.hex()}")
            sensor_kid, channel = session
            try:
                reading = sdi12.parse_reading(channel.unprotect(body))
            except (IntegrityError, ReplayError) as err:
                return self._emit("rejected", reason=f"{type(err).__name__}: {err}")
            return self._emit("accepted", secure=True, sensor_kid=sensor_kid.hex(), reading=reading,
                              decision=sdi12.co2_decision(reading["co2_ppm"]))

        self._emit("rejected", reason=f"unknown frame type 0x{kind:02x}")

    def _reject(self, peer, reason: str):
        self._pending.pop(peer, None)
        self.sock.sendto(bytes([REJECT]) + reason.encode()[:200], peer)
        self._emit("handshake_rejected", reason=reason)


class Sensor:
    """A CO2 probe plus the data logger that forwards its SDI-12 readings."""

    def __init__(self, identity: Identity, gateway_credential: bytes, gateway_address, c_i: bytes = b"\x37"):
        self.identity = identity
        self.gateway_credential = gateway_credential
        self.gateway_address = gateway_address  # may really be the attacker
        self.c_i = c_i
        self.sock = _udp_socket()
        self.sock.settimeout(TIMEOUT)
        self.channel = None
        self.handshake_sizes = None

    def send_plain(self, reading: bytes):
        self.sock.sendto(bytes([PLAIN]) + reading, self.gateway_address)

    def handshake(self):
        """Run EDHOC; return (len(message_1), len(message_2), len(message_3))."""
        edhoc = SensorHandshake(self.identity, self.gateway_credential, c_i=self.c_i)
        message_1 = edhoc.message_1()
        self.sock.sendto(bytes([EDHOC_1]) + message_1, self.gateway_address)
        data, _ = self.sock.recvfrom(2048)
        if data[0] == REJECT:
            raise HandshakeError(f"gateway refused: {data[1:].decode(errors='replace')}")
        message_2 = data[1:]
        message_3 = edhoc.process_message_2(message_2)
        self.sock.sendto(bytes([EDHOC_3]) + message_3, self.gateway_address)
        self.channel = SecureChannel.from_keys(edhoc.keys())
        self.handshake_sizes = (len(message_1), len(message_2), len(message_3))
        return self.handshake_sizes

    def send_secure(self, reading: bytes) -> bytes:
        frame = bytes([SECURE]) + self.channel.protect(reading)
        self.sock.sendto(frame, self.gateway_address)
        return frame

    def close(self):
        self.sock.close()


class Attacker:
    """An on-path relay (a compromised router, rogue access point, or tapped bus).

    It forwards everything between one sensor and the gateway, and an optional
    `uplink_hook(frame) -> list of frames` decides what really reaches the gateway.
    """

    def __init__(self, gateway_address):
        self.gateway_address = gateway_address
        self.sock = _udp_socket()
        self.address = self.sock.getsockname()
        self.uplink_hook = None
        self.downlink_hook = None
        self.log = []          # (direction, frame) as seen on the wire
        self._sensor = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._relay, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self.sock.close()

    def captured(self, kind: int) -> list:
        return [f for d, f in self.log if f and f[0] == kind]

    def inject(self, frame: bytes):
        """Send a frame of the attacker's own making to the gateway."""
        self.sock.sendto(frame, self.gateway_address)

    def reply_to_sensor(self, frame: bytes):
        """Answer the sensor directly, pretending to be the gateway."""
        self.sock.sendto(frame, self._sensor)

    def _relay(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if peer == self.gateway_address:
                self.log.append(("down", data))
                out = self.downlink_hook(data) if self.downlink_hook else [data]
                for frame in out:
                    if self._sensor:
                        self.sock.sendto(frame, self._sensor)
            else:
                self._sensor = peer
                self.log.append(("up", data))
                out = self.uplink_hook(data) if self.uplink_hook else [data]
                for frame in out:
                    self.sock.sendto(frame, self.gateway_address)
