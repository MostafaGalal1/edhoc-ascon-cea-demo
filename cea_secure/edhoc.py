"""EDHOC (RFC 9528) between a sensor (initiator) and its edge gateway (responder).

The protocol itself is lakers, an implementation of RFC 9528 in Rust. We use
method 3 (both sides authenticate with static DH keys), cipher suite 2
(AES-CCM-16-64-128, SHA-256, P-256: the CCM_8 / P-256 profile of Table 1),
credentials sent by reference (1-byte kid), and no EAD items.

After message_3 both sides hold PRK_out. Following RFC 9528, Appendix A.1, the
EDHOC exporter then yields the OSCORE Master Secret and Master Salt, and the
connection identifiers become the OSCORE IDs: the initiator sends with C_R and
receives with C_I; the responder does the opposite.
"""

import io
from dataclasses import dataclass

import cbor2
import lakers
from cryptography.hazmat.primitives.asymmetric import ec
from lakers import CredentialTransfer, EdhocInitiator, EdhocResponder

from .credentials import Identity, kid_from_id_cred

MASTER_SECRET_LEN = 16  # Ascon-AEAD128 key length
MASTER_SALT_LEN = 8     # RFC 9528, Appendix A.1 default

# Connection identifiers that CBOR-encode as a single byte (integers -24..23),
# which is what keeps message_1 at 37 bytes and message_2 at 45 bytes.
ONE_BYTE_IDS = [bytes([b]) for b in list(range(0x00, 0x18)) + list(range(0x20, 0x38))]


class HandshakeError(Exception):
    """The EDHOC exchange was rejected; no keys were established."""


def _check(err: BaseException) -> None:
    """Let Ctrl-C through; everything else from lakers becomes a rejected handshake.

    lakers 0.6.2 signals most bad input with ValueError or RuntimeError, but an
    invalid curve point makes its Rust core panic (pyo3 PanicException, which is
    a BaseException). Uncaught, one forged 37-byte message_1 would kill the
    gateway's receive loop: a denial of service.
    """
    if isinstance(err, (KeyboardInterrupt, SystemExit, GeneratorExit)):
        raise err


def _on_p256(x: bytes) -> bool:
    """True if x is the x-coordinate of a point on P-256."""
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x02" + bytes(x))
        return True
    except ValueError:
        return False


def _g_x(message_1: bytes) -> bytes:
    """message_1 is the CBOR sequence METHOD, SUITES_I, G_X, C_I, ? EAD_1."""
    decoder = cbor2.CBORDecoder(io.BytesIO(message_1))
    decoder.decode()
    decoder.decode()
    return decoder.decode()


@dataclass(frozen=True)
class SessionKeys:
    master_secret: bytes
    master_salt: bytes
    sender_id: bytes
    recipient_id: bytes


def _export(party, sender_id: bytes, recipient_id: bytes) -> SessionKeys:
    return SessionKeys(
        master_secret=bytes(party.edhoc_exporter(0, [], MASTER_SECRET_LEN)),
        master_salt=bytes(party.edhoc_exporter(1, [], MASTER_SALT_LEN)),
        sender_id=sender_id,
        recipient_id=recipient_id,
    )


class SensorHandshake:
    """Initiator side, run by the sensor (or the data logger in front of it)."""

    def __init__(self, me: Identity, gateway_credential: bytes, c_i: bytes = b"\x37"):
        self._me = me
        self._gateway_credential = gateway_credential
        self._edhoc = EdhocInitiator()
        self.c_i = c_i
        self.c_r = None

    def message_1(self) -> bytes:
        return bytes(self._edhoc.prepare_message_1(c_i=self.c_i))

    def process_message_2(self, message_2: bytes) -> bytes:
        """Authenticate the gateway and return message_3."""
        try:
            g_y = bytes(cbor2.loads(message_2))[:32]
        except Exception as err:
            raise HandshakeError(f"malformed message_2: {err}") from err
        if not _on_p256(g_y):
            raise HandshakeError("message_2 carries an invalid ephemeral key G_Y")
        try:
            c_r, id_cred_r, _ead_2 = self._edhoc.parse_message_2(message_2)
            valid_cred_r = lakers.credential_check_or_fetch(id_cred_r, self._gateway_credential)
            self._edhoc.verify_message_2(self._me.private_key, self._me.credential, valid_cred_r)
            message_3, _prk_out = self._edhoc.prepare_message_3(CredentialTransfer.ByReference, [])
            self._edhoc.completed_without_message_4()
        except BaseException as err:
            _check(err)
            raise HandshakeError(f"message_2 did not verify, gateway not authenticated: {err}") from err
        self.c_r = bytes(c_r)
        return bytes(message_3)

    def keys(self) -> SessionKeys:
        return _export(self._edhoc, sender_id=self.c_r, recipient_id=self.c_i)


class GatewayHandshake:
    """Responder side, run by the edge gateway for one incoming handshake."""

    def __init__(self, me: Identity, registered_sensors: dict, c_r: bytes):
        """registered_sensors maps a 1-byte kid to that sensor's CCS credential."""
        self._edhoc = EdhocResponder(me.private_key, me.credential)
        self._registered = registered_sensors
        self.c_r = c_r
        self.c_i = None
        self.sensor_kid = None

    def process_message_1(self, message_1: bytes) -> bytes:
        try:
            g_x = _g_x(message_1)
        except Exception as err:
            raise HandshakeError(f"malformed message_1: {err}") from err
        if not isinstance(g_x, bytes) or len(g_x) != 32 or not _on_p256(g_x):
            raise HandshakeError("message_1 carries an invalid ephemeral key G_X")
        try:
            c_i, _ead_1 = self._edhoc.process_message_1(message_1)
            message_2 = self._edhoc.prepare_message_2(CredentialTransfer.ByReference, self.c_r, [])
        except BaseException as err:
            _check(err)
            raise HandshakeError(f"malformed message_1: {err}") from err
        self.c_i = bytes(c_i)
        return bytes(message_2)

    def process_message_3(self, message_3: bytes) -> bytes:
        """Authenticate the sensor; return its kid."""
        try:
            id_cred_i, _ead_3 = self._edhoc.parse_message_3(message_3)
        except BaseException as err:
            _check(err)
            raise HandshakeError(f"malformed message_3: {err}") from err
        kid = kid_from_id_cred(bytes(id_cred_i))
        credential = self._registered.get(kid)
        if credential is None:
            raise HandshakeError(f"unknown sensor kid 0x{kid.hex()}: not provisioned on this gateway")
        try:
            valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, credential)
            self._edhoc.verify_message_3(valid_cred_i)
            self._edhoc.completed_without_message_4()
        except BaseException as err:
            _check(err)
            raise HandshakeError(f"sensor kid 0x{kid.hex()} failed authentication: {err}") from err
        self.sensor_kid = kid
        return kid

    def keys(self) -> SessionKeys:
        return _export(self._edhoc, sender_id=self.c_i, recipient_id=self.c_r)
