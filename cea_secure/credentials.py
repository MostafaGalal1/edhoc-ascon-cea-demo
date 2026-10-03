"""Device identities for the demo.

Each device has a static P-256 Diffie-Hellman key pair. Its public key is
wrapped in a CWT Claims Set (CCS, RFC 8392) and referenced over the air by a
1-byte key identifier (kid), so no certificate is ever transmitted. This is the
"static DH keys, kid" configuration of Table 1 in the paper.
"""

from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True)
class Identity:
    name: str
    kid: int
    private_key: bytes  # 32-byte P-256 scalar; never leaves the device
    credential: bytes   # CCS holding the public key; provisioned to the peer

    @property
    def kid_bytes(self) -> bytes:
        return bytes([self.kid])


def new_identity(name: str, kid: int) -> Identity:
    """Generate a fresh P-256 key pair and its CCS credential."""
    if not 0 <= kid <= 0xFF:
        raise ValueError("kid must fit in one byte")
    numbers = ec.generate_private_key(ec.SECP256R1()).private_numbers()
    x = numbers.public_numbers.x.to_bytes(32, "big")
    y = numbers.public_numbers.y.to_bytes(32, "big")
    d = numbers.private_value.to_bytes(32, "big")
    # CCS: {sub: name, cnf: {COSE_Key: {kty: EC2, kid, crv: P-256, x, y}}}
    ccs = cbor2.dumps({2: name, 8: {1: {1: 2, 2: bytes([kid]), -1: 1, -2: x, -3: y}}})
    return Identity(name=name, kid=kid, private_key=d, credential=ccs)


def kid_from_id_cred(id_cred: bytes) -> bytes:
    """Extract the kid from an ID_CRED_x value ({4: kid} as CBOR)."""
    try:
        value = cbor2.loads(bytes(id_cred))
    except Exception:
        # A bare kid may be sent in its compact form (RFC 9528, Section 3.5.3.2).
        return bytes(id_cred)
    if isinstance(value, dict) and 4 in value:
        return bytes(value[4])
    if isinstance(value, int):
        return cbor2.dumps(value)
    raise ValueError("ID_CRED does not reference a kid")
