# EDHOC + Ascon for IoT in controlled environment agriculture: demo

Companion demo for the paper *Lightweight Security for IoT in Controlled Environment
Agriculture* (Mostafa M. Galal and Yahya A. Azzam).

A greenhouse CO2 sensor talks to its edge gateway through an attacker that sits on the
path, over real UDP sockets. The demo shows that:

1. Today's clear-text SDI-12 readings can be read, rewritten and invented.
2. The proposed scheme's EDHOC handshake costs **37 + 45 + 19 = 101 bytes**, measured
   on the wire, matching Table 1 of the paper.
3. Readings protected with **Ascon-AEAD128** cannot be read, and seven attacks are
   rejected: tampering, replay, forgery, a fake sensor ID, an unknown sensor ID, a
   tampered handshake and a rogue gateway.
4. On a LoRaWAN link (EU868 DR0, 51-byte frames) the handshake takes 3 frames and
   6.7 s on air, against at least 18 frames and 49.5 s for DTLS 1.3 with raw public keys.

Every claim is checked by the program; the run ends with a pass/fail summary.

## Run it

Needs Python 3.10 to 3.14 on macOS (Apple Silicon), Windows or Linux.

```
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run_demo.py                 # the whole story, about 5 seconds
python run_demo.py --step          # pauses before each act, for presenting live
python -m pytest -q                # 18 tests
```

`docs/sample-output.txt` is a recorded run, if you only want to read it.
On an Intel Mac, `pip` builds lakers from source and needs a Rust toolchain.

## What runs where

| Part | File | Standard |
| --- | --- | --- |
| Device keys and credentials | `cea_secure/credentials.py` | P-256 static DH keys in a CWT Claims Set (RFC 8392), 1-byte kid |
| Handshake | `cea_secure/edhoc.py` | EDHOC, RFC 9528: method 3 (static DH both sides), cipher suite 2, via [lakers](https://github.com/lake-rs/lakers) |
| Key derivation, nonce, AAD, replay window | `cea_secure/channel.py` | OSCORE, RFC 8613 (Sections 3.2.1, 5.2, 5.4, 7.4); EDHOC to OSCORE per RFC 9528 Appendix A.1 |
| Cipher | `cea_secure/ascon.py` | Ascon-AEAD128, NIST SP 800-232 (designers' reference code) |
| Sensor, gateway, attacker | `cea_secure/nodes.py` | UDP; SDI-12 style readings (`cea_secure/sdi12.py`) |
| LoRaWAN cost model | `cea_secure/lora.py` | Semtech SX1276 time-on-air formula, EU868 DR0 |
| The narrated run | `cea_secure/demo.py` | |

## How we know the pieces are right

- **Ascon-AEAD128** passes all 1,089 known-answer vectors of the designers' C reference
  ([ascon-c](https://github.com/ascon/ascon-c), `crypto_aead/asconaead128`) and the
  byte-aligned vector of NIST's ACVP set (tcId 197, 120-bit truncated tag).
- **OSCORE key derivation** reproduces the RFC 8613 Appendix C.1.1 test vector.
- **EDHOC** sizes are measured from the bytes the attacker relays, every run.

## Design notes

- Readings are protected with the OSCORE key schedule, nonce and AAD, but carried in a
  compact frame instead of a CoAP message, so the demo needs no CoAP stack:
  `n | Partial IV | len(kid) | kid | ciphertext || 16-byte tag` (20 bytes of overhead).
- Ascon-AEAD128 has no IANA-registered COSE identifier yet. The demo uses value 35, the
  one requested in draft-ochkas-cose-ascon-04; this is fine for a closed deployment where
  both ends are configured in advance.
- The EDHOC handshake itself runs cipher suite 2 (AES-CCM-16-64-128, SHA-256, P-256),
  the profile behind Table 1. An Ascon-based EDHOC suite needs those COSE codepoints first.

## Findings worth knowing

- **lakers 0.6.2 panics on an invalid curve point.** If an attacker replaces G_X in
  message_1 with a value that is not on P-256, the library's Rust core panics instead of
  returning an error. Uncaught, that panic kills the gateway's receive loop, so one forged
  37-byte packet is a denial of service. `edhoc.py` validates G_X and G_Y before calling
  lakers and converts any panic into a rejected handshake; `tests/test_demo.py` checks the
  gateway keeps serving afterwards.
- **Cryptography does not stop dropped packets.** An on-path attacker can still discard
  traffic. The gateway can only notice the silence and raise an alarm on a missed
  reporting interval.

## Third-party material

- `cea_secure/ascon.py`: [pyascon](https://github.com/meichlseder/pyascon) by Maria
  Eichlseder, commit `ed24e54`, CC0 1.0.
- `tests/vectors/ascon_aead128_kat.txt`: from [ascon-c](https://github.com/ascon/ascon-c),
  commit `446347f`, CC0 1.0.
- `tests/vectors/nist_acvp_ascon_aead128_tc197.json`: from NIST's
  [ACVP-Server](https://github.com/usnistgov/ACVP-Server) repository, commit `975de31`.
