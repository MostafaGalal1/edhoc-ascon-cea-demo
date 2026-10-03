"""What a handshake costs on a LoRaWAN link.

Time on air follows the LoRa modem formula in the Semtech SX1276 datasheet
(the LoRa "time on air" equations). Defaults are EU868 DR0: SF12, 125 kHz, coding rate 4/5,
8-symbol preamble, explicit header, CRC on, low-data-rate optimization on.
At DR0 the largest application payload (FRMPayload) is 51 bytes, and every
LoRaWAN frame adds 13 bytes (MHDR 1, FHDR 7, FPort 1, MIC 4).

Messages larger than 51 bytes are split into ceil(n / 51) frames. This ignores
any fragmentation header, so the DTLS numbers are a lower bound.
"""

import math

LORAWAN_OVERHEAD = 13
DR0_MAX_PAYLOAD = 51


def time_on_air_ms(frm_payload: int, sf: int = 12, bw_hz: int = 125_000, cr: int = 1,
                   preamble: int = 8, crc: bool = True, implicit_header: bool = False) -> float:
    phy_payload = frm_payload + LORAWAN_OVERHEAD
    t_sym = (2 ** sf) / bw_hz * 1000
    low_dr_opt = 1 if t_sym > 16 else 0
    numerator = 8 * phy_payload - 4 * sf + 28 + 16 * int(crc) - 20 * int(implicit_header)
    n_payload = 8 + max(math.ceil(numerator / (4 * (sf - 2 * low_dr_opt))) * (cr + 4), 0)
    return (preamble + 4.25) * t_sym + n_payload * t_sym


def frames(message_len: int, max_payload: int = DR0_MAX_PAYLOAD) -> list:
    """Payload sizes of the frames needed to carry one message."""
    full, rest = divmod(message_len, max_payload)
    return [max_payload] * full + ([rest] if rest else [])


def handshake_cost(message_lengths: list, max_payload: int = DR0_MAX_PAYLOAD, sf: int = 12) -> dict:
    sizes = [f for m in message_lengths for f in frames(m, max_payload)]
    airtime = sum(time_on_air_ms(s, sf=sf) for s in sizes)
    return {"bytes": sum(message_lengths), "frames": len(sizes), "airtime_s": airtime / 1000}
