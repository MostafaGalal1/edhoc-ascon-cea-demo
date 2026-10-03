"""SDI-12 style readings and the greenhouse CO2 rule that acts on them.

An SDI-12 sensor answers a data command with its address followed by signed
values and CR LF, all in printable ASCII (SDI-12 v1.4). For
example, address 0 reporting 24.1 degC, 68.0 %RH and 4800 ppm CO2 sends:

    0+24.1+68.0+4800<CR><LF>

That is exactly what travels in clear text when a logger forwards it unprotected.
"""

import re

_VALUE = re.compile(r"[+-][0-9.]+")

CO2_TARGET_PPM = 1000     # typical CO2 enrichment set point in a greenhouse
OSHA_PEL_PPM = 5000       # OSHA 8-hour permissible exposure limit for CO2
NIOSH_IDLH_PPM = 40000    # NIOSH "immediately dangerous to life or health"


def format_reading(address: str, temperature_c: float, humidity_pct: float, co2_ppm: int) -> bytes:
    return f"{address}{temperature_c:+.1f}{humidity_pct:+.1f}{co2_ppm:+d}\r\n".encode("ascii")


def parse_reading(data: bytes) -> dict:
    text = data.decode("ascii").strip()
    if not text or not text[0].isalnum():
        raise ValueError(f"not an SDI-12 response: {text!r}")
    values = [float(v) for v in _VALUE.findall(text[1:])]
    if len(values) != 3:
        raise ValueError(f"expected 3 values, got {text!r}")
    return {"address": text[0], "temperature_c": values[0], "humidity_pct": values[1], "co2_ppm": int(values[2])}


def co2_decision(co2_ppm: int) -> str:
    """What the climate controller does with a CO2 reading."""
    if co2_ppm >= OSHA_PEL_PPM:
        return "ALARM: CO2 at or above the OSHA 5,000 ppm limit; close CO2 valve, ventilate, evacuate staff"
    if co2_ppm > CO2_TARGET_PPM:
        return "close CO2 valve and ventilate (above the 1,000 ppm set point)"
    return "keep the CO2 valve OPEN (below the 1,000 ppm set point)"
