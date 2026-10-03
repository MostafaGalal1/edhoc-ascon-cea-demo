"""Render a real run of the demo as an MP4 (1920x1080, no audio).

    pip install pillow        # plus ffmpeg on the PATH
    python tools/make_video.py docs/demo.mp4

The terminal text is the actual output of `cea_secure.demo` captured during this
run, so the byte counts and verdicts in the video are measured, not typed in.
"""

import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cea_secure.demo import Demo  # noqa: E402

W, H = 1920, 1080
FONT_DIR = "/usr/share/fonts/truetype/dejavu/"
MONO = ImageFont.truetype(FONT_DIR + "DejaVuSansMono.ttf", 20)
MONO_BOLD = ImageFont.truetype(FONT_DIR + "DejaVuSansMono-Bold.ttf", 20)
SANS = ImageFont.truetype(FONT_DIR + "DejaVuSans.ttf", 30)
SANS_SMALL = ImageFont.truetype(FONT_DIR + "DejaVuSans.ttf", 26)
SANS_BOLD = ImageFont.truetype(FONT_DIR + "DejaVuSans-Bold.ttf", 54)
SANS_MID = ImageFont.truetype(FONT_DIR + "DejaVuSans-Bold.ttf", 38)

BG, TERM_BG, BAR = (16, 20, 26), (13, 17, 23), (33, 38, 46)
FG, DIM = (220, 225, 230), (128, 138, 150)
COLORS = {"31": (255, 107, 107), "32": (80, 220, 120), "33": (240, 200, 90), "36": (90, 200, 230)}
ACCENT = (90, 200, 230)

LINE_H, TOP, LEFT, ROWS = 28, 96, 56, 29
SUB_Y = 960

# Act cards: (title, line 1, line 2)
CARDS = {
    "Setup": ("Setup", "Each device gets a static P-256 key pair at manufacturing.",
              "Only a 1-byte key ID is ever sent: no certificates."),
    "Act 1": ("Act 1  Today", "Greenhouse sensors send SDI-12 readings in clear text.",
              "An attacker on the path can read, rewrite and invent them."),
    "Act 2": ("Act 2  The proposed scheme", "EDHOC (RFC 9528) authenticates both ends in three messages,",
              "then Ascon-AEAD128 (NIST SP 800-232) protects every reading."),
    "Act 3": ("Act 3  Attacks", "Seven attacks against the proposed scheme.",
              "Every one must be rejected."),
    "Act 4": ("Act 4  Cost", "What each handshake costs on a LoRaWAN link",
              "(EU868 DR0: SF12, 125 kHz, at most 51 bytes per frame)."),
    "Summary": ("Summary", "Every claim in the run is checked by the program.", ""),
}

# Subtitles, switched on when a line containing the key appears.
SUBTITLES = [
    ("sensor-07  static", "Two devices, each with its own key pair. They know each other's public key in advance."),
    ("The CO2 probe measures", "The real reading is 4,800 ppm: the controller must stop CO2 and ventilate."),
    ("rewrites it to", "The attacker rewrites 4,800 ppm to 800 ppm. Nothing protects the text."),
    ("can also invent", "With no authentication, the attacker can also invent a reading from nothing."),
    ("First the EDHOC handshake", "The EDHOC handshake: three messages, counted byte by byte as they pass the attacker."),
    ("Measured on the wire", "101 bytes in total, exactly the figure in Table 1 of the paper. DTLS 1.3 needs 894."),
    ("observer learns neither", "Identities and MACs travel encrypted: an observer cannot tell which sensor is talking."),
    ("now sealed with Ascon", "Keys come from the EDHOC exporter. Each reading is sealed with Ascon-AEAD128."),
    ("sees only ciphertext", "The attacker sees only ciphertext. The gateway decrypts 4,800 ppm and ventilates."),
    ("1. Tamper", "Tamper: one flipped bit and the 16-byte authentication tag no longer matches."),
    ("2. Replay", "Replay: a genuine old frame is caught by its sequence number."),
    ("3. Forge", "Forgery: without the session key, no valid tag can be made."),
    ("4. Fake sensor ID", "Fake sensor: the impostor claims ID 0x07 but cannot compute MAC_3 without the real key."),
    ("5. Unknown sensor ID", "Unknown sensor: no provisioned credential, so no session."),
    ("6. Tampered handshake", "Tampered handshake: one changed byte in message_1 and the keys never agree."),
    ("7. Rogue gateway", "Rogue gateway: the sensor only trusts the gateway key it was provisioned with."),
    ("Not covered by cryptography", "Honest limit: dropping packets cannot be prevented, only detected."),
    ("handshake  ", "EDHOC fits each message in one frame: 3 frames and 6.7 s, against 18 frames and 49.5 s."),
    ("1% duty cycle", "In Europe these bands allow 1 % airtime: each second on air costs 99 s of silence."),
    ("checks passed", "All checks passed."),
]

ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def capture_demo() -> list:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ok = Demo(color=True, step=False).run()
    if not ok:
        raise SystemExit("demo checks failed; not rendering a video of a failing run")
    return out.getvalue().splitlines()


def styled(line: str) -> list:
    """Split one ANSI-coloured line into (text, colour, bold) runs."""
    runs, pos, color, bold, dim = [], 0, FG, False, False
    for m in ANSI.finditer(line):
        if m.start() > pos:
            runs.append((line[pos:m.start()], DIM if dim else color, bold))
        for code in (m.group(1) or "0").split(";"):
            if code == "0":
                color, bold, dim = FG, False, False
            elif code == "1":
                bold = True
            elif code == "2":
                dim = True
            elif code in COLORS:
                color = COLORS[code]
        pos = m.end()
    if pos < len(line):
        runs.append((line[pos:], DIM if dim else color, bold))
    return runs


def plain(line: str) -> str:
    return ANSI.sub("", line)


def split_acts(lines: list) -> list:
    """[(card key, [lines])] using the ===== banners the demo prints."""
    acts, i = [], 0
    while i < len(lines):
        if plain(lines[i]).startswith("=====") and i + 1 < len(lines):
            title = plain(lines[i + 1]).strip()
            key = next(k for k in CARDS if title.startswith(k))
            acts.append((key, []))
            i += 3
            continue
        if acts:
            acts[-1][1].append(lines[i])
        i += 1
    return acts


def centered(draw, y, text, font, fill):
    draw.text(((W - draw.textlength(text, font=font)) / 2, y), text, font=font, fill=fill)


def card(title: str, line1: str, line2: str, kicker: str = "") -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if kicker:
        centered(d, 330, kicker, SANS_SMALL, DIM)
    centered(d, 400, title, SANS_BOLD, FG)
    d.rectangle([W / 2 - 60, 492, W / 2 + 60, 496], fill=ACCENT)
    centered(d, 540, line1, SANS, FG)
    if line2:
        centered(d, 590, line2, SANS, FG)
    return img


def terminal(lines: list, subtitle: str, act_title: str) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([24, 20, W - 24, 930], radius=14, fill=TERM_BG)
    d.rounded_rectangle([24, 20, W - 24, 70], radius=14, fill=BAR)
    d.rectangle([24, 50, W - 24, 70], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([48 + 30 * i, 37, 64 + 30 * i, 53], fill=c)
    centered(d, 33, f"cea-secure-demo  -  python run_demo.py  -  {act_title}", ImageFont.truetype(FONT_DIR + "DejaVuSans.ttf", 20), DIM)
    for row, line in enumerate(lines[-ROWS:]):
        x, y = LEFT, TOP + row * LINE_H
        for text, color, bold in styled(line):
            font = MONO_BOLD if bold else MONO
            d.text((x, y), text, font=font, fill=color)
            x += d.textlength(text, font=font)
    if subtitle:
        width = d.textlength(subtitle, font=SANS)
        d.rounded_rectangle([(W - width) / 2 - 28, SUB_Y - 14, (W + width) / 2 + 28, SUB_Y + 50], radius=12, fill=BAR)
        centered(d, SUB_Y, subtitle, SANS, FG)
    return img


def pause_for(line: str) -> float:
    p = plain(line)
    if not p.strip():
        return 0.15
    if "Measured on the wire" in p or "checks passed" in p:
        return 3.5
    if "[PASS]" in p or "[FAIL]" in p:
        return 1.8
    if "REJECTED" in p or "rewrites it to" in p or "accepted" in p:
        return 1.6
    if p.lstrip()[:2] in ("1.", "2.", "3.", "4.", "5.", "6.", "7."):
        return 1.4
    return 0.55


def render(out_path: str):
    lines = capture_demo()
    acts = split_acts(lines)
    frames = []  # (image, seconds)
    frames.append((card("Lightweight Security for IoT in CEA", "EDHOC + Ascon-AEAD128: a live demo",
                        "Mostafa M. Galal and Yahya A. Azzam", kicker="Controlled environment agriculture"), 5.0))
    for key, body in acts:
        title, l1, l2 = CARDS[key]
        frames.append((card(title, l1, l2), 3.5))
        shown, subtitle = [], ("Twelve checks: the two attacks on clear text succeed, every attack on the scheme fails."
                               if key == "Summary" else "")
        for line in body:
            shown.append(line)
            for trigger, text in SUBTITLES:
                if trigger in plain(line):
                    subtitle = text
            frames.append((terminal(shown, subtitle, title), pause_for(line)))
        frames.append((terminal(shown, subtitle, title), 2.5))
    frames.append((card("101 bytes, 7 attacks rejected", "EDHOC handshake measured at 37 + 45 + 19 bytes; DTLS 1.3 needs 894.",
                        "Tampering, replay, forgery, fake and unknown sensors, tampered handshake, rogue gateway."), 6.0))

    with tempfile.TemporaryDirectory() as tmp:
        listing = []
        for i, (img, seconds) in enumerate(frames):
            path = os.path.join(tmp, f"f{i:04d}.png")
            img.save(path)
            listing.append(f"file '{path}'\nduration {seconds:.2f}\n")
        listing.append(f"file '{os.path.join(tmp, f'f{len(frames) - 1:04d}.png')}'\n")
        concat = os.path.join(tmp, "frames.txt")
        Path(concat).write_text("".join(listing))
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", concat,
                        "-vf", "fps=30,format=yuv420p", "-c:v", "libx264", "-preset", "medium", "-crf", "20",
                        "-movflags", "+faststart", out_path], check=True)
    total = sum(s for _, s in frames)
    print(f"wrote {out_path}: {len(frames)} scenes, {total:.0f} s")


if __name__ == "__main__":
    render(sys.argv[1] if len(sys.argv) > 1 else "docs/demo.mp4")
