#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Capture separate full-frame touches from an ELAN 04f3:0c28, optionally verifying each one."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import usb.core
import usb.util

TESTED_DLL_SHA256 = "8f9254d10594ff7479741e72d22abec9417807257ac0c7a967ec7eaa8865a9e9"
SIZE = 96
FRAME_BYTES = SIZE * SIZE * 2
FRAMES_PER_TOUCH = 4
VERIFY_FRAMES = (2, 3, 4)
PRESENCE_THRESHOLD = 500  # 90th percentile of the background-subtracted frame
NEW_TOUCH_GAP = 0.8  # seconds since the last finger frame that start a new touch
POLL_INTERVAL = 0.08
PROBE = Path(__file__).resolve().with_name("probe")

# Commands from libfprint/drivers/elan.h
GET_FW_VER = "40 19"
GET_SENSOR_DIM = "00 0c"
GET_IMAGE = "00 09"
GET_CALIB_STATUS = "40 23"
GET_CALIB_MEAN = "40 24"
LED_ON = "40 31"
PRE_SCAN = "40 3f"
STOP = "00 0b"
EP_IMAGE_IN = 0x82
EP_CMD_IN = 0x83

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path, help="new directory for the captures")
parser.add_argument("--touches", type=int, default=24)
parser.add_argument("--seconds", type=int, default=180, help="give up after this long")
parser.add_argument("--verify", type=Path, metavar="TEMPLATE", help="verify each touch against TEMPLATE")
parser.add_argument("--dll", type=Path, help="EngineAdapter.dll, required with --verify")
args = parser.parse_args()
if args.touches < 1 or args.seconds < 1:
    parser.error("--touches and --seconds must be positive")
if args.verify:
    if not args.dll:
        parser.error("--verify requires --dll")
    if hashlib.sha256(args.dll.read_bytes()).hexdigest() != TESTED_DLL_SHA256:
        parser.error(f"{args.dll} is not the tested ELAN 1.1.0.2111 EngineAdapter.dll")
    if not args.verify.is_file():
        parser.error(f"{args.verify} does not exist")

sys.stdout.reconfigure(line_buffering=True)
os.umask(0o077)
args.output.mkdir(parents=True)
sensor = usb.core.find(idVendor=0x04F3, idProduct=0x0C28)
if sensor is None:
    sys.exit("ELAN 04f3:0c28 is not connected")


def send(cmd):
    if sensor.write(1, bytes.fromhex(cmd), timeout=1000) != 2:
        raise RuntimeError(f"Short write of command {cmd}")


def query(cmd, length, endpoint=EP_CMD_IN):
    send(cmd)
    response = bytes(sensor.read(endpoint, length, timeout=2000))
    if len(response) != length:
        raise RuntimeError(f"Short response to {cmd}: {len(response)}/{length} bytes")
    return response


def read_frame():
    raw = query(GET_IMAGE, FRAME_BYTES, EP_IMAGE_IN)
    return raw, np.frombuffer(raw, dtype="<u2").astype(np.int32)


def calibrate():
    """Return a background frame matching the sensor's calibration mean, as in elan.c."""
    for _ in range(10):
        raw, background = read_frame()
        calibration_mean = int.from_bytes(query(GET_CALIB_MEAN, 2), "big")
        if abs(background.mean() - calibration_mean) <= 500:
            return raw, background
        print(f"Background mean {background.mean():.0f} vs calibration mean {calibration_mean}, recalibrating")
        # Wait for the calibration status to go busy (1) and then done (3).
        busy = False
        for _ in range(30):
            status = query(GET_CALIB_STATUS, 1)[0]
            busy |= status == 1
            if busy and status == 3:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("Calibration did not complete")
    raise RuntimeError("Background did not settle after calibration")


def wait_for_finger(deadline):
    send(PRE_SCAN)
    while time.monotonic() < deadline:
        try:
            status = bytes(sensor.read(EP_CMD_IN, 1, timeout=200))
        except usb.core.USBTimeoutError:
            continue  # still waiting for a finger
        if status != b"\x55":
            raise RuntimeError(f"Unexpected finger status {status.hex()}")
        return True
    return False


def verify_touch(touch):
    prefix = args.output / f"touch-{touch:02d}"
    frames = [f"{prefix}-{i:02d}.linear.raw" for i in VERIFY_FRAMES]
    log = prefix.with_name(prefix.name + ".matcher.log")
    result = subprocess.run([PROBE, args.dll, "verify", args.verify, *frames], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=20)
    log.write_text(result.stdout)
    summary = re.search(r"^Matched (\d+)/", result.stdout, re.MULTILINE)
    if result.returncode not in (0, 1) or not summary:
        raise RuntimeError(f"Matcher failed, see {log}")
    return int(summary[1]) > 0


usb.util.claim_interface(sensor, 0)
try:
    firmware = query(GET_FW_VER, 2).hex()
    dimensions = query(GET_SENSOR_DIM, 4)
    if dimensions != bytes([SIZE, 0, SIZE, 0]):
        raise RuntimeError(f"Unexpected sensor dimensions {dimensions.hex()}")
    print(f"Firmware {firmware}. Calibrating, keep the sensor clear.")
    background_raw, background = calibrate()
    (args.output / "background.raw16").write_bytes(background_raw)

    metadata = {"firmware": firmware, "width": SIZE, "height": SIZE, "frames": [], "verification": []}
    metadata_path = args.output / "capture.json"
    deadline = time.monotonic() + args.seconds
    touch = matches = 0
    pending = []  # frames of the current touch, saved once it has FRAMES_PER_TOUCH
    last_seen = 0.0
    was_present = False
    send(LED_ON)
    print(f"Ready. Touch and hold for about a second, lift for a second, and repeat {args.touches} times.")
    while touch < args.touches and wait_for_finger(deadline):
        raw, signal = read_frame()
        now = time.monotonic()
        pixels = np.maximum(signal - background, 0)
        # The firmware reports a finger even when the sensor is empty, so detect
        # touches from the background-subtracted signal instead.
        if np.percentile(pixels, 90) <= PRESENCE_THRESHOLD:
            was_present = False
            time.sleep(POLL_INTERVAL)
            continue
        if not was_present or now - last_seen >= NEW_TOUCH_GAP:
            if 0 < len(pending) < FRAMES_PER_TOUCH:
                print(f"Touch too short ({len(pending)}/{FRAMES_PER_TOUCH} frames), hold for about a second")
            pending = []
        was_present = True
        last_seen = now
        if len(pending) < FRAMES_PER_TOUCH:
            pending.append((raw, pixels, now))
            if len(pending) == FRAMES_PER_TOUCH:
                touch += 1
                for frame, (raw, pixels, now) in enumerate(pending, 1):
                    name = f"touch-{touch:02d}-{frame:02d}"
                    lo, hi = int(pixels.min()), int(pixels.max())
                    linear = ((pixels - lo) * 255 // max(hi - lo, 1)).astype(np.uint8).tobytes()
                    (args.output / f"{name}.raw16").write_bytes(raw)
                    (args.output / f"{name}.linear.raw").write_bytes(linear)
                    (args.output / f"{name}.pgm").write_bytes(f"P5\n{SIZE} {SIZE}\n255\n".encode() + linear)
                    metadata["frames"].append({"name": name, "touch": touch, "frame": frame,
                                               "time": now, "min": lo, "max": hi})
                result = ""
                if args.verify:
                    matched = verify_touch(touch)
                    matches += matched
                    metadata["verification"].append({"touch": touch, "match": matched})
                    result = ": match" if matched else ": no match"
                metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
                print(f"Touch {touch}/{args.touches}{result}")
        time.sleep(POLL_INTERVAL)

    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    if touch < args.touches:
        print(f"Timed out after {args.seconds} seconds")
    print(f"Saved {touch} touches to {args.output}")
    if args.verify:
        print(f"{matches}/{touch} touches matched")
finally:
    try:
        send(STOP)
    finally:
        usb.util.release_interface(sensor, 0)
        usb.util.dispose_resources(sensor)
