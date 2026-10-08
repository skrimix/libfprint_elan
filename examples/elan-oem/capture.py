#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Capture full, separate ELAN 04f3:0c28 touches without swipe assembly."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import numpy as np
import usb.core
import usb.util

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
parser.add_argument("--touches", type=int, default=24)
parser.add_argument("--seconds", type=int, default=180)
parser.add_argument("--verify", type=Path, help="Verify each touch against this saved template")
parser.add_argument("--dll", type=Path, help="ELAN EngineAdapter.dll (required with --verify)")
args = parser.parse_args()
if args.verify and not args.dll:
    parser.error("--verify requires --dll")
if args.touches < 1 or args.seconds < 1:
    parser.error("--touches and --seconds must be positive")
if args.verify:
    if hashlib.sha256(args.dll.read_bytes()).hexdigest() != "8f9254d10594ff7479741e72d22abec9417807257ac0c7a967ec7eaa8865a9e9":
        parser.error("This experiment requires the tested ELAN 1.1.0.2111 EngineAdapter.dll")
    if not args.verify.is_file():
        parser.error("Template file does not exist")
os.umask(0o077)
args.output.mkdir(parents=True, exist_ok=False)
sensor = usb.core.find(idVendor=0x04F3, idProduct=0x0C28)
if sensor is None:
    raise SystemExit("ELAN 04f3:0c28 is not connected")


def command(data, length=0, endpoint=0x83):
    if sensor.write(1, bytes.fromhex(data), timeout=1000) != 2:
        raise RuntimeError("Short command write")
    if length:
        result = bytes(sensor.read(endpoint, length, timeout=2000))
        if len(result) != length:
            raise RuntimeError(f"Short response to {data}: {len(result)}/{length}")
        return result


usb.util.claim_interface(sensor, 0)
try:
    firmware = command("40 19", 2).hex()
    dimensions = command("00 0c", 4)
    if dimensions != bytes.fromhex("60 00 60 00"):
        raise RuntimeError(f"Unexpected sensor geometry: {dimensions.hex()}")
    print(f"Firmware {firmware}; full frames 96x96. Calibrating; keep sensor clear.", flush=True)
    for attempt in range(10):
        background_bytes = command("00 09", 96 * 96 * 2, 0x82)
        background = np.frombuffer(background_bytes, dtype="<u2").astype(np.int32)
        mean_bytes = command("40 24", 2)
        calibration_mean = int.from_bytes(mean_bytes, "big")
        print(f"Background mean {background.mean():.1f}, calibration {calibration_mean}", flush=True)
        if abs(background.mean() - calibration_mean) <= 500:
            break
        saw_busy = False
        for poll in range(30):
            status = command("40 23", 1)[0]
            if status == 1:
                saw_busy = True
            if status == 3 and saw_busy:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("Calibration never completed")
    else:
        raise RuntimeError("Background did not settle after calibration")
    (args.output / "background.raw16").write_bytes(background_bytes)
    metadata = {"firmware": firmware, "width": 96, "height": 96, "frames": [], "verification": []}
    deadline = time.monotonic() + args.seconds
    last_frame = 0
    was_present = False
    touch = 0
    frame = 0
    matches = 0
    command("40 31")
    print("READY: touch and hold briefly, then lift for at least one second. Use the finger chosen for this test.", flush=True)
    while time.monotonic() < deadline:
        command("40 3f")
        while time.monotonic() < deadline:
            try:
                result = bytes(sensor.read(0x83, 1, timeout=200))
                break
            except usb.core.USBTimeoutError:
                pass  # The pending finger-wait command is still active.
        else:
            break
        if result != b"\x55":
            raise RuntimeError(f"Unexpected finger status: {result.hex()}")
        raw = command("00 09", 96 * 96 * 2, 0x82)
        now = time.monotonic()
        pixels = np.maximum(np.frombuffer(raw, dtype="<u2").astype(np.int32) - background, 0)
        # This firmware returns 0x55 even with an empty sensor. Separate touches
        # using the background-subtracted signal, preserving raw data for tuning.
        present = np.percentile(pixels, 90) > 500
        if not present:
            was_present = False
            time.sleep(0.08)
            continue
        if not was_present or now - last_frame >= 0.8:
            touch += 1
            frame = 0
            if touch > args.touches:
                break
            print(f"Touch {touch}/{args.touches} detected", flush=True)
        was_present = True
        last_frame = now
        frame += 1
        if frame > 4:
            time.sleep(0.08)
            continue
        name = f"touch-{touch:02d}-{frame:02d}"
        lo, hi = int(pixels.min()), int(pixels.max())
        if hi == lo:
            print(f"{name}: flat frame, skipped", flush=True)
            continue
        linear = ((pixels - lo) * 255 // (hi - lo)).astype(np.uint8)
        (args.output / f"{name}.raw16").write_bytes(raw)
        (args.output / f"{name}.linear.raw").write_bytes(linear.tobytes())
        (args.output / f"{name}.pgm").write_bytes(b"P5\n96 96\n255\n" + linear.tobytes())
        metadata["frames"].append({"name": name, "touch": touch, "frame": frame,
                                   "time": now, "min": lo, "max": hi})
        print(f"Saved {name}: signal range {lo}..{hi}", flush=True)
        (args.output / "capture.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if frame == 4:
            if args.verify:
                frames = [str(args.output / f"touch-{touch:02d}-{i:02d}.linear.raw") for i in (2, 3, 4)]
                with (args.output / f"touch-{touch:02d}.matcher.log").open("w") as log:
                    result = subprocess.run([str(Path(__file__).with_name("probe")), str(args.dll),
                                             "verify", str(args.verify), *frames],
                                            stdout=subprocess.PIPE, stderr=log, text=True, timeout=20)
                    log.write(result.stdout)
                if result.returncode not in (0, 1):
                    raise RuntimeError(f"Matcher failed; see touch-{touch:02d}.matcher.log")
                matched = any(line.startswith("VERIFY ") and "hr=0 match=1 " in line
                              for line in result.stdout.splitlines())
                matches += matched
                metadata["verification"].append({"touch": touch, "match": matched})
                (args.output / "capture.json").write_text(json.dumps(metadata, indent=2) + "\n")
                print(f"TOUCH {touch}: {'MATCH' if matched else 'NO MATCH'}", flush=True)
            if touch >= args.touches:
                break
        time.sleep(0.08)
    (args.output / "capture.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Saved {len(metadata['frames'])} frames from {min(touch, args.touches)} touches to {args.output}", flush=True)
    if args.verify:
        print(f"RESULT: {matches}/{len(metadata['verification'])} completed touches matched", flush=True)
finally:
    try:
        command("00 0b")
    finally:
        usb.util.release_interface(sensor, 0)
        usb.util.dispose_resources(sensor)
