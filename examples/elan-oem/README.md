# ELAN 04f3:0c28 OEM matcher experiment

Standalone touch capture, enrollment, and verification for the 96×96 ELAN reader.
The Windows matching engine runs natively on x86-64 Linux; Wine is not used.
This directory is independent of the Meson build and does not install or change
libfprint, fprintd, or login configuration.

## Tested hardware and engine

- USB `04f3:0c28`, firmware `0140`, sensor response `60 00 60 00`.
- ELAN Windows driver `1.1.0.2111`, INF date `2017-07-07`.
- `EngineAdapter.dll` SHA-256:
  `8f9254d10594ff7479741e72d22abec9417807257ac0c7a967ec7eaa8865a9e9`.
- The DLL is supplied separately, not committed to this repository.

The PE loader is adapted from [OMGrant/ft9201-libfprint](https://github.com/OMGrant/ft9201-libfprint),
commit `fcf5499c6ddadf0d2a03be14b173609e760a7ec6`, under LGPL-2.1-or-later.
USB commands and normalization follow `libfprint/drivers/elan.c` and `elan.h`.

## Build and use

Dependencies: GCC, make, Python 3, NumPy, PyUSB, and libusb. The current user must
have access to the USB device, and no other program may hold its interface.

Run these commands from this directory. Set `ELAN_ENGINE_DLL` to the extracted
Windows DLL's full path.

```sh
make
export ELAN_ENGINE_DLL=/path/to/EngineAdapter.dll
./probe "$ELAN_ENGINE_DLL" init
```

For enrollment, leave the sensor empty during calibration. Then make 24 separate
touches with the same finger, holding for about a second and lifting completely
for a second. Vary the contact position slightly. Do not swipe.

```sh
python3 capture.py captures/enroll --touches 24
./probe "$ELAN_ENGINE_DLL" enroll captures/finger.template \
  captures/enroll/*-02.linear.raw 2>captures/enroll.matcher.log
```

The engine decides when enrollment is complete; the tested run needed 18 touches.
`probe` stops enrollment at that point, preserving later touches for independent
verification. If more touches are needed, rerun enrollment with a larger capture
set. Existing templates and capture directories are never overwritten.

To verify live, again leave the sensor empty during calibration:

```sh
python3 capture.py captures/verify --touches 6 \
  --verify captures/finger.template --dll "$ELAN_ENGINE_DLL"
```

Each touch captures four frames. Verification checks frames 2–4 and reports a
match if any one matches. Every frame is compared against the original saved
enrollment, with engine template adaptation discarded. This avoids training on
the samples being evaluated. Detailed matcher output is saved beside captures.

Offline verification accepts any sequence of normalized 96×96 grayscale frames:

```sh
./probe "$ELAN_ENGINE_DLL" verify captures/finger.template \
  captures/verify/*-02.linear.raw 2>captures/verify.matcher.log
```

Exit status is 0 for successful initialization/enrollment or all frames matching,
1 for incomplete enrollment or one or more nonmatching/rejected frames, and 2 for
errors. Unimplemented Windows calls abort with the call name.

## What is implemented

- File-backed PE section mapping without writable executable pages; the TEB is
  installed before TLS callbacks and the DLL entry point run.
- WinBio attach, enrollment, template storage, verification, and detach through
  the DLL's interface, without private engine-context writes.
- ELAN sensor control `0x442080` returns two 32-bit dimensions (96, 96), as
  confirmed in `WbfUsbDriver.dll`.
- ELAN's BIR parser reads width/height at sample-block offsets `0x1c`/`0x1e` and
  grayscale pixels at `0x38`. FocalTech's geometry and private offsets do not apply.
- Full 16-bit USB frames, background subtraction, and linear conversion to 8-bit
  grayscale. The current swipe driver's cropping and stitching are not used.
- Empty-sensor filtering: firmware can return `0x55` for empty captures; the
  harness requires the 90th percentile of the subtracted image to exceed 500.
  This threshold separates touches in this experiment, not an OEM quality check.

Raw captures, normalized images, templates, and logs stay under the ignored
`captures/` directory. New captures use private file permissions. They contain
fingerprint data and are not included in source control.

## Initial hardware results

On 2026-10-08, one frame per touch from touches 1–18 produced a 10,242-byte
template. In a new matcher process, 5/6 held-out same-finger touches matched.
Using three frames per touch produced the same 5/6 result (15/18 frames).
All 8 touches with a different finger were rejected (0/24 frames matched).
After fresh calibration, all 6 new touches with the original finger matched
(18/18 frames), reusing the same saved enrollment in a new process for each touch.
These are small functional checks on one reader, not an accuracy benchmark.

This is a single-threaded development harness. The loader still has deliberately
limited Windows shims; it is not ready to be embedded in fprintd. A libfprint
driver needs proper lifecycle/error handling, capture quality/retry behavior,
and opaque-template integration through `FpDevice` before installation.
