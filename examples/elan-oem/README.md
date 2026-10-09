# ELAN 04f3:0c28 OEM matcher experiment

Captures single touches on the 96×96 ELAN 04f3:0c28 reader and enrolls/verifies
them with ELAN's Windows matching engine, loaded natively on x86-64 Linux
(no Wine). This directory is not part of the Meson build and does not touch
fprintd or the system configuration.

The same engine glue backs the `elan_oem` libfprint driver
(`libfprint/drivers/elan_oem/`), which owns `04f3:0c28` and is built by default
on x86-64 Linux. It loads the DLL from `ELAN_OEM_ENGINE_DLL`, or from
`/usr/lib/libfprint-2/elan_oem/EngineAdapter.dll` by default, and fails to open
the device if the file is missing or is not the build below. Unlike
`capture.py`, the driver does not wait for four frames: enrollment uses frame 2
of each touch, and verify and identify try frames 2 to 4 as they arrive.

## Requirements

- Reader: USB `04f3:0c28`, firmware `0140`.
- Engine: `EngineAdapter.dll` from ELAN Windows driver `1.1.0.2111` (2017-07-07),
  SHA-256 `8f9254d10594ff7479741e72d22abec9417807257ac0c7a967ec7eaa8865a9e9`.
  The DLL is not included in this repository.
- GCC, make, Python 3 with NumPy and PyUSB, and access to the USB device with no
  other program (such as fprintd) holding it.

## Usage

Run from this directory:

```sh
make
export ELAN_ENGINE_DLL=/path/to/EngineAdapter.dll
./probe "$ELAN_ENGINE_DLL" init
```

### Enroll

Keep the sensor clear while `capture.py` calibrates. Then touch the sensor 24
times with the same finger: hold for about a second, lift fully for a second,
and shift the position slightly each time. Do not swipe.

```sh
python3 capture.py captures/enroll --touches 24
./probe "$ELAN_ENGINE_DLL" enroll captures/finger.template \
  captures/enroll/*-02.linear.raw 2>captures/enroll.log
```

The engine decides when enrollment is complete (18 touches in testing); `probe`
stops there and ignores the remaining frames. If it reports that more touches
are needed, capture a larger set. Existing templates and capture directories are
never overwritten.

### Verify

Live, again keeping the sensor clear during calibration:

```sh
python3 capture.py captures/verify --touches 6 \
  --verify captures/finger.template --dll "$ELAN_ENGINE_DLL"
```

A touch counts once four frames (about 0.8 s of contact) are captured; shorter
touches are discarded with a message. A touch matches if any of frames 2–4 matches.
Every frame is compared against the saved template, discarding the engine's
template adaptation, so the frames under test never train the template.
Matcher output for each touch is saved as `touch-NN.matcher.log`.

Offline, with any normalized 96×96 8-bit grayscale frames:

```sh
./probe "$ELAN_ENGINE_DLL" verify captures/finger.template \
  captures/verify/*-02.linear.raw 2>captures/verify.log
```

`probe` exits with 0 on success (initialized, enrolled, or all frames matched),
1 if enrollment is incomplete or any frame did not match, and 2 on errors.
Engine logs go to stderr.

## How it works

- `libfprint/drivers/elan_oem/pe-loader.c` (adapted from [OMGrant/ft9201-libfprint](https://github.com/OMGrant/ft9201-libfprint)
  at `fcf5499c6ddadf0d2a03be14b173609e760a7ec6`, LGPL-2.1-or-later) maps the
  DLL without W+X pages, sets up a TEB, and runs its TLS callbacks and DllMain.
  Windows calls are shimmed just enough for this engine; unexpected ones abort
  with the call name.
- `libfprint/drivers/elan_oem/elan_oem_engine.c` drives the WinBio engine
  interface (attach, enroll, commit, verify, detach) with stub sensor and
  storage adapters; `probe.c` runs it on saved frames. The only sensor control the
  engine uses is `0x442080`, which returns the 96×96 dimensions, as in
  `WbfUsbDriver.dll`. Unlike FocalTech's engine, ELAN's reads the frame size
  from the ANSI 381 header at offsets `0x1c`/`0x1e` of the sample block.
- `capture.py` uses the commands from `libfprint/drivers/elan.h` to read full
  16-bit frames, subtracts the calibration background, and stretches the result
  to 8-bit grayscale. It does not use the swipe driver's cropping or stitching.
  The firmware reports a finger even on an empty sensor, so a touch is detected
  when the 90th percentile of the subtracted frame exceeds 500. This threshold
  is tuned for this reader, not an OEM quality check.

Captures, templates, and logs contain fingerprint data. Keep them under
`captures/`, which is ignored by git; new captures are only readable by you.

## Results

Tested on 2026-10-08 with one reader:

- Enrolling with one frame from each of touches 1–18 gave a 10,242-byte template.
- In a fresh process, 5 of 6 held-out touches of the same finger matched (one
  frame per touch). With three frames per touch, the result was also 5/6
  (15/18 frames).
- All 8 touches of a different finger were rejected (0/24 frames).
- After recalibrating, 6/6 new touches of the enrolled finger matched (18/18
  frames).

This is a small functional check, not an accuracy benchmark.

## Limitations

The engine state is global, so one reader per process, and only x86-64 Linux is
supported. The Windows shims are minimal: a Windows call the engine is not
expected to make aborts the process, including fprintd. `elan_oem` captures the
same way as `capture.py`, so keep the sensor clear while an operation starts.

On Windows, the engine updates the stored template after successful matches
(template adaptation) to follow slow changes such as dry skin. `elan_oem` always
matches against the template from enrollment, because libfprint has no way to
hand an updated template back to fprintd. Re-enroll the finger if matching gets
worse over time.
