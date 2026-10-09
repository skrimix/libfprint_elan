# libfprint with ELAN 04f3:0c28 support

This is a fork of [libfprint] that adds `elan_oem`, a driver for the ELAN
`04f3:0c28` fingerprint reader. Upstream, this reader is handled by the `elan`
swipe driver, which cannot reliably match prints on this 96×96 press sensor.
`elan_oem` captures single touches and enrolls and matches them with ELAN's
own Windows matching engine (`EngineAdapter.dll`), which it loads into the
process on x86-64 Linux without Wine.

This work is largely based on [OMGrant/ft9201-libfprint], which does the same
for FocalTech FT9201 readers. The PE loader in
`libfprint/drivers/elan_oem/pe-loader.c` is adapted from its `src/ft_engine.c`
(at `fcf5499c6ddadf0d2a03be14b173609e760a7ec6`).

Everything else is upstream libfprint. See [upstream's README][Upstream README]
for the project itself.

## Requirements

- Reader: USB `04f3:0c28` (check with `lsusb -d 04f3:0c28`). Only firmware
  `0140` has been tested.
- x86-64 Linux. On other hosts the driver is not built.
- `EngineAdapter.dll` from ELAN's Windows driver `1.1.0.2111` (2017-07-07),
  SHA-256 `8f9254d10594ff7479741e72d22abec9417807257ac0c7a967ec7eaa8865a9e9`.
  The DLL is not included in this repository. The driver refuses to use any
  other file, since its Windows shims only cover this build.

## Installation

### Arch Linux

[`packaging/arch/PKGBUILD`](packaging/arch/PKGBUILD) builds
`libfprint-elan-oem-git`, which replaces the `libfprint` package and includes
the engine DLL, downloaded from Microsoft during the build:

```sh
cd packaging/arch
makepkg -si
```

Then restart fprintd and enroll as usual, for example with `fprintd-enroll`.

### Other distributions

Build and install as usual for libfprint:

```sh
meson setup build --prefix=/usr
meson compile -C build
sudo meson install -C build
```

This replaces your distribution's libfprint, so a package update may overwrite
it again.

The engine is in ELAN's driver package on the
[Microsoft Update Catalog][Driver CAB]. Extract it with `cabextract` and install
it where the driver looks for it by default:

```sh
curl -LO https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2017/07/2553b5f6-cd54-4cb2-a552-c4ee4d4ebe9a_4394725e4cd2b8d73ab385804e2f9e1e760a4e28.cab
cabextract -F EngineAdapter.dll 2553b5f6-*.cab
sha256sum EngineAdapter.dll
sudo install -Dm644 EngineAdapter.dll /usr/lib/libfprint-2/elan_oem/EngineAdapter.dll
```

To use another location, set `ELAN_OEM_ENGINE_DLL` in the environment of the
process using libfprint. For fprintd, add it with `sudo systemctl edit fprintd`:

```ini
[Service]
Environment=ELAN_OEM_ENGINE_DLL=/path/to/EngineAdapter.dll
```

Then restart fprintd and enroll as usual, for example with `fprintd-enroll`.

## Usage notes

- Keep the sensor clear when an enroll or verify operation starts: the driver
  calibrates against an empty sensor first.
- Enrollment needs about 18 touches. Hold the finger on the sensor for about a
  second, lift it fully, and shift its position slightly each time. Do not
  swipe.
- Prints enrolled with the upstream `elan` driver do not work with `elan_oem`.
  Delete them and enroll again.
- On Windows, the engine updates stored templates after successful matches.
  libfprint has no way to hand an updated template back to fprintd, so
  `elan_oem` always matches against the template from enrollment. Re-enroll if
  matching gets worse over time.
- The engine state is global, so only one reader per process is supported.
- A Windows call the engine is not expected to make aborts the process,
  including fprintd. If that happens, please report it with the call name from
  the log.

## Testing without fprintd

`examples/elan-oem/` has a standalone capture and matching tool that uses the
same engine glue as the driver, along with notes on how it works and test
results. See [its README](examples/elan-oem/README.md).

## License

Like libfprint, this fork is licensed under the [LGPL 2.1](COPYING) or later.
ELAN's `EngineAdapter.dll` is proprietary and is not part of this repository.

<!----------------------------------------------------------------------------->

[libfprint]: https://gitlab.freedesktop.org/libfprint/libfprint
[Upstream README]: https://gitlab.freedesktop.org/libfprint/libfprint/-/blob/master/README.md
[OMGrant/ft9201-libfprint]: https://github.com/OMGrant/ft9201-libfprint/
[Driver CAB]: https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2017/07/2553b5f6-cd54-4cb2-a552-c4ee4d4ebe9a_4394725e4cd2b8d73ab385804e2f9e1e760a4e28.cab
