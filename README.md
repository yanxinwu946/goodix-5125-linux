# Goodix 27c6:5125 — working Linux setup

This repository was rewritten from scratch on **2026-11-26**. The old experimental
driver and its history were removed; only the setup that is actually working on
this Kali machine is kept here.

The sensor is the **Goodix TLS Fingerprint Sensor `27c6:5125`** (often integrated
into the power button). Rest your finger on it lightly — do not press, pressing
can suspend the laptop.

## What actually works

- Driver source: a **git submodule** pointing to
  [`arbnorme/libfprint-goodix5125`](https://github.com/arbnorme/libfprint-goodix5125),
  tracking the upstream default branch `goodix5125` (latest, currently `c3bd02b`)
  — see `driver/`. GitHub recognizes the submodule and links it to the original
  repository.
- Matching engine: Goodix proprietary `AlgoChicago.dll`
  (`Milan_v_3.02.00.15`), extracted from the official Windows driver CAB at
  install time. **It is not committed here** (redistribution rights).
- Web console: `webui/` — a local black-and-white management UI at
  `http://127.0.0.1:8899` with enroll / verify / delete / refresh and live events.
- Verified result: `fprintd-verify` → `verify-match`, engine score `32` (threshold `30`).

The old custom capture/upscale route does not work: the sensor only yields a
64×80 image, which is too small for NBIS/SIGFM feature extraction. Goodix's own
engine is required.

## Install (Debian / Kali)

```sh
git clone --recurse-submodules git@github.com:yanxinwu946/goodix-5125-linux.git
cd goodix-5125-linux

sudo apt update
sudo apt install -y build-essential meson ninja-build pkg-config \
  libusb-1.0-0-dev libglib2.0-dev libgudev-1.0-dev cabextract curl python3

./install.sh
```

If you already cloned without submodules:

```sh
git submodule update --init --recursive --remote
```

`install.sh` will also initialize the submodule if it is empty, then:

1. Build `driver/` with `meson` and install to `/usr/local`.
2. Download the official Goodix CAB (SHA-1 checked) and install
   `AlgoChicago.dll` to `/usr/lib64/libfprint-2/goodix5125/`.
3. Write `/etc/systemd/system/fprintd.service.d/goodix5125-engine.conf` so
   `fprintd` can find the engine.
4. Remove any stale `libfprint-2.so.*backup*` from the library path (see
   Troubleshooting) and restart `fprintd`.
5. Install the web console to `/opt/goodix5125` and a desktop launcher.

## Usage

Open **Fingerprint Console** from the desktop, or run:

```sh
./start-webui.sh
```

Then use the tabs:

- **录入**: pick the finger, confirm, then press/lift the sensor 13 times.
- **管理**: verify, delete, re-enroll or refresh. Changes made outside the
  console are picked up automatically (the storage directory is polled, not
  `fprintd-list`, so the device is never double-claimed).

CLI equivalent:

```sh
fprintd-enroll root right-index-finger
fprintd-verify root right-index-finger
fprintd-list root
```

## PAM / boot safety

The fingerprint is **not used at boot**, in BIOS, or for LUKS disk unlock
(`/etc/crypttab` is empty).

`pam_fprintd.so` is intentionally **commented out** in `/etc/pam.d/common-auth`:

```text
# auth [success=2 default=ignore] pam_fprintd.so max-tries=1 timeout=10
auth [success=1 default=ignore] pam_unix.so nullok try_first_pass
```

Reason: on this laptop every time `lightdm` claims the sensor at login, the
`27c6:5125` USB device disconnects a few seconds later and will not re-enumerate
until a cold reboot (`libusb couldn't open /dev/bus/usb/001/003, errno=5`,
`usb 1-7: USB disconnect`, then `error -71/-110`). Login is therefore
**password-only**, which is safe and never locks you out.

The sensor still works for **manual** enrollment/verification via the web
console or `fprintd-*` CLI while it is online. Re-enabling the PAM line is
possible but will likely kill the device at the next login.

## Fingerprint slots

`fprintd` stores each template as a numeric file under
`/var/lib/fprint/<user>/goodixtls5125/0/`:

| Slot | Finger | Slot | Finger |
|---:|---|---:|---|
| 1 | left-thumb | 6 | right-thumb |
| 2 | left-index-finger | 7 | right-index-finger |
| 3 | left-middle-finger | 8 | right-middle-finger |
| 4 | left-ring-finger | 9 | right-ring-finger |
| 5 | left-little-finger | 10 | right-little-finger |

## Layout

```text
driver/                     git submodule -> arbnorme/libfprint-goodix5125 @ goodix5125 (latest)
config/                     fprintd systemd drop-in for the engine
webui/server.py             local HTTP/SSE console backend
webui/index.html            black-and-white frontend
start-webui.sh              launch server (if needed) + Chromium app window
desktop/                    desktop launcher
install.sh                  one-shot installer for Debian/Kali
PROGRESS.md                 research/handoff notes from the old attempt
```

## Troubleshooting

- **No response when touching the sensor**: check
  `journalctl -u fprintd -f`; a healthy load logs
  `goodix5125-engine: Milan biometric matching engine loaded successfully` and
  `claimed device 0`.
- **Sensor disappears right after login**: `lightdm` claiming the device via
  `pam_fprintd` triggers `USB disconnect` on port `1-7`; keep the PAM line
  commented out and use the web console manually. A cold reboot is needed to
  bring the sensor back once this happens.
- **`No driver found for USB device ...`** for unrelated devices (Bluetooth,
  camera, hubs) is normal.
- **`fprintd-list` says `No devices available` while the console is running**:
  the console deliberately reads template files instead of calling
  `fprintd-list`, so this does not affect the management page.
- **Old driver keeps loading**: make sure no
  `libfprint-2.so.2.0.0.aug-backup` sits in `/usr/local/lib/x86_64-linux-gnu`.
  `ldconfig` can register it with higher priority than the real library.
  Move it out and run `ldconfig` + `systemctl restart fprintd`.
- **`Device busy` / failed claim**: stop the current operation in the console,
  then retry. Do not run two enroll/verify clients at once.

## Provenance / license

- `driver/` is a submodule of `arbnorme/libfprint-goodix5125`, licensed
  LGPL-2.1-or-later; see `driver/COPYING`.
- The Goodix DLL comes from Microsoft Update CAB
  `5f2cfe33-8430-4d88-a654-de241785f4dd_3032d6cda11d2be4d1a2f1fee770db85fe60442e.cab`
  (SHA-1 `3032d6cda11d2be4d1a2f1fee770db85fe60442e`). It is downloaded by
  `install.sh` and is **not** included in this repository.
- `webui/`, `install.sh`, `start-webui.sh` and the config/desktop files are
  provided under the MIT license.
