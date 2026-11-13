# Goodix 27c6:5125 Fingerprint Sensor Linux Driver

Linux driver for the **Goodix 27c6:5125** fingerprint sensor, found in Huawei MateBook, Honor MagicBook, and other laptops. The device uses a TLS-PSK encrypted channel over USB CDC.

## Status

This experimental driver targets `27c6:5125` with firmware
`GF_ST411SEC_APP_12509`. It implements device activation, TLS, finger detection,
and image capture for libfprint. Capturing an image requires a TLS PSK that
matches the sensor's current pairing. A successful activation or handshake
alone does not verify image capture or PAM authentication. Verify enrollment
and matching with `fprintd` before enabling fingerprint login through PAM.

## Repository Structure

```
goodix-5125/
├── fp/fork-goodixtls/              # C libfprint driver
│   └── libfprint/drivers/goodixtls/
│       ├── goodix5125.c           # 5125-specific driver
│       ├── goodix5125.h           # 5125 constants
│       ├── goodixtls.c            # TLS server (s_server mode)
│       ├── goodixtls.h
│       ├── goodix.c               # Shared protocol
│       ├── goodix.h
│       ├── goodix5xx.c            # 5xx base class
│       ├── goodix5xx.h
│       ├── goodix511.c / .h       # 511 driver (reference)
│       ├── goodix_proto.c / .h    # Protocol definitions
│       └── meson.build
├── fp/goodix-fp-dump/             # Python research tools
│   ├── exp5125_realpsk.py         # Full TLS + image capture
│   ├── exp5125_v2.py / v3.py      # Activation experiments
│   ├── goodix.py                  # Core protocol library
│   ├── protocol.py                # USB protocol layer
│   ├── tool.py                    # TLS relay helper
│   └── wireshark/                 # Wireshark dissector
└── wbdi_utf8.log                  # Windows driver reference log
```

## Build & Install

### Dependencies

```bash
# Debian/Ubuntu/Kali
apt install meson ninja-build libglib2.0-dev libgusb-dev libusb-1.0-0-dev \
            libjson-glib-dev libpixman-1-dev libnss3-dev libnspr4-dev \
            openssl libfprint-2-dev fprintd
```

### Build

`fp/fork-goodixtls` contains the Goodix driver changes and a top-level Meson
file. A build requires a complete libfprint source tree with these changes
integrated. Run the commands below from that tree's root.

```bash
mkdir -p build && cd build
meson setup --prefix=/usr/local ..
ninja
sudo ninja install
```

### Configure fprintd

```bash
# Debug logging (optional)
mkdir -p /etc/systemd/system/fprintd.service.d
cat > /etc/systemd/system/fprintd.service.d/debug.conf << 'EOF'
[Service]
Environment=G_MESSAGES_DEBUG=all
EOF

# Allow network sockets for s_server (required)
cat > /etc/systemd/system/fprintd.service.d/network.conf << 'EOF'
[Service]
RestrictAddressFamilies=AF_UNIX AF_LOCAL AF_NETLINK AF_INET AF_INET6
EOF

systemctl daemon-reload
systemctl restart fprintd
```

### Enroll

Configure the [TLS PSK file](#tls-psk-file), then run these commands as the user
who will enroll and verify a fingerprint.

```bash
fprintd-enroll
fprintd-verify
```

## Architecture

### TLS-PSK Protocol

The sensor acts as a **TLS 1.2 client** over USB CDC. The host runs a TLS server. The cipher suite is fixed to `TLS_PSK_WITH_AES_128_GCM_SHA256` (0x00A8).

```
Chip (Client)          USB              Host (Server)
    |                                    |
    |--- 0xd0 (TLS CONN) --------------->|
    |<-- ClientHello (52B) -------------->|----> s_server (TCP)
    |                                     |<--- ServerHello + SKX + SHD
    |<-- ServerHello + SKX + SHD --------|
    |--- CKE + CCS + Finished ---------->|----> s_server
    |                                     |<--- CCS + Finished
    |<-- CCS + Finished -----------------|
    |--- 0xd4 (TLS established) -------->|
```

### Activation Sequence

The 5125 needs a specific initialization: **0xd4 (TLS_SUCCESSFULLY_ESTABLISHED) must be sent before enable_chip**. This was discovered by the avail5125 project. Without it, enable_chip returns 0x96 timeout.

```
1. nop
2. 0xd4 (TLS_SUCCESSFULLY_ESTABLISHED)  ← critical for 5125
3. nop
4. enable_chip (0x96)
5. nop
6. firmware_version (0xa8)
7. preset_psk_read (0xe4)
8. reset (0xa2)
9. mcu_switch_to_idle (0x70)
10. read_otp (0xa6)
11. upload_config (0x90, 256 bytes)
12. set_powerdown_scan_frequency (0x94)
13. TLS handshake (0xd0 → relay → 0xd4)
```

## TLS PSK File

Save the TLS PSK for the sensor's current pairing as exactly 32 raw bytes at
`/var/lib/fprint/goodix-5125/psk`. Give the fprintd service access to the file
and restrict access to other users. Set `GOODIX_5125_PSK_FILE` in the fprintd
service environment to use a different path.

The driver uses the file contents as the TLS key. The sensor's `0xbb020003`
response is a separate pairing validator. The driver checks the response
format during activation and supplies the local key to the TLS server.

## Windows Coexistence

This driver's activation path reuses the existing pairing. On a sensor paired
by Windows, use the matching Windows PSK. If Windows changes the active pairing,
the Linux PSK file must match the new pairing before Linux can use the reader.

An independent APP12509 test using a different Linux driver reported successful
re-pairing and Windows Hello authentication across switches between Linux and
one existing Windows 11 VM with USB passthrough. Recovery from a clean Windows
installation or a second independent Windows installation remains unverified
in those tests. [Validation record](https://github.com/sorguido/goodix-27c6-5125/blob/v3.0.1/docs/VALIDATION_SIGFM_LEGACY.md#L54-L56)

## Driver Modifications

### Crop Fix (goodix5125.c)

The sensor's leftmost 9 columns are a dead dark band, and the rightmost 2 carry edge artifacts. NBIS LFS turns these edges into ~10-20 collinear false minutiae. Cropping to 53×80 removes them:

- `CROP_LEFT = 9`, `CROP_RIGHT = 2`, `CROP_WIDTH = 53`
- Bad frames (flat press) → 0 minutiae → framework auto-retries
- Good frames → ~19 real minutiae

### NN6 Upscale (goodix5125.c)

The 64×80 sensor has a ~6px ridge period. NBIS LFS expects ~36px for 500dpi. Nearest-neighbour upscale by 6x preserves ridge edges (bilinear smears them flat):

```c
#define GOODIX5125_UPSCALE_FACTOR 6
// 53×80 → crop → 318×480 → NN6 → minutiae detection
```

### TLS Server (goodixtls.c)

The internal SSL_accept fails with OpenSSL 3.6 ("cipher operation failed"). The driver uses `fork()` + `execlp("openssl", "s_server", ...)` instead:

- TLS handshake data relayed via TCP socket
- Decrypted image data read from s_server's stdout pipe
- Requires `RestrictAddressFamilies` override in fprintd service

### 0xd4 Command (goodix.c)

- Payload changed from 0-byte `GoodixNone` to 2-byte `{0x00, 0x00}`
- Timeout increased from 10ms to 1000ms
- Error propagation fixed (was silently ignored)

## PAM Configuration

`libpam-fprintd` is used for fingerprint authentication:

```bash
apt install libpam-fprintd
pam-auth-update --enable fprintd
```

This adds fingerprint auth to `/etc/pam.d/common-auth`, which is included by `lightdm` and `sudo`. If fingerprint fails, it falls back to password.

## Community Resources

- [AntoG00/libfprint-1 PR #1](https://github.com/gulp/libfprint-1/pull/1) — 5117 fix with PSK extraction guide
- [goodix-fp-dump Issue #61](https://github.com/goodix-fp-linux-dev/goodix-fp-dump/issues/61) — 5125 firmware flashing experiments
- [goodix-fp-dump Issue #63](https://github.com/goodix-fp-linux-dev/goodix-fp-dump/issues/63) — Windows USB traffic pcap available
- [avail5125/goodix-27c6-5125](https://github.com/available314/goodix-27c6-5125) — Independent reverse engineering
- [goodix-fp-linux-dev/goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump) — Python research tools

## License

LGPL-2.1 (inherited from libfprint)
