# Goodix 27c6:5125 Fingerprint Sensor Linux Driver

Linux driver for the **Goodix 27c6:5125** fingerprint sensor, found in Huawei MateBook, Honor MagicBook, and other laptops. The device uses a TLS-PSK encrypted channel over USB CDC.

## Status

- ✅ Device activation (0xd4 + enable_chip)
- ✅ TLS-PSK handshake (via `openssl s_server`)
- ✅ Finger detection
- ✅ Dark band cropping (53×80 → NN6 → 318×480)
- ✅ PAM fingerprint authentication
- ❌ Image capture (0x20) — **needs plaintext PSK from Windows**

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

```bash
cd fp/fork-goodixtls
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

```bash
fprintd-enroll root right-index-finger
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

### PSK Issue

The 32-byte PSK stored at `/var/lib/fprint/goodix-5125/psk` is a **PMK hash** (obfuscated), not the true TLS session key. The Windows driver uses a proprietary whitebox algorithm to derive the real key:

```
seal data (332B) → gf_unseal_data → 32B plaintext PSK → whitebox → 96B → hash → 32B PMK hash
                                        ↑                                       ↑
                                  true TLS key                          stored in psk file
```

**Without the true plaintext PSK, the 0x20 (MCU_GET_IMAGE) command times out.** The chip detects the PSK mismatch and refuses to send image data.

### s_server Workaround

The driver uses `openssl s_server` as an external TLS server instead of the internal SSL_accept. This bypasses the cipher negotiation issue that affects OpenSSL 3.x. The TLS handshake succeeds, but the 0x20 image capture still fails without the true PSK.

## PSK Extraction (from Windows)

To fix the 0x20 timeout, extract the true plaintext PSK from Windows:

1. Install [x64dbg](https://x64dbg.com/) on Windows
2. Run x64dbg as Administrator, attach to `wudfhost.exe`
3. In the Symbols tab, find `gfspi.dll`
4. Search for string references containing `mbedtls_ssl_conf_psk`
5. Set a breakpoint on the `call` instruction before the error log
6. Trigger Windows Hello fingerprint authentication
7. When the breakpoint hits:
   - Verify R8 = 0x20 (32 bytes key length)
   - RDX points to the 32-byte plaintext PSK
   - Right-click RDX → Follow in Dump → Copy 32 bytes
8. Replace the PSK in `goodixtls.c`'s callback with the extracted key

Detailed guide: [AntoG00's PR #1](https://github.com/gulp/libfprint-1/pull/1)

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