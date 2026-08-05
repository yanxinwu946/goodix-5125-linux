#!/usr/bin/env python3
"""Goodix 27c6:5125 full image-capture pipeline (rebuilt 2026-08-05).

Pipeline (VERIFIED working 2026-08-04, PROGRESS.md line 7):
  PSK blob (512B DPAPI seal, raw 0xff passthrough) -> bundled TLS relay
  (tool.connect_device) -> config (256B raw) -> FDT -> 0x20 -> openssl
  decrypt -> 80x64 12-bit image.

CRITICAL details learned from debugging:
  * The avail5125 windows_initialization order is required for the 5125.
  * The 0xd4 prelude (before enable_chip) MUST be sent fire-and-forget
    (expect_ack=0).  goodix.py's tls_successfully_established() waits for
    an ACK that never comes for the prelude -> hang.  After the real TLS
    handshake, 0xd4 DOES get an ACK.
  * The 512B PSK blob write IS part of the working pipeline (the chip's
    whitebox derives the session PSK from the stored DPAPI seal).  The
    READ-ONLY exp5125_realpsk.py never wrote it and never captured.
  * isTlsConnected flag is bit 1 of mcu-state byte[1] (0x02), not bit 0.
    Working: 00023100000800002000000011200000 ; WBDI: 01023000003a00002000000000000000
  * 0x20 returns 7726B RAW (flags=0xb0), body = TLS app-data record
    (17 03 03 1e25).  Forward body to s_server over the established TCP
    connection; read decrypted plaintext from s_server stdout.
  * Plaintext = 7693B.  Optimal decode offset 8 -> 7680B -> 80x64 12-bit.
  * Blank frame: mean~4079, hist all buckets 6-7.  Finger frame: mean~3297,
    score 325, buckets 4/5/6/7 high contrast.

Device-recovery caveat: if the chip deadlocks (enable_chip 0x96 timeout or
0x20 timeout), it self-recovers via an internal watchdog after 5-10 minutes
of COMPLETE silence.  Do NOT probe repeatedly -- it resets the recovery
timer ("越探越死").

Usage:
  python3 exp_img_capture.py                 # single capture, REAL_PSK
  python3 exp_img_capture.py --psk zero      # zero PSK variant
  python3 exp_img_capture.py --frames 5      # capture N frames back-to-back
"""
import argparse
import select
import socket
import subprocess
import sys
import time

T0 = time.monotonic()


def ts():
    return f"[t+{time.monotonic() - T0:6.1f}s]"


sys.path.insert(0, "/root/Projects/goodix-5125/fp/goodix-fp-dump")
import goodix  # noqa: E402
import protocol  # noqa: E402
import tool  # noqa: E402

# Device TLS-PSK session key. NOT committed to the public repo — load it from a
# local-only file (or $GOODIX_5125_PSK). All-zero = ZERO PSK mode (the working
# config after the 08-04 chip reflash).
def _load_real_psk():
    import os
    env = os.environ.get("GOODIX_5125_PSK")
    if env:
        return bytes.fromhex(env)
    for p in ("/var/lib/fprint/goodix-5125/psk.real-backup",
              "/root/.config/goodix-5125/psk"):
        try:
            with open(p, "rb") as f:
                data = f.read().strip()
            return bytes.fromhex(data.decode()) if len(data) == 64 else data[:32]
        except (OSError, ValueError):
            continue
    raise RuntimeError(
        "REAL_PSK not configured: set $GOODIX_5125_PSK or create a local psk file "
        "(see /var/lib/fprint/goodix-5125/psk.real-backup on the dev machine)")

REAL_PSK = _load_real_psk()
ZERO_PSK = bytes(32)

# 512B DPAPI seal blob (avail5125/constants.c PRESET_PSK_WRITE_R_BUF).
# Already fully framed (message-pack 0xa0 + cmd 0xe0), sent RAW via cmd 0xff.
PSK_BLOB = bytes.fromhex(
    "a0c80169e0c501020001bb4c01000001000000d08c9ddf0115d1118c7a00c04f"
    "c297eb01000000d3181fccde211e489719ff4ac140790d040000004000000054"
    "0068006900730020006900730020007400680065002000640065007300630072"
    "0069007000740069006f006e00200073007400720069006e0067002e00000010"
    "660000000100002000000092d8e11c87125e635237d9975e2d58d2824e8f26fd"
    "3f7201685ff73e827bdb03000000000e8000000002000020000000fd5ab5c281"
    "392d57507eea77865319c091ba2318957cfbab5dd815a1df4067e03000000001"
    "d8eb5dc79c01ddadb4b19ca325f5a14c1a6a643f5b848ca903fa407b9aa5c8cc"
    "3719ec41269602f7d24cae213b3fcb4000000076cfeac0818b23f27e8f3a8478"
    "4a82589029339f181c1b8c3fe6e02dc8903adf494519d468a244e4a8733dce45"
    "9f03b211a2757d4b695f9ee13be2553dbf1fc5a7d8b1844f41b3cd030001bb66"
    "000000194d152ea08bcca2d886538be4ca6b15c6097848e56cfb6341278f1537"
    "fb029b02ff20000000aefe57607c64a6e63b1f6d9a7b73f6160c00f3e8992515"
    "99207fca1503aa098f5f9c92f2f7d54a1383513e4877a48f5fe4946975d48647"
    "5e9775e0e0530ee9f40000b3607c64a6e63b1f6d9a7b73f6160c00f3e8992515"
    "99207fca1503aa098f5f9c92f2f7d54a1383513e4877a48f5fe4946975d48647")

# 256B MCU config (avail5125/constants.c MCU_DOWNLOAD_CHIP_CONFIG_BUF).
# Already fully framed, must be sent RAW (double-wrapping fails).
RAW_DEVICE_CONFIG = bytes.fromhex(
    "a0e4008490e1007011748500852cb118c914dd00dd00dd00ba000180ca000400840015b3860000"
    "c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000b6980000009a0000"
    "00d2000000d4000000d6000000d800000050000105d0000000700000007200785674003412200010"
    "405c0000012002480b3602b6003802b4003a02b4002a0182032200012024001400800001005c0000"
    "01560004205800030232000c02660003007c0000588200801f2a0108005400100162000403640019"
    "00660003007c0000582a0108005200080054000001660003007c000058004f538f32000c02660003"
    "007c0000588200801f2a01080054001001")

COMMAND_ACK = 0xb0
COMMAND_UPLOAD_CONFIG_MCU = 0x90


def upload_config_raw(device, raw: bytes, ack_cmd: int) -> bool:
    """Send an already-framed buffer raw (cmd 0xff passthrough), then ACK+reply.

    ack_cmd must match the command embedded in the raw frame (byte 4):
    PSK blob -> 0xe0 (PRESET_PSK_WRITE_R), config -> 0x90 (UPLOAD_CONFIG_MCU).
    """
    print(f"  raw write {len(raw)} bytes (ack cmd=0x{ack_cmd:02x})")
    device.protocol.write(raw)
    goodix.check_ack(
        goodix.check_message_protocol(
            goodix.check_message_pack(device.protocol.read()), COMMAND_ACK),
        ack_cmd)
    message = goodix.check_message_protocol(
        goodix.check_message_pack(device.protocol.read()), ack_cmd)
    if len(message) < 1:
        raise SystemError("Invalid response length")
    return message[0] == 0x01


def read_with_timeout(stream, timeout_s: float, want: int = 0):
    """Read whatever is available from a pipe within timeout; returns bytes."""
    import os
    chunks = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        r, _, _ = select.select([stream], [], [], 0.5)
        if r:
            # Use os.read on the raw fd: BufferedReader.read(4096) BLOCKS
            # trying to fill 4096 bytes when the writer keeps the pipe open.
            data = os.read(stream.fileno(), 4096)
            if not data:
                break
            chunks.append(data)
            if want and sum(len(c) for c in chunks) >= want:
                break
        else:
            continue
    return b"".join(chunks)


def tls_established_fire_forget(device):
    """Send 0xd4 (TLS_SUCCESSFULLY_ESTABLISHED) WITHOUT waiting for ACK.

    avail5125 sends this prelude with expect_ack=0.  goodix.py's
    tls_successfully_established() waits for an ACK that never comes when
    used as the pre-enable_chip prelude, so we must do a raw write.

    NOTE: the device MAY respond to the prelude.  Drain the buffer so the
    next command's read doesn't consume a stale response (avail never reads
    after the prelude, so it is immune; goodix.py's nop()/firmware_version()
    do read and would raise "Invalid ack").
    """
    device.protocol.write(goodix.encode_message_pack(
        goodix.encode_message_protocol(
            b"\x00\x00", goodix.COMMAND_TLS_SUCCESSFULLY_ESTABLISHED)))
    device.empty_buffer()


def windows_initialization(device, write_psk: bool = True):
    """Faithful avail5125 windows_initialization() order for the 5125.

    avail order (goodix_init_seq.c): nop -> 0xd4(0,0) -> nop ->
    firmware(1,1) -> enable_chip(0,0) -> mcu_state(0,1) -> nop ->
    firmware(1,1) -> preset_psk_read(1,1) -> PSK blob 0xff write(1,1)
    -> preset_psk_read(1,1) -> reset(1,1) -> chip_id(1,1) -> otp(1,1)
    -> reset(1,1) -> idle(1,0) -> REG x4(1,0) -> config 0xff(1,1).

    goodix.py semantics: nop reads nothing (returns on timeout); the
    (1,1) commands read ACK + reply.  The 0xd4 prelude is sent
    fire-and-forget + buffer drained (see tls_established_fire_forget).

    write_psk: the chip is FACTORY-provisioned with a PSK.  The WBDI log
    (wbdi_utf8.log production_psk_process) NEVER writes a PSK -- it only
    reads the MCU hash and compares.  Re-writing a PSK blob to an
    already-provisioned chip is REFUSED (no ACK -> USB timeout).  So by
    default we only write when the pre-read reports NO stored PSK.
    """
    device.nop()
    tls_established_fire_forget(device)      # 0xd4 prelude, NO ack wait
    print("  0xd4 prelude sent (fire-and-forget)")
    device.nop()
    try:
        fw = device.firmware_version()
        print(f"  firmware: {fw}")
    except Exception as e:
        print(f"  firmware parse skipped ({e})")
    device.enable_chip(True)
    device.query_mcu_state(b"\x55\x00\x00\x00\x00", True)
    device.nop()
    try:
        fw = device.firmware_version()
        print(f"  firmware(2): {fw}")
    except Exception:
        pass

    # avail: preset_psk_read BEFORE the 0xff blob write
    ok, flags, psk = device.preset_psk_read(
        int.from_bytes(b"\x03\x00\x02\xbb", "little"))
    print(f"  preset_psk_read (pre): ok={ok} flags=0x{flags:08x} "
          f"len={len(psk) if psk else 0}")
    if psk:
        print(f"  chip PSK bytes: {psk.hex()}")

    if write_psk and psk and len(psk) > 0:
        # Chip already provisioned (WBDI never rewrites) -- skip the write,
        # which is REFUSED (no ACK) on an already-provisioned chip.
        print("  chip already has a PSK -- skipping blob write")
    else:
        # PSK blob passthrough (cmd 0xff) - stores DPAPI seal into the chip
        if not upload_config_raw(device, PSK_BLOB,
                                 goodix.COMMAND_PRESET_PSK_WRITE_R):
            raise SystemExit("PSK blob write failed")
        print("  PSK blob written (512B)")

    ok, flags, psk = device.preset_psk_read(
        int.from_bytes(b"\x03\x00\x02\xbb", "little"))
    print(f"  preset_psk_read (post): ok={ok} flags=0x{flags:08x} "
          f"len={len(psk) if psk else 0}")

    success, number = device.reset(True, False, 20)
    print(f"  reset: success={success} number={number}")
    if not success:
        raise SystemExit("Reset failed")

    chip_id = device.read_sensor_register(0x0000, 4)
    print(f"  chip id: {chip_id.hex()}")
    if chip_id != b"\xa2\x04\x25\x00":
        raise SystemExit(f"Unexpected chip id {chip_id.hex()} -- aborting")

    otp = device.read_otp()
    print(f"  otp: {len(otp)}B")

    success, number = device.reset(True, False, 20)
    print(f"  reset2: success={success} number={number}")

    device.mcu_switch_to_idle_mode(0x14)

    # DAC register writes (from avail REG x4)
    device.write_sensor_register(0x0220, b"\x78\x0b")
    device.write_sensor_register(0x0236, b"\xb9\x00")
    device.write_sensor_register(0x0238, b"\xb8\x00")
    device.write_sensor_register(0x023a, b"\xb7\x00")

    if not upload_config_raw(device, RAW_DEVICE_CONFIG,
                             COMMAND_UPLOAD_CONFIG_MCU):
        raise SystemExit("Config upload failed")
    print("  config uploaded (256B raw)")

    if not device.set_powerdown_scan_frequency(100):
        raise SystemExit("set_powerdown_scan_frequency failed")
    print("  powerdown scan freq set")


def capture_frames(device, tls_client, tls_server, frames: int, out_prefix: str,
                   wait_finger: float = 0.0):
    """Switch to FDT and capture N fingerprint frames through the TLS channel."""
    for i in range(frames):
        device.mcu_switch_to_fdt_mode(
            b"\x0d\x01\xb2\xb2\xc2\xc2\xa7\xa7\xb6\xb6\xa6\xa6\xb6\xb6", True)
        device.nav()
        print(f"  [{i}] fdt+nav done")

        device.mcu_switch_to_fdt_mode(
            b"\x0d\x01\x80\xb0\x80\xc0\x80\xa4\x80\xb4\x80\xa3\x80\xb4", True)

        if wait_finger > 0:
            baseline = device.read_sensor_register(0x0082, 2)
            deadline = time.monotonic() + wait_finger
            print(f"  [{i}] PLACE FINGER ON SENSOR NOW (waiting up to "
                  f"{wait_finger:.0f}s, baseline fdt={baseline.hex()})...")
            while time.monotonic() < deadline:
                fdt = device.read_sensor_register(0x0082, 2)
                if fdt != baseline:
                    print(f"  [{i}] finger detected (fdt={fdt.hex()} "
                          f"from baseline {baseline.hex()})")
                    break
                time.sleep(0.3)
            else:
                print(f"  [{i}] timeout: no finger, capturing anyway")
        else:
            device.read_sensor_register(0x0082, 2)

        device.write_sensor_register(0x0220, b"\x78\x0b")
        device.write_sensor_register(0x0236, b"\xb9\x00")
        device.write_sensor_register(0x0238, b"\xb8\x00")
        device.write_sensor_register(0x023a, b"\xb7\x00")

        print(f"  [{i}] mcu_get_image...")
        encrypted = device.mcu_get_image(
            b"\x01\x00", goodix.FLAGS_TRANSPORT_LAYER_SECURITY)
        print(f"  [{i}] got {len(encrypted)} encrypted bytes "
              f"(flags=0x{encrypted[0] if encrypted else 0:02x})")

        if tls_server.poll() is not None:
            print(f"  [{i}] WARNING: s_server exited rc={tls_server.returncode}")
        try:
            tls_client.sendall(encrypted)
            print(f"{ts()}  [{i}] forwarded {len(encrypted)}B to s_server")
        except socket.timeout:
            print(f"{ts()}  [{i}] sendall timed out after 10s")
            break
        plaintext = read_with_timeout(tls_server.stdout, 6.0, want=7693)
        print(f"{ts()}  [{i}] decrypted: {len(plaintext)} bytes")

        if len(plaintext) < 7680:
            print(f"  [{i}] too short for an image -- blank/no-finger frame")
            continue

        # optimal offset 8 -> 7680B -> 80x64 12-bit
        payload = plaintext[8:8 + 7680]
        img = tool.decode_image(payload)
        if len(img) < 80 * 64:
            print(f"  [{i}] decode produced {len(img)} px (<5120)")
            continue
        img = img[:80 * 64]

        # quality metrics
        mean = sum(img) / len(img)
        hist = [0] * 8
        for v in img:
            hist[min(v * 8 // 4096, 7)] += 1
        hist_pct = [round(h * 100 / len(img), 1) for h in hist]
        print(f"  [{i}] mean={mean:.0f} hist%={hist_pct}")

        pgm = f"{out_prefix}_{i}.pgm"
        png = f"{out_prefix}_{i}.png"
        tool.write_pgm(img, 80, 64, pgm)
        try:
            from PIL import Image
            im = Image.new("L", (80, 64))
            im.putdata([v * 255 // 4095 for v in img])
            im.save(png)
            print(f"  [{i}] saved {pgm} + {png}")
        except Exception as e:
            print(f"  [{i}] png failed ({e}), pgm saved")

        time.sleep(1.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--psk", choices=["real", "zero"], default="real")
    ap.add_argument("--frames", type=int, default=1)
    ap.add_argument("--force-psk-write", action="store_true",
                    help="write the PSK blob even if the chip already has a PSK")
    ap.add_argument("--out", default="/tmp/5125_img")
    ap.add_argument("--wait-finger", type=float, default=0.0,
                    help="wait up to N seconds for a finger on the FDT register")
    args = ap.parse_args()

    psk = REAL_PSK if args.psk == "real" else ZERO_PSK
    print(f"=== 5125 image capture (PSK={'REAL' if args.psk=='real' else 'ZERO'}) ===")

    device = goodix.Device(0x5125, protocol.USBProtocol)
    print(f"{ts()} device opened")
    try:
        windows_initialization(device, write_psk=not args.force_psk_write)
        print(f"{ts()} init done")

        tls_server = subprocess.Popen(
            ["openssl", "s_server", "-nocert", "-psk", psk.hex(),
             "-port", "4433", "-quiet", "-cipher", "PSK-AES128-GCM-SHA256"],
            stdin=subprocess.PIPE,  # keep open: closes -> close_notify -> EOF
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        tls_client = socket.socket()
        try:
            for _ in range(20):
                try:
                    tls_client.connect(("localhost", 4433))
                    break
                except ConnectionRefusedError:
                    time.sleep(0.2)
            else:
                raise SystemExit("TLS server never came up")
            tls_client.settimeout(10.0)

            tool.connect_device(device, tls_client)
            print("TLS handshake relayed (bundled)")

            device.tls_successfully_established()  # post-handshake: DOES ack
            device.nop()
            state = device.query_mcu_state(b"\x55", True)
            print(f"mcu state: {state.hex()}")
            tls_connected = len(state) > 1 and (state[1] & 0x02) == 0x02
            if not tls_connected:
                print("WARNING: isTlsConnected flag not set (byte[1]&0x02)")

            capture_frames(device, tls_client, tls_server, args.frames,
                           args.out, wait_finger=args.wait_finger)
            print(f"{ts()} capture done")
        finally:
            tls_client.close()
            tls_server.terminate()
    finally:
        try:
            device.disconnect()
        except TimeoutError:
            print("note: disconnect timed out (known -- device stays connected)")
    print("=== done ===")


if __name__ == "__main__":
    main()
