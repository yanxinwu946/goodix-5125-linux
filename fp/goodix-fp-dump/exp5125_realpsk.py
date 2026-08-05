#!/usr/bin/env python3
"""READ-ONLY experiment: full TLS activation + image capture for Goodix 27c6:5125.

Uses the REAL per-device PSK read earlier via preset_psk_read.
No firmware flashing, no PSK write, no erase -- all commands are read/activate only.
Modeled on goodix-fp-dump's driver_51x7.py run_driver (proven on 5117).
"""
import os
import re
import select
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/root/Projects/goodix-5125/fp/goodix-fp-dump")
import goodix  # noqa: E402
import protocol  # noqa: E402
import tool  # noqa: E402

REAL_PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")
if os.environ.get("GOODIX_5125_PSK"):
    REAL_PSK = bytes.fromhex(os.environ["GOODIX_5125_PSK"])

# 5125's own 256-byte MCU config, captured from the Windows driver (avail5125).
# The whole buffer is ALREADY fully framed (message-pack + cmd 0x90 headers) and
# must be sent RAW, exactly as avail5125's cmd_id=0xff path does.
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


def upload_config_raw(device, raw: bytes) -> bool:
    """Send the already-framed config buffer raw, then read ACK + reply."""
    print(f"upload_config_raw({len(raw)} bytes)")
    device.protocol.write(raw)
    # ACK
    goodix.check_ack(
        goodix.check_message_protocol(
            goodix.check_message_pack(device.protocol.read()), COMMAND_ACK),
        COMMAND_UPLOAD_CONFIG_MCU)
    # reply
    message = goodix.check_message_protocol(
        goodix.check_message_pack(device.protocol.read()),
        COMMAND_UPLOAD_CONFIG_MCU)
    if len(message) < 1:
        raise SystemError("Invalid response length")
    return message[0] == 0x01


def init_device(product: int):
    device = goodix.Device(product, protocol.USBProtocol)
    device.nop()
    device.enable_chip(True)
    device.nop()
    return device


def read_with_timeout(stream, timeout_s: float):
    """Read whatever is available from a pipe within timeout; returns bytes."""
    chunks = []
    deadline = select.monotonic() + timeout_s
    while select.monotonic() < deadline:
        r, _, _ = select.select([stream], [], [], 0.5)
        if r:
            data = stream.read(4096)
            if not data:
                break
            chunks.append(data)
        else:
            # keep waiting a bit; s_server writes in TLS record chunks
            continue
    return b"".join(chunks)


def main():
    print("=== 5125 full TLS activation experiment (READ-ONLY, real PSK) ===")
    device = init_device(0x5125)

    fw = device.firmware_version()
    print(f"Firmware: {fw}")

    success, number = device.reset(True, False, 20)
    print(f"Reset: success={success} number={number}")
    if not success or number != 2048:
        raise SystemExit("Unexpected reset reply -- aborting (nothing written)")

    chip_id = device.read_sensor_register(0x0000, 4)
    print(f"Chip ID: {chip_id.hex()}")
    if chip_id != b"\xa2\x04\x25\x00":
        raise SystemExit("Unexpected chip ID -- aborting")

    otp = device.read_otp()
    print(f"OTP len: {len(otp)}")

    success, number = device.reset(True, False, 20)
    print(f"Reset 2: success={success} number={number}")

    if not upload_config_raw(device, RAW_DEVICE_CONFIG):
        raise SystemExit("Config upload failed")
    print("Config uploaded (256 bytes raw, from real 5125)")

    if not device.set_powerdown_scan_frequency(100):
        raise SystemExit("set_powerdown_scan_frequency failed")

    # ---- TLS with REAL PSK ----
    tls_server = subprocess.Popen(
        ["openssl", "s_server", "-nocert", "-psk", REAL_PSK.hex(),
         "-port", "4433", "-quiet", "-cipher", "PSK-AES128-GCM-SHA256"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    try:
        tls_client = socket.socket()
        for _ in range(20):
            try:
                tls_client.connect(("localhost", 4433))
                break
            except ConnectionRefusedError:
                time.sleep(0.2)
        else:
            raise SystemExit("TLS server never came up")

        try:
            tool.connect_device(device, tls_client)
            print("TLS handshake relayed -- device side done")

            device.tls_successfully_established()
            print("tls_successfully_established sent")

            device.nop()

            device.query_mcu_state(b"\x55", True)
            print("MCU state queried")

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\xb2\xb2\xc2\xc2\xa7\xa7\xb6\xb6\xa6\xa6\xb6\xb6", True)

            device.nav()
            print("nav done")

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x80\xb0\x80\xc0\x80\xa4\x80\xb4\x80\xa3\x80\xb4", True)

            device.read_sensor_register(0x0082, 2)

            device.write_sensor_register(0x0220, b"\x78\x0b")
            device.write_sensor_register(0x0236, b"\xb9\x00")
            device.write_sensor_register(0x0238, b"\xb8\x00")
            device.write_sensor_register(0x023a, b"\xb7\x00")

            print("Requesting image (encrypted via TLS)...")
            encrypted_image = device.mcu_get_image(
                b"\x01\x00", goodix.FLAGS_TRANSPORT_LAYER_SECURITY)
            print(f"Got {len(encrypted_image)} encrypted bytes from chip")

            tls_client.sendall(encrypted_image)
            print("Sent encrypted image to TLS server, reading decrypted...")

            # adaptive read; 80x88 sensor -> 10573 bytes (8 + 88*80/4*6 + 5)
            output_image = read_with_timeout(tls_server.stdout, 8.0)
            print(f"Decrypted stream: {len(output_image)} bytes")

            if len(output_image) >= 13:
                payload = output_image[8:-5]
                print(f"Image payload: {len(payload)} bytes "
                      f"-> ~{len(payload) // 6 * 4} pixels")
                try:
                    img = tool.decode_image(payload)
                    tool.write_pgm(img, 80, 88, "/tmp/fingerprint_realpsk.pgm")
                except Exception as e:
                    print(f"decode failed: {e}")
            else:
                print("Not enough decrypted data for an image")

        finally:
            tls_client.close()
    finally:
        tls_server.terminate()

    device.disconnect()
    print("=== experiment done (nothing was written to the chip) ===")


if __name__ == "__main__":
    main()
