#!/usr/bin/env python3
"""READ-ONLY experiment v2: 5125 image capture following avail5125's sequence.

Fixes over v1:
- Config upload: raw 256-byte send (already-framed buffer) -- WORKS now
- TLS with real PSK -- WORKS now
- Image capture: replicate avail5125 get_first_image:
  FDT switch x2 (2nd payload built from 1st reply) + prebulktransfer + MCU_GET_IMAGE
"""
import select
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/opencode/fp/goodix-fp-dump")
import goodix  # noqa: E402
import protocol  # noqa: E402
import tool  # noqa: E402

REAL_PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")
if os.environ.get("GOODIX_5125_PSK"):
    REAL_PSK = bytes.fromhex(os.environ["GOODIX_5125_PSK"])

RAW_DEVICE_CONFIG = bytes.fromhex(
    "a0e4008490e1007011748500852cb118c914dd00dd00dd00ba000180ca000400840015b3860000"
    "c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000b6980000009a0000"
    "00d2000000d4000000d6000000d800000050000105d0000000700000007200785674003412200010"
    "405c0000012002480b3602b6003802b4003a02b4002a0182032200012024001400800001005c0000"
    "01560004205800030232000c02660003007c0000588200801f2a0108005400100162000403640019"
    "00660003007c0000582a0108005200080054000001660003007c000058004f538f32000c02660003"
    "007c0000588200801f2a01080054001001")

FDT_MODE_BUF = bytes([0x09, 0x01, 0xb3, 0xb3, 0xc3, 0xc3, 0xa8, 0xa8,
                      0xb5, 0xb5, 0xa8, 0xa8, 0xb7, 0xb7])

COMMAND_ACK = 0xb0
COMMAND_UPLOAD_CONFIG_MCU = 0x90


def upload_config_raw(device, raw: bytes) -> bool:
    device.protocol.write(raw)
    goodix.check_ack(
        goodix.check_message_protocol(
            goodix.check_message_pack(device.protocol.read()), COMMAND_ACK),
        COMMAND_UPLOAD_CONFIG_MCU)
    message = goodix.check_message_protocol(
        goodix.check_message_pack(device.protocol.read()),
        COMMAND_UPLOAD_CONFIG_MCU)
    if len(message) < 1:
        raise SystemError("Invalid response length")
    return message[0] == 0x01


def fdt_construct_payload(first_reply: bytes, buf: bytearray) -> None:
    """C: fdt_mode_construct_payload(BUF+2, HELP+11, 12).

    HELP is the RAW USB reply (4B msgpack hdr + 3B proto hdr + data).
    Python reply1 = check_message_protocol(...) = data only.
    So HELP[11+i] == data[4+i].
    """
    help_buf = first_reply + b"\x00" * 32
    for i in range(0, 12, 2):
        value = help_buf[4 + i] | (help_buf[5 + i] << 8)
        value >>= 1
        buf[2 + i] = 0x80
        buf[2 + i + 1] = value & 0xFF


def prebulktransfer(device) -> None:
    try:
        device.protocol.device.read(device.protocol.endpoint_in, 1, timeout=500)
    except Exception:
        pass


def read_with_timeout(stream, timeout_s: float):
    chunks = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        r, _, _ = select.select([stream], [], [], 0.5)
        if r:
            data = stream.read(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def main():
    print("=== 5125 v2: avail5125-style capture, real PSK ===")
    device = goodix.Device(0x5125, protocol.USBProtocol)
    device.nop()
    device.enable_chip(True)
    device.nop()

    print(f"Firmware: {device.firmware_version()}")

    success, number = device.reset(True, False, 20)
    print(f"Reset: {success} {number}")
    if not success or number != 2048:
        raise SystemExit("bad reset")

    chip_id = device.read_sensor_register(0x0000, 4)
    print(f"Chip ID: {chip_id.hex()}")
    if chip_id != b"\xa2\x04\x25\x00":
        raise SystemExit("bad chip id")

    otp = device.read_otp()
    print(f"OTP len: {len(otp)}")

    success, number = device.reset(True, False, 20)
    print(f"Reset 2: {success} {number}")

    if not upload_config_raw(device, RAW_DEVICE_CONFIG):
        raise SystemExit("Config upload failed")
    print("Config uploaded (raw 256B)")

    if not device.set_powerdown_scan_frequency(100):
        raise SystemExit("powerdown freq failed")

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

        tool.connect_device(device, tls_client)
        print("TLS handshake relayed")

        device.tls_successfully_established()
        print("tls_successfully_established")

        device.nop()

        device.query_mcu_state(b"\x55", True)
        print("mcu state queried")

        # ---- avail5125 get_first_image: FDT switch x2 ----
        reply1 = device.mcu_switch_to_fdt_mode(FDT_MODE_BUF, True)
        print(f"FDT switch 1 reply: {reply1[:24].hex()} (len={len(reply1)})")

        second = bytearray(FDT_MODE_BUF)
        fdt_construct_payload(reply1, second)
        print(f"FDT switch 2 payload: {bytes(second).hex()}")

        reply2 = device.mcu_switch_to_fdt_mode(bytes(second), True)
        print(f"FDT switch 2 reply: {reply2[:24].hex() if reply2 else None}")

        prebulktransfer(device)
        print("prebulktransfer done")

        print("Requesting image (TLS-encrypted)...")
        encrypted_image = device.mcu_get_image(
            b"\x01\x00", goodix.FLAGS_TRANSPORT_LAYER_SECURITY)
        print(f"Got {len(encrypted_image)} encrypted bytes")

        tls_client.sendall(encrypted_image)
        print("Forwarded to TLS server, reading decrypted...")

        output_image = read_with_timeout(tls_server.stdout, 10.0)
        print(f"Decrypted stream: {len(output_image)} bytes")

        if len(output_image) >= 13:
            payload = output_image[8:-5]
            print(f"Image payload: {len(payload)} bytes")
            try:
                img = tool.decode_image(payload)
                tool.write_pgm(img, 80, 88, "/tmp/opencode/fp/fingerprint.pgm")
                print("PGM written: /tmp/opencode/fp/fingerprint.pgm")
            except Exception as e:
                print(f"decode failed: {e}")
        else:
            print("Not enough decrypted data")
    finally:
        tls_client.close()
        tls_server.terminate()

    device.disconnect()
    print("=== done (nothing written to chip) ===")


if __name__ == "__main__":
    main()
