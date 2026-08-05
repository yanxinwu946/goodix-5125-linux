#!/usr/bin/env python3
"""READ-ONLY experiment v3: replicate WBDI gf_update_all_base step by step.

WBDI (working device) init after TLS:
  0xae query -> mcu state (isTlsConnected:1)
  3x FDT manual rounds (round0 seed from base file, then derived)
  nav (0x50) -> 3310B nav data
  setmode Image + 0x20 -> 10570B frame (NO finger pressed!)
  savebase to file

Ours returns 0x01ff x6 for FDT manual and times out on 0x20. This script
prints EVERY reply so we can see exactly where our chip diverges.
"""
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

COMMAND_ACK = 0xb0
COMMAND_UPLOAD_CONFIG_MCU = 0x90

# WBDI round-0 seed comes from the base file; we use WBDI's own file seed
# (afaf bfbf a4a4 b8b8 a8a8 b7b7) as well as avail5125's.
SEED_WBDI = bytes([0x09, 0x01, 0xaf, 0xaf, 0xbf, 0xbf, 0xa4, 0xa4,
                   0xb8, 0xb8, 0xa8, 0xa8, 0xb7, 0xb7])
SEED_AV = bytes([0x09, 0x01, 0xb3, 0xb3, 0xc3, 0xc3, 0xa8, 0xa8,
                 0xb5, 0xb5, 0xa8, 0xa8, 0xb7, 0xb7])


def upload_config_raw(device, raw: bytes) -> bool:
    device.protocol.write(raw)
    goodix.check_ack(
        goodix.check_message_protocol(
            goodix.check_message_pack(device.protocol.read()), COMMAND_ACK),
        COMMAND_UPLOAD_CONFIG_MCU)
    message = goodix.check_message_protocol(
        goodix.check_message_pack(device.protocol.read()),
        COMMAND_UPLOAD_CONFIG_MCU)
    return message[0] == 0x01


def fdt_construct_payload(first_reply: bytes, buf: bytearray) -> None:
    help_buf = first_reply + b"\x00" * 32
    for i in range(0, 12, 2):
        value = help_buf[4 + i] | (help_buf[5 + i] << 8)
        value >>= 1
        buf[2 + i] = 0x80
        buf[2 + i + 1] = value & 0xFF


def main():
    print("=== 5125 v3: WBDI gf_update_all_base replication ===")
    device = goodix.Device(0x5125, protocol.USBProtocol)
    device.nop()
    device.enable_chip(True)
    device.nop()
    print(f"Firmware: {device.firmware_version()}")
    success, number = device.reset(True, False, 20)
    print(f"Reset: {success} {number}")
    chip_id = device.read_sensor_register(0x0000, 4)
    print(f"Chip ID: {chip_id.hex()}")
    otp = device.read_otp()
    print(f"OTP len: {len(otp)}")
    success, number = device.reset(True, False, 20)
    print(f"Reset 2: {success} {number}")
    if not upload_config_raw(device, RAW_DEVICE_CONFIG):
        raise SystemExit("Config upload failed")
    print("Config uploaded")
    if not device.set_powerdown_scan_frequency(100):
        raise SystemExit("powerdown freq failed")
    print("powerdown freq set")

    # --- TLS: use s_server and CAPTURE its stderr to verify handshake ---
    tls_server = subprocess.Popen(
        ["openssl", "s_server", "-nocert", "-psk", REAL_PSK.hex(),
         "-port", "4433", "-quiet", "-cipher", "PSK-AES128-GCM-SHA256",
         "-tls1_2"],
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
        print("TLS proxy done")
        device.tls_successfully_established()
        print("tls_successfully_established")
        device.nop()

        # --- 0xae query: compare with WBDI 01023000003a00002000000000000000 ---
        st = device.query_mcu_state(b"\x55", True)
        print(f"0xae mcu state reply: {st.hex()} (len={len(st)})")
        time.sleep(0.2)

        # --- 3x FDT manual rounds (WBDI style) ---
        rounds = [("wbdiseed", SEED_WBDI)]
        for rnd, (name, seed) in enumerate(rounds):
            reply = device.mcu_switch_to_fdt_mode(seed, True)
            base = reply[4:16].hex() if reply and len(reply) >= 16 else "?"
            print(f"FDT manual r{rnd} ({name}) reply: {reply.hex() if reply else None} "
                  f"len={len(reply) if reply else 0} base={base}")
            if reply and len(reply) >= 16:
                second = bytearray(seed)
                fdt_construct_payload(reply, second)
                reply2 = device.mcu_switch_to_fdt_mode(bytes(second), True)
                base2 = reply2[4:16].hex() if reply2 and len(reply2) >= 16 else "?"
                print(f"FDT manual r{rnd}b (derived) reply: "
                      f"{reply2.hex() if reply2 else None} base={base2}")
                time.sleep(0.2)

        # --- nav (0x50): WBDI got 3310B, chicagoHUget_navdata 3200 ---
        print("--- nav ---")
        try:
            nav = device.nav()
            print(f"nav reply: {nav.hex() if nav else None} (len={len(nav) if nav else 0})")
            if nav and len(nav) > 16:
                print(f"nav first 32: {nav[:32].hex()}")
                print(f"nav non-zero count: {sum(1 for b in nav if b != 0)}")
        except Exception as e:
            print(f"nav FAILED: {type(e).__name__}: {e}")

        # --- setmode Image + 0x20 (WBDI got 10570B with NO finger) ---
        print("--- 0x20 (no finger expected) ---")
        try:
            device.mcu_get_image(b"\x01\x00", 0)
            print("0x20 returned OK")
        except Exception as e:
            print(f"0x20 FAILED: {type(e).__name__}: {e}")

    finally:
        tls_client.close()
        tls_server.terminate()
        try:
            tls_server.wait(timeout=3)
        except Exception:
            tls_server.kill()
        out = tls_server.stdout.read().decode(errors="replace") if tls_server.stdout else ""
        print("=== openssl s_server output ===")
        print(out[-3000:] if len(out) > 3000 else out)

    device.disconnect()
    print("=== done ===")


if __name__ == "__main__":
    main()
