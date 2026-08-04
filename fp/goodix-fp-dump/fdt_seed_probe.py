#!/usr/bin/env python3
"""Probe: send different FDT manual seeds, observe chip's fdt base reply.

Goal: determine whether the chip's FDT base reply (bytes 4..15 of the
FDT manual reply) depends on the seed we send. WBDI's device returns real
calibration values (0x0147..0x017f); ours returns 0x01ff x6. If the reply
never changes, the chip's FDT calibration is missing/invalid and the seed
is irrelevant -- pointing at a missing init step instead.
"""
import sys
import time

sys.path.insert(0, "/tmp/opencode/fp/goodix-fp-dump")
import goodix  # noqa: E402
import protocol  # noqa: E402

SEEDS = {
    "avail5125": bytes([0x09, 0x01, 0xb3, 0xb3, 0xc3, 0xc3, 0xa8, 0xa8,
                        0xb5, 0xb5, 0xa8, 0xa8, 0xb7, 0xb7]),
    "wbdi":      bytes([0x09, 0x01, 0xaf, 0xaf, 0xbf, 0xbf, 0xa4, 0xa4,
                        0xb8, 0xb8, 0xa8, 0xa8, 0xb7, 0xb7]),
    "realpsk":   bytes([0x09, 0x01, 0xb2, 0xb2, 0xc2, 0xc2, 0xa7, 0xa7,
                        0xb6, 0xb6, 0xa6, 0xa6, 0xb6, 0xb6]),
    "zeros":     bytes([0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    "ones":      bytes([0x09, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    "derive":    bytes([0x09, 0x01, 0x80, 0xaf, 0x80, 0xbf, 0x80, 0xa3,
                        0x80, 0xb7, 0x80, 0xa7, 0x80, 0xb6]),
}


def main():
    print("=== FDT seed probe ===")
    device = goodix.Device(0x5125, protocol.USBProtocol)
    device.nop()
    device.enable_chip(True)
    device.nop()
    success, number = device.reset(True, False, 20)
    print(f"Reset: {success} {number}")

    for name, seed in SEEDS.items():
        try:
            reply = device.mcu_switch_to_fdt_mode(seed, True)
            base = reply[4:16].hex() if reply and len(reply) >= 16 else "?"
            print(f"seed={name:10s} reply_len={len(reply) if reply else 0} "
                  f"fdt_base(4..15)={base}")
        except Exception as e:
            print(f"seed={name:10s} FAILED: {type(e).__name__}: {e}")
            # maybe need reset between attempts
            try:
                device.reset(True, False, 20)
            except Exception:
                pass
        time.sleep(0.3)

    device.disconnect()
    print("=== done ===")


if __name__ == "__main__":
    main()
