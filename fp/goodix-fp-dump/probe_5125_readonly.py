#!/usr/bin/env python3
"""READ-ONLY probe for Goodix 27c6:5125.

Safely extracts: firmware version, reset number, chip ID, OTP length, PSK.
No flashing, no writes to chip memory, no preset_psk_write.
"""
import sys
import usb.core
import usb.util

sys.path.insert(0, "/tmp/opencode/fp/goodix-fp-dump")
import goodix  # noqa: E402
import protocol  # noqa: E402


def init_device(product: int):
    dev = goodix.Device(product, protocol.USBProtocol)
    dev.nop()
    dev.enable_chip(True)
    dev.nop()
    return dev


def main():
    print("=== READ-ONLY probe of 27c6:5125 ===")
    # Sanity check device presence first
    usb_dev = usb.core.find(idVendor=0x27c6, idProduct=0x5125)
    if usb_dev is None:
        print("FATAL: device 27c6:5125 not found. Is it plugged in / unbound?")
        sys.exit(1)
    print(f"USB device found: bus={usb_dev.bus} addr={usb_dev.address}")

    device = init_device(0x5125)

    # 1. Firmware string
    try:
        fw = device.firmware_version()
        print(f"Firmware: {fw}")
    except Exception as e:
        print(f"firmware_version failed: {e}")

    # 2. Reset (sensor reset only, NOT soft MCU reset; read-only op)
    try:
        success, number = device.reset(True, False, 20)
        print(f"Reset: success={success} number={number}")
    except Exception as e:
        print(f"reset failed: {e}")

    # 3. Chip ID from sensor register 0x0000
    try:
        chip_id = device.read_sensor_register(0x0000, 4)
        print(f"Chip ID register: {chip_id.hex()}")
    except Exception as e:
        print(f"read_sensor_register failed: {e}")

    # 4. OTP read (read-only)
    try:
        otp = device.read_otp()
        print(f"OTP length: {len(otp)}")
        print(f"OTP hex: {otp.hex()}")
        if len(otp) >= 50:
            dac = (otp[46] << 4) | 8
            print(f"DAC bytes[46..49]: {otp[46]:02x} {otp[47]:02x} {otp[48]:02x} {otp[49]:02x}")
            print(f"Derived: 0x0220=0x{dac:04x} 0x0236=0x{otp[47]:04x} "
                  f"0x0238=0x{otp[48]:04x} 0x023a=0x{otp[49]:04x}")
    except Exception as e:
        print(f"read_otp failed: {e}")

    # 5. THE PRIZE: preset PSK read, flags 0xbb020003 (same as 51x7/5F10)
    try:
        success, flags, psk = device.preset_psk_read(0xbb020003)
        print(f"PSK read: success={success} flags=0x{flags:08x} len={len(psk) if psk else 0}")
        if psk:
            print(f"PSK: {psk.hex()}")
    except Exception as e:
        print(f"preset_psk_read failed: {e}")

    device.disconnect()
    print("=== done (nothing was written to the chip) ===")


if __name__ == "__main__":
    main()
