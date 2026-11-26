#!/usr/bin/env bash
# One-shot installer for the working Goodix 27c6:5125 setup on Debian/Kali.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR=/usr/lib64/libfprint-2/goodix5125
DLL="$ENGINE_DIR/AlgoChicago.dll"
CAB_URL='https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2022/05/5f2cfe33-8430-4d88-a654-de241785f4dd_3032d6cda11d2be4d1a2f1fee770db85fe60442e.cab'
CAB_SHA1='3032d6cda11d2be4d1a2f1fee770db85fe60442e'
TMP="$(mktemp -d /tmp/opencode/goodix5125-engine.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0" >&2
  exit 1
fi

echo "[1/5] Installing build dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential meson ninja-build pkg-config git \
  libusb-1.0-0-dev libglib2.0-dev libgudev-1.0-dev cabextract curl python3

if [[ -f "$SRC/.gitmodules" ]]; then
  echo "Initializing/updating driver submodule to latest upstream"
  git -C "$SRC" submodule update --init --recursive --remote
fi

echo "[2/5] Building libfprint + goodixtls5125 from driver/"
cd "$SRC/driver"
meson setup build --wipe \
  -Ddrivers=goodixtls5125 \
  -Dudev_hwdb_dir=/usr/lib/udev/hwdb.d \
  -Ddoc=false
meson compile -C build
meson install -C build

# A stale backup .so in the library path can outrank the real library.
find /usr/local/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu \
  -maxdepth 1 -type f -name 'libfprint-2.so.*backup*' -print -delete 2>/dev/null || true
ldconfig

echo "[3/5] Installing Goodix matching engine"
mkdir -p "$ENGINE_DIR"
if [[ ! -f "$DLL" ]]; then
  curl -fL --retry 3 -o "$TMP/goodix.cab" "$CAB_URL"
  echo "$CAB_SHA1  $TMP/goodix.cab" | sha1sum -c -
  mkdir -p "$TMP/extracted"
  cabextract -L -q -d "$TMP/extracted" "$TMP/goodix.cab"
  FOUND="$(find "$TMP/extracted" -type f -iname 'AlgoChicago.dll' -print -quit)"
  [[ -n "$FOUND" ]] || { echo "AlgoChicago.dll not found in CAB" >&2; exit 1; }
  install -m 0644 "$FOUND" "$DLL"
fi
echo "Engine: $DLL"

echo "[4/5] Configuring fprintd"
install -d /etc/systemd/system/fprintd.service.d
install -m 0644 "$SRC/config/goodix5125-engine.conf" \
  /etc/systemd/system/fprintd.service.d/goodix5125-engine.conf
systemctl daemon-reload
systemctl restart fprintd

echo "[5/5] Installing web console"
install -d /opt/goodix5125
install -m 0755 "$SRC/start-webui.sh" /opt/goodix5125/start-webui.sh
install -m 0644 "$SRC/webui/server.py" /opt/goodix5125/server.py
install -m 0644 "$SRC/webui/index.html" /opt/goodix5125/index.html
install -m 0644 "$SRC/desktop/Fingerprint Console.desktop" \
  /usr/share/applications/fingerprint-console.desktop
if [[ -d /root/Desktop ]]; then
  install -m 0644 "$SRC/desktop/Fingerprint Console.desktop" \
    '/root/Desktop/Fingerprint Console.desktop'
fi

echo
echo "Done. Open 'Fingerprint Console' on the desktop, or run /opt/goodix5125/start-webui.sh"
echo "Check with: journalctl -u fprintd -f"
