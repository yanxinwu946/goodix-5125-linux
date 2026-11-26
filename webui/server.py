#!/usr/bin/env python3
"""Local web console for Goodix 5125 fingerprint enroll / manage / verify."""

import json
import queue
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 8899
ROOT = Path(__file__).parent
USER = "root"
STORAGE = Path("/var/lib/fprint") / USER

# fprintd/libfprint slot numbers used by the goodixtls5125 driver.
FINGER_BY_SLOT = {
    1: "left-thumb",
    2: "left-index-finger",
    3: "left-middle-finger",
    4: "left-ring-finger",
    5: "left-little-finger",
    6: "right-thumb",
    7: "right-index-finger",
    8: "right-middle-finger",
    9: "right-ring-finger",
    10: "right-little-finger",
}

FINGERS = {
    "right-index-finger": "右食指",
    "right-thumb": "右拇指",
    "right-middle-finger": "右中指",
    "right-ring-finger": "右无名指",
    "right-little-finger": "右小指",
    "left-index-finger": "左食指",
    "left-thumb": "左拇指",
    "left-middle-finger": "左中指",
    "left-ring-finger": "左无名指",
    "left-little-finger": "左小指",
}

clients: set[queue.Queue] = set()
lock = threading.Lock()
state = {
    "mode": "manage",
    "running": False,
    "op": None,
    "finger": None,
    "stage": 0,
    "total": 13,
    "message": "就绪",
    "detail": "",
    "prints": [],
    "verify_result": None,
    "log": [],
}
proc: subprocess.Popen | None = None


def broadcast(event: dict) -> None:
    for q in list(clients):
        try:
            q.put_nowait(event)
        except queue.Full:
            pass


def emit(kind: str, message: str, detail: str | None = None, **extra) -> None:
    with lock:
        state["message"] = message
        if detail is not None:
            state["detail"] = detail
        state["log"].append(
            {"time": time.strftime("%H:%M:%S"), "kind": kind, "text": message}
        )
        state["log"] = state["log"][-200:]
        state.update(extra)
        snapshot = dict(state)
    broadcast({"type": "status", "kind": kind, **snapshot})


def run(cmd: list[str]) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    return r.returncode, (r.stdout + r.stderr).strip()


def list_prints() -> list[dict]:
    """Read fprintd's storage directly.

    fprintd-list claims the device, which conflicts with enroll/verify and
    reports 'No devices available' while the console is using it.  The files
    under /var/lib/fprint/<user>/<driver>/<device>/ are the source of truth.
    """
    prints: list[dict] = []
    for path in STORAGE.glob("*/*/*"):
        if not path.is_file() or not path.name.isdigit():
            continue
        slot = int(path.name)
        finger = FINGER_BY_SLOT.get(slot)
        if not finger:
            continue
        prints.append(
            {
                "slot": slot,
                "finger": finger,
                "label": FINGERS.get(finger, finger),
            }
        )
    prints.sort(key=lambda p: p["slot"])
    with lock:
        state["prints"] = prints
    return prints


def viewer_kind(line: str) -> str:
    for k in ("enroll-stage-passed", "enroll-complete", "enroll-retry-scan",
              "enroll-too-fast", "enroll-low-quality", "enroll-discover",
              "failed to claim"):
        if k in line:
            return k
    return "info"


def handle_line(line: str, op: str) -> None:
    line = line.strip()
    if not line:
        return
    if op == "enroll":
        kind = viewer_kind(line)
        if kind == "enroll-stage-passed":
            with lock:
                state["stage"] += 1
                stage = state["stage"]
                total = state["total"]
            emit("ok", f"采集成功 {stage}/{total}", "很好，保持同一根手指，抬起后再按一次。")
        elif kind == "enroll-complete":
            emit("done", "录入完成", "指纹模板已保存。")
        elif kind == "enroll-retry-scan":
            emit("warn", "未采到指纹 · 请重试", "指腹盖住整个传感器，按住约 1 秒再抬起。")
        elif kind == "failed to claim":
            emit("error", "设备被占用或握手超时", "停止后重启 fprintd，再重新开始。")
        elif "Using device" in line:
            emit("info", "设备已找到", "Goodix TLS Fingerprint Sensor 27c6:5125")
        elif "Enrolling" in line:
            emit("info", "设备已就绪", "现在把手指平放在传感器上。")
        else:
            emit("info", line[:160])
    elif op == "verify":
        if "Verify started" in line:
            emit("info", "验证已启动", "请按已录入的手指。")
        elif "verify-match" in line:
            emit("done", "验证通过 ✅", "引擎匹配成功。", verify_result="match")
            with lock:
                state["running"] = False
        elif "verify-no-match" in line:
            emit("warn", "验证失败", "不是这根手指，或按压位置偏差太大。", verify_result="no-match")
            with lock:
                state["running"] = False
        elif "Verify result" in line:
            emit("info", line[:160])
        else:
            emit("info", line[:160])


def reader(p: subprocess.Popen, op: str) -> None:
    completed = False
    try:
        for raw in p.stdout:
            line = raw.strip()
            if not line:
                continue
            if op == "enroll" and "enroll-complete" in line:
                completed = True
            handle_line(line, op)
    finally:
        code = p.wait()
        with lock:
            state["running"] = False
            state["op"] = None
        if op == "enroll":
            list_prints()
            if completed and code == 0:
                label = FINGERS.get(state["finger"], state["finger"] or "")
                emit("done", f"录入完成 · {label}", "指纹模板已保存，可在「管理」里查看。")
            elif code != 0:
                emit("error", f"录入进程结束（退出码 {code}）", "可重新开始。")
        elif op == "verify" and code != 0:
            emit("error", f"验证进程结束（退出码 {code}）", "可重新验证。")


def launch(op: str, finger: str) -> None:
    global proc
    with lock:
        if state["running"]:
            return
        state["running"] = True
        state["op"] = op
        state["finger"] = finger
        state["stage"] = 0
        state["verify_result"] = None
        if op == "enroll":
            state["log"] = []
    cmd = (
        ["stdbuf", "-oL", "-eL", "fprintd-enroll", USER, finger]
        if op == "enroll"
        else ["stdbuf", "-oL", "-eL", "fprintd-verify", USER, finger]
    )
    label = FINGERS.get(finger, finger)
    emit("start", f"开始{'录入' if op == 'enroll' else '验证'} · {label}", "TLS 握手与引擎加载约需 1 秒。")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    threading.Thread(target=reader, args=(proc, op), daemon=True).start()


def stop() -> None:
    global proc
    with lock:
        state["running"] = False
        state["op"] = None
    if proc and proc.poll() is None:
        proc.terminate()
    emit("stop", "已停止", "设备已释放。")


def delete(finger: str) -> None:
    code, out = run(["fprintd-delete", USER, finger])
    list_prints()
    if code == 0:
        emit("done", f"已删除 {FINGERS.get(finger, finger)}", f"存储槽位已释放。")
    else:
        emit("error", "删除失败", out[:200])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: dict, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, (ROOT / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/state":
            list_prints()
            with lock:
                self._json(dict(state))
        elif path == "/prints":
            self._json({"prints": list_prints()})
        elif path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q: queue.Queue = queue.Queue(maxsize=100)
            clients.add(q)
            with lock:
                self.wfile.write(
                    f"data: {json.dumps({'type': 'status', **dict(state)}, ensure_ascii=False)}\n\n".encode()
                )
            try:
                while True:
                    try:
                        ev = q.get(timeout=15)
                        self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                clients.discard(q)
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", 0))
        body = {}
        if length:
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                pass
        finger = body.get("finger") or state["finger"] or "right-index-finger"
        if path == "/enroll":
            launch("enroll", finger)
        elif path == "/verify":
            launch("verify", finger)
        elif path == "/delete":
            delete(finger)
        elif path == "/stop":
            stop()
        elif path == "/refresh":
            list_prints()
            emit("info", "列表已刷新")
        else:
            self._send(404, b"not found", "text/plain")
            return
        self._json({"ok": True})


def print_watch() -> None:
    """Keep the UI in sync even when enrollment happens outside this console."""
    last: list[str] | None = None
    while True:
        prints = list_prints()
        signature = [p["finger"] for p in prints]
        if signature != last:
            last = signature
            broadcast({"type": "prints", "prints": prints})
        time.sleep(4)


if __name__ == "__main__":
    list_prints()
    threading.Thread(target=print_watch, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
