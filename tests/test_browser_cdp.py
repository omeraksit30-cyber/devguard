"""End-to-end headless Chrome CDP test: real mouse events, real file downloads, and local /docs."""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest
import uvicorn

from devguard import runner
from devguard.app import create_app
from devguard.config import load_settings

ROOT = Path(__file__).resolve().parent.parent
SECRETS = (Path(__file__).resolve().parent / "fixture_secrets.txt").read_text().split()


def find_chrome() -> str | None:
    mac_chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if mac_chrome.is_file():
        return str(mac_chrome)
    for name in ("google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CDPClient:
    """Minimal stdlib WebSocket client for Chrome DevTools Protocol."""

    def __init__(self, ws_url: str):
        rest = ws_url.removeprefix("ws://")
        host_port, path = rest.split("/", 1)
        host, port_s = host_port.split(":")
        self.sock = socket.create_connection((host, int(port_s)), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET /{path} HTTP/1.1\r\n"
            f"Host: {host_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("CDP handshake EOF")
            buf += chunk
        header, self._buf = buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in header.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"CDP handshake failed: {header!r}")
        self._next_id = 0
        self.events: list[dict] = []

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("CDP socket closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _recv_frame(self) -> str:
        b1, b2 = self._recv_exact(2)
        opcode = b1 & 0x0F
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        if b2 & 0x80:
            mask = self._recv_exact(4)
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(self._recv_exact(length)))
        else:
            payload = self._recv_exact(length)
        if opcode == 0x8:
            raise RuntimeError("CDP websocket closed")
        return payload.decode("utf-8", errors="replace")

    def _send_frame(self, text: str) -> None:
        data = text.encode("utf-8")
        mask = os.urandom(4)
        header = bytearray([0x81])
        n = len(data)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", n))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", n))
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(header + masked)

    def call(self, method: str, **params) -> dict:
        self._next_id += 1
        cid = self._next_id
        self._send_frame(json.dumps({"id": cid, "method": method, "params": params}))
        while True:
            msg = json.loads(self._recv_frame())
            if msg.get("id") == cid:
                if "error" in msg:
                    raise RuntimeError(f"CDP {method} error: {msg['error']}")
                return msg.get("result", {})
            self.events.append(msg)

    def eval(self, expr: str):
        res = self.call("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in res:
            raise RuntimeError(f"JS exception in {expr}: {res['exceptionDetails']}")
        return res.get("result", {}).get("value")

    def wait_for(self, js_predicate: str, timeout: float = 15.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            val = self.eval(js_predicate)
            if val:
                return val
            time.sleep(0.05)
        raise AssertionError(f"Timed out waiting for: {js_predicate}")

    def real_click(self, selector: str, text_contains: str | None = None) -> dict:
        js = f"""(() => {{
            const nodes = Array.from(document.querySelectorAll({json.dumps(selector)}));
            const needle = {json.dumps(text_contains)};
            const el = needle ? nodes.find(n => n.textContent.includes(needle)) : nodes[0];
            if (!el) return null;
            el.scrollIntoView({{block: 'center', inline: 'center'}});
            const r = el.getBoundingClientRect();
            const x = Math.round(r.left + r.width / 2);
            const y = Math.round(r.top + r.height / 2);
            const hit = document.elementFromPoint(x, y);
            const ok = hit === el || el.contains(hit) || (hit && hit.contains(el));
            return {{x, y, ok, tag: el.tagName, hitTag: hit ? hit.tagName : null}};
        }})()"""
        info = self.eval(js)
        assert info is not None, f"Element not found: {selector} ({text_contains})"
        assert info["ok"], f"Element covered at ({info['x']}, {info['y']}): {info}"
        x, y = info["x"], info["y"]
        self.call("Input.dispatchMouseEvent", type="mouseMoved", x=x, y=y)
        self.call("Input.dispatchMouseEvent", type="mousePressed", x=x, y=y, button="left", clickCount=1)
        self.call("Input.dispatchMouseEvent", type="mouseReleased", x=x, y=y, button="left", clickCount=1)
        return info

    def real_key(self, key: str, code: str, vk: int) -> None:
        self.call("Input.dispatchKeyEvent", type="rawKeyDown", key=key, code=code,
                  windowsVirtualKeyCode=vk, nativeVirtualKeyCode=vk)
        self.call("Input.dispatchKeyEvent", type="keyUp", key=key, code=code,
                  windowsVirtualKeyCode=vk, nativeVirtualKeyCode=vk)

    def real_type(self, selector: str, text: str) -> None:
        self.real_click(selector)
        self.eval(f"""(() => {{
            const el = document.querySelector({json.dumps(selector)});
            el.value = '';
            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
        }})()""")
        if text:
            self.call("Input.insertText", text=text)


@pytest.mark.integration
def test_browser_real_mouse_downloads_and_docs():
    chrome_bin = find_chrome()
    if not chrome_bin or not (runner.find_binary("trivy") and runner.find_binary("gitleaks")):
        pytest.skip("Chrome, Trivy, and Gitleaks are required")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        download_dir = tmp_path / "downloads"
        download_dir.mkdir()
        port = free_port()
        cdp_port = free_port()

        base_settings = load_settings(ROOT / "devguard.toml")
        settings = dataclasses.replace(base_settings, port=port, database=tmp_path / "e2e.db")
        app = create_app(settings)

        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()

        for _ in range(100):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                time.sleep(0.05)

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/evaluation/run",
            data=b"{}",
            headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            eval_id = json.loads(resp.read())["id"]
        for _ in range(300):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/evaluation/runs/{eval_id}") as resp:
                ev = json.loads(resp.read())
                if ev["status"] != "running":
                    assert ev["status"] == "passed", ev
                    break
            time.sleep(0.1)

        chrome = subprocess.Popen(
            [
                chrome_bin,
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={tmp_path / 'chrome-profile'}",
                f"--remote-debugging-port={cdp_port}",
                "--window-size=1440,900",
                f"http://127.0.0.1:{port}/",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            targets = None
            for _ in range(100):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json/list", timeout=1) as resp:
                        targets = [t for t in json.loads(resp.read()) if t.get("type") == "page"]
                        if targets:
                            break
                except Exception:
                    time.sleep(0.05)
            assert targets, "No Chrome page target found"

            cdp = CDPClient(targets[0]["webSocketDebuggerUrl"])
            cdp.call("Page.enable")
            cdp.call("Runtime.enable")
            cdp.call("Network.enable")
            cdp.call("Log.enable")
            cdp.call("Browser.setDownloadBehavior", behavior="allow", downloadPath=str(download_dir))

            # 1. Dashboard & New scan form via real mouse clicks
            cdp.wait_for("document.querySelector('h1')?.textContent === 'Dashboard'")
            assert cdp.eval("document.title") == "Dashboard — DevGuard"
            cdp.real_click('nav a[data-nav="new"]')
            cdp.wait_for("document.querySelector('h1')?.textContent === 'New scan'")

            # Unchecked #confirm blocks form submission on real click
            cdp.real_click('button[type="submit"]', "Start scan")
            time.sleep(0.1)
            assert cdp.eval("location.hash") == "#/scans/new"
            assert cdp.eval("!document.querySelector('#confirm').checkValidity()")

            # Check #confirm with real mouse click and test disallowed path
            cdp.real_click("#confirm")
            assert cdp.eval("document.querySelector('#confirm').checked") is True
            cdp.real_type("#target", "/etc")
            cdp.real_click('button[type="submit"]', "Start scan")
            cdp.wait_for("document.querySelector('.banner.error')?.textContent?.includes('allowed roots')")

            # 2. Navigate to Scan #1 and verify real file downloads to disk (JSON, Markdown, HTML)
            cdp.real_click('nav a[data-nav="dashboard"]')
            cdp.wait_for("document.querySelector('h1')?.textContent === 'Dashboard'")
            cdp.real_click('a[href="#/scans/1"]')
            cdp.wait_for("document.querySelector('h1')?.textContent?.startsWith('Scan #1')")
            cdp.wait_for("document.querySelectorAll('tbody tr').length >= 49")

            for ext, label in (("json", "JSON"), ("md", "Markdown"), ("html", "HTML")):
                cdp.real_click(f'a[href="/api/scans/1/export?format={ext}"]', label)
                target_file = download_dir / f"devguard-scan-1.{ext}"
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if target_file.exists() and target_file.stat().st_size > 0 and not list(download_dir.glob("*.crdownload")):
                        break
                    time.sleep(0.05)
                assert target_file.exists() and target_file.stat().st_size > 100
                raw = target_file.read_text()
                assert all(sec not in raw for sec in SECRETS)
                assert "DevGuard reports scanner observations, not proof that an application is secure." in raw

            # 3. Finding drawer, background inert, real Escape key, and auto-close on route change
            cdp.real_click('button[role="tab"]', "Secrets")
            cdp.wait_for("location.hash.includes('category=secret')")
            cdp.wait_for("document.querySelectorAll('.section tbody tr').length === 4")

            cdp.real_click(".section tbody button.linklike")
            cdp.wait_for("Boolean(document.querySelector('.drawer h2'))")
            assert cdp.eval("document.querySelector('main').inert === true")
            assert "Value redacted" in cdp.eval("document.querySelector('.drawer .banner.info')?.textContent")

            cdp.eval("""(() => {
                const s = document.querySelector('#triage-status');
                s.value = 'false_positive';
                s.dispatchEvent(new Event('change', { bubbles: true }));
            })()""")
            cdp.real_type("#triage-note", "real mouse triage test")
            cdp.real_click('.drawer button[type="submit"]', "Save")
            cdp.wait_for("document.querySelector('.drawer [role=\"status\"]')?.textContent === 'Saved.'")

            cdp.real_key("Escape", "Escape", 27)
            cdp.wait_for("!document.querySelector('.drawer')")
            assert cdp.eval("document.querySelector('main').inert === false")
            cdp.wait_for("document.querySelectorAll('.section tbody tr').length === 3")

            cdp.real_click("label", "Show false positives")
            cdp.wait_for("document.querySelectorAll('.section tbody tr.fp').length === 1")
            cdp.real_click(".section tbody tr.fp button.linklike")
            cdp.wait_for("Boolean(document.querySelector('.drawer h2'))")
            cdp.eval("""(() => {
                const s = document.querySelector('#triage-status');
                s.value = 'open';
                s.dispatchEvent(new Event('change', { bubbles: true }));
            })()""")
            cdp.real_type("#triage-note", "")
            cdp.real_click('.drawer button[type="submit"]', "Save")
            cdp.wait_for("document.querySelector('.drawer [role=\"status\"]')?.textContent === 'Saved.'")
            cdp.real_click('.drawer a[href="#/scans/2"]')
            cdp.wait_for("document.querySelector('h1')?.textContent?.startsWith('Scan #2')")
            assert not cdp.eval("Boolean(document.querySelector('.drawer'))")
            assert cdp.eval("document.querySelector('main').inert === false")

            # 4. History selection & Compare tabs via real mouse clicks
            cdp.real_click('nav a[data-nav="history"]')
            cdp.wait_for("document.querySelector('h1')?.textContent === 'History'")
            cdp.real_click('tbody tr:nth-child(1) input[type="checkbox"]')
            cdp.real_click('tbody tr:nth-child(2) input[type="checkbox"]')
            cdp.wait_for("!document.querySelector('.page-head button.btn.primary').disabled")
            cdp.real_click(".page-head button.btn.primary", "Compare selected (2/2)")
            cdp.wait_for("document.querySelector('h1')?.textContent === 'Compare scans'")
            cdp.real_click('button[role="tab"]', "Resolved")
            cdp.wait_for("document.querySelectorAll('tbody tr').length >= 49")

            # 5. Evaluation page & real download of Markdown evidence
            cdp.real_click('nav a[data-nav="evaluation"]')
            cdp.wait_for("document.querySelector('h1')?.textContent === 'Evaluation'")
            cdp.wait_for("document.querySelectorAll('.pass').length === 4")
            cdp.real_click('a[href="/api/evaluation/runs/1/export"]', "Export evidence (Markdown)")
            eval_md = download_dir / "devguard-evaluation-1.md"
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if eval_md.exists() and eval_md.stat().st_size > 0 and not list(download_dir.glob("*.crdownload")):
                    break
                time.sleep(0.05)
            assert eval_md.exists() and eval_md.stat().st_size > 100
            assert all(sec not in eval_md.read_text() for sec in SECRETS)

            # 6. Locally vendored /docs page renders all 16 operations without external CDN
            cdp.call("Page.navigate", url=f"http://127.0.0.1:{port}/docs")
            cdp.wait_for("document.querySelectorAll('.opblock').length === 16")

            # 7. Downloaded self-contained HTML report opens cleanly via file://
            html_file = download_dir / "devguard-scan-1.html"
            cdp.call("Page.navigate", url=html_file.as_uri())
            cdp.wait_for("document.querySelector('h1')?.textContent?.includes('DevGuard scan report #1')")
            assert cdp.eval("document.querySelectorAll('table').length >= 4")

            # 8. Zero external network requests and zero console/CSP errors
            bad_urls = []
            console_errors = []
            for ev in cdp.events:
                method = ev.get("method")
                if method == "Network.requestWillBeSent":
                    url = ev["params"]["request"]["url"]
                    if not (url.startswith(f"http://127.0.0.1:{port}/") or url.startswith("data:") or url.startswith("file://")):
                        bad_urls.append(url)
                elif method in ("Runtime.exceptionThrown", "Security.securityStateChanged"):
                    console_errors.append(ev)
                elif method == "Log.entryAdded" and ev["params"]["entry"].get("level") == "error":
                    entry = ev["params"]["entry"]
                    if entry.get("source") == "network" and entry.get("url", "").endswith("/api/scans") and "400" in entry.get("text", ""):
                        continue
                    console_errors.append(entry)
            assert not bad_urls, f"External requests detected: {bad_urls}"
            assert not console_errors, f"Console/CSP errors detected: {console_errors}"
        finally:
            chrome.kill()
            chrome.wait()
            server.should_exit = True
            thread.join(timeout=5)
