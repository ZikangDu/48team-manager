"""Run the bundled GPTAuthBridge as a private child process of Team48.

The Bridge source lives in vendor/auth-bridge (MIT; see its LICENSE). Team48
starts it on a loopback port when the app starts, waits for /api/health, and
stops it on shutdown, so only 48team-manager has to be run. It is given its own
runtime directory under data/, never reads a .env of its own, and uses Team48's
Python environment for its curl_cffi / Playwright helpers.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import httpx
from app.core.proxy import normalize_proxy_url

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[3]
VENDOR_DIR = ROOT / "vendor" / "auth-bridge"
ENTRY = VENDOR_DIR / "server.js"
NODE_CANDIDATES = (
    os.environ.get("TEAM48_NODE", ""),
    str(Path.home() / ".local" / "bin" / "node"),
    "/opt/homebrew/bin/node",
    "/usr/local/bin/node",
)


class BridgeSupervisor:
    def __init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self._log = None
        self._proxy_origin = ""
        self._outbound_proxy = ""
        self.port: int | None = None
        self.state = "stopped"  # stopped | starting | running | external | failed | disabled
        self.reason = ""

    @staticmethod
    def find_node() -> str:
        for candidate in NODE_CANDIDATES:
            if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
                return candidate
        found = shutil.which("node")
        return found or ""

    @property
    def bundled(self) -> bool:
        return ENTRY.is_file() and (VENDOR_DIR / "node_modules").is_dir()

    async def _healthy(self, port: int, timeout: float = 2.0) -> bool:
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=timeout) as client:
                response = await client.get(f"http://127.0.0.1:{port}/api/health")
                data = response.json()
                return response.status_code == 200 and data.get("ok") is True and data.get("service") == "email-server"
        except Exception:
            return False

    async def start(
        self,
        *,
        port: int,
        runtime_dir: Path,
        python: str,
        proxy: str = "",
        yescaptcha_api_key: str = "",
        yescaptcha_api_base_url: str = "https://api.yescaptcha.com",
        turnstile_sitekey: str = "",
    ) -> str:
        """Start the bundled Bridge (or adopt a compatible one already on the port)."""
        self.port = port
        if await self._healthy(port):
            # Something compatible already answers here (for example a standalone install).
            self.state, self.reason = "external", "端口上已有兼容的授权桥，直接使用"
            return self.state
        if not self.bundled:
            self.state, self.reason = "failed", "未找到内置授权桥（vendor/auth-bridge）"
            return self.state
        node = self.find_node()
        if not node:
            self.state, self.reason = "failed", "未找到 Node.js 运行时；请安装 Node 22+ 或设置 TEAM48_NODE"
            return self.state
        runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", str(Path.home())),
            "HOST": "127.0.0.1",
            "PORT": str(port),
            "RUNTIME_DIR": str(runtime_dir),
            "PYTHON": python,
            "SKIP_DOTENV": "1",  # never read a .env from the vendored tree
            "PYTHONDONTWRITEBYTECODE": "1",
            "NODE_ENV": "production",
            # Login hardening as shipped in gpt-auth-bridge's own configuration. Without these the
            # official login validation fails (observed: VALIDATION_* on a known-good account).
            "AUTH_MODE": "rt",
            "PROTOCOL_HARDENING_ENABLED": "true",
            "PROTOCOL_RANDOM_FINGERPRINT": "true",
            "PROTOCOL_FINGERPRINT_REGION": "US",
            "PROTOCOL_HUMAN_PACING": "true",
            "TURNSTILE_BROWSER_FALLBACK": "true",
            "BROWSER_REUSE_ENABLED": "true",
            "BROWSER_RESIDENT_COUNT": "5",
            "BROWSER_REUSE_IDLE_MS": "60000",
            "BROWSER_REUSE_MAX_TASKS": "20",
            "TASK_CONCURRENCY": "10",
            "SESSION_RELOGIN_MAX_ATTEMPTS": "3",
            "CODEX_AGENT_VERSION": "0.145.0",
            "CODEX_AGENT_RUNNING_LOCATION": "cli-windows",
        }
        # Operator overrides: any TEAM48_BRIDGE_<NAME> variable is passed through as <NAME>.
        for key, value in os.environ.items():
            if key.startswith("TEAM48_BRIDGE_") and len(key) > len("TEAM48_BRIDGE_"):
                env[key[len("TEAM48_BRIDGE_"):]] = value
        if yescaptcha_api_key:
            env["YESCAPTCHA_API_KEY"] = yescaptcha_api_key
        if yescaptcha_api_base_url:
            env["YESCAPTCHA_API_BASE_URL"] = yescaptcha_api_base_url
        if turnstile_sitekey:
            env["OPENAI_TURNSTILE_SITEKEY"] = turnstile_sitekey
        if proxy:
            env["OPENAI_PROXY_URL"] = proxy
        # The workbench can honor a pinned account only on this exact managed exit.
        self._proxy_origin = f"http://{env['HOST']}:{env['PORT']}"
        self._outbound_proxy = env.get("OPENAI_PROXY_URL", "")
        self._log = open(runtime_dir / "bridge.log", "ab", buffering=0)
        self.state, self.reason = "starting", ""
        try:
            self._process = subprocess.Popen(
                [node, str(ENTRY)], cwd=str(VENDOR_DIR), env=env,
                stdin=subprocess.DEVNULL, stdout=self._log, stderr=subprocess.STDOUT,
                start_new_session=True,  # its own process group, so stop() reaches its python workers too
            )
        except OSError as exc:
            self.state, self.reason = "failed", f"授权桥无法启动：{exc.__class__.__name__}"
            return self.state
        for _ in range(60):  # up to ~30 s for the first start (browser pool warm-up)
            if self._process.poll() is not None:
                self.state, self.reason = "failed", f"授权桥启动后退出（代码 {self._process.returncode}），见 {runtime_dir / 'bridge.log'}"
                return self.state
            if await self._healthy(port, timeout=1.0):
                self.state = "running"
                logger.info("auth bridge running on 127.0.0.1:%s pid=%s", port, self._process.pid)
                return self.state
            await asyncio.sleep(0.5)
        self.state, self.reason = "failed", "授权桥启动超时"
        await self.stop()
        self.state = "failed"
        return self.state

    async def stop(self) -> None:
        self._proxy_origin = self._outbound_proxy = ""
        process, self._process = self._process, None
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                await asyncio.to_thread(process.wait, 15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                await asyncio.to_thread(process.wait, 5)
        if self._log is not None:
            self._log.close()
            self._log = None
        if self.state in {"running", "starting"}:
            self.state = "stopped"

    def summary(self) -> dict:
        return {"state": self.state, "port": self.port, "reason": self.reason,
                "pid": self._process.pid if self._process and self._process.poll() is None else None}

    def uses_fixed_proxy(self, origin: str, proxy: str) -> bool:
        if (self.state != "running" or self._process is None or self._process.poll() is not None
                or origin != self._proxy_origin or "://" not in self._outbound_proxy):
            return False
        try:
            return normalize_proxy_url(proxy) == normalize_proxy_url(self._outbound_proxy)
        except ValueError:
            return False


bridge_supervisor = BridgeSupervisor()


def team48_python() -> str:
    """Interpreter for the Bridge's curl_cffi / Playwright helpers.

    The bundled copy carries its own venv pinned to the exact versions it was
    validated with (Playwright must match the installed Chromium build). Falls
    back to the interpreter running Team48.
    """
    for candidate in (VENDOR_DIR / ".venv" / "bin" / "python", VENDOR_DIR / ".venv" / "Scripts" / "python.exe"):
        if candidate.is_file():
            return str(candidate)
    return sys.executable
