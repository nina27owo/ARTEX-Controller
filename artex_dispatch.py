#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARTEX 任务下发工具（SSH 隧道，无需对公网开放端口）

流程
----
1. ↑/↓ 选**一台**主机 → 输入该机 SSH 密码（不落盘，本次运行内记住）
2. 选 LLM（默认 OpenRouter DeepSeek V4.1 Flash 1017）
3. 输入要渗透的名称或网址（同时作为任务名称）
   描述自动生成为「渗透<名称>源站及其子站」，目标固定用 config.toml 的 goal
   再填任务时长上限（默认 600 分钟）
4. 确认后下发，打印任务 id / 状态
5. 下发完选：继续下发这台机器（不用再输密码）/ 使用别的机器

用法
----
    python artex_dispatch.py                                   # 交互下发
    python artex_dispatch.py -m 192.0.2.10                  # 跳过选主机
    python artex_dispatch.py -m 1.2.3.4 -n example.com -T 600 --yes
    python artex_dispatch.py -m 192.0.2.10 --self-test      # 通道自检（自动清理）
    python artex_dispatch.py --cleanup-test                    # 清理测试任务

依赖：pip install paramiko ；读取 config.toml 需要 Python >= 3.11
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import select
import socket
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

try:
    import paramiko
except ImportError:
    print("缺少依赖 paramiko，请先执行:  pip install paramiko")
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "config.toml")


# --------------------------------------------------------------------------
# 终端交互
# --------------------------------------------------------------------------

def _init_console():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
        except Exception:
            pass
    global _COLOR
    try:
        _COLOR = sys.stdout.isatty() and not _fake_mode()
    except Exception:
        _COLOR = False
    if _COLOR:
        sys.stdout = _ColorStdout(sys.stdout)


_COLOR = False


class _ColorStdout:
    """把 ✓ / ✗ 自动上色（仅终端；重定向/管道时保持纯文本）。"""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        if _COLOR and text:
            text = text.replace("✓", "\x1b[32m✓\x1b[0m").replace("✗", "\x1b[31m✗\x1b[0m")
        return self._stream.write(text)

    def __getattr__(self, name):
        return getattr(self._stream, name)


def c(text, code):
    """ANSI 上色；非终端自动降级为纯文本。"""
    return "\x1b[%sm%s\x1b[0m" % (code, text) if _COLOR else str(text)


def hr(width=54):
    print(c("─" * width, "2"))


def heading(text):
    print()
    print(c(text, "1;36"))


_FAKE_KEYS = []
_FAKE_MODE = None


def _fake_mode():
    """测试用：ARTEX_DISPATCH_KEYS="down,down,space,enter" 可脚本化驱动菜单。"""
    global _FAKE_KEYS, _FAKE_MODE
    if _FAKE_MODE is None:
        raw = os.environ.get("ARTEX_DISPATCH_KEYS", "")
        _FAKE_MODE = bool(raw)
        if raw:
            _FAKE_KEYS = [k.strip() for k in raw.split(",") if k.strip()]
    return _FAKE_MODE


def read_key() -> str:
    """读一个键：up/down/left/right/enter/space/esc/字符。"""
    if _fake_mode():
        return _FAKE_KEYS.pop(0) if _FAKE_KEYS else "enter"
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            ch2 = msvcrt.getch()
            return {b"H": "up", b"P": "down", b"K": "left", b"M": "right"}.get(ch2, "")
        if ch in (b"\r", b"\n"):
            return "enter"
        if ch == b" ":
            return "space"
        if ch == b"\x1b":
            return "esc"
        try:
            return ch.decode("utf-8", "ignore").lower()
        except Exception:
            return ""
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            rest = sys.stdin.read(2)
            return {"[A": "up", "[B": "down", "[C": "right", "[D": "left"}.get(rest, "")
        if ch in ("\r", "\n"):
            return "enter"
        if ch == " ":
            return "space"
        return ch.lower()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


class Screen:
    """原地重画若干行。"""

    def __init__(self):
        self.lines = 0

    def draw(self, lines):
        sys.stdout.write("".join("\x1b[2K" + ln + "\n" for ln in lines))
        sys.stdout.flush()
        self.lines = len(lines)

    def clear(self):
        if not self.lines:
            return
        sys.stdout.write("\x1b[%dA" % self.lines)
        sys.stdout.write("".join("\x1b[2K\n" for _ in range(self.lines)))
        sys.stdout.write("\x1b[%dA" % self.lines)
        sys.stdout.flush()
        self.lines = 0


def _tty_ok() -> bool:
    return _fake_mode() or (sys.stdin.isatty() and sys.stdout.isatty())


def _input(prompt):
    try:
        return input(prompt)
    except EOFError:
        return ""


def select_one(title, rows, default=0, hint="↑/↓ 移动 · 回车 选择 · q 退出"):
    """单选，返回下标。"""
    if len(rows) == 1:
        return 0
    if not _tty_ok():
        print(title)
        for i, r in enumerate(rows, 1):
            print("  %2d) %s" % (i, r))
        raw = _input("输入编号: ").strip()
        return (int(raw) - 1) if raw.isdigit() and 1 <= int(raw) <= len(rows) else default

    idx, sc = default, Screen()
    print(c(title, "1;36"))
    print("  " + c(hint, "2"))
    while True:
        lines = [" %s %s" % (c("❯", "1;36") if i == idx else " ", r)
                 for i, r in enumerate(rows)]
        sc.draw(lines)
        k = read_key()
        sc.clear()
        if k == "up":
            idx = (idx - 1) % len(rows)
        elif k == "down":
            idx = (idx + 1) % len(rows)
        elif k == "enter":
            return idx
        elif k == "q":
            print("已退出")
            sys.exit(0)


def pick_machine(cfg):
    rows = ["%-16s %s" % (m["ip"], m.get("label", "")) for m in cfg["machines"]]
    return cfg["machines"][select_one("选择目标主机", rows, 0)]


def ask(prompt, default=""):
    val = _input("%s: " % prompt).strip()
    return val or default


def ask_password(prompt):
    """明文输入密码（不回显屏蔽，方便直接粘贴）。"""
    return _input(prompt).strip()


# --------------------------------------------------------------------------
# SSH 本地端口转发（等价 ssh -L）
# --------------------------------------------------------------------------

class _ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class SSHTunnel:
    def __init__(self, host, user, password, remote_port=8787, port=22,
                 remote_host="127.0.0.1", timeout=20):
        self.host, self.port, self.user = host, port, user
        self.password = password
        self.remote_host, self.remote_port = remote_host, remote_port
        self.timeout = timeout
        self.transport = None
        self.server = None
        self.local_port = None

    def start(self):
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        tr = paramiko.Transport(sock)
        tr.banner_timeout = self.timeout
        tr.auth_timeout = self.timeout
        tr.connect(username=self.user, password=self.password)
        self.transport = tr
        tunnel = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    chan = tunnel.transport.open_channel(
                        "direct-tcpip",
                        (tunnel.remote_host, tunnel.remote_port),
                        self.request.getpeername())
                except Exception:
                    return
                if chan is None:
                    return
                try:
                    while True:
                        r, _, _ = select.select([self.request, chan], [], [], 0.0)
                        if self.request in r:
                            data = self.request.recv(8192)
                            if not data:
                                break
                            chan.sendall(data)
                        if chan in r:
                            data = chan.recv(8192)
                            if not data:
                                break
                            self.request.sendall(data)
                except Exception:
                    pass
                finally:
                    for x in (chan, self.request):
                        try:
                            x.close()
                        except Exception:
                            pass

        self.server = _ForwardServer(("127.0.0.1", 0), Handler)
        self.local_port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self.local_port

    def stop(self):
        try:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
        except Exception:
            pass
        try:
            if self.transport:
                self.transport.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# ARTEX API
# --------------------------------------------------------------------------

class ArtexClient:
    def __init__(self, base, user, password):
        self.base = base.rstrip("/")
        self.user, self.password = user, password
        self.token = None

    def _req(self, method, path, body=None, timeout=60):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", "replace")
                return r.status, (json.loads(raw) if raw.strip() else {})
        except urllib.error.HTTPError as e:
            return e.code, {"error": e.read().decode("utf-8", "replace")[:600]}
        except Exception as e:
            return -1, {"error": "%s: %s" % (type(e).__name__, e)}

    def login(self):
        st, res = self._req("POST", "/api/auth/login",
                            {"username": self.user, "password": self.password})
        self.token = (res or {}).get("token")
        if not self.token:
            raise RuntimeError("登录失败 (HTTP %s): %s" % (st, res))
        return self.token

    def profiles(self):
        return self._req("GET", "/api/llm/profiles")[1].get("profiles") or []

    def tasks(self):
        return self._req("GET", "/api/tasks")[1].get("tasks") or []

    def create_task(self, **payload):
        return self._req("POST", "/api/tasks", payload, timeout=90)

    def get_task(self, tid):
        return self._req("GET", "/api/tasks/%s" % tid, timeout=30)

    def delete_task(self, tid):
        return self._req("DELETE", "/api/tasks/%s" % tid, timeout=180)


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------

def load_config(path):
    if tomllib is None:
        print("需要 Python 3.11+ 才能读 config.toml（当前 %s）" % sys.version.split()[0])
        sys.exit(1)
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    machines = cfg.get("machines") or []
    if not machines:
        print("config.toml 里没有配置任何主机")
        sys.exit(1)
    for m in machines:
        m.setdefault("port", 22)
        m.setdefault("user", "root")
        m.setdefault("label", "")
    cfg.setdefault("defaults", {})
    cfg.setdefault("llm", [])
    return cfg


def pick_llm(cfg, key=None):
    wanted = key or cfg["defaults"].get("llm")
    for item in cfg["llm"]:
        if item.get("key") == wanted:
            return item
    return cfg["llm"][0] if cfg["llm"] else {"key": "default"}


def resolve_profile_id(client, llm_cfg):
    """把配置里的 llm 项映射为目标机器上的 llm_profile_id。"""
    profiles = client.profiles()
    if not profiles:
        raise RuntimeError("该主机没有任何 LLM 配置")
    match = (llm_cfg or {}).get("model_match", "")
    for p in profiles:
        if match and match.lower() in (p.get("model") or "").lower():
            return int(p["id"]), p
    for p in profiles:
        if p.get("is_default"):
            return int(p["id"]), p
    return int(profiles[0]["id"]), profiles[0]


# --------------------------------------------------------------------------
# 业务动作
# --------------------------------------------------------------------------

class AuthError(Exception):
    """SSH 认证失败（密码 / 用户名不对）"""


class ConnectError(Exception):
    """SSH 连不上（网络 / 端口 / 握手 / ARTEX 登录）"""


def connect(machine, cfg, password):
    d = cfg["defaults"]
    tunnel = SSHTunnel(machine["ip"], machine["user"], password,
                       remote_port=int(d.get("artex_port", 8787)),
                       port=int(machine.get("port", 22)))
    try:
        tunnel.start()
    except paramiko.AuthenticationException:
        tunnel.stop()
        raise AuthError("SSH 认证失败：密码错误，或该主机不允许 root 用密码登录")
    except (socket.timeout, TimeoutError):
        tunnel.stop()
        raise ConnectError("SSH 连接超时：检查 IP / 22 端口 / 网络")
    except (paramiko.SSHException, OSError) as e:
        tunnel.stop()
        raise ConnectError("SSH 连接失败：%s" % e)
    client = ArtexClient("http://127.0.0.1:%d" % tunnel.local_port,
                         d.get("login_user", "ARTEX"),
                         d.get("login_password", ""))
    try:
        client.login()
    except Exception as e:
        tunnel.stop()
        raise ConnectError("ARTEX 登录失败（检查 config.toml 的 login_password）：%s" % e)
    return tunnel, client


def connect_or_report(machine, cfg, password):
    """连不上就打印原因并返回 (None, None)，不抛异常。"""
    try:
        return connect(machine, cfg, password)
    except (AuthError, ConnectError) as e:
        print("  ✗ %s" % e)
    except Exception as e:
        print("  ✗ 连接异常：%s: %s" % (type(e).__name__, e))
    return None, None


def build_payload(cfg, name, desc, goal, profile_id, timeout_min):
    d = cfg["defaults"]
    if not str(name).strip():
        name = "任务-" + _dt.datetime.now().strftime("%m%d-%H%M")
    return {
        "name": name.strip(),
        "description": desc,
        "goal": goal,
        "llm_profile_ids": [profile_id],
        "timeout_seconds": int(timeout_min) * 60,
        "plan_heartbeat_seconds": int(d.get("plan_heartbeat_minutes", 10)) * 60,
        "coverage_enabled": bool(d.get("coverage_enabled", True)),
        "seed_first_intent": bool(d.get("seed_first_intent", False)),
    }


def dispatch_one(machine, cfg, password, name, desc, goal, llm_cfg, timeout_min):
    """下发一个任务。返回 (ip, task_id, status, err)，err ∈ None/'auth'/'conn'/'http'。"""
    ip = machine["ip"]
    print()

    # 连接（认证失败可重输密码，最多 3 次）
    tunnel = client = None
    for attempt in range(1, 4):
        try:
            tunnel, client = connect(machine, cfg, password)
            break
        except AuthError as e:
            print("  ✗ %s" % e)
            if attempt >= 3:
                print("  → 放弃 %s" % ip)
                return (ip, None, "SSH 认证失败", "auth")
            print("  → 密码或用户名不对；确认 config.toml 里 ip 对应的 root 密码")
            if not sys.stdin.isatty():
                return (ip, None, "SSH 认证失败", "auth")
            password = ask_password("  重新输入 %s 的 SSH 密码: " % ip)
        except ConnectError as e:
            print("  ✗ %s" % e)
            return (ip, None, str(e), "conn")
        except Exception as e:
            print("  ✗ 连接异常：%s: %s" % (type(e).__name__, e))
            return (ip, None, "连接异常", "conn")

    try:
        pid, prof = resolve_profile_id(client, llm_cfg)
        payload = build_payload(cfg, name, desc, goal, pid, timeout_min)
        st, res = client.create_task(**payload)
        if st not in (200, 201) or not res.get("id"):
            print("  ✗ 下发失败 HTTP %s: %s" % (st, res))
            return (ip, None, "下发失败 HTTP %s" % st, "http")
        tid = res["id"]
        print("  ✓ 下发成功   任务 #%s   状态 %s" % (tid, res.get("status")))
        time.sleep(1.5)
        st, got = client.get_task(tid)
        print("  ✓ 回读校验   HTTP %s   状态 %s" % (st, (got or {}).get("status")))
        return (ip, tid, (got or {}).get("status", "created"), None)
    finally:
        tunnel.stop()


def do_self_test(machine, cfg, password, llm_cfg, timeout_min):
    heading("下发自检")
    print("  " + c(machine["ip"], "1"))
    tunnel, client = connect_or_report(machine, cfg, password)
    if not client:
        return False
    try:
        pid, prof = resolve_profile_id(client, llm_cfg)
        print("  LLM: #%d %s" % (pid, prof.get("name")))
        prefix = cfg["defaults"].get("test_prefix", "[DISPATCH-TEST]")
        st, res = client.create_task(
            name="%s 下发通道自检" % prefix,
            description="仅验证下发通道，立即删除。",
            goal="确认任务可创建、可查询、可删除",
            llm_profile_ids=[pid],
            timeout_seconds=int(timeout_min) * 60,
            plan_heartbeat_seconds=600,
            coverage_enabled=True)
        if st not in (200, 201) or not res.get("id"):
            print("  ✗ 创建失败 HTTP %s: %s" % (st, res))
            return False
        tid = res["id"]
        print("  ✓ 创建成功  任务 #%s" % tid)
        time.sleep(2)
        st, got = client.get_task(tid)
        print("  ✓ 回读 HTTP %s 状态=%s" % (st, (got or {}).get("status")))
        st, _ = client.delete_task(tid)
        print("  %s 删除 HTTP %s" % ("✓" if st in (200, 204) else "✗", st))
        st, _ = client.get_task(tid)
        print("  %s 删除后查询 HTTP %s（期望 404）" % ("✓" if st == 404 else "✗", st))
        return st == 404
    finally:
        tunnel.stop()


def do_cleanup_test(machine, cfg, password):
    heading("清理测试任务")
    print("  " + c(machine["ip"], "1"))
    tunnel, client = connect_or_report(machine, cfg, password)
    if not client:
        return False
    try:
        prefix = cfg["defaults"].get("test_prefix", "[DISPATCH-TEST]")
        found = [t for t in client.tasks() if (t.get("name") or "").startswith(prefix)]
        if not found:
            print("  没有 %s 开头的任务" % prefix)
            return True
        for t in found:
            st, _ = client.delete_task(t["id"])
            print("  %s #%s %s -> HTTP %s" % ("✓" if st in (200, 204) else "✗",
                                             t["id"], t.get("name"), st))
        return True
    finally:
        tunnel.stop()


def do_cleanup_one(machine, cfg, password, task_id):
    heading("删除任务 #%s" % task_id)
    print("  " + c(machine["ip"], "1"))
    tunnel, client = connect_or_report(machine, cfg, password)
    if not client:
        return False
    try:
        st, res = client.delete_task(task_id)
        print("  HTTP %s  %s" % (st, str(res)[:200]))
        return st in (200, 204)
    finally:
        tunnel.stop()


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    _init_console()
    ap = argparse.ArgumentParser(description="ARTEX 任务下发工具（SSH 隧道）")
    ap.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="配置文件路径")
    ap.add_argument("-m", "--machine", action="append", default=[], help="指定主机 IP（跳过选择，取第一个）")
    ap.add_argument("-n", "--name", help="要渗透的名称或网址（同时作为任务名称）")
    ap.add_argument("-d", "--desc", help="覆盖自动生成的描述（默认：渗透<名称>源站及其子站）")
    ap.add_argument("-g", "--goal", help="目标（默认用 config.toml 里的 goal）")
    ap.add_argument("-T", "--timeout", type=int, help="任务时长上限（分钟）")
    ap.add_argument("--llm", help="LLM key（默认取配置 defaults.llm）")
    ap.add_argument("--password", help="SSH 密码（默认逐台询问）")
    ap.add_argument("--password-env", default="ARTEX_SSH_PASSWORD", help="从该环境变量读 SSH 密码")
    ap.add_argument("--yes", action="store_true", help="跳过确认")
    ap.add_argument("--self-test", action="store_true", help="下发->校验->删除 自检")
    ap.add_argument("--cleanup-test", action="store_true", help="删除所有测试前缀任务")
    ap.add_argument("--cleanup-task", help="删除指定任务 id")
    args = ap.parse_args()

    cfg = load_config(args.config)
    d = cfg["defaults"]

    if not (args.cleanup_task or args.cleanup_test or args.self_test):
        print()
        print("  " + c("ARTEX 任务下发", "1;36") +
              c("   ·  %d 台主机" % len(cfg["machines"]), "2"))
        hr()

    # ── 一次性动作：清理 / 自检 ─────────────────────────────────────
    if args.cleanup_task or args.cleanup_test or args.self_test:
        m = _machine_arg(cfg, args.machine) or pick_machine(cfg)
        pw = args.password or os.environ.get(args.password_env or "", "") or \
            ask_password("  %s 的 SSH 密码（root）: " % m["ip"])
        if args.cleanup_task:
            sys.exit(0 if do_cleanup_one(m, cfg, pw, args.cleanup_task) else 1)
        if args.cleanup_test:
            sys.exit(0 if do_cleanup_test(m, cfg, pw) else 1)
        ok = do_self_test(m, cfg, pw, pick_llm(cfg, args.llm),
                          args.timeout if args.timeout is not None
                          else int(d.get("timeout_minutes", 600)))
        print("\n自检结果: %s" % ("通过" if ok else "失败"))
        sys.exit(0 if ok else 1)

    interactive = _tty_ok()
    env_pw = os.environ.get(args.password_env or "", "")
    passwords = {}          # 本次运行内记住密码：同一台机器不再重复询问
    current = _machine_arg(cfg, args.machine)   # -m 指定的主机
    llm_key = d.get("llm")
    last_timeout = args.timeout if args.timeout is not None else int(d.get("timeout_minutes", 600))

    while True:
        # ── 1) 选主机 ────────────────────────────────────────────
        if current is None:
            current = pick_machine(cfg)
            print()
            print("  " + c("目标主机", "2") + "  " + c(current["ip"], "1") +
                  ("  " + c(current["label"], "2") if current.get("label") else ""))
        ip = current["ip"]

        # ── 2) 密码（这台机器本次首次才问）──────────────────────
        pw = passwords.get(ip) or args.password or env_pw
        if not pw:
            pw = ask_password("  %s 的 SSH 密码（root）: " % ip)

        # ── 3) LLM ──────────────────────────────────────────────
        if args.llm:
            llm_cfg = pick_llm(cfg, args.llm)
        elif len(cfg["llm"]) > 1:
            rows = ["%-10s %s" % (i.get("key", ""), i.get("label", "")) for i in cfg["llm"]]
            default_idx = next((k for k, i in enumerate(cfg["llm"])
                                if i.get("key") == llm_key), 0)
            llm_cfg = cfg["llm"][select_one("选择 LLM：", rows, default_idx)]
            llm_key = llm_cfg.get("key")
        else:
            llm_cfg = pick_llm(cfg, llm_key)

        # ── 4) 任务输入（目标固定，描述自动生成）────────────────
        name = (args.name if args.name is not None else ask("输入要渗透的名称或网址")).strip()
        if not name:
            if not interactive:
                print("名称不能为空（可用 -n 指定）")
                sys.exit(1)
            while not name:
                name = ask("名称不能为空，输入要渗透的名称或网址").strip()
        desc = args.desc if args.desc is not None else "渗透%s源站及其子站" % name
        goal = args.goal if args.goal is not None else str(d.get("goal", "")).strip()
        if not goal:
            print("config.toml 里没有 goal，且未用 -g 指定")
            sys.exit(1)

        if args.timeout is not None:
            timeout_min = args.timeout
        elif not interactive:
            timeout_min = last_timeout
        else:
            raw = ask("任务时长上限（分钟）", str(last_timeout))
            timeout_min = int(raw) if str(raw).isdigit() else last_timeout
            last_timeout = timeout_min

        # ── 5) 确认 ─────────────────────────────────────────────
        print()
        hr()
        print("  主机    %s" % c(ip, "1"))
        print("  名称    %s" % name)
        print("  描述    %s" % desc)
        print("  目标    %s" % (goal if len(goal) <= 100 else goal[:97] + "..."))
        print("  LLM    %s" % llm_cfg.get("label", llm_cfg.get("key")))
        print("  时长    %s 分钟" % timeout_min)
        hr()
        if interactive and not args.yes:
            if _input("确认下发？[Y/n] ").strip().lower() not in ("", "y", "yes"):
                print("已取消")
                current = None
                continue

        # ── 6) 下发 ─────────────────────────────────────────────
        rip, tid, status, err = dispatch_one(current, cfg, pw, name, desc, goal, llm_cfg, timeout_min)
        if err == "auth":
            passwords.pop(ip, None)      # 密码不对，下次重新问
        elif rip:
            passwords[ip] = pw           # 连通成功，记住密码
        if tid:
            print()
            hr()
            print("  " + c("已下发", "1;32") + "  %s   任务 #%s   %s" % (ip, tid, status))
            hr()

        # ── 7) 结束或继续 ───────────────────────────────────────
        if not interactive:
            return
        choice = select_one("接下来", [
            "继续下发这台机器（%s，不用再输密码）" % ip,
            "使用别的机器（重新选主机 + 输密码）",
        ], 0)
        if choice == 1:
            current = None
        print()


def _machine_arg(cfg, machines):
    """-m 指定主机时返回该主机配置，否则 None。"""
    if not machines:
        return None
    by_ip = {m["ip"]: m for m in cfg["machines"]}
    ip = machines[0]
    if ip not in by_ip:
        print("配置里没有主机 %s，请先加到 config.toml" % ip)
        sys.exit(1)
    return by_ip[ip]


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已中断")
        sys.exit(130)
