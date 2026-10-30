#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARTEX 本地多机控制台。

动态服务器列表、多机总览、常连接自动刷新与重连、任务下发、
提问记录和报告导出；只监听 127.0.0.1，数据通过 SSH 转发。

用法：
    python artex_console.py                 # 默认 http://127.0.0.1:8900
    python artex_console.py --port 8901
    python artex_console.py --no-browser

依赖：pip install paramiko ；读取 config.toml 需要 Python >= 3.11
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import posixpath
import re
import select
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
import zipfile
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import tomllib
except ImportError:
    tomllib = None

try:
    import paramiko
    import logging as _logging
    _logging.getLogger("paramiko").setLevel(_logging.CRITICAL)
except ImportError:
    print("缺少依赖 paramiko，请先执行:  pip install paramiko")
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "config.toml")
DEFAULT_GOAL = "获取权限"   # 仅在 config.toml 没写 goal 时兜底
DEFAULT_DESC_TEMPLATE = "渗透<名称>源站及其子站"   # 仅在 config.toml 没写 desc_template 时兜底
EXPORT_ROOT = os.path.join(HERE, "machine")
KNOWN_HOSTS_FILE = os.path.join(HERE, "ssh_host_keys.json")
UI_STATE_FILE = os.path.join(HERE, "ui_state.json")


# --------------------------------------------------------------------------
# SSH 主机密钥校验（首次记录、之后严格比对，防中间人）
# --------------------------------------------------------------------------

def _load_known_hosts():
    try:
        with open(KNOWN_HOSTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_known_hosts(d):
    try:
        tmp = KNOWN_HOSTS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1, sort_keys=True)
        os.replace(tmp, KNOWN_HOSTS_FILE)
    except Exception:
        pass


def host_fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def verify_host_key(host, port, key):
    """首次连接记录指纹；指纹变化直接报错而不是继续连。"""
    fp = host_fingerprint(key)
    tag = "%s:%d" % (host, port)
    known = _load_known_hosts()
    old = known.get(tag)
    if old is None:
        known[tag] = fp
        _save_known_hosts(known)
        print("[固定] 首次连接 %s，已记录主机密钥 %s" % (tag, fp), flush=True)
        return
    if old != fp:
        raise RuntimeError(
            "主机密钥指纹不一致，已中止连接（可能是中间人攻击）\n"
            "  主机   %s\n  已记录 %s\n  本次   %s\n"
            "  确认服务器确实重装/换过密钥后，删除 ssh_host_keys.json 里这一条再试。" % (tag, old, fp))


# --------------------------------------------------------------------------
# SSH 本地端口转发（用完即关）
# --------------------------------------------------------------------------

class _ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def load_pkey(path):
    """按常见顺序尝试加载私钥文件。"""
    if not path:
        return None
    if not os.path.isabs(path):
        path = os.path.join(HERE, path)
    if not os.path.isfile(path):
        raise RuntimeError("密钥文件不存在：%s" % path)
    last = None
    classes = [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]
    if hasattr(paramiko, "DSSKey"):
        classes.append(paramiko.DSSKey)
    for cls in classes:
        try:
            return cls.from_private_key_file(path)
        except Exception as e:
            last = e
    raise RuntimeError("无法解析密钥文件（需要 openssh 私钥）：%s" % last)


class SSHTunnel:
    def __init__(self, host, user, password, remote_port=8787, port=22,
                 remote_host="127.0.0.1", timeout=12, key_file=""):
        self.host, self.port, self.user = host, port, user
        self.password = password
        self.key_file = key_file
        self.remote_host, self.remote_port = remote_host, remote_port
        self.timeout = timeout
        self.transport = None
        self.server = None
        self.local_port = None

    def start(self):
        """建连 + 握手 + 认证。

        握手容易因为「服务器忙 / 自己在短时间内握手太多」失败，所以：
        * 全局最多 2 条同时握手（_HANDSHAKE_SEM），避免瞬时冲击 sshd 的 MaxStartups；
        * 失败按 1s / 2s / 3s 退避重试，最多 4 次（约 6 秒窗口）。
        """
        delays = [0, 1.0, 2.0, 3.0]
        last = None
        for attempt in range(4):
            if delays[attempt]:
                time.sleep(delays[attempt])
            tr = None
            got = _HANDSHAKE_SEM.acquire(timeout=30)
            try:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                sock.settimeout(self.timeout)
                tr = paramiko.Transport(sock)
                tr.banner_timeout = max(self.timeout, 15)
                tr.auth_timeout = self.timeout
                tr.start_client(timeout=max(self.timeout, 15))
                verify_host_key(self.host, self.port, tr.get_remote_server_key())
                pkey = load_pkey(self.key_file) if self.key_file else None
                if pkey is not None:
                    tr.auth_publickey(self.user, pkey)
                else:
                    tr.auth_password(self.user, self.password)
                if not tr.is_authenticated():
                    tr.close()
                    raise paramiko.AuthenticationException("密码或用户名不对")
                tr.set_keepalive(30)      # 常连接保活
                self.transport = tr
                return self._serve()
            except paramiko.AuthenticationException:
                raise
            except RuntimeError:
                raise                      # 主机密钥不一致，不重试
            except (paramiko.SSHException, EOFError, OSError) as e:
                last = e
                if tr is not None:
                    try:
                        tr.close()
                    except Exception:
                        pass
                if attempt == 3:
                    raise
            finally:
                if got:
                    _HANDSHAKE_SEM.release()
        raise last

    def _serve(self):
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
                            d = self.request.recv(8192)
                            if not d:
                                break
                            chan.sendall(d)
                        if chan in r:
                            d = chan.recv(8192)
                            if not d:
                                break
                            self.request.sendall(d)
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

    def _req(self, method, path, body=None, timeout=25):
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
            return e.code, {"error": e.read().decode("utf-8", "replace")[:300]}
        except Exception as e:
            return -1, {"error": "%s: %s" % (type(e).__name__, e)}

    def login(self):
        st, res = self._req("POST", "/api/auth/login",
                            {"username": self.user, "password": self.password})
        self.token = (res or {}).get("token")
        if not self.token:
            raise RuntimeError("ARTEX 登录失败（HTTP %s）" % st)

    def tasks(self):
        st, res = self._req("GET", "/api/tasks")
        if st != 200:
            raise RuntimeError("拉取任务失败（HTTP %s）%s" % (st, (res.get("error") or "")[:120]))
        return res.get("tasks") or []

    def profiles(self):
        st, res = self._req("GET", "/api/llm/profiles")
        if st != 200:
            raise RuntimeError("拉取 LLM 配置失败（HTTP %s）" % st)
        return res.get("profiles") or []

    def create_task(self, payload):
        return self._req("POST", "/api/tasks", payload, timeout=60)

    def workspace_list(self, path=""):
        q = urllib.parse.quote(path or "", safe="")
        st, res = self._req("GET", "/api/workspace/list?path=" + q)
        if st != 200:
            raise RuntimeError("读取目录失败（HTTP %s）%s"
                               % (st, str((res or {}).get("error") or "")[:120]))
        return res or {}

    def workspace_stream(self, path, timeout=600):
        """流式打开工作区文件，调用方负责关闭。"""
        q = urllib.parse.quote(path or "", safe="")
        req = urllib.request.Request(self.base + "/api/workspace/download?path=" + q)
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        return urllib.request.urlopen(req, timeout=timeout)

    def delete_task(self, task_id, options):
        return self._req("DELETE", "/api/tasks/" + str(task_id), options, timeout=180)

    def raw(self, path, timeout=120):
        """取原始字节（markdown / zip）。"""
        req = urllib.request.Request(self.base + path)
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(), r.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            return e.code, e.read()[:300], ""
        except Exception as e:
            return -1, str(e).encode("utf-8", "replace"), ""


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------

def load_config(path):
    if tomllib is None:
        print("需要 Python 3.11+ 才能读 config.toml")
        sys.exit(1)
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    if not cfg.get("machines"):
        print("提示：配置里还没有服务器，启动后点左侧「＋ 添加」即可")
        cfg["machines"] = []
    for m in cfg["machines"]:
        m.setdefault("port", 22)
        m.setdefault("user", "root")
        m.setdefault("label", "")
        m.setdefault("ssh_password", "")
        if not m.get("artex_port"):
            m["artex_port"] = cfg["defaults"].get("artex_port", 8787)
    cfg.setdefault("defaults", {})
    cfg.setdefault("console", {})
    return cfg


def console_options(cfg):
    c = cfg.get("console") or {}
    return {
        "lang": c.get("lang", "zh"),
        "theme": c.get("theme", "light"),
        "refresh_seconds": int(c.get("refresh_seconds", 8)),
        "background_refresh_seconds": int(c.get("background_refresh_seconds", 30)),
        "auto_connect": bool(c.get("auto_connect", False)),
        "auto_reconnect": bool(c.get("auto_reconnect", True)),
        "reconnect_seconds": int(c.get("reconnect_seconds", 15)),
        "ssh_timeout": int(c.get("ssh_timeout", 12)),
        "desktop_notifications": bool(c.get("desktop_notifications", False)),
        "export_dir": c.get("export_dir", "machine"),
    }


def apply_export_dir(cfg):
    global EXPORT_ROOT
    value = (cfg.get("console") or {}).get("export_dir", "machine")
    EXPORT_ROOT = os.path.abspath(os.path.join(HERE, value))


_CONFIG_PATH = DEFAULT_CONFIG


def _toml_val(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        if "\n" in v:
            body = v.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
            return '"""' + body + '"""'
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_val(x) for x in v) + "]"
    return json.dumps(str(v), ensure_ascii=False)


def dump_config(cfg):
    out = ["# ARTEX 控制台配置（由界面自动生成，也可手工编辑）", ""]

    def table(name, d):
        out.append("[%s]" % name)
        for k, v in d.items():
            out.append("%s = %s" % (k, _toml_val(v)))
        out.append("")

    table("defaults", cfg.get("defaults") or {})
    for name in ("console", "monitor"):
        if cfg.get(name):
            table(name, cfg[name])
    for name in ("llm", "machines"):
        for item in cfg.get(name) or []:
            out.append("[[%s]]" % name)
            for k, v in item.items():
                out.append("%s = %s" % (k, _toml_val(v)))
            out.append("")
    return "\n".join(out)


def save_config(cfg, path=None):
    path = path or _CONFIG_PATH
    try:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()
            with open(path + ".bak", "wb") as f:
                f.write(data)
    except Exception:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(dump_config(cfg))
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# 本机界面状态：每台机器的「最近任务」顺序（与配置、凭据分开保存）
# --------------------------------------------------------------------------

_UI_STATE = None
_UI_LOCK = threading.Lock()


def _ui_state():
    global _UI_STATE
    if _UI_STATE is None:
        try:
            with open(UI_STATE_FILE, "r", encoding="utf-8") as f:
                _UI_STATE = json.load(f) or {}
        except Exception:
            _UI_STATE = {}
    return _UI_STATE


def _ui_flush():
    tmp = UI_STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_ui_state(), f, indent=1, ensure_ascii=False)
    os.replace(tmp, UI_STATE_FILE)


def get_task_order(ip):
    with _UI_LOCK:
        order = (_ui_state().get("task_order") or {}).get(ip) or []
        return [str(x) for x in order]


def set_task_order(ip, order):
    with _UI_LOCK:
        _ui_state().setdefault("task_order", {})[ip] = list(order)
        try:
            _ui_flush()
        except Exception:
            return False
    return True


def move_task_order(old_ip, new_ip):
    with _UI_LOCK:
        orders = _ui_state().setdefault("task_order", {})
        if old_ip in orders:
            orders[new_ip] = orders.pop(old_ip)
            try:
                _ui_flush()
            except Exception:
                pass


def drop_task_order(ip):
    with _UI_LOCK:
        orders = _ui_state().setdefault("task_order", {})
        if orders.pop(ip, None) is not None:
            try:
                _ui_flush()
            except Exception:
                pass


def get_ask_history(ip, task_id):
    with _UI_LOCK:
        items = (((_ui_state().get("ask_history") or {}).get(ip) or {}).get(str(task_id)) or [])
        return list(items)


def append_ask_history(ip, task_id, message, result):
    entry = {"message": message, "ok": bool(result.get("ok")),
             "reply": result.get("reply") or result.get("error") or "",
             "ts": int(time.time())}
    with _UI_LOCK:
        by_ip = _ui_state().setdefault("ask_history", {}).setdefault(ip, {})
        items = by_ip.setdefault(str(task_id), [])
        items.append(entry)
        del items[:-20]
        try:
            _ui_flush()
        except Exception:
            pass
    return entry


def safe_filename(ip):
    return re.sub(r"[^0-9A-Za-z._-]", "_", ip)


_HANDSHAKE_SEM = threading.Semaphore(2)   # 同时最多 2 条 SSH 握手
_CONNS = {}                 # ip -> {"tunnel","client","machine"}
_CONNS_LOCK = threading.Lock()


def conn_get(ip):
    with _CONNS_LOCK:
        return _CONNS.get(ip)


def conn_set(ip, tunnel, client, machine):
    with _CONNS_LOCK:
        _CONNS[ip] = {"tunnel": tunnel, "client": client, "machine": machine,
                      "lock": threading.Lock()}


def conn_close(ip):
    with _CONNS_LOCK:
        c = _CONNS.pop(ip, None)
    if c:
        try:
            c["tunnel"].stop()
        except Exception:
            pass
    return bool(c)


def conn_list():
    with _CONNS_LOCK:
        return sorted(_CONNS)


_HOST_LOCKS = {}
_HOST_LOCKS_GUARD = threading.Lock()


def _host_lock(ip):
    with _HOST_LOCKS_GUARD:
        return _HOST_LOCKS.setdefault(ip, threading.Lock())


def open_persistent(cfg, machine, password):
    """建一条常连接（不走 Session，因为它退出去会关隧道）。"""
    d = cfg["defaults"]
    password = password or machine.get("ssh_password") or ""
    key_file = machine.get("ssh_key_file") or ""
    if not password and not key_file:
        raise RuntimeError("缺少 SSH 凭据（密码或密钥文件都没填）")
    lock = _host_lock(machine["ip"])
    if not lock.acquire(timeout=90):
        raise RuntimeError("等待该机器上一条连接释放超时")
    try:
        tunnel = SSHTunnel(machine["ip"], machine["user"], password,
                           remote_port=int(machine.get("artex_port") or d.get("artex_port", 8787)),
                           port=int(machine.get("port", 22)),
                           timeout=int((cfg.get("console") or {}).get("ssh_timeout", 12)),
                           key_file=key_file)
        tunnel.start()
        client = ArtexClient("http://127.0.0.1:%d" % tunnel.local_port,
                             machine.get("artex_user") or d.get("login_user", "ARTEX"),
                             machine.get("artex_password") or d.get("login_password", ""))
        try:
            client.login()
        except Exception:
            tunnel.stop()
            raise
        return tunnel, client
    except paramiko.AuthenticationException:
        raise
    except paramiko.SSHException as e:
        raise RuntimeError("SSH 握手失败（服务器繁忙或连接被限速）：%s" % e)
    finally:
        lock.release()


@contextlib.contextmanager
def client_ctx(cfg, machine, password):
    """优先复用常连接；没连就开一条临时的（用完即关）。"""
    c = conn_get(machine["ip"])
    if c:
        with c["lock"]:
            yield c["client"]
        return
    with Session(cfg, machine, password) as cl:
        yield cl


class Session:
    """一次「现连现断」的连接。"""

    def __init__(self, cfg, machine, password=""):
        self.cfg = cfg
        self.d = cfg["defaults"]
        self.m = machine
        self.password = password or machine.get("ssh_password") or ""
        self.tunnel = None
        self.client = None

    def __enter__(self):
        self.key_file = self.m.get("ssh_key_file") or ""
        if not self.password and not self.key_file:
            raise RuntimeError("缺少 SSH 凭据（密码或密钥文件都没填）")
        # 同一台机器同一时刻只允许一条 SSH（避免并发握手被 sshd 限速）
        self._lock = _host_lock(self.m["ip"])
        if not self._lock.acquire(timeout=90):
            raise RuntimeError("等待该机器上一条连接释放超时")
        try:
            self.tunnel = SSHTunnel(self.m["ip"], self.m["user"], self.password,
                                    remote_port=int(self.m.get("artex_port") or self.d.get("artex_port", 8787)),
                                    port=int(self.m.get("port", 22)),
                                    timeout=int((self.cfg.get("console") or {}).get("ssh_timeout", 12)),
                                    key_file=self.key_file)
            self.tunnel.start()
            self.client = ArtexClient("http://127.0.0.1:%d" % self.tunnel.local_port,
                                      self.m.get("artex_user") or self.d.get("login_user", "ARTEX"),
                                      self.m.get("artex_password") or self.d.get("login_password", ""))
            self.client.login()
            return self.client
        except paramiko.AuthenticationException:
            self._release()
            raise
        except paramiko.SSHException as e:
            self._release()
            raise RuntimeError("SSH 握手失败（服务器繁忙或连接被限速，已重试 3 次）：%s" % e)
        except OSError as e:
            self._release()
            raise RuntimeError("SSH 连接失败：%s" % e)
        except Exception:
            self._release()
            raise

    def _release(self):
        if self.tunnel:
            try:
                self.tunnel.stop()
            except Exception:
                pass
            self.tunnel = None
        lock = getattr(self, "_lock", None)
        if lock is not None and lock.locked():
            try:
                lock.release()
            except Exception:
                pass
            self._lock = None

    def __exit__(self, *exc):
        self._release()
        return False


def _task_num(t):
    try:
        return int(t.get("id"))
    except Exception:
        return -1


def summarize(tasks):
    counts, findings = {}, {"critical": 0, "high": 0, "medium": 0, "low": 0}
    inflight, last = 0, 0
    rows = []
    for t in tasks:
        st = t.get("status") or "?"
        counts[st] = counts.get(st, 0) + 1
        f = t.get("findings") or {}
        for k in findings:
            findings[k] += int(f.get(k) or 0)
        inflight += int(t.get("in_flight") or 0)
        last = max(last, int(t.get("last_activity_unix") or 0))
        rows.append({
            "id": t.get("id"), "name": t.get("name") or "(未命名)", "status": st,
            "in_flight": int(t.get("in_flight") or 0),
            "findings": {k: int(f.get(k) or 0) for k in findings},
        })
    rows.sort(key=_task_num, reverse=True)
    all_tasks = [{"id": r["id"], "name": r["name"], "status": r["status"],
                  "in_flight": r["in_flight"], "findings": r["findings"]}
                 for r in rows]
    return {
        "tasks_total": len(tasks), "counts": counts, "findings": findings,
        "in_flight": inflight, "last_activity": last,
        "all_tasks": all_tasks,
    }


def _safe_dirname(name, fallback):
    """任务名/主机名 -> 合法目录名。"""
    n = re.sub(r'[\\/:*?"<>|\r\n\t]+', "_", str(name or "")).strip(" .")
    return n[:64] or fallback


def _safe_extract(zip_path, dest):
    """解压 zip 到 dest，跳过绝对路径/../ 等不安全条目，返回写入文件数。"""
    count = 0
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            if info.is_dir() or name.startswith("/") or ".." in name.split("/"):
                continue
            target = os.path.join(dest, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
            count += 1
    return count


def export_task(client, ip, task_id, task_name, progress=None):
    """导出总报告与严重/高危单漏洞报告，并回报当前阶段。"""
    tid = str(task_id).strip()
    base = os.path.join(EXPORT_ROOT,
                        _safe_dirname(ip, "unknown-ip"),
                        _safe_dirname(task_name, "task_" + tid))
    os.makedirs(base, exist_ok=True)
    res = {"critical": 0, "high": 0, "main_report": 0, "errors": []}

    if progress:
        progress("report")
    st, data, _ = client.raw("/api/report?task=" + tid)
    if st == 200 and data:
        with open(os.path.join(base, "总报告.md"), "wb") as f:
            f.write(data)
        res["main_report"] = 1
    else:
        res["errors"].append("总报告 HTTP %s" % st)

    for sev, label, key in (("critical", "严重", "critical"), ("high", "高危", "high")):
        if progress:
            progress(sev)
        q = ("/api/exploration/findings/export?scope=filtered&task_id=%s"
             "&severity=%s&format=md-zip" % (tid, sev))
        st, data, _ = client.raw(q, timeout=180)
        if st != 200:
            res["errors"].append("%s导出 HTTP %s" % (label, st))
            continue
        if len(data) < 4 or data[:2] != b"PK":
            res[key] = 0
            continue
        tmp = os.path.join(base, "_%s.zip" % sev)
        with open(tmp, "wb") as f:
            f.write(data)
        dest = os.path.join(base, label)
        os.makedirs(dest, exist_ok=True)
        res[key] = _safe_extract(tmp, dest)
        os.remove(tmp)

    if progress:
        progress("finishing")
    with open(os.path.join(base, "导出信息.txt"), "w", encoding="utf-8") as f:
        f.write("任务 #%s  %s\n" % (tid, task_name))
        f.write("导出时间：%s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
        f.write("严重报告：%d 个\n高危报告：%d 个\n" % (res["critical"], res["high"]))
        if res["errors"]:
            f.write("异常：%s\n" % "；".join(res["errors"]))
    res["dir"] = os.path.relpath(base, HERE).replace("\\", "/")
    return res


# --------------------------------------------------------------------------
# 服务器工作区文件
# --------------------------------------------------------------------------

_WS_MAX_FILES = 5000
_WS_MAX_BYTES = 1 << 30          # 打包上限 1 GiB
_DOWNLOAD_TTL = 1800
_DOWNLOAD_TICKETS = {}
_DOWNLOAD_LOCK = threading.Lock()


def _ws_norm(path):
    """工作区相对路径规范化；拒绝绝对路径与 .. 穿越。"""
    p = str(path or "").replace("\\", "/").strip()
    if "\x00" in p or len(p) > 4096:
        raise ValueError("路径不合法")
    parts = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            raise ValueError("路径不合法")
        parts.append(seg)
    return "/".join(parts)


def _ws_entry(client, rel):
    parent, base = posixpath.split(rel)
    st, res = client._req("GET", "/api/workspace/list?path=" +
                          urllib.parse.quote(parent, safe=""))
    if st == 404:
        return None
    if st != 200:
        raise RuntimeError("读取目录失败（HTTP %s）" % st)
    for entry in (res or {}).get("entries") or []:
        if entry.get("name") == base:
            return entry
    return None


def _ws_collect(client, rel, out, budget, depth=0):
    """递归收集目录下的文件；超过数量或体积上限直接中止。"""
    if depth > 16:
        raise RuntimeError("目录层级过深，已中止")
    data = client.workspace_list(rel)
    for entry in data.get("entries") or []:
        child = _ws_norm(entry.get("path") or "")
        if not child:
            continue
        if entry.get("dir"):
            _ws_collect(client, child, out, budget, depth + 1)
            continue
        budget["files"] += 1
        budget["bytes"] += int(entry.get("size") or 0)
        if budget["files"] > _WS_MAX_FILES:
            raise RuntimeError("文件数量超过 %d 个，请分批下载" % _WS_MAX_FILES)
        if budget["bytes"] > _WS_MAX_BYTES:
            raise RuntimeError("总大小超过 1 GB，请分批下载")
        out.append((child, int(entry.get("size") or 0)))


def ws_task_stat(client, task_id):
    """统计某任务工作目录的文件数与总字节数。"""
    root = "tasks/" + str(task_id)
    st, res = client._req("GET", "/api/workspace/list?path=" + root)
    if st == 404:
        return {"exists": False, "files": 0, "bytes": 0, "truncated": False}
    if st != 200:
        raise RuntimeError("读取任务目录失败（HTTP %s）" % st)
    out = []
    budget = {"files": 0, "bytes": 0}
    try:
        _ws_collect(client, root, out, budget)
    except RuntimeError as e:
        return {"exists": True, "files": budget["files"], "bytes": budget["bytes"],
                "truncated": True, "warning": str(e)}
    return {"exists": True, "files": budget["files"], "bytes": budget["bytes"],
            "truncated": False}


def _download_dir():
    path = os.path.join(tempfile.gettempdir(), "artex-controller-downloads")
    os.makedirs(path, exist_ok=True)
    return path


def _download_cleanup():
    now = time.time()
    with _DOWNLOAD_LOCK:
        for tid, item in list(_DOWNLOAD_TICKETS.items()):
            if now - item.get("created", 0) <= _DOWNLOAD_TTL:
                continue
            _DOWNLOAD_TICKETS.pop(tid, None)
            try:
                os.remove(item["path"])
            except Exception:
                pass


def prepare_workspace_download(client, paths):
    """把选中的文件/目录准备成本地临时文件，返回 (path, name, size)。"""
    clean = []
    for raw in paths or []:
        p = _ws_norm(raw)
        if p and p not in clean:
            clean.append(p)
    if not clean:
        raise ValueError("没有选中文件")
    if len(clean) > 200:
        raise ValueError("一次最多选择 200 项，请分批下载")

    if len(clean) == 1:
        entry = _ws_entry(client, clean[0])
        if entry is None:
            raise RuntimeError("文件不存在或已被移动")
        if not entry.get("dir"):
            fd, tmp = tempfile.mkstemp(prefix="ws-file-", dir=_download_dir())
            try:
                with os.fdopen(fd, "wb") as out, client.workspace_stream(clean[0]) as src:
                    shutil.copyfileobj(src, out, 256 * 1024)
            except Exception:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
                raise
            name = posixpath.basename(clean[0]) or "download"
            return tmp, name, os.path.getsize(tmp)

    items, budget = [], {"files": 0, "bytes": 0}
    for rel in clean:
        entry = _ws_entry(client, rel)
        if entry is None:
            raise RuntimeError("文件不存在或已被移动：%s" % rel)
        if entry.get("dir"):
            before = len(items)
            _ws_collect(client, rel, items, budget)
            if len(items) == before:
                items.append((rel.rstrip("/") + "/", 0))
        else:
            budget["files"] += 1
            budget["bytes"] += int(entry.get("size") or 0)
            if budget["files"] > _WS_MAX_FILES or budget["bytes"] > _WS_MAX_BYTES:
                raise RuntimeError("文件过多或总大小超过 1 GB，请分批下载")
            items.append((rel, int(entry.get("size") or 0)))

    fd, tmp = tempfile.mkstemp(prefix="ws-zip-", suffix=".zip", dir=_download_dir())
    try:
        with os.fdopen(fd, "wb") as raw, zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel, _size in items:
                if rel.endswith("/"):
                    zf.writestr(rel, b"")
                    continue
                with client.workspace_stream(rel) as src, zf.open(rel, "w") as dst:
                    shutil.copyfileobj(src, dst, 256 * 1024)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise

    if len(clean) == 1:
        name = _safe_dirname(posixpath.basename(clean[0]), "files") + ".zip"
    else:
        name = "artex-files-%s.zip" % time.strftime("%Y%m%d-%H%M%S")
    return tmp, name, os.path.getsize(tmp)


def drop_task_state(ip, task_id):
    """任务删除后清掉本地展示顺序与提问记录。"""
    tid = str(task_id)
    with _UI_LOCK:
        state = _ui_state()
        dirty = False
        order = (state.get("task_order") or {}).get(ip) or []
        kept = [x for x in order if str(x) != tid]
        if len(kept) != len(order):
            state.setdefault("task_order", {})[ip] = kept
            dirty = True
        by_ip = (state.get("ask_history") or {}).get(ip) or {}
        if by_ip.pop(tid, None) is not None:
            dirty = True
        if dirty:
            try:
                _ui_flush()
            except Exception:
                pass


def _latest_seq(client, task_id):
    """取该任务当前最新一条活动的 seq（作为“发消息之前”的游标）。"""
    st, res = client._req("GET", "/api/exploration/activity/history?task=%s&limit=1" % task_id)
    if st == 200:
        items = res.get("items") or []
        if items:
            try:
                return int(items[0].get("seq") or 0)
            except Exception:
                return 0
    return 0


def ask_main_agent(client, task_id, message, timeout=240):
    """向任务的主 Agent 发一条消息，等它跑完，把最终回复取回来。

    ARTEX 的 /api/chat 是异步的（202 + SSE 推流）；这里用「活动历史」轮询：
    history 接口返回最新在前，按 seq > 发送前的游标 过滤出本轮新增的活动，
    抓 worker=mainagent 的 kind=result 作为最终回复。
    """
    before = _latest_seq(client, task_id)

    st, res = client._req("POST", "/api/chat?task=%s" % task_id,
                          {"message": message}, timeout=60)
    if st not in (200, 202):
        return {"ok": False, "error": "发送失败 HTTP %s：%s" % (st, str(res.get("error") or res)[:160])}
    if st == 200 and (res or {}).get("reply"):      # 无 LLM 时的规则模式，直接有回复
        return {"ok": True, "reply": res["reply"], "steps": []}

    t0 = time.time()
    deadline = t0 + max(30, timeout)
    steps, reply, idle = [], None, 0
    while time.time() < deadline:
        time.sleep(1.5)
        st, res = client._req(
            "GET", "/api/exploration/activity/history?task=%s&limit=60" % task_id, timeout=30)
        fresh = []
        if st == 200:
            for it in (res.get("items") or []):
                try:
                    seq = int(it.get("seq") or 0)
                except Exception:
                    continue
                if seq <= before:
                    continue
                fresh.append((seq, it))
        fresh.sort(key=lambda x: x[0])
        for seq, it in fresh:
            before = max(before, seq)
            if it.get("worker") != "mainagent":
                continue
            kind = it.get("kind") or ""
            if kind == "usage":
                continue
            steps.append({"kind": kind, "summary": (it.get("summary") or "")[:4000],
                          "ts": it.get("ts") or "", "error": bool(it.get("is_error"))})
            if kind == "result" and not it.get("is_error"):
                # 列表里的 summary 是截断过的（百来字），完整回复要按 seq 取 detail
                full = ""
                st_d, d_res = client._req(
                    "GET", "/api/exploration/activity/%s?task=%s" % (seq, task_id), timeout=30)
                if st_d == 200:
                    full = (d_res.get("detail") or "").strip()
                reply = full or it.get("summary") or ""

        st2, s2 = client._req("GET", "/api/tasks/%s/chat/status" % task_id, timeout=20)
        running = bool((s2 or {}).get("running")) if st2 == 200 else False
        if reply and not running:
            break
        if not running:
            idle += 1
            if idle >= 3 and steps:      # 已经结束且拿到过程，取最后一条
                break
        else:
            idle = 0

    if reply is None and steps:
        reply = steps[-1]["summary"]
    if reply is None:
        return {"ok": False, "error": "等待超时（%d 秒内没有回复）" % timeout, "steps": steps[-10:]}
    return {"ok": True, "reply": reply, "steps": steps[-40:]}


_EXPORT_JOBS = {}
_EXPORT_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# 页面
# --------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>ARTEX Controller</title>
<link rel="icon" href="/icon.ico">
<style>
  :root{
    --bg:#f6f1e7;
    --panel:#fdfaf4;
    --panel-2:#f1e9db;
    --line:#e6dccb;
    --line-soft:#efe7d9;
    --ink:#4a4136;
    --ink-2:#786c5d;
    --ink-3:#a59a8b;
    --accent:#96683f;
    --accent-d:#7d5533;
    --ok:#4b7357;
    --crit:#a8452f;
    --high:#bf7132;
    --med:#9c8636;
    --low:#5d7f93;
  }
  *{box-sizing:border-box}
  [hidden]{display:none !important}
  html,body{margin:0;height:100%;overflow:hidden}
  body{
    background:var(--bg);color:var(--ink);
    font:13.5px/1.65 "Segoe UI","Microsoft YaHei","PingFang SC",system-ui,sans-serif;
    -webkit-font-smoothing:antialiased;
  }
  *{scrollbar-width:thin;scrollbar-color:#d8c9b2 transparent}
  ::-webkit-scrollbar{width:8px;height:8px}
  ::-webkit-scrollbar-thumb{background:#d8c9b2;border-radius:4px;border:2px solid transparent;background-clip:content-box}
  ::-webkit-scrollbar-thumb:hover{background:#c6b399;background-clip:content-box}
  ::-webkit-scrollbar-track{background:transparent}

  .app{display:flex;height:100vh;overflow:hidden}

  aside{
    width:236px;flex:none;display:flex;flex-direction:column;
    transition:width .18s ease;
    background:linear-gradient(180deg,#f3ebdd 0%,#efe6d5 100%);
    border-right:1px solid var(--line);
  }
  .brand{
    padding:16px 18px 12px;font-size:15px;font-weight:600;letter-spacing:.4px;color:var(--accent);
  }
  .brand small{display:block;margin-top:3px;font-size:11px;font-weight:400;letter-spacing:0;color:var(--ink-3)}
  .switch{position:relative;display:inline-block;width:46px;height:24px;flex:none}
  .switch input{opacity:0;width:0;height:0}
  .switch .slider{position:absolute;inset:0;cursor:pointer;background:#ded2c0;
                  border-radius:12px;transition:background .18s ease;box-shadow:inset 0 1px 2px rgba(120,95,60,.15)}
  .switch .slider:before{content:"";position:absolute;height:18px;width:18px;left:3px;top:3px;
                         background:#fffdf8;border-radius:50%;transition:transform .18s ease;
                         box-shadow:0 1px 2px rgba(120,95,60,.3)}
  .switch input:checked + .slider{background:#7c9c76}
  .switch input:checked + .slider:before{transform:translateX(22px)}
  .side-head{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;
             padding:14px 12px 12px 18px;border-bottom:1px solid var(--line-soft)}
  .side-brand .brand{padding:0;font-size:15px;font-weight:600;letter-spacing:.4px;color:var(--accent)}
  .side-brand small{display:block;margin-top:3px;font-size:11px;letter-spacing:0;color:var(--ink-3)}
  .collapser{flex:none;margin-top:2px;height:22px}
  .side-title{padding:12px 18px 7px;font-size:10.5px;letter-spacing:1.4px;color:var(--ink-3)}
  body.collapsed aside{width:62px}
  body.collapsed .side-brand,body.collapsed .side-title,body.collapsed .side-actions{display:none}
  body.collapsed .side-head{justify-content:center;padding:14px 0 6px}
  body.collapsed .item{justify-content:center;padding:9px 0;border-left-width:0}
  body.collapsed .item .ip,body.collapsed .item .lb,body.collapsed .item .ops{display:none}
  body.collapsed .item .dot{margin-top:0}
  .side-actions{padding:0 14px 10px;display:flex;flex-direction:column;gap:5px}
  .side-actions .row{gap:6px;margin:0}
  .side-actions .row button{flex:1}
  #btn-add{background:var(--accent);border-color:var(--accent-d);color:#fdfaf4;
           box-shadow:0 1px 2px rgba(125,85,51,.2)}
  #btn-add:hover{background:var(--accent-d)}
  body.dark #btn-add{color:#231e18}
  .side-foot{display:flex;gap:6px;padding:8px 14px 10px;border-top:1px solid var(--line)}
  .foot-btn{flex:1;height:30px;display:flex;align-items:center;justify-content:center;padding:0;
            background:rgba(253,250,244,.45);border-color:var(--line-soft);border-radius:7px}
  .foot-btn:hover{background:#fffdf8}
  body.dark .foot-btn{background:rgba(255,255,255,.03)}
  body.dark .foot-btn:hover{background:#362e25}
  .foot-btn svg{display:block}
  #ico-sun{display:none}
  body.dark #ico-sun{display:block}
  body.dark #ico-moon{display:none}
  body.collapsed .side-foot{flex-direction:column;align-items:center;padding:8px 0 10px}
  body.collapsed .foot-btn{flex:none;width:38px}
  .item .ops{margin-left:auto;display:none;gap:2px}
  body.editing .item .ops{display:flex}
  .icon{background:transparent;border:1px solid var(--line);color:var(--ink-2);
        border-radius:5px;padding:0 6px;font:inherit;font-size:12px;line-height:20px;cursor:pointer}
  .icon:hover{background:#f2ebdf;color:var(--ink)}
  .lnk{color:var(--accent);font-size:11.5px;text-decoration:none;margin-left:8px;cursor:pointer}
  .lnk:hover{text-decoration:underline}
  .auto-row{display:flex;align-items:center}
  .fold-tri{width:16px;height:16px;padding:0;margin-right:2px;display:inline-flex;align-items:center;
    justify-content:center;flex:none;background:transparent;border:0;box-shadow:none;color:var(--ink-3)}
  .fold-tri:hover{background:transparent;color:var(--ink-2)}
  .fold-tri:active{transform:none}
  .fold-tri::before{content:'';display:block;border-left:5px solid currentColor;
    border-top:4px solid transparent;border-bottom:4px solid transparent;transition:transform .15s ease}
  .fold-tri[aria-expanded="true"]::before{transform:rotate(90deg)}
  .fold-body{margin:0;padding:8px 10px;border:1px solid var(--line);border-radius:6px;
    background:var(--panel-2);color:var(--ink-2);font-size:12.5px;line-height:1.6;letter-spacing:.2px;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;word-break:break-word}
  .fold-body.open{white-space:pre-wrap;overflow:auto;text-overflow:clip;max-height:120px}
  .fold-body:empty{display:none}
  .modal{position:fixed;inset:0;background:rgba(60,48,36,.35);display:flex;
         align-items:center;justify-content:center;z-index:50}
  .modal-box{background:var(--panel);border:1px solid var(--line);border-radius:12px;
             padding:20px 22px;width:min(560px,92vw);box-shadow:0 12px 40px rgba(80,60,40,.22)}
  .modal-box h3{margin:0 0 16px;font-size:13px;letter-spacing:.6px;color:var(--ink-2)}
  .modal-box .row{margin-bottom:12px}
  .modal-box input[type=file]{padding:5px;font-size:12px}
  button.small{width:100%;padding:5px 10px;font-size:12px}
  #all-note{font-size:10.5px;min-height:13px;letter-spacing:.2px}
  #list{flex:1;min-height:0;overflow-y:auto;overflow-x:hidden;padding:2px 0 10px}
  .item{
    padding:9px 16px;cursor:pointer;display:flex;align-items:flex-start;gap:9px;
    border-left:3px solid transparent;transition:background .12s ease;
  }
  .item:hover{background:rgba(255,255,255,.55)}
  .item.on{background:linear-gradient(90deg,#fffdf8 0%,#f8f1e3 100%);
           border-left-color:var(--accent);box-shadow:0 1px 0 rgba(150,104,63,.06)}
  .item.on .ip{color:var(--accent)}
  .item .ip{font-size:13px;font-weight:500;letter-spacing:.2px;color:var(--ink)}
  .item .lb{font-size:11px;color:var(--ink-3);letter-spacing:.2px}
  .dot{position:relative;width:7px;height:7px;border-radius:50%;flex:none;margin-top:6px;
       box-shadow:0 0 0 2px rgba(255,255,255,.7)}
  .d0{background:#cfc3b1}.d1{background:#6fa07c}.d2{background:#c1705c}
  .dot.d1:after{content:"";position:absolute;inset:-3px;border-radius:50%;
                border:1.5px solid rgba(111,160,124,.45);animation:dotRing 2.4s ease-out infinite}
  @keyframes dotRing{0%{transform:scale(.65);opacity:.85}100%{transform:scale(1.7);opacity:0}}

  main{flex:1;min-width:0;overflow-y:auto;overflow-x:hidden;padding:18px 24px 28px}
  #tasks{overflow:auto;max-height:min(56vh,470px);border-radius:7px}

  .hdr{display:flex;align-items:center;gap:10px;flex-wrap:wrap;
       padding-bottom:13px;margin-bottom:18px;border-bottom:1px solid var(--line-soft)}
  .hdr h1{margin:0;font-size:15.5px;font-weight:600;letter-spacing:.3px;color:var(--ink)}
  .hdr .muted{font-size:12px}
  .hdr .spacer{flex:1}

  button{
    font:inherit;font-size:13px;padding:6px 16px;border-radius:6px;cursor:pointer;
    background:var(--accent);border:1px solid var(--accent-d);color:#fdfaf4;
    letter-spacing:.3px;transition:background .12s ease,box-shadow .12s ease;
    box-shadow:0 1px 2px rgba(125,85,51,.18);
  }
  button:hover{background:var(--accent-d)}
  button:active{box-shadow:none;transform:translateY(.5px)}
  button:disabled{opacity:.5;cursor:not-allowed;box-shadow:none}

  input,select{
    font:inherit;font-size:13px;color:var(--ink);
    background:#fffdf9;border:1px solid var(--line);border-radius:6px;
    padding:6px 10px;transition:border-color .12s ease,box-shadow .12s ease;
  }
  input:focus,select:focus{
    outline:none;border-color:#c8a986;
    box-shadow:0 0 0 3px rgba(150,104,63,.10);
  }
  input::placeholder{color:#bdb0a0}

  .row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:12px}
  .field{display:flex;flex-direction:column;gap:5px}
  .field label{font-size:11px;letter-spacing:.4px;color:var(--ink-3)}

  .chips{display:flex;gap:10px;flex-wrap:wrap;margin:2px 0 18px}
  .chip{
    position:relative;overflow:hidden;
    background:var(--panel);
    background:linear-gradient(180deg,color-mix(in srgb,var(--c) 8%,var(--panel)) 0%,var(--panel) 72%);
    border:1px solid var(--line);border-radius:10px;
    padding:9px 15px;min-width:86px;box-shadow:0 1px 2px rgba(120,95,60,.05);
    transition:transform .14s ease,box-shadow .14s ease;
  }
  .chip:before{content:"";position:absolute;left:13px;right:13px;top:0;height:3px;
               border-radius:0 0 3px 3px;background:var(--c);opacity:.7}
  .chip:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(120,95,60,.10)}
  .chip .k{font-size:10.5px;letter-spacing:.4px;color:var(--ink-3)}
  .chip .v{font-size:19px;font-weight:600;line-height:1.25;color:var(--c);font-variant-numeric:tabular-nums}

  table{width:100%;border-collapse:separate;border-spacing:0}
  th,td{padding:8px 10px;text-align:left;white-space:nowrap}
  th{
    position:sticky;top:0;z-index:2;
    font-size:10.5px;font-weight:600;letter-spacing:.7px;color:var(--ink-3);
    border-bottom:1px solid var(--line);background:var(--panel-2);
  }
  th:first-child{border-radius:7px 0 0 7px}
  th:last-child{border-radius:0 7px 7px 0}
  td{font-size:12.5px;color:var(--ink);border-bottom:1px solid var(--line-soft)}
  tbody tr{transition:background .12s ease}
  tbody tr:last-child td{border-bottom:none}
  tbody tr:hover td{background:rgba(255,255,255,.55)}
  tbody tr:hover td:first-child{box-shadow:inset 3px 0 0 rgba(150,104,63,.35)}
  .num{text-align:right;font-variant-numeric:tabular-nums}

  .c-critical{color:var(--crit);font-weight:600}
  .c-high{color:var(--high);font-weight:600}
  .c-medium{color:var(--med)}
  .c-low{color:var(--low)}

  .muted{color:var(--ink-3)}
  .ok{color:var(--ok);font-weight:500}
  .err{
    background:#fbeeea;border:1px solid #eccfc6;color:var(--crit);
    border-radius:8px;padding:8px 12px;margin-bottom:14px;font-size:12.5px;
  }

  .sec{
    background:var(--panel);border:1px solid var(--line);border-radius:10px;
    padding:14px 16px 16px;margin-bottom:16px;
    box-shadow:0 1px 3px rgba(120,95,60,.05);
  }
  .sec h3{
    display:flex;align-items:center;flex-wrap:wrap;row-gap:6px;gap:8px;margin:0 0 12px;
    font-size:11.5px;font-weight:600;letter-spacing:.8px;color:var(--ink-2);
  }
  .sec h3 .sp{flex:1}
  button.mini{width:auto;padding:3px 11px;font-size:11.5px;letter-spacing:.2px}
  #tasks tbody tr{cursor:pointer}
  #tasks td.ops,#tasks th.ops{text-align:right;white-space:nowrap}
  #tasks td.ops button{margin-left:5px;padding:2px 10px;font-size:11px}
  #tasks tbody tr.sel td{background:#f7efdf}
  #tasks tbody tr.sel td:first-child{box-shadow:inset 3px 0 0 var(--accent)}
  .sec h3 .muted{font-weight:400;letter-spacing:0}

  .tag{
    display:inline-flex;align-items:center;gap:5px;padding:1px 8px;border-radius:9px;font-size:11px;
    background:var(--line-soft);color:var(--ink-2);letter-spacing:.2px;
  }
  .tag i{width:5px;height:5px;border-radius:50%;background:currentColor;opacity:.65;flex:none}
  .s-running{background:#e2efe5;color:#3f6b4d}
  .s-paused{background:#f7ecd2;color:#8a6a2a}
  .s-queued,.s-created{background:#eae4d8;color:#7b6f61}

  details summary{cursor:pointer;font-size:11.5px;color:var(--ink-3);letter-spacing:.3px;outline:none}
  details summary:hover{color:var(--ink-2)}
  pre{
    margin:8px 0 0;white-space:pre-wrap;color:var(--ink-2);font-size:11.5px;
    line-height:1.6;max-height:120px;overflow:auto;
    background:#f8f3e9;border:1px solid var(--line-soft);border-radius:6px;padding:8px 10px;
  }

  .confirm{
    margin-top:12px;padding:11px 14px;border:1px solid #e2cbb0;border-radius:8px;
    background:#fbf3e5;color:var(--ink-2);font-size:12.5px;line-height:1.7;
    display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  }
  .confirm b{color:var(--ink);font-weight:600}
  .confirm[hidden]{display:none}
  .confirm .sp{flex:1}
  button.ghost{background:transparent;color:var(--ink-2);border:1px solid var(--line);box-shadow:none}
  button.ghost:hover{background:#f2ebdf;color:var(--ink)}

  textarea{
    width:100%;font:inherit;font-size:12.5px;color:var(--ink);background:#fffdf9;
    border:1px solid var(--line);border-radius:6px;padding:8px 10px;resize:vertical;
    line-height:1.6;
  }
  textarea:focus{outline:none;border-color:#c8a986;box-shadow:0 0 0 3px rgba(150,104,63,.10)}
  .reply{margin-top:12px;padding:11px 13px;background:#f8f3e9;border:1px solid var(--line-soft);
         border-radius:8px;font-size:12.5px;line-height:1.75;white-space:pre-wrap;word-break:break-word;
         max-height:320px;overflow:auto}
  .reply b{color:var(--accent)}
  .empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
         min-height:72vh;user-select:none}
  .placeholder{display:flex;flex-direction:column;align-items:center;justify-content:center;
               min-height:52vh;user-select:none}
  .slogan{display:flex;flex-direction:column;align-items:center;text-align:center}
  .wordmark{
    font-family:"Georgia","Times New Roman",serif;
    font-size:54px;font-weight:400;letter-spacing:16px;text-indent:16px;
    color:#e1d1b4;
    text-shadow:0 1px 0 rgba(255,255,255,.8), 0 -1px 0 rgba(160,130,90,.10);
  }
  .wordmark-sub{
    margin-top:2px;font-size:12px;letter-spacing:12px;text-indent:12px;
    color:#d7c6a8;font-weight:400;
  }
  .rule{
    width:180px;height:1px;margin:20px 0 16px;
    background:linear-gradient(90deg,rgba(220,206,183,0),rgba(214,198,172,.9),rgba(220,206,183,0));
  }
  .tagline{
    font-family:"Georgia","Times New Roman",serif;font-style:italic;
    font-size:13.5px;letter-spacing:1.4px;color:#cbb896;
  }

  body.dark{
    --bg:#1f1a15;--panel:#272119;--panel-2:#2f2820;--line:#3b332a;--line-soft:#332c24;
    --ink:#e6dccc;--ink-2:#bdb09e;--ink-3:#8a7d6c;
    --accent:#d0a271;--accent-d:#b98a55;--ok:#83b18e;--crit:#d97f68;--high:#d99a5f;
    --med:#c4ad63;--low:#86a9bd;
  }
  body.dark aside{background:linear-gradient(180deg,#28221b 0%,#231e18 100%)}
  body.dark input,body.dark select{background:#231e18}
  body.dark input::placeholder{color:#7b7062}
  body.dark .item:hover,body.dark tbody tr:hover td{background:rgba(255,255,255,.045)}
  body.dark .item.on{background:#2e271f;box-shadow:none}
  body.dark .icon:hover{background:#362e25}
  body.dark .switch .slider{background:#463c31}
  body.dark .switch .slider:before{background:#cfc4b3}
  body.dark .err{background:#3a2620;border-color:#5c352a}
  body.dark .modal{background:rgba(0,0,0,.55)}
  body.dark .modal-box{box-shadow:0 12px 40px rgba(0,0,0,.55)}
  body.dark .dot{box-shadow:0 0 0 2px rgba(0,0,0,.35)}
  body.dark .wordmark{color:#382f24;text-shadow:none}
  body.dark .wordmark-sub{color:#453a2c}
  body.dark .tagline{color:#4b3e2f}
  body.dark .rule{background:linear-gradient(90deg,rgba(80,66,50,0),rgba(90,75,56,.9),rgba(80,66,50,0))}
  body.dark *{scrollbar-color:#4a4036 transparent}
  body.dark ::-webkit-scrollbar-thumb{background:#4a4036;border-radius:4px;border:2px solid transparent;background-clip:content-box}

  /* —— 「全部任务」与全局细节 —— */
  .modal{backdrop-filter:blur(3px);animation:modalFade .15s ease}
  .modal-box{animation:modalPop .18s ease-out}
  @keyframes modalFade{from{opacity:0}}
  @keyframes modalPop{from{opacity:0;transform:translateY(8px) scale(.985)}}

  #btn-all{display:inline-flex;align-items:center;gap:6px}
  #btn-all svg{opacity:.7}
  #btn-all .cnt{min-width:18px;padding:0 6px;border-radius:8px;background:var(--panel-2);
                color:var(--ink-2);font-size:10.5px;line-height:16px;text-align:center;
                font-variant-numeric:tabular-nums}
  #btn-all:disabled .cnt{opacity:.6}

  .tasks-box{width:min(620px,94vw);padding:18px 20px 16px}
  .modal-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px}
  .modal-head h3{margin:0;font-size:14px;font-weight:600;letter-spacing:.4px;color:var(--ink)}
  .modal-sub{font-size:11.5px;color:var(--ink-3);margin-top:3px;line-height:1.5}
  .modal-head .icon{margin-left:auto;flex:none;border-radius:7px;height:26px}
  .tlist{max-height:min(56vh,520px);overflow-y:auto;margin:2px -4px 0;padding:0 4px}
  .trow{display:flex;align-items:center;gap:9px;padding:8px 10px;margin-bottom:6px;
        border:1px solid var(--line-soft);border-radius:8px;background:var(--panel);
        cursor:grab;user-select:none;
        transition:background .12s ease,border-color .12s ease,box-shadow .12s ease}
  .trow:hover{border-color:var(--line);box-shadow:0 1px 3px rgba(120,95,60,.06)}
  .trow.on{background:#fbf6eb;border-color:#eadcc6}
  .trow.dragging{opacity:.45;border-style:dashed;cursor:grabbing}
  .grip{width:10px;height:16px;flex:none;color:var(--ink-3);opacity:.65;
        background-image:radial-gradient(currentColor 1px,transparent 1.2px);
        background-size:5px 5px;background-position:0 1px}
  .rank{width:20px;height:20px;line-height:20px;flex:none;border-radius:50%;
        background:var(--panel-2);color:var(--ink-3);font-size:10.5px;text-align:center;
        font-variant-numeric:tabular-nums}
  .trow.on .rank{background:var(--accent);color:#fdfaf4}
  .tid{flex:none;font-size:11px;color:var(--ink-3);font-variant-numeric:tabular-nums}
  .tname{flex:1;min-width:0;font-size:12.5px;color:var(--ink);
         overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .trow .tag{flex:none}
  .tshow{flex:none;padding:0 6px;border:1px solid rgba(150,104,63,.35);border-radius:8px;
         color:var(--accent);font-size:10px;letter-spacing:.3px}
  .tcut{display:flex;align-items:center;gap:8px;margin:8px 2px 7px;
        color:var(--ink-3);font-size:10.5px;letter-spacing:.2px}
  .tcut:before,.tcut:after{content:"";height:1px;background:var(--line);flex:1}
  .modal-foot{display:flex;align-items:center;gap:10px;margin-top:12px;padding-top:12px;
              border-top:1px solid var(--line-soft)}
  .modal-foot .sp{flex:1}

  /* 服务器文件 */
  .ws-box{width:min(780px,95vw);padding:18px 20px 16px}
  .ws-bar{display:flex;align-items:center;gap:8px;margin:4px 0 6px}
  .ws-bar .icon{height:24px;min-width:27px;padding:0 6px}
  .ws-path{font-size:11.5px;color:var(--ink-3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .ws-path b{color:var(--ink);font-weight:500}
  .ws-path a{color:var(--accent);cursor:pointer;text-decoration:none}
  .ws-path a:hover{text-decoration:underline}
  .ws-path .sep{margin:0 5px;color:var(--ink-3)}
  .ws-quick{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 8px}
  .ws-chip{font:inherit;font-size:11px;padding:2px 10px;border-radius:12px;border:1px solid var(--line);
           background:var(--panel-2);color:var(--ink-2);cursor:pointer;box-shadow:none;
           transition:border-color .12s ease,color .12s ease}
  .ws-chip:hover{border-color:#d7c2a4;color:var(--ink);background:var(--panel-2)}
  .ws-chip.on{border-color:var(--accent);color:var(--accent)}
  .ws-list{max-height:min(54vh,470px);overflow:auto;border:1px solid var(--line-soft);border-radius:8px}
  .ws-table{width:100%;border-collapse:collapse;table-layout:fixed}
  .ws-table th{position:sticky;top:0;z-index:1;background:var(--panel-2);
               font-size:10.5px;letter-spacing:.6px;color:var(--ink-3);font-weight:500;
               text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}
  .ws-table td{padding:6px 10px;font-size:12.5px;border-bottom:1px solid var(--line-soft);white-space:nowrap}
  .ws-table tbody tr:last-child td{border-bottom:none}
  .ws-table tbody tr{cursor:pointer}
  .ws-table tbody tr:hover td{background:rgba(255,255,255,.55)}
  .ws-table tr.on td{background:#f7efdf}
  .ws-table tr.on td:first-child{box-shadow:inset 3px 0 0 var(--accent)}
  .ws-table th.wsc,.ws-table td.wsc{width:30px;padding-right:0;text-align:center}
  .ws-table .wsize{text-align:right;font-variant-numeric:tabular-nums;color:var(--ink-3);width:92px}
  .ws-table .wtime{color:var(--ink-3);width:154px}
  .ws-table .wname{display:flex;align-items:center;gap:8px;min-width:0}
  .ws-table .wname .nm{overflow:hidden;text-overflow:ellipsis;min-width:0;flex:0 1 auto}
  .ws-table .wname .sub{color:var(--ink-3);font-size:11px;margin-left:6px;overflow:hidden;text-overflow:ellipsis;flex:none;max-width:45%}
  .ws-ico{flex:none;width:15px;height:15px;color:var(--ink-3);opacity:.8}
  .ws-ico.dir{color:var(--accent);opacity:.9}
  .ws-empty,.ws-loading{padding:26px 0;text-align:center;color:var(--ink-3);font-size:12px}
  .ws-count{font-variant-numeric:tabular-nums}
  input[type=checkbox]{accent-color:var(--accent)}
  .ws-table input[type=checkbox]{width:13px;height:13px;margin:0;vertical-align:-2px}

  /* 危险操作 */
  button.danger{background:transparent;color:var(--crit);border-color:#e0c3b8;box-shadow:none}
  button.danger:hover:not(:disabled){background:#fbeeea;color:#963a27}
  button#del-confirm{background:var(--crit);border-color:#8f3524;color:#fffaf4;
                     box-shadow:0 1px 2px rgba(120,45,30,.2)}
  button#del-confirm:hover:not(:disabled){background:#8f3524}
  .del-box{width:min(560px,94vw)}
  .del-warn{background:#fbeeea;border:1px solid #eccfc6;color:var(--crit);border-radius:8px;
            padding:9px 12px;font-size:12px;line-height:1.6;margin-bottom:10px}
  .del-stat{font-size:12px;color:var(--ink-2);background:var(--panel-2);border:1px solid var(--line-soft);
            border-radius:7px;padding:7px 11px;margin-bottom:8px;line-height:1.6}
  .del-opts{display:flex;flex-direction:column;gap:1px;max-height:min(38vh,300px);
            overflow:auto;margin-bottom:8px}
  .opt,.ack{display:flex;align-items:flex-start;gap:9px;padding:7px 8px;border-radius:7px;
            cursor:pointer;transition:background .12s ease}
  .opt:hover,.ack:hover{background:var(--panel-2)}
  .opt input,.ack input{margin:3px 0 0;flex:none}
  .opt b{display:block;font-weight:500;font-size:12.5px;color:var(--ink)}
  .opt em{display:block;font-style:normal;font-size:11px;color:var(--ink-3);line-height:1.55;margin-top:1px}
  .opt.all{border:1px dashed var(--line);margin-bottom:4px}
  .ack{margin:0;border-top:1px solid var(--line-soft);border-radius:0;padding-top:9px}
  .ack span{font-size:12px;color:var(--ink-2)}

  .t-empty{display:flex;flex-direction:column;align-items:center;gap:7px;
           padding:30px 0 26px;color:var(--ink-3);font-size:12px}
  .t-empty svg{opacity:.45}

  .toast{position:fixed;left:50%;bottom:26px;z-index:80;transform:translate(-50%,12px);
         padding:8px 16px;border-radius:20px;background:#3d342a;color:#fdf8ee;
         font-size:12.5px;letter-spacing:.2px;box-shadow:0 8px 24px rgba(60,45,30,.28);
         opacity:0;pointer-events:none;transition:opacity .18s ease,transform .18s ease}
  .toast.show{opacity:1;transform:translate(-50%,0)}

  :focus-visible{outline:2px solid rgba(150,104,63,.45);outline-offset:2px}
  input:focus-visible,select:focus-visible,textarea:focus-visible{outline:none}

  body.dark .trow{background:#241f18}
  body.dark .trow:hover{border-color:#463a2c;box-shadow:none}
  body.dark .trow.on{background:#2f2820;border-color:#4a3c2c}
  body.dark .trow.on .rank{color:#231e18}
  body.dark #tasks tbody tr.sel td{background:#332b22}
  body.dark .ws-table th{background:#2f2820}
  body.dark .ws-table tbody tr:hover td{background:rgba(255,255,255,.045)}
  body.dark .ws-table tr.on td{background:#332b22}
  body.dark .ws-chip{background:#2f2820}
  body.dark .ws-chip:hover{border-color:#4a3c2c;background:#2f2820}
  body.dark .del-warn{background:#3a2620;border-color:#5c352a}
  body.dark .del-stat{background:#2f2820}
  body.dark button.danger{color:var(--crit);border-color:#5c352a}
  body.dark button.danger:hover:not(:disabled){background:#3a2620}
  body.dark button#del-confirm{background:#b4543d;border-color:#8f3524;color:#231e18}
  body.dark .toast{background:#e6dccc;color:#231e18;box-shadow:0 8px 24px rgba(0,0,0,.45)}
  body.dark .dot.d1:after{border-color:rgba(131,177,142,.5)}
  body.dark .chip{background:var(--panel);
                  background:linear-gradient(180deg,color-mix(in srgb,var(--c) 12%,var(--panel)) 0%,var(--panel) 72%)}

  button{position:relative;overflow:hidden;transform:translateY(0);transition:background .14s ease,box-shadow .14s ease,transform .14s ease}
  button:hover:not(:disabled){transform:translateY(-1px)}
  button:active:not(:disabled){transform:translateY(1px) scale(.985)}
  .ripple{position:absolute;border-radius:50%;background:currentColor;opacity:.13;pointer-events:none;
          transform:scale(0);animation:rippleOut .45s ease-out}
  @keyframes rippleOut{to{transform:scale(3);opacity:0}}
  .view-enter{animation:viewIn .22s ease-out}
  @keyframes viewIn{from{opacity:0;transform:translateY(5px)}}
  .modal.closing{animation:modalOut .14s ease forwards}
  .modal.closing .modal-box{animation:modalBoxOut .14s ease forwards}
  @keyframes modalOut{to{opacity:0}}
  @keyframes modalBoxOut{to{opacity:0;transform:translateY(6px) scale(.985)}}
  button.chip{font:inherit;text-align:left;cursor:pointer;color:var(--ink);transform:translateY(0)}
  button.chip:active:not(:disabled){transform:translateY(1px) scale(.985)}
  .chip.active{border-color:var(--c);box-shadow:0 0 0 2px color-mix(in srgb,var(--c) 16%,transparent),0 5px 15px rgba(120,95,60,.10)}
  .chip.active:after{content:"✓";position:absolute;right:9px;bottom:8px;color:var(--c);font-size:10px;font-weight:700}
  .chip .v{transition:transform .18s ease}
  .chip.bump .v{animation:valueBump .25s ease}
  @keyframes valueBump{50%{transform:translateY(-2px) scale(1.08)}}
  .state-icon{width:44px;height:44px;border:1px solid var(--line);border-radius:50%;display:grid;place-items:center;
              color:var(--accent);font-size:24px;margin-bottom:14px;background:var(--panel)}
  .state-title{font-size:14px;color:var(--ink-2);margin-bottom:4px}.placeholder{min-height:42vh;text-align:center}
  .skeleton{display:flex;gap:8px;margin-top:22px}.skeleton i{width:72px;height:7px;border-radius:5px;background:var(--line);
              animation:skeletonPulse 1.1s ease-in-out infinite alternate}.skeleton i:nth-child(2){animation-delay:.18s}.skeleton i:nth-child(3){animation-delay:.36s}
  @keyframes skeletonPulse{to{opacity:.3;transform:scaleX(.8)}}
  .empty-table{display:flex;align-items:center;justify-content:center;gap:9px;min-height:80px;color:var(--ink-3);
               border:1px dashed var(--line);border-radius:8px;background:color-mix(in srgb,var(--panel-2) 45%,transparent)}
  .empty-table:before{content:"◇";font-size:18px;opacity:.6}
  .overview-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(265px,1fr));gap:14px}
  .machine-card{position:relative;text-align:left;padding:16px 17px;border:1px solid var(--line);border-radius:12px;
                background:var(--panel);color:var(--ink);cursor:pointer;box-shadow:0 2px 7px rgba(120,95,60,.05);
                transition:transform .16s,border-color .16s,box-shadow .16s;animation:viewIn .22s ease both}
  .machine-card:hover{transform:translateY(-3px);border-color:#cfb99b;box-shadow:0 8px 22px rgba(120,95,60,.11)}
  .machine-card .mc-head{display:flex;align-items:center;gap:8px}.machine-card .mc-ip{font-weight:600;font-size:14px}
  .machine-card .mc-label{font-size:11px;color:var(--ink-3);margin:2px 0 13px}.machine-card .mc-stats{display:grid;
                grid-template-columns:repeat(4,1fr);gap:8px}.machine-card .mc-stat{padding:7px 4px;border-radius:7px;
                background:var(--panel-2);text-align:center}.machine-card .mc-stat b{display:block;font-size:17px;line-height:1.3}
  .machine-card .mc-stat span{font-size:10px;color:var(--ink-3)}.machine-card .mc-foot{margin-top:12px;font-size:11px;color:var(--ink-3)}
  .machine-card .mc-error{margin-top:10px;color:var(--crit);font-size:11px;white-space:normal}
  .unread{display:inline-flex;align-items:center;justify-content:center;min-width:17px;height:17px;padding:0 5px;
          border-radius:9px;background:var(--crit);color:#fff;font-size:9.5px;line-height:1;margin-left:5px;animation:unreadPop .25s ease}
  @keyframes unreadPop{from{transform:scale(.4);opacity:0}}
  .item .unread{position:absolute;right:12px;top:10px}.item{position:relative}.item .ops{position:relative;z-index:2}
  .task-unread{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--crit);margin-left:6px;box-shadow:0 0 0 3px color-mix(in srgb,var(--crit) 12%,transparent)}
  .progress{height:5px;border-radius:4px;background:var(--line-soft);overflow:hidden;margin-top:12px}
  .progress>div{height:100%;width:12%;border-radius:inherit;background:var(--accent);transition:width .35s ease}
  .progress.indeterminate>div{animation:progressSlide 1.15s ease-in-out infinite}
  @keyframes progressSlide{0%{transform:translateX(-100%)}100%{transform:translateX(850%)}}
  .ask-history{margin-top:12px}.ask-history details{border:1px solid var(--line-soft);border-radius:8px;margin-top:7px;
               background:color-mix(in srgb,var(--panel-2) 45%,transparent);overflow:hidden;animation:viewIn .18s ease}
  .ask-history summary{padding:8px 11px;color:var(--ink-2)}.ask-history .qa{padding:0 11px 10px;white-space:pre-wrap;
               word-break:break-word;font-size:12px}.ask-history .qa b{display:block;color:var(--accent);margin:5px 0 2px}
  #btn-mobile-side{display:none;margin-bottom:10px}#side-scrim{position:fixed;inset:0;background:rgba(30,22,15,.35);z-index:25}
  @media(max-width:1050px){.chips{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))}.chip{min-width:0}}
  @media(max-width:760px){
    aside{position:fixed;left:0;top:0;bottom:0;z-index:30;width:min(270px,82vw);transform:translateX(-102%);transition:transform .2s ease;box-shadow:8px 0 30px rgba(50,35,20,.16)}
    body.mobile-side aside{transform:translateX(0)}body.collapsed aside{width:min(270px,82vw)}
    body.collapsed .side-brand,body.collapsed .side-title,body.collapsed .side-actions{display:block}
    body.collapsed .item{justify-content:flex-start;padding:9px 16px;border-left-width:3px}
    body.collapsed .item .ip,body.collapsed .item .lb,body.collapsed .item .ops{display:block}
    #btn-mobile-side{display:block}main{padding:14px 15px 24px}.hdr{margin-bottom:14px}.overview-grid{grid-template-columns:1fr}
    .modal-box{max-height:92vh;overflow:auto}.tasks-box{padding:16px 14px}.trow .tag{display:none}
    .ws-box,.del-box{width:96vw;padding:15px 14px}
    .ws-table .wtime,.ws-table th.wtime{display:none}
    .ws-table .wsize{width:70px}
  }
  @media(max-width:520px){.chips{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.chip{padding:9px 12px}.hdr h1{font-size:14px}
    #p-time{width:100%;order:5}.row{gap:10px}.wordmark{font-size:42px;letter-spacing:10px;text-indent:10px}.trow .tid{display:none}}
  @media (prefers-reduced-motion: reduce){
    *,*:before,*:after{animation:none !important;transition:none !important}
  }
</style>
</head>
<body>
<script>try{if(localStorage.getItem('artex_theme')==='1')document.body.classList.add('dark')}catch(e){}</script>
<div class="app">
  <aside id="sidebar">
    <div class="side-head">
      <div class="side-brand">
        <div class="brand">ARTEX Controller</div>
        <small data-i18n="sub_local">仅本地 · 连接后自动刷新</small>
      </div>
      <button id="btn-collapse" class="icon collapser" title="折叠侧栏" data-i18n-title="collapse">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor"
             stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="4" width="18" height="16" rx="2.5"></rect>
          <path d="M9.5 4v16"></path>
        </svg>
      </button>
    </div>
    <div class="side-title" data-i18n="servers">服务器列表</div>
    <div class="side-actions">
      <button id="btn-overview" class="mini ghost" data-i18n="overview">全部服务器</button>
      <div class="row">
        <button id="btn-add" class="mini ghost" data-i18n="add">＋ 添加</button>
        <button id="btn-edit" class="mini ghost" data-i18n="edit">编辑</button>
      </div>
      <div id="all-note" class="muted"></div>
    </div>
    <div id="list"></div>
    <div class="side-foot">
      <button id="btn-theme" class="icon foot-btn" title="夜间模式" data-i18n-title="theme_dark">
        <svg id="ico-moon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
             stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
          <path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11z"></path>
        </svg>
        <svg id="ico-sun" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
             stroke-width="1.7" stroke-linecap="round">
          <circle cx="12" cy="12" r="4.2"></circle>
          <path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"></path>
        </svg>
      </button>
      <button id="btn-settings" class="icon foot-btn" title="设置" data-i18n-title="settings">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
             stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="3"></circle>
          <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.55-1 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.01a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55h.01a1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.01a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.55 1z"></path>
        </svg>
      </button>
    </div>
  </aside>
  <div id="side-scrim" hidden></div>
  <main>
    <button id="btn-mobile-side" class="icon" title="服务器列表" data-i18n-title="servers">☰</button>
    <div id="overview" hidden>
      <div class="hdr"><h1 data-i18n="overview">全部服务器</h1><span class="muted" id="o-time"></span><span class="spacer"></span>
        <button id="btn-refresh-all" class="ghost" data-i18n="refresh_all">刷新全部</button></div>
      <div class="chips" id="o-chips"></div>
      <div id="o-cards" class="overview-grid"></div>
    </div>
    <div id="empty" class="empty"><div class="slogan"><div class="wordmark">ARTEX</div><div class="wordmark-sub">CONTROLLER</div><div class="rule"></div><div class="tagline">Easy to wire, built to control.</div></div></div>
    <div id="panel" hidden>
      <div class="hdr">
        <h1 id="p-ip"></h1><span class="muted" id="p-label"></span>
        <span style="flex:1"></span>
        <button id="btn-files" class="ghost mini" data-i18n="files" data-i18n-title="files_title">文件</button>
        <span class="muted" id="p-time" style="font-size:11.5px"></span>
        <input id="p-pw" type="password" placeholder="SSH 密码" data-i18n-ph="ssh_pw_ph" style="width:150px" hidden>
        <label class="switch" title="连接后自动刷新" data-i18n-title="auto_refresh_title">
          <input type="checkbox" id="p-conn">
          <span class="slider"></span>
        </label>
        <span id="conn-label" class="muted" style="font-size:11.5px;min-width:92px">未连接</span>
      </div>
      <div id="p-err" class="err" hidden><div id="p-err-text"></div><details><summary data-i18n="error_details">详细原因</summary><pre id="p-err-detail"></pre></details></div>
      <div id="p-placeholder" class="placeholder" hidden>
        <div class="state-icon">⌁</div><div id="p-state-title" class="state-title" data-i18n="empty_title">选择右上角开关建立连接</div>
        <div id="p-state-sub" class="muted" data-i18n="empty_hint">连接成功后会自动加载任务与漏洞概览</div>
        <div id="connect-skeleton" class="skeleton" hidden><i></i><i></i><i></i></div>
      </div>
      <div id="p-body" hidden>
        <div class="chips" id="chips"></div>
        <div class="sec">
          <h3><span data-i18n="recent_tasks">最近任务</span> <span class="muted" id="t-note"></span><span class="sp"></span>
            <button id="btn-all" class="ghost mini" disabled data-i18n-title="all_tasks_title">
              <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor"
                   stroke-width="2" stroke-linecap="round">
                <path d="M8 6h12M8 12h12M8 18h12"></path>
                <circle cx="4" cy="6" r="1.2" fill="currentColor" stroke="none"></circle>
                <circle cx="4" cy="12" r="1.2" fill="currentColor" stroke="none"></circle>
                <circle cx="4" cy="18" r="1.2" fill="currentColor" stroke="none"></circle>
              </svg>
              <span data-i18n="all_tasks">全部任务</span><span class="cnt" id="all-count">0</span>
            </button>
            <button id="btn-export" class="ghost mini" disabled data-i18n="export">导出报告</button>
            <button id="btn-del-task" class="ghost mini danger" disabled data-i18n="delete_task">删除任务</button></h3>
          <div id="tasks"></div>
          <div id="exp-progress" class="progress" hidden><div id="exp-bar"></div></div>
          <div id="exp-msg" class="muted" style="margin-top:8px;font-size:12px"></div>
        </div>

        <div class="sec" id="ask-sec" hidden>
          <h3><span data-i18n="ask_main">提问主 Agent</span> · <span id="ask-title" style="color:var(--ink)"></span>
            <span class="sp"></span>
            <button id="btn-copy-reply" class="ghost mini" hidden data-i18n="copy_reply">复制回复</button>
            <span id="ask-status" class="muted"></span>
          </h3>
          <textarea id="ask-msg" rows="3" placeholder="输入要给主 Agent 的指令或问题，Ctrl+Enter 发送" data-i18n-ph="ask_ph"></textarea>
          <div class="row" style="margin-top:10px;margin-bottom:0">
            <button id="btn-ask" data-i18n="send">发送</button>
            <span class="muted" style="font-size:11.5px" data-i18n="ask_hint">点任务行右侧「提问」切换目标任务</span>
          </div>
          <div id="ask-reply" class="reply" hidden></div>
          <div id="ask-history" class="ask-history"></div>
        </div>
      </div>
      <div class="sec" id="dispatch-sec" hidden>
        <h3 data-i18n="dispatch">下发任务</h3>
        <div class="row">
          <div class="field" style="flex:1;min-width:220px">
            <label data-i18n="name_url">名称 / 网址</label>
            <input id="f-name" placeholder="example.com">
          </div>
          <div class="field" style="min-width:230px">
            <label data-i18n="inherit">继承任务（可选）</label>
            <select id="f-src"><option value="" data-i18n="no_inherit">不继承 · 用固定模板</option></select>
          </div>
          <div class="field" style="min-width:110px">
            <label data-i18n="duration">时长（分钟）</label>
            <input id="f-timeout" type="number" style="width:100px">
          </div>
        </div>

        <!-- 不继承：描述自动 + 目标固定 -->
        <div id="f-auto" style="margin-bottom:10px">
          <div class="field">
            <div class="auto-row">
              <button type="button" class="fold-tri" id="desc-toggle" aria-expanded="false" aria-controls="f-desc-auto" title="展开 / 收起描述" data-i18n-title="desc_toggle_title"></button>
              <label data-i18n="desc_auto">描述（自动生成）</label>
              <a class="lnk" id="lnk-desc" title="临时修改本次任务的描述" data-i18n="edit_short" data-i18n-title="edit_desc_title">编辑</a>
            </div>
            <div class="fold-body" id="f-desc-auto"></div>
            <textarea id="f-desc-tmp" rows="2" hidden placeholder="临时修改本次任务的描述" data-i18n-ph="edit_desc_title"></textarea>
          </div>
          <div class="field" style="margin-top:8px">
            <div class="auto-row">
              <button type="button" class="fold-tri" id="goal-toggle" aria-expanded="false" aria-controls="f-goal-fixed" title="展开 / 收起目标" data-i18n-title="goal_toggle_title"></button>
              <label data-i18n="goal_fixed">目标（默认）</label>
              <a class="lnk" id="lnk-goal" title="临时修改本次任务的目标" data-i18n="edit_short" data-i18n-title="edit_goal_title">编辑</a>
            </div>
            <div class="fold-body" id="f-goal-fixed"></div>
            <textarea id="f-goal-tmp" rows="3" hidden placeholder="临时修改本次任务的目标" data-i18n-ph="edit_goal_title"></textarea>
          </div>
        </div>

        <!-- 继承：描述和目标自己填 -->
        <div id="f-manual" hidden>
          <div class="field" style="margin-bottom:10px">
            <label data-i18n="desc_req">描述（继承任务时必填）</label>
            <textarea id="f-desc" rows="2" placeholder="例如：在 xxx 基础上做二次利用验证" data-i18n-ph="desc_ph"></textarea>
          </div>
          <div class="field" style="margin-bottom:10px">
            <label data-i18n="goal_req">目标（继承任务时必填）</label>
            <textarea id="f-goal" rows="3" placeholder="例如：拿到该后台的管理权限" data-i18n-ph="goal_ph"></textarea>
          </div>
        </div>

        <div class="row">
          <div class="field" style="min-width:240px">
            <label><span data-i18n="llm">LLM</span> <span class="muted" style="letter-spacing:0" data-i18n="llm_note">（使用服务器中设定配置）</span></label>
            <select id="f-llm"><option value="" data-i18n="llm_ph">（刷新后可选）</option></select>
          </div>
          <div class="field" style="flex:1">
            <label>&nbsp;</label>
            <div><button id="btn-send" data-i18n="send_task">下发</button> <span id="f-msg"></span></div>
          </div>
        </div>
        <div id="f-confirm" class="confirm" hidden>
          <span id="f-confirm-text"></span>
          <span class="sp"></span>
          <button id="btn-confirm-send" data-i18n="confirm_send">确认下发</button>
          <button id="btn-cancel-send" class="ghost" data-i18n="cancel">取消</button>
        </div>
      </div>
    </div>
  </main>
</div>

<div id="m-modal" class="modal" hidden>
  <div class="modal-box">
    <h3 id="m-title">添加机器</h3>
    <div class="row">
      <div class="field" style="flex:1">
        <label data-i18n="ip_host">IP / 主机名</label>
        <input id="m-ip" placeholder="1.2.3.4">
      </div>
      <div class="field" style="width:92px">
        <label data-i18n="ssh_port">SSH 端口</label>
        <input id="m-port" type="number" value="22">
      </div>
      <div class="field" style="width:112px">
        <label title="目标机器上 ARTEX 监听的端口" data-i18n="artex_port" data-i18n-title="artex_port_title">ARTEX 端口</label>
        <input id="m-artex-port" type="number" placeholder="8787" value="8787">
      </div>
    </div>
    <div class="muted" style="font-size:11px;margin:-4px 0 10px" data-i18n="port_hint">
      SSH 端口用于登录（一般 22）；ARTEX 端口是目标机器上 ARTEX 网页监听的端口（默认 8787，改了才需要动）
    </div>
    <div class="row">
      <div class="field" style="flex:1">
        <label data-i18n="note_label">备注</label>
        <input id="m-label" placeholder="机器1">
      </div>
      <div class="field" style="width:120px">
        <label data-i18n="user_label">用户</label>
        <input id="m-user" value="root">
      </div>
    </div>
    <div class="row">
      <div class="field" style="flex:1">
        <label data-i18n="auth">认证方式</label>
        <select id="m-auth">
          <option value="pwd" data-i18n="pwd">密码</option>
          <option value="key" data-i18n="keyfile">密钥文件</option>
        </select>
      </div>
    </div>
    <div id="m-pwd-box" class="field">
      <label data-i18n="ssh_pw">SSH 密码</label>
      <input id="m-pwd" type="password" placeholder="编辑时留空＝不修改" data-i18n-ph="leave_blank">
    </div>
    <div id="m-key-box" class="field" hidden>
      <label data-i18n="key_hint">私钥文件（会复制到程序目录 keys/ 下）</label>
      <input id="m-keyfile" type="file">
      <div id="m-keyinfo" class="muted" style="font-size:11px;margin-top:4px"></div>
    </div>
    <div class="row">
      <div class="field" style="flex:1">
        <label data-i18n="artex_user">ARTEX 网页账号</label>
        <input id="m-artex-user" placeholder="ARTEX">
      </div>
      <div class="field" style="flex:1">
        <label data-i18n="artex_pw">ARTEX 网页密码</label>
        <input id="m-artex-pwd" type="password" placeholder="编辑时留空＝不修改" data-i18n-ph="leave_blank">
      </div>
    </div>
    <div class="muted" style="font-size:11px;margin:-4px 0 10px" data-i18n="artex_ph_hint">
      用于登录目标机上的 ARTEX 控制台；留空则回退到 config.toml [defaults] 的 login_user / login_password
    </div>
    <div class="row" style="margin-top:16px;margin-bottom:0;align-items:center">
      <button id="m-save" data-i18n="save">保存</button>
      <button id="m-cancel" class="ghost" data-i18n="cancel">取消</button>
      <span id="m-msg" class="muted" style="font-size:12px"></span>
    </div>
  </div>
</div>

<div id="t-modal" class="modal" hidden>
  <div class="modal-box tasks-box">
    <div class="modal-head">
      <div>
        <h3 data-i18n="all_tasks">全部任务</h3>
        <div class="modal-sub"><span id="t-sub-ip"></span> · <span id="t-sub"></span></div>
      </div>
      <button id="t-close" class="icon" title="关闭" data-i18n-title="close">✕</button>
    </div>
    <div id="t-list" class="tlist"></div>
    <div class="modal-foot">
      <span id="t-msg" class="muted" style="font-size:11.5px"></span>
      <span class="sp"></span>
      <button id="t-cancel" class="ghost" data-i18n="cancel">取消</button>
      <button id="t-save" data-i18n="save">保存</button>
    </div>
  </div>
</div>

<div id="ws-modal" class="modal" hidden>
  <div class="modal-box ws-box">
    <div class="modal-head">
      <div>
        <h3 data-i18n="ws_title">服务器文件</h3>
        <div class="modal-sub"><span id="ws-ip"></span> · <span id="ws-sub"></span></div>
      </div>
      <button id="ws-close" class="icon" data-i18n-title="close">✕</button>
    </div>
    <div class="ws-bar">
      <button id="ws-up" class="icon" data-i18n-title="ws_up">↑</button>
      <div id="ws-path" class="ws-path"></div>
      <span class="sp"></span>
      <button id="ws-refresh" class="ghost mini" data-i18n="ws_refresh">刷新</button>
    </div>
    <div id="ws-quick" class="ws-quick"></div>
    <div id="ws-list" class="ws-list"></div>
    <div class="modal-foot">
      <span id="ws-msg" class="muted"></span>
      <span class="sp"></span>
      <span id="ws-count" class="muted"></span>
      <button id="ws-download" disabled data-i18n="ws_download">下载所选</button>
    </div>
  </div>
</div>

<div id="del-modal" class="modal" hidden>
  <div class="modal-box del-box">
    <div class="modal-head">
      <div>
        <h3 data-i18n="delete_task">删除任务</h3>
        <div class="modal-sub" id="del-sub"></div>
      </div>
      <button id="del-close" class="icon" data-i18n-title="close">✕</button>
    </div>
    <div class="del-warn" data-i18n="del_warn">删除后无法恢复。正在运行的任务会先被中止。</div>
    <div id="del-stat" class="del-stat"></div>
    <div class="del-opts">
      <label class="opt all"><input type="checkbox" id="del-all"><span><b data-i18n="del_all">全部关联数据</b><em data-i18n="del_all_hint">包括资产、流量、文件、漏洞和 LLM 请求/响应记录。</em></span></label>
      <label class="opt"><input type="checkbox" data-opt="delete_files"><span><b data-i18n="del_files">任务文件</b><em data-i18n="del_files_hint">删除该任务工作目录中的上传文件、命令输出和其他产物。</em></span></label>
      <label class="opt"><input type="checkbox" data-opt="delete_assets"><span><b data-i18n="del_assets">关联资产</b><em data-i18n="del_assets_hint">删除仅属于该任务的资产；共享资产只解除关联。</em></span></label>
      <label class="opt"><input type="checkbox" data-opt="delete_traffic"><span><b data-i18n="del_traffic">关联流量</b><em data-i18n="del_traffic_hint">按关联资产的主机名删除；仍被其他任务引用的流量会保留。</em></span></label>
      <label class="opt"><input type="checkbox" data-opt="delete_findings"><span><b data-i18n="del_findings">关联漏洞</b><em data-i18n="del_findings_hint">永久删除该任务产生的独立漏洞记录与漏洞报告。</em></span></label>
      <label class="opt"><input type="checkbox" data-opt="delete_llm_records"><span><b data-i18n="del_llm">LLM 记录</b><em data-i18n="del_llm_hint">删除该任务的 LLM 请求与响应记录。</em></span></label>
    </div>
    <label class="ack"><input type="checkbox" id="del-ack"><span data-i18n="del_ack">我已知晓该操作不可恢复</span></label>
    <div class="modal-foot">
      <span id="del-msg" class="muted"></span>
      <span class="sp"></span>
      <button id="del-cancel" class="ghost" data-i18n="cancel">取消</button>
      <button id="del-confirm" class="danger" disabled data-i18n="del_confirm">确认删除</button>
    </div>
  </div>
</div>
<div id="toast" class="toast"></div>

<script>
let MACHINES = [], CUR = null, CFG = {}, PWD = {}, REFRESHED = {}, SEL = null, ASK = null;
let T_ORDER = null, T_ORIG = '', DRAG_ID = null, FILTER = null, OVERVIEW = false;
let WANTED = {}, RECONNECT = {}, UNREAD = {}, TASK_UNREAD = {}, EXPORTING = {}, EXPORT_RESULTS = {};
const $ = id => document.getElementById(id);
const esc = s => String(s==null?"":s).replace(/[&<>"]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

let LANG = 'zh';
const I18N = {
  zh: {
    sub_local: '仅本地 · 连接后自动刷新',
    collapse: '折叠侧栏', expand: '展开侧栏',
    servers: '服务器列表', add: '＋ 添加', edit: '编辑', done: '完成',
    del: '删除', no_creds: ' · 未配凭据',
    theme_dark: '夜间模式', theme_light: '日间模式', settings: '设置',
    ssh_pw_ph: 'SSH 密码', auto_refresh_title: '连接后自动刷新',
    disconnected: '未连接', connected: '已连接 · 自动刷新', connecting: '连接中…',
    refreshed_at: '刷新于 ',
    tasks_total: '任务', running: '运行中', paused: '暂停', critical: '严重',
    high: '高危', medium: '中危', low: '低危', intent: '意图',
    tasks_note: '（显示 {1} 个 / 共 {2} 个）',
    tasks_note_custom: '（自定义顺序 · 显示 {1} / 共 {2}）',
    all_tasks: '全部任务', all_tasks_title: '查看全部任务并调整展示顺序',
    all_sub: '共 {1} 个任务 · 拖动任务块调整顺序，前 5 个显示在「最近任务」',
    all_sub_short: '共 {1} 个任务',
    cut_label: '以上 5 项显示在「最近任务」', show_badge: '展示中',
    drag_hint: '拖动任务块调整顺序', order_dirty: '顺序已调整，点「保存」后长期生效',
    order_saved: '✓ 展示顺序已保存', order_fail: '顺序保存失败', close: '关闭',
    th_task: '任务', th_status: '状态', ask: '提问',
    no_tasks: '这台机器还没有任务',
    st_running: '运行中', st_paused: '暂停', st_queued: '排队中', st_created: '已创建',
    st_completed: '已完成', st_failed: '失败', st_stopped: '已停止',
    pause: '暂停', resume: '继续', pausing: '暂停中…', resuming: '继续中…',
    recent_tasks: '最近任务', export: '导出报告', exporting: '导出中…',
    exported_to: '✓ 已导出到 {1}（严重 {2} 个，高危 {3} 个）', open_dir: '打开目录',
    ask_main: '提问主 Agent',
    ask_ph: '输入要给主 Agent 的指令或问题，Ctrl+Enter 发送',
    send: '发送', sending: '发送中…',
    ask_hint: '点任务行右侧「提问」切换目标任务',
    ask_empty: '先输入内容', waiting: '等待主 Agent… ', empty_reply: '(空回复)',
    dispatch: '下发任务', name_url: '名称 / 网址', inherit: '继承任务（可选）',
    no_inherit: '不继承 · 用固定模板', duration: '时长（分钟）',
    desc_auto: '描述（自动生成）', desc_toggle_title: '展开 / 收起描述',
    goal_toggle_title: '展开 / 收起目标', edit_short: '编辑',
    edit_desc_title: '临时修改本次任务的描述', edit_goal_title: '临时修改本次任务的目标',
    goal_fixed: '目标（默认）',
    desc_req: '描述（继承任务时必填）', goal_req: '目标（继承任务时必填）',
    desc_ph: '例如：在 xxx 基础上做二次利用验证', goal_ph: '例如：拿到该后台的管理权限',
    llm: 'LLM', llm_note: '（使用服务器中设定配置）', llm_ph: '（刷新后可选）',
    send_task: '下发', dispatching: '下发中…', confirm_send: '确认下发', cancel: '取消',
    desc_template: '渗透<名称>源站及其子站',
    read_inherit_fail: '读取继承任务失败', retry_hint: '（重新选一次这个任务即可重试）',
    m_add: '添加机器', m_edit: '编辑机器 · ',
    ip_host: 'IP / 主机名', ssh_port: 'SSH 端口', artex_port: 'ARTEX 端口',
    artex_port_title: '目标机器上 ARTEX 监听的端口',
    port_hint: 'SSH 端口用于登录（一般 22）；ARTEX 端口是目标机器上 ARTEX 网页监听的端口（默认 8787，改了才需要动）',
    note_label: '备注', user_label: '用户', auth: '认证方式', pwd: '密码', keyfile: '密钥文件',
    ssh_pw: 'SSH 密码', leave_blank: '编辑时留空＝不修改',
    key_hint: '私钥文件（会复制到程序目录 keys/ 下）', current_key: '当前密钥：',
    artex_user: 'ARTEX 网页账号', artex_pw: 'ARTEX 网页密码', already_set: '已设置，留空＝不修改',
    artex_ph_hint: '用于登录目标机上的 ARTEX 控制台；留空则回退到 config.toml [defaults] 的 login_user / login_password',
    save: '保存', saving: '保存中…', save_failed: '保存失败', req_failed: '请求失败：',
    fill_ip: '先填 IP', pick_key: '请选择私钥文件', saved: '已保存', deleted: '已删除',
    del_confirm: '删除机器 {1} ？（只从列表移除，不影响服务器）', del_failed: '删除失败',
    conn_failed: '连接失败', conn_failed_e: '连接失败：', disconnected_e: '连接已断开：',
    no_pw_top: '这台没配置密码，请先在右上角输入 SSH 密码',
    no_pw: '这台没配置密码，请先输入 SSH 密码',
    fill_name: '先填名称/网址', need_desc_goal: '继承任务时，描述和目标必须填',
    confirm_text: '确认对 {1} 下发「{2}」',
    inherit_from: '继承自：', goal_label: '目标：', duration_llm: '时长 {1} 分钟 · LLM {2}',
    dispatched: '✓ 已下发 任务 #{1}（{2}）', dispatch_failed: '下发失败',
    request_failed_short: '✗ 请求失败',
    paused_ok: '✓ 任务 #{1} 已暂停', resumed_ok: '✓ 任务 #{1} 已继续', queued: '（排队中）',
    op_failed: '操作失败', active_mark: '（激活）',
    overview: '全部服务器', refresh_all: '刷新全部', refreshing_all: '刷新中…',
    machines_online: '在线机器', findings_total: '严重 + 高危', no_machines: '还没有服务器，请先添加',
    no_saved_credentials: '未保存凭据', click_machine: '点击查看机器', never_refreshed: '尚未刷新',
    empty_title: '选择右上角开关建立连接', empty_hint: '连接成功后会自动加载任务与漏洞概览',
    connecting_body: '正在建立 SSH 隧道并登录 ARTEX…', filter_note: '筛选：{1} · {2} 个任务',
    reconnecting: '等待重连', reconnect_in: '第 {1} 次重连 · {2}s', reconnect_done: '✓ {1} 已重新连接',
    poll_failed: '刷新失败：', new_findings: '{1} 新增严重/高危 {2} 个',
    copy_reply: '复制回复', copied: '✓ 已复制', ask_history: '历史提问', no_history: '暂无历史提问',
    question: '问题', answer: '回复', export_report_step: '正在导出总报告…',
    export_critical_step: '正在导出严重漏洞报告…', export_high_step: '正在导出高危漏洞报告…',
    export_finishing: '正在整理导出结果…', export_failed: '导出失败', export_partial: '部分报告失败：{1} 个',
    export_running: '该任务已有导出正在进行', task_unread: '有新发现', error_details: '详细原因',
    files: '文件', files_title: '浏览并下载服务器工作区文件',
    ws_title: '服务器文件', ws_up: '上一级', ws_refresh: '刷新', ws_loading: '加载中…',
    ws_empty: '这个目录是空的', ws_load_failed: '读取目录失败', ws_name: '名称',
    ws_size: '大小', ws_mtime: '修改时间', ws_root: '工作区', ws_task_link: '任务 #{1}',
    ws_selected: '已选 {1} 项 · {2}', ws_download: '下载所选', ws_downloading: '打包中…',
    ws_download_started: '✓ 已开始下载 {1}', ws_download_failed: '下载失败',
    delete_task: '删除任务', del_warn: '删除后无法恢复。正在运行的任务会先被中止。',
    del_all: '全部关联数据', del_all_hint: '包括资产、流量、文件、漏洞和 LLM 请求/响应记录。',
    del_files: '任务文件', del_files_hint: '删除该任务工作目录中的上传文件、命令输出和其他产物。',
    del_assets: '关联资产', del_assets_hint: '删除仅属于该任务的资产；共享资产只解除关联。',
    del_traffic: '关联流量', del_traffic_hint: '按关联资产的主机名删除；仍被其他任务引用的流量会保留。',
    del_findings: '关联漏洞', del_findings_hint: '永久删除该任务产生的独立漏洞记录与漏洞报告。',
    del_llm: 'LLM 记录', del_llm_hint: '删除该任务的 LLM 请求与响应记录。',
    del_ack: '我已知晓该操作不可恢复', del_confirm: '确认删除', deleting: '删除中…',
    del_stat: '任务文件：{1} 个，共 {2}', del_stat_none: '任务文件：无',
    del_stat_loading: '任务文件：统计中…', del_stat_unknown: '任务文件：无法统计',
    del_running_warn: '该任务正在运行，删除会先中止它。',
    del_selected: '已选择 {1} 项关联数据', del_ok: '✓ 任务 #{1} 已删除', del_fail: '删除失败'
  },
  en: {
    sub_local: 'Local only · auto-refresh',
    collapse: 'Collapse sidebar', expand: 'Expand sidebar',
    servers: 'SERVERS', add: '+ Add', edit: 'Edit', done: 'Done',
    del: 'Delete', no_creds: ' · no credentials',
    theme_dark: 'Dark mode', theme_light: 'Light mode', settings: 'Settings',
    ssh_pw_ph: 'SSH password', auto_refresh_title: 'Auto-refresh when connected',
    disconnected: 'Disconnected', connected: 'Connected · auto-refresh', connecting: 'Connecting…',
    refreshed_at: 'Updated ',
    tasks_total: 'Tasks', running: 'Running', paused: 'Paused', critical: 'Critical',
    high: 'High', medium: 'Medium', low: 'Low', intent: 'Intent',
    tasks_note: ' (showing {1} of {2})',
    tasks_note_custom: ' (custom order · showing {1} of {2})',
    all_tasks: 'All tasks', all_tasks_title: 'View all tasks and reorder',
    all_sub: '{1} tasks · drag rows to reorder; the top 5 appear in Recent tasks',
    all_sub_short: '{1} tasks',
    cut_label: 'Top 5 shown in Recent tasks', show_badge: 'SHOWN',
    drag_hint: 'Drag rows to reorder', order_dirty: 'Order changed — click Save to keep it',
    order_saved: '✓ Display order saved', order_fail: 'Failed to save order', close: 'Close',
    th_task: 'Task', th_status: 'Status', ask: 'Ask',
    no_tasks: 'No tasks on this machine yet',
    st_running: 'running', st_paused: 'paused', st_queued: 'queued', st_created: 'created',
    st_completed: 'completed', st_failed: 'failed', st_stopped: 'stopped',
    pause: 'Pause', resume: 'Resume', pausing: 'Pausing…', resuming: 'Resuming…',
    recent_tasks: 'Recent tasks', export: 'Export report', exporting: 'Exporting…',
    exported_to: '✓ Exported to {1} (critical {2}, high {3})', open_dir: 'Open folder',
    ask_main: 'Ask main Agent',
    ask_ph: 'Instruction or question for the main Agent, Ctrl+Enter to send',
    send: 'Send', sending: 'Sending…',
    ask_hint: 'Click "Ask" on a task row to switch target',
    ask_empty: 'Enter a message first', waiting: 'Waiting for main Agent… ', empty_reply: '(empty reply)',
    dispatch: 'Dispatch task', name_url: 'Name / URL', inherit: 'Inherit task (optional)',
    no_inherit: "Don't inherit · fixed template", duration: 'Duration (min)',
    desc_auto: 'Description (auto)', desc_toggle_title: 'Expand / collapse description',
    goal_toggle_title: 'Expand / collapse goal', edit_short: 'Edit',
    edit_desc_title: 'Temporarily override the description for this task',
    edit_goal_title: 'Temporarily override the goal for this task',
    goal_fixed: 'Goal (default)',
    desc_req: 'Description (required when inheriting)', goal_req: 'Goal (required when inheriting)',
    desc_ph: 'e.g. post-exploitation based on xxx', goal_ph: 'e.g. gain admin access to the panel',
    llm: 'LLM', llm_note: '(configured on the server)', llm_ph: '(available after refresh)',
    send_task: 'Dispatch', dispatching: 'Dispatching…', confirm_send: 'Confirm dispatch', cancel: 'Cancel',
    desc_template: 'Pentest <名称> origin and subdomains',
    read_inherit_fail: 'Failed to load inherited task', retry_hint: ' (reselect the task to retry)',
    m_add: 'Add machine', m_edit: 'Edit machine · ',
    ip_host: 'IP / hostname', ssh_port: 'SSH port', artex_port: 'ARTEX port',
    artex_port_title: 'Port where ARTEX listens on the target',
    port_hint: 'SSH port is for login (usually 22); ARTEX port is where the ARTEX web UI listens on the target (default 8787)',
    note_label: 'Label', user_label: 'User', auth: 'Auth method', pwd: 'Password', keyfile: 'Key file',
    ssh_pw: 'SSH password', leave_blank: 'leave blank to keep',
    key_hint: 'Private key (copied to keys/ under the app directory)', current_key: 'Current key: ',
    artex_user: 'ARTEX web user', artex_pw: 'ARTEX web password', already_set: 'set — leave blank to keep',
    artex_ph_hint: 'Used to sign in to ARTEX on the target; blank falls back to login_user / login_password in config.toml [defaults]',
    save: 'Save', saving: 'Saving…', save_failed: 'Save failed', req_failed: 'Request failed: ',
    fill_ip: 'Enter IP first', pick_key: 'Choose a key file', saved: 'Saved', deleted: 'Deleted',
    del_confirm: 'Delete machine {1}? (removes from list only)', del_failed: 'Delete failed',
    conn_failed: 'Connect failed', conn_failed_e: 'Connect failed: ', disconnected_e: 'Disconnected: ',
    no_pw_top: 'No password configured; enter the SSH password at top right',
    no_pw: 'No password configured; enter the SSH password',
    fill_name: 'Enter name/URL first', need_desc_goal: 'Description and goal are required when inheriting',
    confirm_text: 'Dispatch "{2}" to {1}',
    inherit_from: 'Inherited from: ', goal_label: 'Goal: ', duration_llm: '{1} min · LLM {2}',
    dispatched: '✓ Dispatched task #{1} ({2})', dispatch_failed: 'Dispatch failed',
    request_failed_short: '✗ Request failed',
    paused_ok: '✓ Task #{1} paused', resumed_ok: '✓ Task #{1} resumed', queued: ' (queued)',
    op_failed: 'Operation failed', active_mark: ' (active)',
    overview: 'All servers', refresh_all: 'Refresh all', refreshing_all: 'Refreshing…',
    machines_online: 'Online machines', findings_total: 'Critical + high', no_machines: 'No servers yet — add one first',
    no_saved_credentials: 'No saved credentials', click_machine: 'Click to open', never_refreshed: 'Not refreshed yet',
    empty_title: 'Use the toggle at top right to connect', empty_hint: 'Tasks and findings load automatically after connection',
    connecting_body: 'Opening SSH tunnel and signing in to ARTEX…', filter_note: 'Filter: {1} · {2} tasks',
    reconnecting: 'Reconnect pending', reconnect_in: 'Reconnect attempt {1} · {2}s', reconnect_done: '✓ {1} reconnected',
    poll_failed: 'Refresh failed: ', new_findings: '{1}: {2} new critical/high findings',
    copy_reply: 'Copy reply', copied: '✓ Copied', ask_history: 'Previous questions', no_history: 'No previous questions',
    question: 'Question', answer: 'Reply', export_report_step: 'Exporting main report…',
    export_critical_step: 'Exporting critical findings…', export_high_step: 'Exporting high findings…',
    export_finishing: 'Finishing export…', export_failed: 'Export failed', export_partial: '{1} report(s) failed',
    export_running: 'This task already has an export in progress', task_unread: 'New findings', error_details: 'Error details',
    files: 'Files', files_title: 'Browse and download files in the server workspace',
    ws_title: 'Server files', ws_up: 'Up one level', ws_refresh: 'Refresh', ws_loading: 'Loading…',
    ws_empty: 'This folder is empty', ws_load_failed: 'Failed to read folder', ws_name: 'Name',
    ws_size: 'Size', ws_mtime: 'Modified', ws_root: 'Workspace', ws_task_link: 'Task #{1}',
    ws_selected: '{1} selected · {2}', ws_download: 'Download selected', ws_downloading: 'Packaging…',
    ws_download_started: '✓ Download started: {1}', ws_download_failed: 'Download failed',
    delete_task: 'Delete task', del_warn: 'This cannot be undone. A running task will be aborted first.',
    del_all: 'All related data', del_all_hint: 'Assets, traffic, files, findings and LLM request/response records.',
    del_files: 'Task files', del_files_hint: 'Uploads, command output and other artifacts in the task workspace.',
    del_assets: 'Related assets', del_assets_hint: 'Deletes assets owned only by this task; shared assets are detached.',
    del_traffic: 'Related traffic', del_traffic_hint: 'Deletes by exact host; traffic still referenced elsewhere is kept.',
    del_findings: 'Related findings', del_findings_hint: 'Permanently deletes this task’s standalone findings and reports.',
    del_llm: 'LLM records', del_llm_hint: 'Deletes this task’s LLM request and response records.',
    del_ack: 'I understand this action is irreversible', del_confirm: 'Delete permanently', deleting: 'Deleting…',
    del_stat: 'Task files: {1} file(s), {2}', del_stat_none: 'Task files: none',
    del_stat_loading: 'Task files: calculating…', del_stat_unknown: 'Task files: unavailable',
    del_running_warn: 'This task is running; deleting it will abort it first.',
    del_selected: '{1} related data option(s) selected', del_ok: '✓ Task #{1} deleted', del_fail: 'Delete failed'
  }
};
function T(k, ...args){
  let s = (I18N[LANG] && I18N[LANG][k]) || I18N.zh[k] || k;
  args.forEach((a, i) => { s = s.split('{' + (i + 1) + '}').join(a); });
  return s;
}
function applyLang(){
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = T(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = T(el.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-title]').forEach(el => { el.title = T(el.dataset.i18nTitle); });
  document.documentElement.lang = LANG === 'en' ? 'en' : 'zh-CN';
  const th = $('btn-theme');
  if (th) th.title = T(document.body.classList.contains('dark') ? 'theme_light' : 'theme_dark');
  const cl = $('btn-collapse');
  if (cl) cl.title = T(document.body.classList.contains('collapsed') ? 'expand' : 'collapse');
  const be = $('btn-edit');
  if (be) be.textContent = T(document.body.classList.contains('editing') ? 'done' : 'edit');
  if ($('f-name')) updateDesc();
}
function stName(s){ const k = 'st_' + (s || ''); return (I18N.zh[k] || I18N.en[k]) ? T(k) : (s || ''); }

async function api(path, body){
  const r = await fetch(path, body ? {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)} : {});
  return await r.json();
}
function num(v, cls){ return '<td class="num ' + (cls||'') + '">' + (v||0) + '</td>'; }
function animateView(el){
  if (!el) return;
  el.classList.remove('view-enter');
  void el.offsetWidth;
  el.classList.add('view-enter');
}
function openModal(el){
  clearTimeout(el._closeTimer);
  el.classList.remove('closing');
  el.hidden = false;
  animateView(el.querySelector('.modal-box'));
}
function closeModal(el, after){
  if (!el || el.hidden) return;
  el.classList.add('closing');
  clearTimeout(el._closeTimer);
  el._closeTimer = setTimeout(() => {
    el.hidden = true; el.classList.remove('closing');
    if (after) after();
  }, 140);
}
function setMobileSide(on){
  document.body.classList.toggle('mobile-side', on);
  $('side-scrim').hidden = !on;
}

async function boot(){
  await loadMachines();
  try {
    const c = await api('/api/connected', {});
    (c.ips || []).forEach(ip => { CONNECTED[ip] = true; WANTED[ip] = true; setDot(ip, 'd1'); });
    if (Object.keys(CONNECTED).length){ startPoll(); pollOnce(); }
  } catch(e){}
  if (CFG.auto_connect){
    MACHINES.filter(m => (m.has_password || m.has_key) && !CONNECTED[m.ip])
      .forEach(m => doConnect(m.ip, true));
  }
}

function renderMachines(){
  $('list').innerHTML = MACHINES.map(m =>
    '<div class="item" data-ip="' + esc(m.ip) + '">' +
      '<span class="dot ' + (CONNECTED[m.ip] ? 'd1' : (RECONNECT[m.ip] ? 'd2' : 'd0')) + '" id="dot-' + esc(m.ip) + '"></span>' +
      '<span><div class="ip">' + esc(m.ip) + '</div><div class="lb">' + esc(m.label || '') +
        ((m.has_password || m.has_key) ? '' : esc(T('no_creds'))) + '</div></span>' +
      (UNREAD[m.ip] ? '<span class="unread">' + UNREAD[m.ip] + '</span>' : '') +
      '<span class="ops">' +
        '<button class="icon btn-medit" data-ip="' + esc(m.ip) + '" title="' + esc(T('edit')) + '">✎</button>' +
        '<button class="icon btn-mdel" data-ip="' + esc(m.ip) + '" title="' + esc(T('del')) + '">✕</button>' +
      '</span></div>').join('');
  $('list').querySelectorAll('.item').forEach(el => {
    el.classList.toggle('on', !OVERVIEW && el.dataset.ip === CUR);
    el.onclick = (ev) => {
      if (!ev.target.classList || !ev.target.classList.contains('icon')) select(el.dataset.ip);
    };
  });
  $('list').querySelectorAll('.btn-medit').forEach(b =>
    b.onclick = (e) => { e.stopPropagation(); openMachineForm(b.dataset.ip); });
  $('list').querySelectorAll('.btn-mdel').forEach(b =>
    b.onclick = (e) => { e.stopPropagation(); delMachine(b.dataset.ip); });
  $('btn-overview').classList.toggle('active', OVERVIEW);
}

async function loadMachines(){
  const d = await api('/api/machines');
  MACHINES = d.machines; CFG = d;
  LANG = d.lang === 'en' ? 'en' : 'zh';
  applyLang();
  let hasTheme = false;
  try { hasTheme = localStorage.getItem(THEME_KEY) !== null; } catch(e){}
  if (!hasTheme) applyTheme(d.theme === 'dark');
  $('f-goal-fixed').textContent = d.goal || '';
  $('f-goal-fixed').dataset.raw = d.goal || '';
  $('f-timeout').value = d.timeout_minutes || 600;
  renderMachines();
  if (OVERVIEW) renderOverview();
  startPoll();
}

function openOverview(){
  closeTasks();
  OVERVIEW = true; CUR = null; FILTER = null;
  $('overview').hidden = false; $('panel').hidden = true; $('empty').hidden = true;
  setMobileSide(false);
  renderMachines(); renderOverview(); animateView($('overview'));
}

function overviewChip(k, v, color){
  return '<div class="chip" style="--c:' + color + '"><div class="k">' + esc(k) + '</div><div class="v">' + (v || 0) + '</div></div>';
}

function renderOverview(){
  const rows = MACHINES.map(m => ({m, d: REFRESHED[m.ip]}));
  const online = rows.filter(x => x.d && x.d.ok).length;
  const critical = rows.reduce((n, x) => n + ((x.d && x.d.findings) ? x.d.findings.critical + x.d.findings.high : 0), 0);
  const running = rows.reduce((n, x) => n + ((x.d && x.d.counts) ? (x.d.counts.running || 0) : 0), 0);
  $('o-chips').innerHTML = overviewChip(T('machines_online'), online + '/' + MACHINES.length, '#4b7357') +
    overviewChip(T('running'), running, '#96683f') + overviewChip(T('findings_total'), critical, '#a8452f');
  $('o-cards').innerHTML = rows.length ? rows.map(({m, d}) => {
    const f = d && d.findings || {}, c = d && d.counts || {};
    return '<button class="machine-card" data-ip="' + esc(m.ip) + '">' +
      '<div class="mc-head"><span class="dot ' + (CONNECTED[m.ip] ? 'd1' : (d && d.ok ? 'd1' : 'd2')) + '"></span>' +
      '<span class="mc-ip">' + esc(m.ip) + '</span>' + (UNREAD[m.ip] ? '<span class="unread">' + UNREAD[m.ip] + '</span>' : '') + '</div>' +
      '<div class="mc-label">' + esc(m.label || T('click_machine')) + '</div>' +
      '<div class="mc-stats"><div class="mc-stat"><b>' + (d && d.ok ? d.tasks_total : '—') + '</b><span>' + esc(T('tasks_total')) + '</span></div>' +
      '<div class="mc-stat"><b>' + (d && d.ok ? (c.running || 0) : '—') + '</b><span>' + esc(T('running')) + '</span></div>' +
      '<div class="mc-stat"><b class="c-critical">' + (d && d.ok ? (f.critical || 0) : '—') + '</b><span>' + esc(T('critical')) + '</span></div>' +
      '<div class="mc-stat"><b class="c-high">' + (d && d.ok ? (f.high || 0) : '—') + '</b><span>' + esc(T('high')) + '</span></div></div>' +
      (d && d.error ? '<div class="mc-error">' + esc(d.error) + '</div>' : '') +
      '<div class="mc-foot">' + esc(d && d.fetched_at ? T('refreshed_at') + new Date(d.fetched_at * 1000).toLocaleTimeString() : T('never_refreshed')) + '</div></button>';
  }).join('') : '<div class="empty-table">' + esc(T('no_machines')) + '</div>';
  $('o-cards').querySelectorAll('.machine-card').forEach(el => el.onclick = () => select(el.dataset.ip));
}

async function refreshOverview(){
  const btn = $('btn-refresh-all');
  btn.disabled = true; btn.textContent = T('refreshing_all');
  try {
    const d = await api('/api/overview', {});
    (d.results || []).forEach(r => {
      if (r.ok){
        storeRefreshed(r);
        if (CUR === r.ip && CONNECTED[r.ip]) render(REFRESHED[r.ip]);
      } else if (WANTED[r.ip]) handleConnectionLoss(r.ip, r.error || T('poll_failed'));
      else REFRESHED[r.ip] = Object.assign({}, REFRESHED[r.ip] || {}, r);
    });
    $('o-time').textContent = T('refreshed_at') + new Date().toLocaleTimeString();
    renderOverview();
  } catch(e){ toast(T('req_failed') + e); }
  finally { btn.disabled = false; btn.textContent = T('refresh_all'); }
}

/* ---------- 机器增删改 ---------- */
let M_EDIT = null;

function toggleAuth(){
  const key = $('m-auth').value === 'key';
  $('m-pwd-box').hidden = key;
  $('m-key-box').hidden = !key;
}

function openMachineForm(ip){
  M_EDIT = ip || null;
  const m = ip ? MACHINES.find(x => x.ip === ip) : null;
  $('m-title').textContent = ip ? (T('m_edit') + ip) : T('m_add');
  $('m-ip').value = m ? m.ip : '';
  $('m-ip').disabled = !!m;
  $('m-port').value = m ? (m.port || 22) : 22;
  $('m-artex-port').value = m ? (m.artex_port || 8787) : (CFG.default_artex_port || 8787);
  $('m-label').value = m ? (m.label || '') : '';
  $('m-user').value = m ? (m.user || 'root') : 'root';
  $('m-auth').value = (m && m.has_key) ? 'key' : 'pwd';
  $('m-pwd').value = m ? (m.ssh_password || '') : '';
  $('m-keyfile').value = '';
  $('m-keyinfo').textContent = (m && m.key_file) ? (T('current_key') + m.key_file) : '';
  $('m-artex-user').value = m ? (m.artex_user || '') : '';
  $('m-artex-pwd').value = m ? (m.artex_password || '') : '';
  $('m-artex-pwd').placeholder = (m && m.has_artex_password) ? T('already_set') : '';
  $('m-msg').textContent = '';
  toggleAuth();
  openModal($('m-modal'));
}

async function saveMachine(){
  const ip = $('m-ip').value.trim();
  if (!ip){ $('m-msg').textContent = T('fill_ip'); return; }
  const useKey = $('m-auth').value === 'key';
  const cur = M_EDIT ? MACHINES.find(x => x.ip === M_EDIT) : null;
  const body = {ip: ip, old_ip: M_EDIT || '', label: $('m-label').value.trim(),
                user: $('m-user').value.trim() || 'root',
                port: parseInt($('m-port').value || 22, 10),
                artex_port: parseInt($('m-artex-port').value || 8787, 10),
                artex_user: $('m-artex-user').value.trim(),
                artex_password: $('m-artex-pwd').value,
                use_key: useKey, password: $('m-pwd').value};
  const f = $('m-keyfile').files[0];
  if (useKey && f){
    body.key_pem = await f.text();
  } else if (useKey && !(cur && cur.has_key)){
    $('m-msg').textContent = T('pick_key');
    return;
  }
  $('m-save').disabled = true;
  $('m-msg').textContent = T('saving');
  try {
    const d = await api('/api/machines/save', body);
    if (d.ok){
      closeModal($('m-modal'));
      setEditing(false);
      await loadMachines();
      $('all-note').textContent = T('saved') + ' ' + ip;
    } else {
      $('m-msg').textContent = d.error || T('save_failed');
    }
  } catch(e){ $('m-msg').textContent = T('req_failed') + e; }
  finally { $('m-save').disabled = false; }
}

async function delMachine(ip){
  if (!window.confirm(T('del_confirm', ip))) return;
  try {
    const d = await api('/api/machines/delete', {ip});
    if (d.ok){
      delete CONNECTED[ip]; delete WANTED[ip]; delete REFRESHED[ip]; delete UNREAD[ip];
      clearReconnect(ip);
      await loadMachines();
      if (CUR === ip){ CUR = null; $('panel').hidden = true; $('empty').hidden = false; }
      $('all-note').textContent = T('deleted') + ' ' + ip;
    } else { alert(d.error || T('del_failed')); }
  } catch(e){ alert(T('req_failed') + e); }
}

$('btn-add').onclick = () => openMachineForm(null);
function setEditing(on){
  document.body.classList.toggle('editing', on);
  $('btn-edit').textContent = on ? T('done') : T('edit');
}
$('btn-edit').onclick = () => setEditing(!document.body.classList.contains('editing'));
const COL_KEY = 'artex_sidebar_collapsed';
function applyCollapse(on){
  document.body.classList.toggle('collapsed', on);
  const b = $('btn-collapse');
  if (b) b.title = T(on ? 'expand' : 'collapse');
  try { localStorage.setItem(COL_KEY, on ? '1' : '0'); } catch(e){}
}
$('btn-collapse').onclick = () => applyCollapse(!document.body.classList.contains('collapsed'));
try { if (localStorage.getItem(COL_KEY) === '1') applyCollapse(true); } catch(e){}

const THEME_KEY = 'artex_theme';
function applyTheme(dark){
  document.body.classList.toggle('dark', dark);
  $('btn-theme').title = T(dark ? 'theme_light' : 'theme_dark');
  try { localStorage.setItem(THEME_KEY, dark ? '1' : '0'); } catch(e){}
}
applyTheme(document.body.classList.contains('dark'));
$('btn-theme').onclick = () => applyTheme(!document.body.classList.contains('dark'));

$('btn-settings').onclick = () => { location.href = '/settings'; };

$('m-auth').addEventListener('change', toggleAuth);
$('m-save').onclick = saveMachine;
$('m-cancel').onclick = () => closeModal($('m-modal'));
$('m-modal').addEventListener('mousedown', e => { if (e.target === $('m-modal')) closeModal($('m-modal')); });
$('btn-overview').onclick = openOverview;
$('btn-refresh-all').onclick = refreshOverview;
$('btn-mobile-side').onclick = () => setMobileSide(!document.body.classList.contains('mobile-side'));
$('side-scrim').onclick = () => setMobileSide(false);

function select(ip){
  closeTasks();
  if (!OVERVIEW && CUR === ip){
    CUR = null; FILTER = null; SEL = null; ASK = null;
    $('panel').hidden = true; $('overview').hidden = true; $('empty').hidden = false;
    renderMachines(); animateView($('empty')); setMobileSide(false);
    return;
  }
  OVERVIEW = false; CUR = ip; FILTER = null; SEL = null;
  delete UNREAD[ip];
  const m = MACHINES.find(x => x.ip === ip);
  if (!m) return;
  $('empty').hidden = true; $('overview').hidden = true; $('panel').hidden = false;
  $('p-ip').textContent = ip;
  $('p-label').textContent = m.label || '';
  $('p-pw').hidden = !!(m.has_password || m.has_key);
  $('p-pw').value = PWD[ip] || '';
  $('p-err').hidden = true;
  $('f-msg').textContent = '';
  $('p-time').textContent = '';
  $('f-confirm').hidden = true;
  $('btn-send').disabled = false;
  setConnUI(!!CONNECTED[ip]);
  $('f-name').value = '';
  $('f-src').innerHTML = '<option value="">' + esc(T('no_inherit')) + '</option>';
  onSrcChange();
  $('f-src').value = '';
  $('ask-sec').hidden = true;
  ASK = null;
  $('f-desc-tmp').value = ''; $('f-goal-tmp').value = '';
  setEditOpen('f-desc-auto', 'f-desc-tmp', false);
  setEditOpen('f-goal-fixed', 'f-goal-tmp', false);
  updateDesc();
  setDescOpen(false);
  setGoalOpen(false);
  const conn = !!CONNECTED[ip];
  $('p-state-title').textContent = RECONNECT[ip] ? T('reconnecting') : T('empty_title');
  $('p-state-sub').textContent = RECONNECT[ip] ? (RECONNECT[ip].error || '') : T('empty_hint');
  $('p-placeholder').hidden = conn;
  if (conn){
    const cached = REFRESHED[ip];
    if (cached && cached.ok) render(cached);
    else $('p-body').hidden = true;
    pollOnce();
  } else {
    $('p-body').hidden = true;
  }
  renderMachines(); animateView($('panel')); setMobileSide(false);
}
function fillDescTemplate(name){
  const tpl = CFG.desc_template || T('desc_template');
  return name ? tpl.split('<名称>').join(name) : tpl;
}
function updateDesc(){
  $('f-desc-auto').textContent = fillDescTemplate($('f-name').value.trim());
}
function setFoldOpen(triId, bodyId, open){
  $(triId).setAttribute('aria-expanded', open ? 'true' : 'false');
  $(bodyId).classList.toggle('open', open);
}
function setDescOpen(open){ setFoldOpen('desc-toggle', 'f-desc-auto', open); }
function setGoalOpen(open){ setFoldOpen('goal-toggle', 'f-goal-fixed', open); }
$('desc-toggle').onclick = () => setDescOpen($('desc-toggle').getAttribute('aria-expanded') !== 'true');
$('goal-toggle').onclick = () => setGoalOpen($('goal-toggle').getAttribute('aria-expanded') !== 'true');

/* 继承任务：切换后描述/目标改为手填 */
async function onSrcChange(){
  const src = $('f-src').value;
  $('f-auto').hidden = !!src;
  $('f-manual').hidden = !src;
  if (src){
    $('f-desc-tmp').value = ''; $('f-goal-tmp').value = '';
    setEditOpen('f-desc-auto', 'f-desc-tmp', false);
    setEditOpen('f-goal-fixed', 'f-goal-tmp', false);
  }
  $('f-msg').textContent = '';
  if (!src) return;
  if (!CUR) return;
  const m = MACHINES.find(x => x.ip === CUR);
  const pw = m.has_password ? '' : $('p-pw').value;
  $('f-desc').value = '';
  $('f-goal').value = '';
  try {
    const d = await api('/api/task-info', {ip: CUR, password: pw, task_id: src});
    if (d.ok){
      $('f-desc').value = d.description || '';
      $('f-goal').value = d.goal || '';
      if (!$('f-name').value.trim()) $('f-name').value = d.name || '';
    } else {
      $('f-msg').innerHTML = '<span style="color:#a8452f">' + esc(T('read_inherit_fail')) + '：' + esc(d.error || '') +
        esc(T('retry_hint')) + '</span>';
    }
  } catch(e){
    $('f-msg').innerHTML = '<span style="color:#a8452f">' + esc(T('read_inherit_fail')) + '</span>';
  }
}
$('f-src').addEventListener('change', onSrcChange);
$('f-name').addEventListener('input', updateDesc);

function setEditOpen(boxId, tmpId, open){
  $(boxId).hidden = open;
  $(tmpId).hidden = !open;
}
$('lnk-desc').onclick = (e) => {
  e.preventDefault();
  const t = $('f-desc-tmp');
  if (t.hidden){
    setDescOpen(false);
    t.value = $('f-desc-auto').textContent || '';
    setEditOpen('f-desc-auto', 'f-desc-tmp', true);
    t.focus();
  } else {
    setEditOpen('f-desc-auto', 'f-desc-tmp', false);
  }
};
$('lnk-goal').onclick = (e) => {
  e.preventDefault();
  const t = $('f-goal-tmp');
  if (t.hidden){
    setGoalOpen(false);
    t.value = $('f-goal-fixed').dataset.raw || CFG.goal || '';
    setEditOpen('f-goal-fixed', 'f-goal-tmp', true);
    t.focus();
  } else {
    setEditOpen('f-goal-fixed', 'f-goal-tmp', false);
  }
};

function setDot(ip, cls){ const d = $('dot-' + ip); if (d) d.className = 'dot ' + cls; }

let CONNECTED = {}, CONNECTING = {};
let pollTimer = null, pollBusy = false, reconnectTicker = null;

function setConnUI(on){
  if (!CUR) return;
  $('p-conn').checked = !!on;
  if (on){ $('conn-label').textContent = T('connected'); $('conn-label').style.color = 'var(--ok)'; }
  else if (RECONNECT[CUR]){ updateReconnectUI(); }
  else { $('conn-label').textContent = T('disconnected'); $('conn-label').style.color = 'var(--ink-3)'; }
  $('dispatch-sec').hidden = !on;
  $('p-placeholder').hidden = !!on;
  if (!on) $('connect-skeleton').hidden = true;
}

function updateReconnectUI(){
  const r = CUR && RECONNECT[CUR];
  if (!r) return;
  const secs = Math.max(0, Math.ceil((r.next - Date.now()) / 1000));
  $('conn-label').textContent = T('reconnect_in', r.attempt, secs);
  $('conn-label').style.color = 'var(--high)';
  $('p-state-title').textContent = T('reconnecting');
  $('p-state-sub').textContent = r.error || T('empty_hint');
}

function ensureReconnectTicker(){
  if (reconnectTicker) return;
  reconnectTicker = setInterval(() => {
    if (!Object.keys(RECONNECT).length){ clearInterval(reconnectTicker); reconnectTicker = null; return; }
    updateReconnectUI();
  }, 1000);
}

function clearReconnect(ip){
  const r = RECONNECT[ip];
  if (r && r.timer) clearTimeout(r.timer);
  delete RECONNECT[ip];
}

function scheduleReconnect(ip, error){
  if (!CFG.auto_reconnect || !WANTED[ip]) return;
  const old = RECONNECT[ip] || {attempt: 0};
  if (old.timer) return;
  const attempt = (old.attempt || 0) + 1;
  const delay = Math.min((CFG.reconnect_seconds || 15) * Math.pow(2, attempt - 1), 120);
  const r = {attempt, next: Date.now() + delay * 1000, error: error || '', timer: null};
  r.timer = setTimeout(() => { if (RECONNECT[ip]) RECONNECT[ip].timer = null; doConnect(ip, true); }, delay * 1000);
  RECONNECT[ip] = r;
  ensureReconnectTicker(); updateReconnectUI();
}

async function doConnect(ip, automatic){
  ip = ip || CUR;
  const m = MACHINES.find(x => x.ip === ip);
  if (!m || CONNECTING[ip]) return;
  WANTED[ip] = true;
  const previousAttempt = RECONNECT[ip] ? RECONNECT[ip].attempt : 0;
  if (!automatic) clearReconnect(ip);
  else if (RECONNECT[ip] && RECONNECT[ip].timer){ clearTimeout(RECONNECT[ip].timer); RECONNECT[ip].timer = null; }
  const hasSaved = m.has_password || m.has_key;
  const pw = hasSaved ? '' : (CUR === ip ? $('p-pw').value : (PWD[ip] || ''));
  if (!hasSaved && !pw){ delete WANTED[ip]; clearReconnect(ip); if (CUR === ip){ showErr(T('no_pw_top')); setConnUI(false); } return; }
  if (pw) PWD[ip] = pw;
  CONNECTING[ip] = true;
  if (CUR === ip){
    $('p-err').hidden = true; $('conn-label').textContent = T('connecting');
    $('p-placeholder').hidden = false; $('p-body').hidden = true;
    $('p-state-title').textContent = T('connecting'); $('p-state-sub').textContent = T('connecting_body');
    $('connect-skeleton').hidden = false;
  }
  try {
    const d = await api('/api/connect', {ip, password: pw});
    if (!WANTED[ip]){ api('/api/disconnect', {ip}).catch(() => {}); return; }
    if (!d.ok) throw new Error(d.error || T('conn_failed'));
    CONNECTED[ip] = true; WANTED[ip] = true;
    clearReconnect(ip); setDot(ip, 'd1'); storeRefreshed(d);
    if (CUR === ip){ render(REFRESHED[ip]); setConnUI(true); $('p-err').hidden = true; }
    startPoll();
    if (previousAttempt) toast(T('reconnect_done', ip));
  } catch(e){
    delete CONNECTED[ip]; setDot(ip, 'd2');
    if (CUR === ip){ setConnUI(false); $('p-body').hidden = true; showErr(T('conn_failed_e') + e.message); }
    scheduleReconnect(ip, e.message);
    if (CUR === ip && !RECONNECT[ip]){
      $('p-state-title').textContent = T('empty_title'); $('p-state-sub').textContent = T('empty_hint');
    }
  } finally {
    delete CONNECTING[ip];
    if (CUR === ip) $('connect-skeleton').hidden = true;
  }
}

async function doDisconnect(){
  if (!CUR) return;
  const ip = CUR;
  delete WANTED[ip]; clearReconnect(ip); delete CONNECTED[ip];
  setConnUI(false); $('p-body').hidden = true;
  $('p-state-title').textContent = T('empty_title'); $('p-state-sub').textContent = T('empty_hint');
  try { await api('/api/disconnect', {ip}); } catch(e){}
  if (!Object.keys(CONNECTED).length) stopPoll();
}

function startPoll(){
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  if (!Object.keys(CONNECTED).length) return;
  const seconds = document.hidden ? (CFG.background_refresh_seconds || 30) : (CFG.refresh_seconds || 8);
  pollTimer = setInterval(pollOnce, Math.max(3, seconds) * 1000);
}
function stopPoll(){
  if (pollTimer){ clearInterval(pollTimer); pollTimer = null; }
}

document.addEventListener('visibilitychange', () => { startPoll(); if (!document.hidden) pollOnce(); });

function storeRefreshed(r){
  const old = REFRESHED[r.ip];
  if (old && old.ok) noteFindings(old, r);
  REFRESHED[r.ip] = Object.assign({}, old || {}, r);
}

function noteFindings(old, next){
  const before = new Map((old.all_tasks || []).map(t => [String(t.id), (t.findings.critical || 0) + (t.findings.high || 0)]));
  let delta = 0;
  (next.all_tasks || []).forEach(t => {
    const id = String(t.id), value = (t.findings.critical || 0) + (t.findings.high || 0);
    const diff = Math.max(0, value - (before.has(id) ? before.get(id) : value));
    if (diff){
      delta += diff;
      if (!TASK_UNREAD[next.ip]) TASK_UNREAD[next.ip] = {};
      TASK_UNREAD[next.ip][id] = (TASK_UNREAD[next.ip][id] || 0) + diff;
    }
  });
  if (!delta) return;
  UNREAD[next.ip] = (UNREAD[next.ip] || 0) + delta;
  renderMachines(); if (OVERVIEW) renderOverview();
  toast(T('new_findings', next.ip, delta));
  if (CFG.desktop_notifications && document.hidden && 'Notification' in window && Notification.permission === 'granted')
    new Notification('ARTEX Controller', {body: T('new_findings', next.ip, delta), icon: '/icon.ico'});
}

function handleConnectionLoss(ip, error){
  delete CONNECTED[ip]; setDot(ip, 'd2');
  if (CUR === ip){
    setConnUI(false); $('p-body').hidden = true; $('p-placeholder').hidden = false;
    showErr(T('disconnected_e') + (error || ''));
  }
  scheduleReconnect(ip, error);
}

async function pollOnce(){
  const ips = Object.keys(CONNECTED);
  if (!ips.length || pollBusy){ if (!ips.length) stopPoll(); return; }
  pollBusy = true;
  try {
    const d = await api('/api/poll', {ips});
    (d.results || []).forEach(r => {
      if (r.ok){
        clearReconnect(r.ip); storeRefreshed(r); setDot(r.ip, 'd1');
        if (r.ip === CUR && CONNECTED[r.ip]) render(REFRESHED[r.ip]);
      } else handleConnectionLoss(r.ip, r.error || T('poll_failed'));
    });
    if (OVERVIEW) renderOverview();
  } catch(e){
    ips.forEach(ip => handleConnectionLoss(ip, T('poll_failed') + e));
  } finally {
    pollBusy = false;
    if (!Object.keys(CONNECTED).length) stopPoll();
  }
}

$('p-conn').addEventListener('change', () => {
  if ($('p-conn').checked) doConnect(); else doDisconnect();
});

function showErr(msg){
  const text = String(msg || '');
  $('p-err-text').textContent = text.length > 110 ? text.slice(0, 110) + '…' : text;
  $('p-err-detail').textContent = text; $('p-err').hidden = false;
}

function numId(id){ const n = parseInt(id, 10); return isNaN(n) ? -1 : n; }
function orderedTasks(d){
  const all = d.all_tasks || [];
  const order = (d.task_order || []).map(String);
  const pos = new Map(order.map((id, i) => [id, i]));
  const known = all.filter(t => pos.has(String(t.id)))
                   .sort((a, b) => pos.get(String(a.id)) - pos.get(String(b.id)));
  const fresh = all.filter(t => !pos.has(String(t.id)))
                   .sort((a, b) => numId(b.id) - numId(a.id));
  return fresh.concat(known);
}

function taskMatches(t, filter){
  if (!filter || filter === 'all') return true;
  if (filter === 'running' || filter === 'paused') return t.status === filter;
  if (filter === 'intent') return (t.in_flight || 0) > 0;
  return ((t.findings || {})[filter] || 0) > 0;
}

function render(d){
  $('p-body').hidden = false; $('p-placeholder').hidden = true;
  $('p-time').textContent = d.fetched_at ? (T('refreshed_at') + new Date(d.fetched_at*1000).toLocaleTimeString()) : '';
  const f = d.findings, c = d.counts || {};
  const oldValues = [...$('chips').querySelectorAll('.v')].map(x => x.textContent);
  $('chips').innerHTML =
    chip('all', T('tasks_total'), d.tasks_total, '#96683f') +
    chip('running', T('running'), c.running || 0, '#4b7357') +
    chip('paused', T('paused'), c.paused || 0, '#9c8636') +
    chip('critical', T('critical'), f.critical, '#a8452f') +
    chip('high', T('high'), f.high, '#bf7132') +
    chip('medium', T('medium'), f.medium, '#9c8636') +
    chip('low', T('low'), f.low, '#5d7f93') +
    chip('intent', T('intent'), d.in_flight, '#786c5d');
  [...$('chips').children].forEach((el, i) => {
    if (oldValues[i] != null && oldValues[i] !== el.querySelector('.v').textContent) el.classList.add('bump');
    el.onclick = () => {
      FILTER = FILTER === el.dataset.filter ? null : el.dataset.filter;
      SEL = null; $('exp-msg').textContent = ''; $('exp-progress').hidden = true;
      render(REFRESHED[CUR]);
    };
  });
  const list = orderedTasks(d), filtered = list.filter(t => taskMatches(t, FILTER));
  const shown = FILTER && FILTER !== 'all' ? filtered : filtered.slice(0, 5);
  const total = d.tasks_total != null ? d.tasks_total : list.length;
  const custom = (d.task_order || []).length > 0;
  $('t-note').textContent = FILTER && FILTER !== 'all'
    ? T('filter_note', T(FILTER), filtered.length)
    : (shown.length ? T(custom ? 'tasks_note_custom' : 'tasks_note', shown.length, total) : '');
  $('btn-all').disabled = !list.length;
  $('all-count').textContent = total;
  $('tasks').innerHTML = shown.length ? ('<table><thead><tr><th>#</th><th>' + T('th_task') + '</th><th>' + T('th_status') + '</th>' +
      '<th class="num">' + T('intent') + '</th><th class="num">' + T('critical') + '</th><th class="num">' + T('high') + '</th><th class="num">' + T('medium') + '</th><th class="num">' + T('low') + '</th><th class="ops"></th></tr></thead><tbody>' +
      shown.map(t => {
        const unread = TASK_UNREAD[d.ip] && TASK_UNREAD[d.ip][String(t.id)];
        return '<tr data-id="' + esc(t.id) + '" data-name="' + esc(t.name) + '"' + (SEL && SEL.id === String(t.id) ? ' class="sel"' : '') + '>' +
        '<td class="muted">' + esc(t.id) + '</td><td>' + esc(t.name) + (unread ? '<span class="task-unread" title="' + esc(T('task_unread')) + '"></span>' : '') + '</td>' +
        '<td><span class="tag s-' + esc(t.status) + '"><i></i>' + esc(stName(t.status)) + '</span></td>' +
        '<td class="num">' + t.in_flight + '</td>' + num(t.findings.critical, t.findings.critical?'c-critical':'') +
        num(t.findings.high, t.findings.high?'c-high':'') + num(t.findings.medium, t.findings.medium?'c-medium':'') +
        num(t.findings.low, t.findings.low?'c-low':'') + '<td class="ops">' + ctrlBtn(t) +
        '<button class="mini ghost btn-ask" data-id="' + esc(t.id) + '" data-name="' + esc(t.name) + '">' + T('ask') + '</button></td></tr>';
      }).join('') + '</tbody></table>')
    : '<div class="empty-table">' + esc(T('no_tasks')) + '</div>';
  if (SEL && !list.some(t => String(t.id) === SEL.id)) SEL = null;
  $('btn-export').disabled = !SEL || !!(SEL && EXPORTING[CUR + ':' + SEL.id]);
  $('btn-del-task').disabled = !SEL;

  const srcSel = $('f-src');
  const keep = srcSel.value;
  srcSel.innerHTML = '<option value="">' + esc(T('no_inherit')) + '</option>' +
    (d.all_tasks || []).map(t => '<option value="' + esc(t.id) + '">#' + esc(t.id) + ' ' +
      esc(t.name) + '（' + esc(stName(t.status)) + '）</option>').join('');
  if (keep) srcSel.value = keep;

  document.querySelectorAll('#tasks .btn-ctrl').forEach(btn => {
    btn.onclick = (ev) => { ev.stopPropagation(); doControl(btn); };
  });
  document.querySelectorAll('#tasks .btn-ask').forEach(btn => {
    btn.onclick = (ev) => { ev.stopPropagation(); openAsk(btn.dataset.id, btn.dataset.name); };
  });
  document.querySelectorAll('#tasks tbody tr[data-id]').forEach(tr => {
    tr.onclick = () => {
      document.querySelectorAll('#tasks tbody tr').forEach(x => x.classList.remove('sel'));
      tr.classList.add('sel');
      SEL = {id: tr.dataset.id, name: tr.dataset.name};
      if (TASK_UNREAD[CUR]) delete TASK_UNREAD[CUR][String(SEL.id)];
      tr.querySelector('.task-unread')?.remove();
      const exportKey = CUR + ':' + SEL.id;
      $('btn-export').disabled = !!EXPORTING[exportKey];
      $('btn-del-task').disabled = false;
      if (!EXPORTING[exportKey]){
        $('exp-progress').hidden = true;
        if (EXPORT_RESULTS[exportKey]) showExportResult(EXPORT_RESULTS[exportKey]);
        else $('exp-msg').textContent = '';
      }
    };
  });

  const sel = $('f-llm');
  if (d.llms && d.llms.length){
    const prev = sel.value;
    sel.innerHTML = d.llms.map(p =>
      '<option value="' + esc(p.id) + '">' + esc(p.name) + (p.is_default ? esc(T('active_mark')) : '') + '</option>').join('');
    if (prev) { sel.value = prev; }
    else {
      const dft = d.llms.find(p => p.is_default);
      if (dft) sel.value = String(dft.id);
    }
  }
}
function chip(filter, k, v, color){
  const active = FILTER === filter || (!FILTER && filter === 'all');
  return '<button class="chip' + (active ? ' active' : '') + '" data-filter="' + filter + '" aria-pressed="' + active + '" style="--c:' + color + '"><div class="k">' + esc(k) + '</div><div class="v">' + (v||0) + '</div></button>';
}

function askSend(){
  if (!CUR) return;
  const name = $('f-name').value.trim();
  if (!name){ $('f-msg').innerHTML = '<span style="color:#bf7132">' + T('fill_name') + '</span>'; return; }
  const src = $('f-src').value;
  if (src && (!$('f-desc').value.trim() || !$('f-goal').value.trim())){
    $('f-msg').innerHTML = '<span style="color:#bf7132">' + T('need_desc_goal') + '</span>'; return;
  }
  const m = MACHINES.find(x => x.ip === CUR);
  const pw = m.has_password ? '' : $('p-pw').value;
  if (!m.has_password && !pw){ showErr(T('no_pw')); return; }
  const opt = $('f-llm').selectedOptions[0];
  const llmName = opt ? opt.textContent : '-';
  const mins = $('f-timeout').value || 600;
  const tmpDesc = (!$('f-desc-tmp').hidden && $('f-desc-tmp').value.trim());
  const desc = src ? $('f-desc').value.trim()
                   : (tmpDesc || fillDescTemplate(name));
  const goalTxt = src ? $('f-goal').value.trim() : '';
  let extra = '';
  if (src){
    const optSrc = $('f-src').selectedOptions[0];
    extra = '<br><span class="muted">' + esc(T('inherit_from')) + esc(optSrc ? optSrc.textContent : ('#' + src)) + '</span>';
  }
  let ct = T('confirm_text', '\u0001', '\u0002');
  ct = ct.split('\u0001').join('<b>' + esc(CUR) + '</b>').split('\u0002').join(esc(desc));
  $('f-confirm-text').innerHTML = ct + extra +
      (goalTxt ? '<br><span class="muted">' + esc(T('goal_label')) + esc(goalTxt.slice(0, 80)) + '</span>' : '') +
      '<br><span class="muted">' + esc(T('duration_llm', mins, llmName)) + '</span>';
  $('f-confirm').hidden = false;
  $('btn-send').disabled = true;
  $('btn-confirm-send').focus();
}
function cancelSend(){
  $('f-confirm').hidden = true;
  $('btn-send').disabled = false;
  $('f-msg').textContent = '';
}

async function send(){
  if (!CUR) return;
  const name = $('f-name').value.trim();
  if (!name){ $('f-msg').innerHTML = '<span style="color:#bf7132">' + T('fill_name') + '</span>'; return; }
  const m = MACHINES.find(x => x.ip === CUR);
  const pw = m.has_password ? '' : $('p-pw').value;
  if (!m.has_password && !pw){ showErr(T('no_pw')); return; }
  if (pw) PWD[CUR] = pw;
  $('btn-send').disabled = true; $('btn-send').textContent = T('dispatching');
  $('f-msg').textContent = '';
  try {
    const src = $('f-src').value;
    const body = {ip: CUR, password: pw, name,
      timeout_min: parseInt($('f-timeout').value || 600, 10),
      llm_id: $('f-llm').value || null};
    if (src){
      body.source_task_id = src;
      body.description = $('f-desc').value.trim();
      body.goal = $('f-goal').value.trim();
    } else {
      if (!$('f-desc-tmp').hidden && $('f-desc-tmp').value.trim())
        body.description = $('f-desc-tmp').value.trim();
      if (!$('f-goal-tmp').hidden && $('f-goal-tmp').value.trim())
        body.goal = $('f-goal-tmp').value.trim();
    }
    const d = await api('/api/dispatch', body);
    if (d.ok){
      $('f-msg').innerHTML = '<span class="ok">' + esc(T('dispatched', d.task_id, d.status)) + '</span>';
      $('f-name').value = '';
      $('f-desc-tmp').value = ''; $('f-goal-tmp').value = '';
      setEditOpen('f-desc-auto', 'f-desc-tmp', false);
      setEditOpen('f-goal-fixed', 'f-goal-tmp', false);
      $('f-src').value = '';
      onSrcChange();
      updateDesc();
      setDescOpen(false);
      setGoalOpen(false);
      await pollOnce();
    } else {
      $('f-msg').innerHTML = '<span style="color:#a8452f">✗ ' + esc(d.error || T('dispatch_failed')) + '</span>';
    }
  } catch(e){ $('f-msg').innerHTML = '<span style="color:#a8452f">' + esc(T('request_failed_short')) + '</span>'; }
  finally {
    $('f-confirm').hidden = true;
    $('btn-send').disabled = false;
    $('btn-send').textContent = T('send_task');
  }
}


function ctrlBtn(t){
  const s = t.status || "";
  const id = esc(t.id), nm = esc(t.name);
  if (s === "running" || s === "queued" || s === "created")
    return '<button class="mini ghost btn-ctrl" data-id="' + id + '" data-name="' + nm +
           '" data-action="pause">' + T('pause') + '</button>';
  if (s === "paused")
    return '<button class="mini ghost btn-ctrl" data-id="' + id + '" data-name="' + nm +
           '" data-action="resume">' + T('resume') + '</button>';
  return "";
}

async function doControl(btn){
  if (!CUR) return;
  const id = btn.dataset.id, action = btn.dataset.action;
  const m = MACHINES.find(x => x.ip === CUR);
  const pw = m.has_password ? '' : $('p-pw').value;
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = T(action === 'pause' ? 'pausing' : 'resuming');
  $('exp-msg').textContent = '';
  try {
    const d = await api('/api/control', {ip: CUR, password: pw, task_id: id, action: action});
    if (d.ok){
      $('exp-msg').innerHTML = '<span class="ok">' + esc(T(action === 'pause' ? 'paused_ok' : 'resumed_ok', id)) +
        (d.queued ? esc(T('queued')) : '') + '</span>';
      await pollOnce();
      return;
    }
    $('exp-msg').innerHTML = '<span style="color:#a8452f">✗ ' + esc(d.error || T('op_failed')) + '</span>';
  } catch(e){
    $('exp-msg').innerHTML = '<span style="color:#a8452f">✗ ' + esc(T('req_failed')) + esc(e) + '</span>';
  }
  btn.disabled = false;
  btn.textContent = old;
}

function openAsk(id, name){
  ASK = {ip: CUR, id: String(id), name: name, history: [], latestReply: ''};
  $('ask-sec').hidden = false;
  $('ask-title').textContent = '#' + id + ' ' + name;
  $('ask-reply').hidden = true; $('ask-reply').textContent = '';
  $('btn-copy-reply').hidden = true;
  $('ask-status').textContent = ''; $('ask-history').innerHTML = '';
  $('ask-msg').value = ''; $('btn-ask').disabled = askPending;
  loadAskHistory();
  $('ask-msg').focus();
  $('ask-sec').scrollIntoView({block: 'nearest', behavior: 'smooth'});
}

async function loadAskHistory(){
  if (!ASK) return;
  const target = ASK;
  try {
    const d = await api('/api/ask-history', {ip: target.ip, task_id: target.id});
    if (ASK === target && d.ok) renderAskHistory(d.items || [], true);
  } catch(e){}
}

function renderAskHistory(items, showLatest){
  if (!ASK) return;
  ASK.history = items;
  $('ask-history').innerHTML = items.length ? '<div class="muted" style="margin-top:12px">' + esc(T('ask_history')) + '</div>' +
    items.slice().reverse().map((it, i) => '<details' + (i === 0 && items.length > 1 ? '' : '') + '><summary>' + esc(it.message.slice(0, 100)) + '</summary>' +
      '<div class="qa"><b>' + esc(T('question')) + '</b>' + esc(it.message) + '<b>' + esc(T('answer')) + '</b>' + esc(it.reply || T('empty_reply')) + '</div></details>').join('')
    : '<div class="muted" style="margin-top:12px">' + esc(T('no_history')) + '</div>';
  if (showLatest && items.length){
    const latest = items[items.length - 1];
    ASK.latestReply = latest.reply || '';
    $('ask-reply').textContent = latest.reply || T('empty_reply');
    $('ask-reply').hidden = false; $('btn-copy-reply').hidden = !ASK.latestReply;
  }
}

let askPending = false;
async function doAsk(){
  if (!ASK || !CUR || askPending) return;
  const msg = $('ask-msg').value.trim();
  if (!msg){ $('ask-status').textContent = T('ask_empty'); return; }
  const target = ASK, ip = CUR;
  const m = MACHINES.find(x => x.ip === ip);
  const pw = (m.has_password || m.has_key) ? '' : $('p-pw').value;
  askPending = true; $('btn-ask').disabled = true; $('btn-ask').textContent = T('sending');
  $('ask-reply').hidden = true; $('btn-copy-reply').hidden = true;
  const t0 = Date.now();
  const timer = setInterval(() => {
    if (ASK === target) $('ask-status').textContent = T('waiting') + Math.round((Date.now() - t0) / 1000) + 's';
  }, 1000);
  try {
    const d = await api('/api/ask', {ip, password: pw, task_id: target.id, message: msg});
    if (ASK !== target || CUR !== ip) return;
    $('ask-reply').hidden = false;
    if (d.ok){
      $('ask-status').textContent = '';
      ASK.latestReply = d.reply || '';
      $('ask-reply').textContent = d.reply || T('empty_reply');
      $('btn-copy-reply').hidden = !ASK.latestReply;
      $('ask-msg').value = '';
    } else {
      $('ask-status').textContent = '';
      $('ask-reply').innerHTML = '<span style="color:#a8452f">✗ ' + esc(d.error || T('op_failed')) + '</span>';
    }
    if (d.history) renderAskHistory(d.history, false);
  } catch(e){
    if (ASK === target){
      $('ask-status').textContent = ''; $('ask-reply').hidden = false;
      $('ask-reply').textContent = T('req_failed') + e;
    }
  } finally {
    clearInterval(timer); askPending = false;
    $('btn-ask').disabled = false; $('btn-ask').textContent = T('send');
  }
}

$('btn-copy-reply').onclick = async () => {
  if (!ASK || !ASK.latestReply) return;
  try { await navigator.clipboard.writeText(ASK.latestReply); }
  catch(e){
    const ta = document.createElement('textarea'); ta.value = ASK.latestReply; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy'); ta.remove();
  }
  toast(T('copied'));
};

$('btn-ask').onclick = doAsk;
$('ask-msg').addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)){ e.preventDefault(); doAsk(); }
});

function exportStageText(stage){
  return T({report: 'export_report_step', critical: 'export_critical_step', high: 'export_high_step',
            finishing: 'export_finishing'}[stage] || 'export_report_step');
}

function updateExportProgress(ctx, stage){
  if (CUR !== ctx.ip || !SEL || SEL.id !== ctx.task_id) return;
  const widths = {report: 18, critical: 45, high: 73, finishing: 92};
  $('exp-progress').hidden = false; $('exp-progress').classList.add('indeterminate');
  $('exp-bar').style.width = (widths[stage] || 12) + '%';
  $('exp-msg').textContent = exportStageText(stage);
}

function showExportResult(d){
  if (!d) return;
  $('exp-progress').hidden = true;
  if (!d.ok){ $('exp-msg').innerHTML = '<span style="color:#a8452f">✗ ' + esc(d.error || T('export_failed')) + '</span>'; return; }
  const errors = (d.errors || []).length;
  $('exp-msg').innerHTML = '<span class="ok">' + esc(T('exported_to', d.dir, d.critical || 0, d.high || 0)) + '</span> ' +
    (errors ? '<span style="color:var(--high)">' + esc(T('export_partial', errors)) + '</span> ' : '') +
    '<a href="#" id="lnk-open" style="color:var(--accent)">' + esc(T('open_dir')) + '</a>';
  $('lnk-open').onclick = async (e) => {
    e.preventDefault();
    const r = await api('/api/open-dir', {dir: d.dir});
    if (!r.ok) toast(r.error || T('op_failed'));
  };
}

async function pollExport(ctx){
  let failures = 0;
  while (EXPORTING[ctx.key]){
    try {
      const d = await api('/api/export-status', {job_id: ctx.job_id});
      failures = 0;
      if (d.status === 'running'){ updateExportProgress(ctx, d.stage); }
      else {
        delete EXPORTING[ctx.key]; EXPORT_RESULTS[ctx.key] = d;
        if (CUR === ctx.ip && SEL && SEL.id === ctx.task_id){
          showExportResult(d); $('btn-export').disabled = false; $('btn-export').textContent = T('export');
        } else if (d.ok) toast(T('export') + ' ✓');
        return;
      }
    } catch(e){
      failures++;
      if (failures >= 5){
        const d = {ok: false, error: T('req_failed') + e};
        delete EXPORTING[ctx.key]; EXPORT_RESULTS[ctx.key] = d;
        if (CUR === ctx.ip && SEL && SEL.id === ctx.task_id){
          showExportResult(d); $('btn-export').disabled = false; $('btn-export').textContent = T('export');
        }
        return;
      }
    }
    await new Promise(resolve => setTimeout(resolve, 700));
  }
}

async function doExport(){
  if (!CUR || !SEL) return;
  const ip = CUR, selection = {id: SEL.id, name: SEL.name}, key = ip + ':' + SEL.id;
  if (EXPORTING[key]){ toast(T('export_running')); return; }
  const m = MACHINES.find(x => x.ip === ip);
  const pw = (m.has_password || m.has_key) ? '' : $('p-pw').value;
  EXPORTING[key] = true; delete EXPORT_RESULTS[key];
  $('btn-export').disabled = true; $('btn-export').textContent = T('exporting');
  $('exp-msg').textContent = ''; $('exp-progress').hidden = false; $('exp-bar').style.width = '12%';
  try {
    const d = await api('/api/export', {ip, password: pw, task_id: selection.id, task_name: selection.name});
    if (!d.ok) throw new Error(d.error || T('export_failed'));
    const ctx = {ip, task_id: selection.id, key, job_id: d.job_id};
    EXPORTING[key] = ctx; updateExportProgress(ctx, 'report'); pollExport(ctx);
  } catch(e){
    delete EXPORTING[key];
    const result = {ok: false, error: e.message}; EXPORT_RESULTS[key] = result;
    if (CUR === ip && SEL && SEL.id === selection.id){
      showExportResult(result); $('btn-export').disabled = false; $('btn-export').textContent = T('export');
    }
  }
}
$('btn-export').onclick = doExport;

/* ---------- 服务器文件 ---------- */
let WS = {ip: null, path: '', entries: [], sel: new Set(), loading: false, busy: false};
let WS_REQ = 0;
const DEL_OPTS = ['delete_files', 'delete_assets', 'delete_traffic', 'delete_findings', 'delete_llm_records'];
let DEL = {ip: null, task_id: null, name: '', running: false, error: ''};

const WS_DIR_ICO = '<svg class="ws-ico dir" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M1.6 3.9c0-.6.5-1.1 1.1-1.1h3.1l1.4 1.6h6.1c.6 0 1.1.5 1.1 1.1v6.6c0 .6-.5 1.1-1.1 1.1H2.7c-.6 0-1.1-.5-1.1-1.1z"/></svg>';
const WS_FILE_ICO = '<svg class="ws-ico" viewBox="0 0 16 16" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="1.1" d="M3.9 1.8h5l3.7 3.7v8.7H3.9z"/><path fill="none" stroke="currentColor" stroke-width="1.1" d="M8.8 1.9v3.7h3.6"/></svg>';

function fmtSize(n){
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return (n >= 100 ? Math.round(n) : n.toFixed(n >= 10 ? 1 : 2)) + ' ' + units[i];
}
function fmtTime(ts){
  const d = new Date((Number(ts) || 0) * 1000);
  if (!ts || isNaN(d.getTime())) return '—';
  const p = x => String(x).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
    p(d.getHours()) + ':' + p(d.getMinutes());
}
function pwFor(ip){
  const m = MACHINES.find(x => x.ip === ip);
  return (m && (m.has_password || m.has_key)) ? '' : $('p-pw').value;
}
function wsTaskIndex(){
  const d = REFRESHED[WS.ip] || {};
  const out = {};
  (d.all_tasks || []).forEach(t => { out[String(t.id)] = t; });
  return out;
}

function openFiles(path){
  if (!CUR) return;
  WS.ip = CUR; WS.sel.clear(); WS.busy = false;
  $('ws-msg').textContent = '';
  openModal($('ws-modal'));
  loadWs(path || '');
}

async function loadWs(path){
  if (!WS.ip) return;
  const req = ++WS_REQ;
  WS.loading = true; WS.sel.clear();
  $('ws-msg').textContent = '';
  $('ws-list').innerHTML = '<div class="ws-loading">' + esc(T('ws_loading')) + '</div>';
  updateWsSel();
  try {
    const d = await api('/api/ws/list', {ip: WS.ip, password: pwFor(WS.ip), path: path || ''});
    if (req !== WS_REQ) return;
    WS.loading = false;
    if (!d.ok){
      $('ws-msg').innerHTML = '<span style="color:var(--crit)">' + esc(d.error || T('ws_load_failed')) + '</span>';
      $('ws-list').innerHTML = '';
      renderWs();
      return;
    }
    WS.path = d.path || '';
    WS.entries = d.entries || [];
    renderWs();
  } catch(e){
    if (req !== WS_REQ) return;
    WS.loading = false;
    $('ws-msg').innerHTML = '<span style="color:var(--crit)">' + esc(T('req_failed') + e) + '</span>';
    $('ws-list').innerHTML = '';
    renderWs();
  }
}

function renderWs(){
  $('ws-ip').textContent = WS.ip || '';
  $('ws-sub').textContent = WS.path ? ('/' + WS.path) : '/';
  const parts = WS.path ? WS.path.split('/') : [];
  let crumb = '<a data-ws-go="">' + esc(T('ws_root')) + '</a>';
  const acc = [];
  parts.forEach((p, i) => {
    acc.push(p);
    crumb += '<span class="sep">/</span>' + (i === parts.length - 1
      ? '<b>' + esc(p) + '</b>'
      : '<a data-ws-go="' + esc(acc.join('/')) + '">' + esc(p) + '</a>');
  });
  $('ws-path').innerHTML = crumb;
  $('ws-path').querySelectorAll('a[data-ws-go]').forEach(a => {
    a.onclick = () => loadWs(a.dataset.wsGo);
  });
  $('ws-up').disabled = !WS.path;

  const chips = [{p: '', label: T('ws_root')}, {p: 'tasks', label: 'tasks'}];
  if (SEL && CUR === WS.ip) chips.push({p: 'tasks/' + SEL.id, label: T('ws_task_link', SEL.id)});
  $('ws-quick').innerHTML = chips.map(c =>
    '<button class="ws-chip' + (WS.path === c.p ? ' on' : '') + '" data-ws-go="' + esc(c.p) + '">' +
    esc(c.label) + '</button>').join('');
  $('ws-quick').querySelectorAll('button[data-ws-go]').forEach(b => {
    b.onclick = () => loadWs(b.dataset.wsGo);
  });

  if (WS.loading){ updateWsSel(); return; }
  if (!WS.entries.length){
    $('ws-list').innerHTML = '<div class="ws-empty">' + esc(T('ws_empty')) + '</div>';
    updateWsSel();
    return;
  }

  const tasks = WS.path === 'tasks' ? wsTaskIndex() : null;
  const rows = WS.entries.map((e, i) => {
    const checked = WS.sel.has(e.path);
    let sub = '';
    if (tasks && e.dir && /^\d+$/.test(e.name) && tasks[e.name])
      sub = '<span class="sub">' + esc(tasks[e.name].name) + '</span>';
    return '<tr data-i="' + i + '"' + (checked ? ' class="on"' : '') + '>' +
      '<td class="wsc"><input type="checkbox" data-ws-sel="' + esc(e.path) + '"' + (checked ? ' checked' : '') + '></td>' +
      '<td><div class="wname">' + (e.dir ? WS_DIR_ICO : WS_FILE_ICO) +
        '<span class="nm" title="' + esc(e.name) + '">' + esc(e.name) + '</span>' + sub + '</div></td>' +
      '<td class="wsize">' + (e.dir ? '—' : esc(fmtSize(e.size))) + '</td>' +
      '<td class="wtime">' + esc(fmtTime(e.mtime)) + '</td></tr>';
  }).join('');
  $('ws-list').innerHTML = '<table class="ws-table"><thead><tr>' +
    '<th class="wsc"><input type="checkbox" id="ws-all"></th>' +
    '<th>' + esc(T('ws_name')) + '</th><th class="wsize">' + esc(T('ws_size')) + '</th>' +
    '<th class="wtime">' + esc(T('ws_mtime')) + '</th></tr></thead><tbody>' + rows + '</tbody></table>';

  $('ws-list').querySelectorAll('tbody tr[data-i]').forEach(tr => {
    const entry = WS.entries[Number(tr.dataset.i)];
    if (!entry) return;
    tr.onclick = (ev) => {
      if (ev.target.closest('input[type=checkbox]')) return;
      if (entry.dir) loadWs(entry.path);
      else toggleWsSel(entry.path);
    };
    const cb = tr.querySelector('input[data-ws-sel]');
    if (cb){
      cb.onclick = ev => ev.stopPropagation();
      cb.onchange = () => toggleWsSel(entry.path, cb.checked);
    }
  });
  const all = $('ws-all');
  if (all){
    all.onclick = ev => ev.stopPropagation();
    all.onchange = () => {
      if (all.checked) WS.entries.forEach(e => WS.sel.add(e.path));
      else WS.sel.clear();
      $('ws-list').querySelectorAll('input[data-ws-sel]').forEach(cb => {
        cb.checked = all.checked;
        const tr = cb.closest('tr'); if (tr) tr.classList.toggle('on', all.checked);
      });
      updateWsSel();
    };
  }
  updateWsSel();
}

function toggleWsSel(path, force){
  if (typeof force === 'boolean'){
    if (force) WS.sel.add(path); else WS.sel.delete(path);
  } else if (WS.sel.has(path)) WS.sel.delete(path);
  else WS.sel.add(path);
  $('ws-list').querySelectorAll('input[data-ws-sel]').forEach(cb => {
    if (cb.dataset.wsSel !== path) return;
    cb.checked = WS.sel.has(path);
    const tr = cb.closest('tr'); if (tr) tr.classList.toggle('on', cb.checked);
  });
  updateWsSel();
}

function updateWsSel(){
  const n = WS.sel.size;
  let bytes = 0;
  WS.entries.forEach(e => { if (WS.sel.has(e.path) && !e.dir) bytes += Number(e.size) || 0; });
  $('ws-count').textContent = n ? T('ws_selected', n, fmtSize(bytes)) : '';
  $('ws-download').disabled = !n || WS.loading || WS.busy;
  const all = $('ws-all');
  if (all){
    const total = WS.entries.length;
    all.checked = total > 0 && n === total;
    all.indeterminate = n > 0 && n < total;
  }
}

async function downloadSelected(){
  if (!WS.ip || WS.busy || !WS.sel.size) return;
  const paths = [...WS.sel];
  WS.busy = true;
  $('ws-msg').textContent = '';
  $('ws-download').disabled = true;
  $('ws-download').textContent = T('ws_downloading');
  try {
    const d = await api('/api/ws/download', {ip: WS.ip, password: pwFor(WS.ip), paths});
    if (!d.ok) throw new Error(d.error || T('ws_download_failed'));
    const a = document.createElement('a');
    a.href = '/api/ws/download?id=' + encodeURIComponent(d.id);
    a.download = d.name || '';
    document.body.appendChild(a); a.click(); a.remove();
    toast(T('ws_download_started', d.name || ''));
  } catch(e){
    $('ws-msg').innerHTML = '<span style="color:var(--crit)">' + esc(T('ws_download_failed') + ': ' + (e.message || e)) + '</span>';
  } finally {
    WS.busy = false;
    $('ws-download').textContent = T('ws_download');
    updateWsSel();
  }
}

function closeFiles(){
  closeModal($('ws-modal'));
}

/* ---------- 删除任务 ---------- */
function delOptions(){
  const out = {};
  DEL_OPTS.forEach(k => {
    const cb = document.querySelector('#del-modal input[data-opt="' + k + '"]');
    out[k] = !!(cb && cb.checked);
  });
  return out;
}

function syncDelOpts(){
  const boxes = [...document.querySelectorAll('#del-modal input[data-opt]')];
  const n = boxes.filter(b => b.checked).length;
  const all = $('del-all');
  all.checked = n === boxes.length;
  all.indeterminate = n > 0 && n < boxes.length;
  $('del-ack').disabled = DEL.running;
  $('del-confirm').disabled = DEL.running || !$('del-ack').checked;
  if (!DEL.running && !DEL.error) $('del-msg').textContent = n ? T('del_selected', n) : '';
}

function openDelete(){
  if (!CUR || !SEL) return;
  DEL = {ip: CUR, task_id: String(SEL.id), name: SEL.name || '', running: false, error: ''};
  $('del-sub').textContent = '#' + DEL.task_id + ' · ' + DEL.name + ' · ' + DEL.ip;
  $('del-msg').textContent = '';
  document.querySelectorAll('#del-modal input[data-opt]').forEach(cb => { cb.checked = false; cb.disabled = false; });
  $('del-all').disabled = false; $('del-all').indeterminate = false;
  $('del-ack').checked = false; $('del-ack').disabled = false;
  $('del-close').disabled = false; $('del-cancel').disabled = false;
  $('del-confirm').textContent = T('del_confirm');
  $('del-stat').textContent = T('del_stat_loading');
  syncDelOpts();
  openModal($('del-modal'));
  loadDelStat();
}

async function loadDelStat(){
  const ip = DEL.ip, tid = DEL.task_id;
  if (!ip || !tid) return;
  try {
    const d = await api('/api/ws/stat', {ip, password: pwFor(ip), task_id: tid});
    if (DEL.task_id !== tid || DEL.ip !== ip) return;
    let line;
    if (!d.ok) line = T('del_stat_unknown');
    else if (!d.exists) line = T('del_stat_none');
    else line = T('del_stat', d.files, fmtSize(d.bytes)) + (d.truncated ? ' …' : '');
    const t = ((REFRESHED[ip] || {}).all_tasks || []).find(x => String(x.id) === tid);
    if (t && ['running', 'queued', 'created'].includes(t.status)) line += ' ' + T('del_running_warn');
    $('del-stat').textContent = line;
  } catch(e){
    if (DEL.task_id === tid) $('del-stat').textContent = T('del_stat_unknown');
  }
}

function closeDelete(){
  if (DEL.running) return;
  closeModal($('del-modal'));
}

async function doDeleteTask(){
  if (!DEL.ip || !DEL.task_id || DEL.running || !$('del-ack').checked) return;
  const opts = delOptions(), ip = DEL.ip, tid = DEL.task_id;
  DEL.running = true; DEL.error = '';
  $('del-confirm').disabled = true; $('del-confirm').textContent = T('deleting');
  $('del-close').disabled = true; $('del-cancel').disabled = true;
  document.querySelectorAll('#del-modal input[data-opt]').forEach(cb => { cb.disabled = true; });
  $('del-all').disabled = true; $('del-ack').disabled = true;
  $('del-msg').innerHTML = '<span class="muted">' + esc(T('deleting')) + '</span>';
  try {
    const d = await api('/api/task-delete', Object.assign({ip, password: pwFor(ip), task_id: tid}, opts));
    if (!d.ok) throw new Error(d.error || T('del_fail'));
    closeModal($('del-modal'));
    toast(T('del_ok', tid));
    if (SEL && SEL.id === tid) SEL = null;
    if (ASK && ASK.id === tid){ ASK = null; $('ask-sec').hidden = true; }
    if (TASK_UNREAD[ip]) delete TASK_UNREAD[ip][tid];
    if (REFRESHED[ip] && Array.isArray(REFRESHED[ip].all_tasks)){
      REFRESHED[ip].all_tasks = REFRESHED[ip].all_tasks.filter(t => String(t.id) !== tid);
      if (REFRESHED[ip].tasks_total) REFRESHED[ip].tasks_total = Math.max(0, REFRESHED[ip].tasks_total - 1);
    }
    if (CUR === ip && REFRESHED[ip]) render(REFRESHED[ip]);
    pollOnce();
  } catch(e){
    DEL.error = e.message || String(e);
    $('del-msg').innerHTML = '<span style="color:var(--crit)">' + esc(DEL.error) + '</span>';
  } finally {
    DEL.running = false;
    $('del-confirm').textContent = T('del_confirm');
    $('del-close').disabled = false; $('del-cancel').disabled = false;
    document.querySelectorAll('#del-modal input[data-opt]').forEach(cb => { cb.disabled = false; });
    $('del-all').disabled = false; $('del-ack').disabled = false;
    syncDelOpts();
  }
}

$('btn-files').onclick = () => openFiles('');
$('ws-close').onclick = closeFiles;
$('ws-up').onclick = () => {
  if (!WS.path) return;
  loadWs(WS.path.split('/').slice(0, -1).join('/'));
};
$('ws-refresh').onclick = () => loadWs(WS.path);
$('ws-download').onclick = downloadSelected;
$('ws-modal').addEventListener('mousedown', e => { if (e.target === $('ws-modal')) closeFiles(); });

$('btn-del-task').onclick = openDelete;
$('del-close').onclick = closeDelete;
$('del-cancel').onclick = closeDelete;
$('del-modal').addEventListener('mousedown', e => { if (e.target === $('del-modal')) closeDelete(); });
$('del-all').onchange = () => {
  document.querySelectorAll('#del-modal input[data-opt]').forEach(cb => { cb.checked = $('del-all').checked; });
  DEL.error = ''; syncDelOpts();
};
document.querySelectorAll('#del-modal input[data-opt]').forEach(cb => {
  cb.onchange = () => { DEL.error = ''; syncDelOpts(); };
});
$('del-ack').onchange = () => { DEL.error = ''; syncDelOpts(); };
$('del-confirm').onclick = doDeleteTask;

$('btn-send').onclick = askSend;
$('btn-confirm-send').onclick = () => { $('f-confirm').hidden = true; $('btn-send').disabled = false; send(); };
$('btn-cancel-send').onclick = cancelSend;
$('f-name').addEventListener('keydown', e => { if (e.key === 'Enter'){ e.preventDefault(); askSend(); } });

/* ---------- 全部任务：拖动排序 ---------- */
function taskRowHTML(t, i){
  const unread = TASK_UNREAD[CUR] && TASK_UNREAD[CUR][String(t.id)];
  return '<div class="trow' + (i < 5 ? ' on' : '') + '" draggable="true" data-id="' + esc(t.id) + '">' +
    '<span class="grip"></span>' +
    '<span class="rank">' + (i + 1) + '</span>' +
    '<span class="tid">#' + esc(t.id) + '</span>' +
    '<span class="tname" title="' + esc(t.name) + '">' + esc(t.name) + (unread ? '<span class="task-unread"></span>' : '') + '</span>' +
    '<span class="tag s-' + esc(t.status) + '"><i></i>' + esc(stName(t.status)) + '</span>' +
    (i < 5 ? '<span class="tshow">' + esc(T('show_badge')) + '</span>' : '') +
    '</div>';
}

function syncCut(){
  const wrap = $('t-list');
  let cut = $('t-cut');
  if (!cut){
    cut = document.createElement('div');
    cut.id = 't-cut'; cut.className = 'tcut';
    wrap.appendChild(cut);
  }
  cut.textContent = T('cut_label');
  const rows = wrap.querySelectorAll('.trow');
  if (rows.length > 5){ rows[4].after(cut); cut.hidden = false; }
  else cut.hidden = true;
}

function syncTaskRows(){
  const rows = [...$('t-list').querySelectorAll('.trow')];
  T_ORDER = rows.map(r => r.dataset.id);
  rows.forEach((r, i) => {
    r.classList.toggle('on', i < 5);
    const rank = r.querySelector('.rank');
    if (rank) rank.textContent = i + 1;
    const badge = r.querySelector('.tshow');
    if (i < 5 && !badge){
      const b = document.createElement('span');
      b.className = 'tshow'; b.textContent = T('show_badge');
      r.appendChild(b);
    } else if (i >= 5 && badge){ badge.remove(); }
  });
  syncCut();
  $('t-msg').textContent = T_ORDER.join(',') === T_ORIG ? '' : T('order_dirty');
}

function openTasks(){
  if (!CUR) return;
  const d = REFRESHED[CUR];
  if (!d || !d.ok) return;
  const tasks = orderedTasks(d);
  if (!tasks.length) return;
  T_ORDER = tasks.map(t => String(t.id));
  T_ORIG = T_ORDER.join(',');
  $('t-sub-ip').textContent = CUR;
  $('t-sub').textContent = T(tasks.length > 5 ? 'all_sub' : 'all_sub_short', tasks.length);
  $('t-msg').textContent = '';
  $('t-save').disabled = false;
  $('t-list').innerHTML = tasks.map(taskRowHTML).join('');
  syncCut();
  $('t-list').scrollTop = 0;
  openModal($('t-modal'));
  $('t-save').focus();
}

function closeTasks(){
  if ($('t-modal').hidden) return;
  closeModal($('t-modal'), () => {
    $('t-list').innerHTML = '';
    T_ORDER = null; T_ORIG = ''; DRAG_ID = null;
  });
}

async function saveTasks(){
  if (!CUR || !T_ORDER || !T_ORDER.length) return;
  const ip = CUR, order = T_ORDER.slice();
  $('t-save').disabled = true;
  $('t-msg').textContent = T('saving');
  try {
    const d = await api('/api/task-order', {ip: ip, order: order});
    if (d.ok){
      const cached = REFRESHED[ip];
      if (cached){ cached.task_order = (d.order || order).slice(); render(cached); }
      closeTasks();
      toast(T('order_saved'));
    } else {
      $('t-msg').innerHTML = '<span style="color:#a8452f">✗ ' + esc(d.error || T('order_fail')) + '</span>';
      $('t-save').disabled = false;
    }
  } catch(e){
    $('t-msg').innerHTML = '<span style="color:#a8452f">✗ ' + esc(T('req_failed')) + esc(e) + '</span>';
    $('t-save').disabled = false;
  }
}

function onDragStart(e){
  const row = e.target.closest('.trow');
  if (!row) return;
  DRAG_ID = row.dataset.id;
  row.classList.add('dragging');
  e.dataTransfer.effectAllowed = 'move';
  try { e.dataTransfer.setData('text/plain', DRAG_ID); } catch(err){}
}

function onDragOver(e){
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  const wrap = $('t-list');
  const dragging = wrap.querySelector('.trow.dragging');
  if (!dragging) return;
  const after = [...wrap.querySelectorAll('.trow:not(.dragging)')].find(r => {
    const box = r.getBoundingClientRect();
    return e.clientY < box.top + box.height / 2;
  });
  if (after) wrap.insertBefore(dragging, after);
  else wrap.appendChild(dragging);
  syncTaskRows();
}

function onDragEnd(){
  const wrap = $('t-list');
  wrap.querySelectorAll('.trow.dragging').forEach(r => r.classList.remove('dragging'));
  DRAG_ID = null;
  syncTaskRows();
}

let toastTimer = null;
function toast(msg){
  const el = $('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2000);
}

$('btn-all').onclick = openTasks;
$('t-close').onclick = closeTasks;
$('t-cancel').onclick = closeTasks;
$('t-save').onclick = saveTasks;
$('t-modal').addEventListener('mousedown', e => { if (e.target === $('t-modal')) closeTasks(); });
$('t-list').addEventListener('dragstart', onDragStart);
$('t-list').addEventListener('dragover', onDragOver);
$('t-list').addEventListener('drop', e => e.preventDefault());
$('t-list').addEventListener('dragend', onDragEnd);

document.addEventListener('pointerdown', e => {
  const b = e.target.closest('button');
  if (!b || b.disabled || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const box = b.getBoundingClientRect(), size = Math.max(box.width, box.height);
  const r = document.createElement('span'); r.className = 'ripple';
  r.style.cssText = 'width:' + size + 'px;height:' + size + 'px;left:' + (e.clientX - box.left - size / 2) + 'px;top:' + (e.clientY - box.top - size / 2) + 'px';
  b.appendChild(r); setTimeout(() => r.remove(), 480);
});

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (!$('ws-modal').hidden){ closeFiles(); return; }
  if (!$('del-modal').hidden){ closeDelete(); return; }
  if (!$('t-modal').hidden){ closeTasks(); return; }
  if (!$('m-modal').hidden){ closeModal($('m-modal')); return; }
  if (document.body.classList.contains('mobile-side')){ setMobileSide(false); return; }
  if (!$('f-confirm').hidden) cancelSend();
});

boot();
</script>
</body>
</html>
"""


SETTINGS_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>ARTEX · Settings</title>
<link rel="icon" href="/icon.ico">
<style>
  :root{--bg:#f6f1e7;--panel:#fdfaf4;--panel2:#f1e9db;--line:#e6dccb;--soft:#efe7d9;
    --ink:#4a4136;--ink2:#786c5d;--ink3:#a59a8b;--accent:#96683f;--accentd:#7d5533;
    --ok:#4b7357;--crit:#a8452f}
  *{box-sizing:border-box}[hidden]{display:none!important}
  body.dark{--bg:#1f1a15;--panel:#272119;--panel2:#2f2820;--line:#3b332a;--soft:#332c24;
    --ink:#e6dccc;--ink2:#bdb09e;--ink3:#8a7d6c;--accent:#d0a271;--accentd:#b98a55;
    --ok:#83b18e;--crit:#d97f68}
  html,body{margin:0;min-height:100%}
  body{background:var(--bg);color:var(--ink);font:13.5px/1.65 "Segoe UI","Microsoft YaHei",system-ui,sans-serif;
    padding:38px 20px 90px;-webkit-font-smoothing:antialiased;transition:background .2s,color .2s}
  .wrap{width:min(850px,100%);margin:auto}
  .head{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:20px;gap:16px}
  .brand{font-size:17px;font-weight:600;letter-spacing:.4px;color:var(--accent)}
  .sub{font-size:12px;color:var(--ink3);letter-spacing:1px;margin-top:2px}
  .back{color:var(--accent);font-size:12px;text-decoration:none;white-space:nowrap}
  .back:hover{text-decoration:underline}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:20px 22px;
    box-shadow:0 2px 8px rgba(120,95,60,.05);margin-bottom:16px;animation:rise .25s ease both}
  .card:nth-of-type(3){animation-delay:.035s}.card:nth-of-type(4){animation-delay:.07s}
  .card:nth-of-type(5){animation-delay:.105s}
  @keyframes rise{from{opacity:0;transform:translateY(7px)}}
  h2{font-size:13px;margin:0 0 3px;letter-spacing:.5px}h2+div{margin-bottom:17px}
  .row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px}.row:last-child{margin-bottom:0}
  .field{display:flex;flex-direction:column;gap:5px;min-width:130px;flex:1}.field.small{flex:0;min-width:120px}
  .field label,.label{font-size:11px;letter-spacing:.35px;color:var(--ink3)}
  input,select,textarea{font:inherit;font-size:13px;color:var(--ink);background:#fffdf9;width:100%;
    border:1px solid var(--line);border-radius:7px;padding:7px 10px;transition:border-color .15s,box-shadow .15s}
  textarea{resize:vertical;line-height:1.6}
  body.dark input,body.dark select,body.dark textarea{background:#231e18}
  input:focus,select:focus,textarea:focus{outline:none;border-color:#c8a986;box-shadow:0 0 0 3px rgba(150,104,63,.10)}
  .check{display:flex;align-items:center;gap:9px;padding:8px 0;cursor:pointer;flex:1;min-width:220px}
  .check input{width:16px;height:16px;accent-color:var(--accent);margin:0}.check span{font-size:12.5px}
  .hint{font-size:11.5px;color:var(--ink3);line-height:1.6}.warn{color:var(--crit)}
  button{position:relative;overflow:hidden;font:inherit;font-size:12.5px;padding:6px 16px;border-radius:7px;
    cursor:pointer;background:var(--accent);border:1px solid var(--accentd);color:#fdfaf4;
    transition:transform .12s,background .12s,box-shadow .12s;box-shadow:0 1px 2px rgba(125,85,51,.16)}
  button:hover{background:var(--accentd);transform:translateY(-1px)}button:active{transform:translateY(1px) scale(.98)}
  button:disabled{opacity:.5;cursor:not-allowed;transform:none}.ghost{background:transparent;color:var(--ink2);
    border-color:var(--line);box-shadow:none}.ghost:hover{background:var(--panel2);color:var(--ink)}
  .danger{color:var(--crit);border-color:color-mix(in srgb,var(--crit) 35%,var(--line))}
  .actions{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.actions .field{max-width:250px}
  .savebar{position:fixed;left:50%;bottom:18px;transform:translateX(-50%);width:min(850px,calc(100% - 40px));
    display:flex;align-items:center;gap:12px;padding:11px 14px;border:1px solid var(--line);border-radius:12px;
    background:color-mix(in srgb,var(--panel) 92%,transparent);backdrop-filter:blur(12px);
    box-shadow:0 8px 30px rgba(70,50,30,.14);z-index:5}
  .savebar .sp{flex:1}.muted{color:var(--ink3);font-size:12px}.ok{color:var(--ok)}
  .host{border:1px solid var(--soft);border-radius:8px;padding:9px 11px;margin-top:7px;display:flex;gap:12px;
    align-items:center;animation:rise .18s ease}.host .fp{min-width:0;flex:1}.host code{display:block;font-size:11px;
    color:var(--ink2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.host b{font-size:12px}
  .empty{padding:12px;border:1px dashed var(--line);border-radius:8px;color:var(--ink3);font-size:12px;margin-top:8px}
  .ripple{position:absolute;border-radius:50%;background:currentColor;opacity:.12;pointer-events:none;
    transform:scale(0);animation:rip .42s ease-out}@keyframes rip{to{transform:scale(3);opacity:0}}
  .toast{position:fixed;left:50%;bottom:86px;transform:translate(-50%,10px);background:var(--ink);color:var(--panel);
    padding:8px 16px;border-radius:20px;font-size:12px;opacity:0;pointer-events:none;transition:.18s;z-index:8}
  .toast.show{opacity:1;transform:translate(-50%,0)}
  @media(max-width:600px){body{padding:24px 12px 92px}.card{padding:17px 15px}.field.small{flex:1}.savebar{width:calc(100% - 24px)}}
  @media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<script>try{if(localStorage.getItem('artex_theme')==='1')document.body.classList.add('dark')}catch(e){}</script>
<div class="wrap">
  <div class="head"><div><div class="brand">ARTEX Controller</div><div class="sub" data-i18n="sub">全局设置</div></div>
    <a class="back" href="/" data-i18n="back">← 返回控制台</a></div>
  <section class="card"><h2 data-i18n="ui">界面与刷新</h2><div class="hint" data-i18n="ui_sub">控制默认外观、自动连接和轮询频率</div>
    <div class="row"><div class="field"><label data-i18n="lang">语言</label><select id="lang"><option value="zh">简体中文</option><option value="en">English</option></select></div>
      <div class="field"><label data-i18n="theme">默认主题</label><select id="theme"><option value="light" data-i18n="light">浅色</option><option value="dark" data-i18n="dark">深色</option></select></div></div>
    <div class="row"><div class="field"><label data-i18n="refresh">前台刷新间隔（秒）</label><input id="refresh_seconds" type="number" min="3" max="120"></div>
      <div class="field"><label data-i18n="background_refresh">后台刷新间隔（秒）</label><input id="background_refresh_seconds" type="number" min="10" max="600"></div></div>
    <div class="row"><label class="check"><input id="auto_connect" type="checkbox"><span data-i18n="auto_connect">启动后自动连接已保存凭据的机器</span></label>
      <label class="check"><input id="desktop_notifications" type="checkbox"><span data-i18n="notifications">后台出现新严重 / 高危漏洞时发送系统通知</span></label></div>
  </section>
  <section class="card"><h2 data-i18n="task_defaults">任务默认值</h2><div class="hint" data-i18n="task_sub">新任务将使用这些参数，单台下发时仍可临时修改</div>
    <div class="row"><div class="field"><label data-i18n="timeout">默认时长（分钟）</label><input id="timeout_minutes" type="number" min="1" max="10080"></div>
      <div class="field"><label data-i18n="heartbeat">计划心跳（分钟）</label><input id="plan_heartbeat_minutes" type="number" min="1" max="120"></div>
      <div class="field"><label>LLM</label><input id="llm" data-i18n-ph="llm_ph" placeholder="服务器默认"></div></div>
    <div class="row"><div class="field"><label data-i18n="test_prefix">测试任务前缀</label><input id="test_prefix"></div></div>
    <div class="row"><label class="check"><input id="coverage_enabled" type="checkbox"><span data-i18n="coverage">启用覆盖检查</span></label>
      <label class="check"><input id="seed_first_intent" type="checkbox"><span data-i18n="seed">生成首个意图</span></label></div>
    <div class="field"><label data-i18n="goal">固定目标模板</label><textarea id="goal" rows="5"></textarea></div>
    <div class="field" style="margin-top:10px"><label data-i18n="desc_template">任务描述模板</label>
      <textarea id="desc_template" rows="2" data-i18n-ph="desc_template_ph" placeholder="渗透&lt;名称&gt;源站及其子站"></textarea>
      <div class="hint" data-i18n="desc_template_hint">不继承任务时自动生成描述，&lt;名称&gt; 会替换为「名称 / 网址」</div></div>
  </section>
  <section class="card"><h2 data-i18n="connection">连接与安全</h2><div class="hint" data-i18n="conn_sub">机器单独填写的端口和账号优先于这里的默认值</div>
    <div class="row"><div class="field"><label data-i18n="artex_port">ARTEX 默认端口</label><input id="default_artex_port" type="number" min="1" max="65535"></div>
      <div class="field"><label data-i18n="ssh_timeout">SSH 超时（秒）</label><input id="ssh_timeout" type="number" min="3" max="60"></div>
      <div class="field"><label data-i18n="reconnect_seconds">重连基础间隔（秒）</label><input id="reconnect_seconds" type="number" min="3" max="120"></div></div>
    <div class="row"><div class="field"><label data-i18n="login_user">ARTEX 默认账号</label><input id="login_user" autocomplete="username"></div>
      <div class="field"><label data-i18n="login_password">ARTEX 默认密码</label><input id="login_password" type="password" autocomplete="current-password"></div></div>
    <div class="row"><label class="check"><input id="auto_reconnect" type="checkbox"><span data-i18n="auto_reconnect">连接中断后自动重连（指数退避）</span></label></div>
    <div class="hint warn" data-i18n="plaintext">密码以明文保存在本机 config.toml，请控制文件权限且不要提交到仓库。</div>
  </section>
  <section class="card"><h2 data-i18n="data">数据与维护</h2><div class="hint" data-i18n="data_sub">管理报告位置、配置备份、任务顺序和受信任主机密钥</div>
    <div class="row"><div class="field"><label data-i18n="export_dir">报告导出目录（相对于程序目录）</label><input id="export_dir"></div></div>
    <div class="actions"><button class="ghost" id="open-config" data-i18n="open_config">打开配置目录</button>
      <button class="ghost" id="open-export" data-i18n="open_export">打开报告目录</button>
      <button class="ghost" id="backup" data-i18n="backup">立即备份配置</button><span id="backup-state" class="hint"></span></div>
    <hr style="border:0;border-top:1px solid var(--soft);margin:18px 0">
    <div class="label" data-i18n="reset_order">重置任务展示顺序</div>
    <div class="actions" style="margin-top:7px"><select id="order-machine" style="max-width:280px"></select>
      <button class="ghost danger" id="reset-order" data-i18n="reset">重置</button></div>
    <div class="label" style="margin-top:18px" data-i18n="host_keys">已信任主机密钥</div>
    <div id="host-keys"></div>
  </section>
  <div class="hint" style="text-align:center;margin:22px 0">ARTEX Controller · 127.0.0.1 · <span data-i18n="local_only">仅本机访问</span></div>
</div>
<div class="savebar"><span id="msg" class="muted"></span><span class="sp"></span><button id="save" data-i18n="save">保存设置</button></div>
<div id="toast" class="toast"></div>
<script>
let LANG='zh', SETTINGS={};
const D={
 zh:{sub:'全局设置',back:'← 返回控制台',ui:'界面与刷新',ui_sub:'控制默认外观、自动连接和轮询频率',lang:'语言',theme:'默认主题',light:'浅色',dark:'深色',refresh:'前台刷新间隔（秒）',background_refresh:'后台刷新间隔（秒）',auto_connect:'启动后自动连接已保存凭据的机器',notifications:'后台出现新严重 / 高危漏洞时发送系统通知',task_defaults:'任务默认值',task_sub:'新任务将使用这些参数，单台下发时仍可临时修改',timeout:'默认时长（分钟）',heartbeat:'计划心跳（分钟）',llm_ph:'服务器默认',test_prefix:'测试任务前缀',coverage:'启用覆盖检查',seed:'生成首个意图',goal:'固定目标模板',desc_template:'任务描述模板',desc_template_ph:'例如：渗透<名称>源站及其子站',desc_template_hint:'不继承任务时自动生成描述，<名称> 会替换为「名称 / 网址」',connection:'连接与安全',conn_sub:'机器单独填写的端口和账号优先于这里的默认值',artex_port:'ARTEX 默认端口',ssh_timeout:'SSH 超时（秒）',reconnect_seconds:'重连基础间隔（秒）',login_user:'ARTEX 默认账号',login_password:'ARTEX 默认密码',auto_reconnect:'连接中断后自动重连（指数退避）',plaintext:'密码以明文保存在本机 config.toml，请控制文件权限且不要提交到仓库。',data:'数据与维护',data_sub:'管理报告位置、配置备份、任务顺序和受信任主机密钥',export_dir:'报告导出目录（相对于程序目录）',open_config:'打开配置目录',open_export:'打开报告目录',backup:'立即备份配置',reset_order:'重置任务展示顺序',reset:'重置',host_keys:'已信任主机密钥',local_only:'仅本机访问',save:'保存设置',saving:'保存中…',saved:'设置已保存',fail:'保存失败',req_fail:'请求失败：',no_keys:'尚未记录主机密钥，首次 SSH 连接后会显示在这里。',no_machines:'没有可重置的机器',delete_key:'删除',delete_confirm:'确认删除 {1} 的受信任密钥？下次连接会重新记录，请确认目标主机可信。',reset_confirm:'确认重置 {1} 的任务顺序？',done:'操作完成',backup_exists:'已有 config.toml.bak'},
 en:{sub:'Settings',back:'← Back to console',ui:'Interface & refresh',ui_sub:'Default appearance, startup connections and polling frequency',lang:'Language',theme:'Default theme',light:'Light',dark:'Dark',refresh:'Foreground refresh interval (sec)',background_refresh:'Background refresh interval (sec)',auto_connect:'Connect machines with saved credentials at startup',notifications:'Send system notifications for new critical/high findings in background',task_defaults:'Task defaults',task_sub:'Used for new tasks; individual dispatches can still override them',timeout:'Default duration (min)',heartbeat:'Plan heartbeat (min)',llm_ph:'Server default',test_prefix:'Test task prefix',coverage:'Enable coverage checks',seed:'Generate first intent',goal:'Fixed goal template',desc_template:'Task description template',desc_template_ph:'e.g. Pentest <名称> origin and subdomains',desc_template_hint:'Used for new tasks; <名称> is replaced with the name / URL',connection:'Connection & security',conn_sub:'Per-machine ports and credentials override these defaults',artex_port:'Default ARTEX port',ssh_timeout:'SSH timeout (sec)',reconnect_seconds:'Reconnect base delay (sec)',login_user:'Default ARTEX user',login_password:'Default ARTEX password',auto_reconnect:'Reconnect automatically after connection loss (exponential backoff)',plaintext:'Passwords are stored in plaintext in local config.toml. Protect the file and never commit it.',data:'Data & maintenance',data_sub:'Manage reports, configuration backups, task order and trusted host keys',export_dir:'Report export directory (relative to app)',open_config:'Open config folder',open_export:'Open report folder',backup:'Back up config now',reset_order:'Reset task display order',reset:'Reset',host_keys:'Trusted host keys',local_only:'local access only',save:'Save settings',saving:'Saving…',saved:'Settings saved',fail:'Save failed',req_fail:'Request failed: ',no_keys:'No host keys yet. They appear after the first SSH connection.',no_machines:'No machines to reset',delete_key:'Delete',delete_confirm:'Delete the trusted key for {1}? The next connection will trust a new key; verify the host first.',reset_confirm:'Reset task order for {1}?',done:'Done',backup_exists:'config.toml.bak exists'}
};
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function T(k,...a){let s=(D[LANG]||D.zh)[k]||D.zh[k]||k;a.forEach((v,i)=>s=s.split('{'+(i+1)+'}').join(v));return s}
function applyLang(){document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=T(el.dataset.i18n));document.querySelectorAll('[data-i18n-ph]').forEach(el=>el.placeholder=T(el.dataset.i18nPh));document.documentElement.lang=LANG==='en'?'en':'zh-CN';document.title=LANG==='en'?'ARTEX · Settings':'ARTEX · 设置';renderHosts()}
function applyTheme(theme){document.body.classList.toggle('dark',theme==='dark');try{localStorage.setItem('artex_theme',theme==='dark'?'1':'0')}catch(e){}}
async function api(path,body){const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});return await r.json()}
const keys=['lang','theme','refresh_seconds','background_refresh_seconds','auto_connect','desktop_notifications','timeout_minutes','plan_heartbeat_minutes','llm','test_prefix','coverage_enabled','seed_first_intent','goal','desc_template','default_artex_port','ssh_timeout','reconnect_seconds','login_user','login_password','auto_reconnect','export_dir'];
function fill(d){SETTINGS=d;LANG=d.lang==='en'?'en':'zh';keys.forEach(k=>{const el=$(k);if(!el)return;if(el.type==='checkbox')el.checked=!!d[k];else el.value=d[k]==null?'':d[k]});$('order-machine').innerHTML=(d.machines||[]).map(m=>'<option value="'+esc(m.ip)+'">'+esc(m.ip)+(m.label?' · '+esc(m.label):'')+'</option>').join('')||'<option value="">'+esc(T('no_machines'))+'</option>';$('backup-state').textContent=d.config_backup_exists?T('backup_exists'):'';applyLang()}
async function load(){try{fill(await api('/api/settings'))}catch(e){$('msg').textContent=T('req_fail')+e}}
function renderHosts(){const items=SETTINGS.host_keys||[];$('host-keys').innerHTML=items.length?items.map(h=>'<div class="host"><div class="fp"><b>'+esc(h.tag)+'</b><code title="'+esc(h.fingerprint)+'">'+esc(h.fingerprint)+'</code></div><button class="ghost danger del-key" data-tag="'+esc(h.tag)+'">'+esc(T('delete_key'))+'</button></div>').join(''):'<div class="empty">'+esc(T('no_keys'))+'</div>';document.querySelectorAll('.del-key').forEach(b=>b.onclick=()=>maintenance('delete_host_key',{tag:b.dataset.tag},T('delete_confirm',b.dataset.tag)))}
function payload(){const p={};keys.forEach(k=>{const el=$(k);p[k]=el.type==='checkbox'?el.checked:el.value});['refresh_seconds','background_refresh_seconds','timeout_minutes','plan_heartbeat_minutes','default_artex_port','ssh_timeout','reconnect_seconds'].forEach(k=>p[k]=parseInt(p[k],10));return p}
let toastTimer;function toast(s){$('toast').textContent=s;$('toast').classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').classList.remove('show'),2200)}
async function maintenance(action,extra,confirmation){if(confirmation&&!confirm(confirmation))return;try{const d=await api('/api/maintenance',Object.assign({action},extra||{}));if(!d.ok){toast(d.error||T('fail'));return}toast(d.message||T('done'));if(action==='delete_host_key'||action==='backup_config')fill(await api('/api/settings'))}catch(e){toast(T('req_fail')+e)}}
$('lang').onchange=e=>{LANG=e.target.value;applyLang()};$('theme').onchange=e=>applyTheme(e.target.value);
$('open-config').onclick=()=>maintenance('open_config_dir');$('open-export').onclick=()=>maintenance('open_export_dir');$('backup').onclick=()=>maintenance('backup_config');
$('reset-order').onclick=()=>{const ip=$('order-machine').value;if(ip)maintenance('reset_order',{ip},T('reset_confirm',ip))};
$('save').onclick=async()=>{const p=payload();if(p.desktop_notifications&&!SETTINGS.desktop_notifications&&'Notification'in window&&Notification.permission==='default'){try{await Notification.requestPermission()}catch(e){}}$('save').disabled=true;$('msg').className='muted';$('msg').textContent=T('saving');try{const d=await api('/api/settings',p);if(d.ok){fill(d.settings);applyTheme(d.settings.theme);$('msg').className='muted ok';$('msg').textContent=T('saved');toast(T('saved'))}else{$('msg').textContent=d.error||T('fail')}}catch(e){$('msg').textContent=T('req_fail')+e}finally{$('save').disabled=false}};
document.addEventListener('pointerdown',e=>{const b=e.target.closest('button');if(!b||b.disabled||matchMedia('(prefers-reduced-motion: reduce)').matches)return;const r=document.createElement('span'),box=b.getBoundingClientRect(),size=Math.max(box.width,box.height);r.className='ripple';r.style.cssText='width:'+size+'px;height:'+size+'px;left:'+(e.clientX-box.left-size/2)+'px;top:'+(e.clientY-box.top-size/2)+'px';b.appendChild(r);setTimeout(()=>r.remove(),450)});
load();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    cfg = None
    port = 0
    allowed_hosts = set()

    def log_message(self, fmt, *args):
        pass

    def _guard(self):
        """只接受本机访问：校验 Host（防 DNS rebinding）与 Origin/Referer。"""
        host = (self.headers.get("Host") or "").lower()
        if host not in self.allowed_hosts:
            self._json({"ok": False, "error": "forbidden host"}, 403)
            return False
        if self.command == "POST":
            origin = (self.headers.get("Origin") or "").lower()
            if origin and not any(origin == "http://" + h for h in self.allowed_hosts):
                self._json({"ok": False, "error": "forbidden origin"}, 403)
                return False
        return True

    def _common_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._common_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._guard():
            return
        if self.path.startswith("/api/machines"):
            d = self.cfg["defaults"]
            out = {
                "machines": [{"ip": m["ip"], "label": m.get("label", ""),
                              "user": m.get("user", "root"), "port": m.get("port", 22),
                              "artex_port": m.get("artex_port") or d.get("artex_port", 8787),
                              "artex_user": m.get("artex_user", ""),
                              "artex_password": m.get("artex_password", ""),
                              "ssh_password": m.get("ssh_password", ""),
                              "has_password": bool(m.get("ssh_password")),
                              "has_key": bool(m.get("ssh_key_file")),
                              "has_artex_password": bool(m.get("artex_password")),
                              "key_file": m.get("ssh_key_file", "")}
                             for m in self.cfg["machines"]],
                "goal": (d.get("goal") or "").strip() or DEFAULT_GOAL,
                "desc_template": (d.get("desc_template") or "").strip() or DEFAULT_DESC_TEMPLATE,
                "timeout_minutes": int(d.get("timeout_minutes", 600)),
                "llm_key": d.get("llm", ""),
                "login_user": d.get("login_user", ""),
                "login_password": d.get("login_password", ""),
                "default_artex_port": int(d.get("artex_port", 8787)),
            }
            out.update(console_options(self.cfg))
            self._json(out)
            return
        if self.path.startswith("/api/settings"):
            self._json(self._settings_data())
            return
        if self.path.split("?")[0] in ("/settings", "/settings/"):
            body = SETTINGS_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._common_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.split("?")[0] in ("/icon.ico", "/favicon.ico"):
            try:
                with open(os.path.join(HERE, "icon.ico"), "rb") as f:
                    body = f.read()
            except Exception:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self._common_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/api/ws/download"):
            self._serve_download()
            return
        if self.path in ("/", "/index.html"):
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._common_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        if not self._guard():
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._json({"ok": False, "error": "请求体不是合法 JSON"}, 400)
            return

        if self.path.startswith("/api/machines/save"):
            self._json(self._save_machine(body))
            return
        if self.path.startswith("/api/settings"):
            self._json(self._save_settings(body))
            return
        if self.path.startswith("/api/machines/delete"):
            self._json(self._delete_machine(body))
            return
        if self.path.startswith("/api/task-order"):
            self._json(self._save_task_order(body))
            return
        if self.path.startswith("/api/maintenance"):
            self._json(self._maintenance(body))
            return
        if self.path.startswith("/api/overview"):
            self._json(self._refresh_all())
            return
        if self.path.startswith("/api/poll"):
            self._json(self._poll(body))
            return
        if self.path.startswith("/api/disconnect"):
            self._json(self._disconnect(body))
            return
        if self.path.startswith("/api/connected"):
            self._json({"ok": True, "ips": conn_list()})
            return
        if self.path.startswith("/api/open-dir"):
            self._json(self._open_dir(body))
            return
        if self.path.startswith("/api/export-status"):
            self._json(self._export_status(body))
            return
        if self.path.startswith("/api/ask-history"):
            ip = str(body.get("ip") or "")
            tid = str(body.get("task_id") or "")
            if not any(m["ip"] == ip for m in self.cfg["machines"]) or not tid.isdigit():
                self._json({"ok": False, "error": "任务或主机无效"}, 404)
            else:
                self._json({"ok": True, "items": get_ask_history(ip, tid)})
            return

        machine = next((m for m in self.cfg["machines"] if m["ip"] == body.get("ip")), None)
        if not machine:
            self._json({"ok": False, "error": "未知主机 %s" % body.get("ip")}, 404)
            return
        pw = body.get("password") or ""

        if self.path.startswith("/api/connect"):
            self._json(self._connect(machine, pw))
            return
        if self.path.startswith("/api/refresh"):
            self._json(self._refresh(machine, pw))
            return
        if self.path.startswith("/api/control"):
            self._json(self._control(machine, pw, body))
            return
        if self.path.startswith("/api/task-info"):
            self._json(self._task_info(machine, pw, body))
            return
        if self.path.startswith("/api/ws/list"):
            self._json(self._ws_list(machine, pw, body))
            return
        if self.path.startswith("/api/ws/stat"):
            self._json(self._ws_stat(machine, pw, body))
            return
        if self.path.startswith("/api/ws/download"):
            self._json(self._ws_download(machine, pw, body))
            return
        if self.path.startswith("/api/task-delete"):
            self._json(self._task_delete(machine, pw, body))
            return
        if self.path.startswith("/api/ask"):
            self._json(self._ask(machine, pw, body))
            return
        if self.path.startswith("/api/export"):
            self._json(self._export(machine, pw, body))
            return
        if self.path.startswith("/api/dispatch"):
            self._json(self._dispatch(machine, pw, body))
            return
        self.send_error(404)

    # ---- 业务 ----
    def _refresh(self, machine, password):
        try:
            with client_ctx(self.cfg, machine, password) as c:
                tasks = c.tasks()
                try:
                    profs = c.profiles()
                except Exception:
                    profs = []
            out = summarize(tasks)
            out["ok"] = True
            out["ip"] = machine["ip"]
            out["llms"] = [{"id": p.get("id"), "name": p.get("name"),
                            "model": p.get("model"), "is_default": bool(p.get("is_default"))}
                           for p in profs]
            out["fetched_at"] = time.time()
            out["connected"] = bool(conn_get(machine["ip"]))
            out["task_order"] = get_task_order(machine["ip"])
            return out
        except paramiko.AuthenticationException:
            return {"ok": False, "ip": machine["ip"], "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "ip": machine["ip"],
                    "error": "%s: %s" % (type(e).__name__, str(e)[:150])}

    def _refresh_all(self):
        """并行刷新所有主机（4 路），一次点击、刷完即断。"""
        machines = self.cfg["machines"]
        results = []

        def one(m):
            if not (m.get("ssh_password") or m.get("ssh_key_file")):
                return {"ok": False, "ip": m["ip"], "error": "未保存 SSH 凭据"}
            try:
                return self._refresh(m, "")
            except Exception as e:
                return {"ok": False, "ip": m["ip"], "error": str(e)[:150]}

        with ThreadPoolExecutor(max_workers=4) as ex:
            for r in ex.map(one, machines):
                results.append(r)
        return {"ok": True, "results": results}

    def _export(self, machine, password, body):
        tid = str(body.get("task_id") or "").strip()
        if not tid.isdigit():
            return {"ok": False, "error": "任务 id 无效"}
        ip = machine["ip"]
        with _EXPORT_LOCK:
            if any(j.get("status") == "running" and j.get("ip") == ip and j.get("task_id") == tid
                   for j in _EXPORT_JOBS.values()):
                return {"ok": False, "error": "该任务已有导出正在进行"}
            job_id = uuid.uuid4().hex
            _EXPORT_JOBS[job_id] = {"status": "running", "stage": "report", "ip": ip,
                                    "task_id": tid, "created": time.time()}
            for old_id, job in list(_EXPORT_JOBS.items()):
                if time.time() - job.get("created", 0) > 3600:
                    _EXPORT_JOBS.pop(old_id, None)
        name = (body.get("task_name") or "").strip() or ("task_" + tid)

        def run():
            def progress(stage):
                with _EXPORT_LOCK:
                    _EXPORT_JOBS[job_id]["stage"] = stage
            try:
                with client_ctx(self.cfg, machine, password) as c:
                    res = export_task(c, ip, tid, name, progress)
                res.update({"ok": True, "status": "done", "stage": "done"})
            except Exception as e:
                res = {"ok": False, "status": "error", "stage": "error",
                       "error": "%s: %s" % (type(e).__name__, str(e)[:240])}
            with _EXPORT_LOCK:
                _EXPORT_JOBS[job_id].update(res)

        threading.Thread(target=run, daemon=True, name="export-" + tid).start()
        return {"ok": True, "job_id": job_id, "status": "running"}

    def _export_status(self, body):
        job_id = str(body.get("job_id") or "")
        with _EXPORT_LOCK:
            job = _EXPORT_JOBS.get(job_id)
            if not job:
                return {"ok": False, "error": "导出任务不存在或已过期"}
            return dict(job)

    def _open_dir(self, body):
        root = os.path.abspath(EXPORT_ROOT)
        p = os.path.abspath(os.path.join(HERE, (body.get("dir") or "").strip()))
        if not (p == root or p.startswith(root + os.sep)) or not os.path.isdir(p):
            return {"ok": False, "error": "目录不存在或越界"}
        try:
            if os.name == "nt":
                os.startfile(p)
            else:
                subprocess.Popen(["xdg-open", p])
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _settings_data(self):
        d = self.cfg.get("defaults") or {}
        out = console_options(self.cfg)
        out.update({
            "default_artex_port": int(d.get("artex_port", 8787)),
            "login_user": d.get("login_user", "ARTEX"),
            "login_password": d.get("login_password", ""),
            "llm": d.get("llm", ""),
            "timeout_minutes": int(d.get("timeout_minutes", 600)),
            "plan_heartbeat_minutes": int(d.get("plan_heartbeat_minutes", 10)),
            "coverage_enabled": bool(d.get("coverage_enabled", True)),
            "seed_first_intent": bool(d.get("seed_first_intent", False)),
            "test_prefix": d.get("test_prefix", "[DISPATCH-TEST]"),
            "goal": d.get("goal", ""),
            "desc_template": d.get("desc_template", ""),
            "machines": [{"ip": m["ip"], "label": m.get("label", "")}
                         for m in self.cfg["machines"]],
            "host_keys": [{"tag": k, "fingerprint": v}
                          for k, v in sorted(_load_known_hosts().items())],
            "config_backup_exists": os.path.isfile(_CONFIG_PATH + ".bak"),
        })
        return out

    def _save_settings(self, body):
        if body.get("lang") not in ("zh", "en") or body.get("theme") not in ("light", "dark"):
            return {"ok": False, "error": "语言或主题不合法"}

        def bounded(key, low, high):
            try:
                value = int(body.get(key))
            except Exception:
                raise ValueError("%s 必须是整数" % key)
            if not low <= value <= high:
                raise ValueError("%s 应在 %d–%d 之间" % (key, low, high))
            return value

        try:
            values = {
                "refresh_seconds": bounded("refresh_seconds", 3, 120),
                "background_refresh_seconds": bounded("background_refresh_seconds", 10, 600),
                "reconnect_seconds": bounded("reconnect_seconds", 3, 120),
                "ssh_timeout": bounded("ssh_timeout", 3, 60),
                "default_artex_port": bounded("default_artex_port", 1, 65535),
                "timeout_minutes": bounded("timeout_minutes", 1, 10080),
                "plan_heartbeat_minutes": bounded("plan_heartbeat_minutes", 1, 120),
            }
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        export_dir = str(body.get("export_dir") or "machine").strip()
        candidate = os.path.abspath(os.path.join(HERE, export_dir))
        if (not export_dir or os.path.isabs(export_dir) or candidate == os.path.abspath(HERE)
                or not candidate.startswith(os.path.abspath(HERE) + os.sep)):
            return {"ok": False, "error": "导出目录必须是程序目录内的子目录"}
        goal = str(body.get("goal") or "")
        if len(goal) > 100000:
            return {"ok": False, "error": "目标模板过长"}
        desc_template = str(body.get("desc_template") or "")
        if len(desc_template) > 100000:
            return {"ok": False, "error": "描述模板过长"}

        c = self.cfg.setdefault("console", {})
        c.update(values)
        c.update({
            "lang": body["lang"], "theme": body["theme"],
            "refresh_seconds": values["refresh_seconds"],
            "background_refresh_seconds": values["background_refresh_seconds"],
            "reconnect_seconds": values["reconnect_seconds"],
            "ssh_timeout": values["ssh_timeout"],
            "auto_connect": bool(body.get("auto_connect")),
            "auto_reconnect": bool(body.get("auto_reconnect")),
            "desktop_notifications": bool(body.get("desktop_notifications")),
            "export_dir": os.path.relpath(candidate, HERE).replace("\\", "/"),
        })
        c.pop("default_artex_port", None)
        c.pop("timeout_minutes", None)
        c.pop("plan_heartbeat_minutes", None)
        d = self.cfg.setdefault("defaults", {})
        d.update({
            "artex_port": values["default_artex_port"],
            "login_user": str(body.get("login_user") or "").strip(),
            "login_password": str(body.get("login_password") or ""),
            "llm": str(body.get("llm") or "").strip(),
            "timeout_minutes": values["timeout_minutes"],
            "plan_heartbeat_minutes": values["plan_heartbeat_minutes"],
            "coverage_enabled": bool(body.get("coverage_enabled")),
            "seed_first_intent": bool(body.get("seed_first_intent")),
            "test_prefix": str(body.get("test_prefix") or ""),
            "goal": goal,
            "desc_template": desc_template,
        })
        try:
            save_config(self.cfg)
            apply_export_dir(self.cfg)
        except Exception as e:
            return {"ok": False, "error": "配置写入失败：%s" % e}
        return {"ok": True, "settings": self._settings_data()}

    def _maintenance(self, body):
        action = str(body.get("action") or "")
        if action == "backup_config":
            try:
                save_config(self.cfg)
            except Exception as e:
                return {"ok": False, "error": str(e)}
            return {"ok": True, "message": "已备份为 config.toml.bak"}
        if action == "reset_order":
            ip = str(body.get("ip") or "")
            if not any(m["ip"] == ip for m in self.cfg["machines"]):
                return {"ok": False, "error": "未知主机"}
            drop_task_order(ip)
            return {"ok": True}
        if action == "delete_host_key":
            tag = str(body.get("tag") or "")
            known = _load_known_hosts()
            if tag not in known:
                return {"ok": False, "error": "主机密钥不存在"}
            del known[tag]
            _save_known_hosts(known)
            return {"ok": True}
        if action in ("open_config_dir", "open_export_dir"):
            path = HERE if action == "open_config_dir" else EXPORT_ROOT
            try:
                os.makedirs(path, exist_ok=True)
                if os.name == "nt":
                    os.startfile(path)
                else:
                    subprocess.Popen(["xdg-open", path])
                return {"ok": True}
            except Exception as e:
                return {"ok": False, "error": str(e)}
        return {"ok": False, "error": "未知维护操作"}

    def _save_machine(self, body):
        ip = (body.get("ip") or "").strip()
        if not re.match(r"^[0-9A-Za-z._:-]+$", ip):
            return {"ok": False, "error": "IP / 主机名不合法"}
        old_ip = (body.get("old_ip") or "").strip() or ip
        label = (body.get("label") or "").strip()
        user = (body.get("user") or "root").strip() or "root"
        try:
            port = int(body.get("port") or 22)
        except Exception:
            port = 22
        try:
            artex_port = int(body.get("artex_port") or 8787)
        except Exception:
            artex_port = 8787
        if not (1 <= artex_port <= 65535):
            return {"ok": False, "error": "ARTEX 端口不合法"}
        password = body.get("password") or ""
        key_pem = body.get("key_pem") or ""
        use_key = bool(body.get("use_key"))

        machines = self.cfg["machines"]
        item = next((m for m in machines if m["ip"] == old_ip), None)
        if item is None:
            item = {"ip": ip}
            machines.append(item)
        item["ip"] = ip
        item["label"] = label
        item["user"] = user
        item["port"] = port
        item["artex_port"] = artex_port

        artex_user = (body.get("artex_user") or "").strip()
        if artex_user:
            item["artex_user"] = artex_user
        else:
            item.pop("artex_user", None)
        artex_password = body.get("artex_password") or ""
        if artex_password:
            item["artex_password"] = artex_password

        if key_pem.strip():
            kdir = os.path.join(HERE, "keys")
            os.makedirs(kdir, exist_ok=True)
            kpath = os.path.join(kdir, safe_filename(ip) + ".key")
            with open(kpath, "w", encoding="utf-8", newline="\n") as f:
                f.write(key_pem.strip() + "\n")
            try:
                os.chmod(kpath, 0o600)
            except Exception:
                pass
            item["ssh_key_file"] = os.path.relpath(kpath, HERE).replace("\\", "/")
            item["ssh_password"] = ""
        elif use_key and item.get("ssh_key_file"):
            item["ssh_password"] = ""
        else:
            if password:
                item["ssh_password"] = password
            item.pop("ssh_key_file", None)

        save_config(self.cfg)
        if old_ip != ip:
            move_task_order(old_ip, ip)
        conn_close(old_ip)
        conn_close(ip)
        return {"ok": True, "ip": ip}

    def _delete_machine(self, body):
        ip = (body.get("ip") or "").strip()
        before = len(self.cfg["machines"])
        self.cfg["machines"] = [m for m in self.cfg["machines"] if m["ip"] != ip]
        if len(self.cfg["machines"]) == before:
            return {"ok": False, "error": "没有这台机器"}
        conn_close(ip)
        drop_task_order(ip)
        save_config(self.cfg)
        return {"ok": True, "ip": ip}

    def _save_task_order(self, body):
        ip = str(body.get("ip") or "").strip()
        if not any(m["ip"] == ip for m in self.cfg["machines"]):
            return {"ok": False, "error": "未知主机"}
        order = body.get("order")
        if not isinstance(order, list) or len(order) > 5000:
            return {"ok": False, "error": "排序数据不合法"}
        clean = []
        for x in order:
            s = str(x).strip()
            if not s.isdigit() or len(s) > 20:
                return {"ok": False, "error": "排序数据不合法"}
            clean.append(s)
        if not set_task_order(ip, clean):
            return {"ok": False, "error": "排序写入失败"}
        return {"ok": True, "order": clean}

    def _connect(self, machine, password):
        ip = machine["ip"]
        if conn_get(ip):
            return self._poll({"ips": [ip]})["results"][0]
        try:
            tunnel, client = open_persistent(self.cfg, machine, password)
        except paramiko.AuthenticationException:
            return {"ok": False, "connected": False, "ip": ip, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "connected": False, "ip": ip,
                    "error": "%s: %s" % (type(e).__name__, str(e)[:160])}
        conn_set(ip, tunnel, client, machine)
        res = self._poll({"ips": [ip]})["results"][0]
        if res.get("ok"):
            try:
                c = conn_get(ip)
                with c["lock"]:
                    profs = c["client"].profiles()
                res["llms"] = [{"id": p.get("id"), "name": p.get("name"),
                                "model": p.get("model"),
                                "is_default": bool(p.get("is_default"))} for p in profs]
            except Exception:
                res["llms"] = []
        return res

    def _disconnect(self, body):
        ip = str(body.get("ip") or "").strip()
        conn_close(ip)
        return {"ok": True, "connected": False, "ip": ip}

    def _poll_one(self, ip):
        c = conn_get(ip)
        if not c:
            return {"ok": False, "connected": False, "ip": ip, "error": "未连接"}
        try:
            with c["lock"]:
                tasks = c["client"].tasks()
            res = summarize(tasks)
            res.update({"ok": True, "connected": True, "ip": ip, "fetched_at": time.time()})
            res["task_order"] = get_task_order(ip)
            return res
        except Exception as e:
            conn_close(ip)
            return {"ok": False, "connected": False, "ip": ip,
                    "error": "%s: %s" % (type(e).__name__, str(e)[:120])}

    def _poll(self, body, password=""):
        """用常连接取数据；只读，不新建连接（多台并行）。"""
        ips = body.get("ips") or conn_list()
        if not ips:
            return {"ok": True, "results": []}
        with ThreadPoolExecutor(max_workers=min(6, max(1, len(ips)))) as ex:
            results = list(ex.map(self._poll_one, ips))
        return {"ok": True, "results": results}

    def _control(self, machine, password, body):
        """暂停 / 继续某个任务。"""
        tid = str(body.get("task_id") or "").strip()
        action = (body.get("action") or "").strip()
        if not tid.isdigit():
            return {"ok": False, "error": "任务 id 无效"}
        if action not in ("pause", "resume"):
            return {"ok": False, "error": "action 只能是 pause / resume"}
        try:
            with client_ctx(self.cfg, machine, password) as c:
                st, res = c._req("POST", "/api/tasks/%s/control" % tid,
                                 {"action": action}, timeout=120)
            if st == 200:
                return {"ok": True, "action": action,
                        "status": (res or {}).get("status") or "",
                        "queued": bool((res or {}).get("queued"))}
            return {"ok": False, "error": "HTTP %s：%s" % (st, str(res.get("error") or res)[:160])}
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:160])}

    def _task_info(self, machine, password, body):
        tid = str(body.get("task_id") or "").strip()
        if not tid.isdigit():
            return {"ok": False, "error": "任务 id 无效"}
        try:
            with client_ctx(self.cfg, machine, password) as c:
                st, res = c._req("GET", "/api/tasks/" + tid)
            if st != 200:
                return {"ok": False, "error": "读取任务失败 HTTP %s" % st}
            return {"ok": True, "name": res.get("name") or "",
                    "description": res.get("description") or "",
                    "goal": res.get("goal") or "",
                    "status": res.get("status") or ""}
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:160])}

    def _ws_list(self, machine, password, body):
        try:
            path = _ws_norm(body.get("path"))
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        try:
            with client_ctx(self.cfg, machine, password) as c:
                data = c.workspace_list(path)
            entries = []
            for e in data.get("entries") or []:
                try:
                    rel = _ws_norm(e.get("path"))
                except ValueError:
                    continue
                entries.append({"name": str(e.get("name") or ""), "path": rel,
                                "dir": bool(e.get("dir")), "size": int(e.get("size") or 0),
                                "mtime": int(e.get("mtime") or 0)})
            try:
                cur = _ws_norm(data.get("path") or path)
            except ValueError:
                cur = path
            return {"ok": True, "path": cur, "entries": entries}
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:200])}

    def _ws_stat(self, machine, password, body):
        tid = str(body.get("task_id") or "").strip()
        if not tid.isdigit():
            return {"ok": False, "error": "任务 id 无效"}
        try:
            with client_ctx(self.cfg, machine, password) as c:
                stats = ws_task_stat(c, tid)
            stats["ok"] = True
            return stats
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:200])}

    def _ws_download(self, machine, password, body):
        paths = body.get("paths")
        if not isinstance(paths, list) or not paths:
            return {"ok": False, "error": "没有选中文件"}
        try:
            with Session(self.cfg, machine, password) as c:
                tmp, name, size = prepare_workspace_download(c, paths)
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except (ValueError, RuntimeError) as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:200])}
        ticket = uuid.uuid4().hex
        _download_cleanup()
        with _DOWNLOAD_LOCK:
            _DOWNLOAD_TICKETS[ticket] = {"path": tmp, "name": name, "size": size,
                                         "created": time.time()}
        return {"ok": True, "id": ticket, "name": name, "size": size}

    def _serve_download(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        ticket = (q.get("id") or [""])[0]
        _download_cleanup()
        with _DOWNLOAD_LOCK:
            item = _DOWNLOAD_TICKETS.pop(ticket, None)
        if not item or time.time() - item.get("created", 0) > _DOWNLOAD_TTL:
            if item:
                try:
                    os.remove(item["path"])
                except Exception:
                    pass
            self._json({"ok": False, "error": "下载已过期，请重新打包"}, 404)
            return
        path = item["path"]
        try:
            name = str(item.get("name") or os.path.basename(path))
            ascii_name = (re.sub(r"[^0-9A-Za-z._-]", "_", name) or "download")[:120]
            quoted = urllib.parse.quote(name)
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition",
                             'attachment; filename="%s"; filename*=UTF-8\'\'%s'
                             % (ascii_name, quoted))
            self.send_header("Content-Length", str(size))
            self._common_headers()
            self.end_headers()
            with open(path, "rb") as f:
                shutil.copyfileobj(f, self.wfile, 256 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            pass
        finally:
            try:
                os.remove(path)
            except Exception:
                pass

    def _task_delete(self, machine, password, body):
        tid = str(body.get("task_id") or "").strip()
        if not tid.isdigit():
            return {"ok": False, "error": "任务 id 无效"}
        opts = {key: bool(body.get(key)) for key in
                ("delete_files", "delete_assets", "delete_traffic",
                 "delete_findings", "delete_llm_records")}
        try:
            with client_ctx(self.cfg, machine, password) as c:
                st, res = c.delete_task(tid, opts)
            if st == 200:
                drop_task_state(machine["ip"], tid)
                return {"ok": True, "result": res or {}}
            return {"ok": False, "error": "HTTP %s：%s"
                    % (st, str((res or {}).get("error") or res)[:200])}
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:200])}

    def _ask(self, machine, password, body):
        """给某任务的主 Agent 发消息，并把回复取回来。"""
        tid = str(body.get("task_id") or "").strip()
        msg = (body.get("message") or "").strip()
        if not tid.isdigit():
            return {"ok": False, "error": "任务 id 无效"}
        if not msg:
            return {"ok": False, "error": "内容为空"}
        try:
            with client_ctx(self.cfg, machine, password) as c:
                result = ask_main_agent(c, tid, msg,
                                        timeout=int(body.get("timeout") or 240))
            append_ask_history(machine["ip"], tid, msg, result)
            result["history"] = get_ask_history(machine["ip"], tid)
            return result
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:160])}

    def _dispatch(self, machine, password, body):
        d = self.cfg["defaults"]
        name = (body.get("name") or "").strip()
        if not name:
            return {"ok": False, "error": "名称为空"}
        try:
            timeout_min = int(body.get("timeout_min") or d.get("timeout_minutes", 600))
        except Exception:
            timeout_min = int(d.get("timeout_minutes", 600))

        src = str(body.get("source_task_id") or "").strip()
        desc = (body.get("description") or "").strip()
        goal_text = (body.get("goal") or "").strip()
        if src:
            # 继承模式：描述和目标必须自己填，不再用模板
            if not desc or not goal_text:
                return {"ok": False, "error": "继承任务时，描述和目标必须填写"}
        else:
            if not desc:
                tpl = (d.get("desc_template") or "").strip() or DEFAULT_DESC_TEMPLATE
                desc = tpl.replace("<名称>", name)
            if not goal_text:
                goal_text = (d.get("goal") or "").strip() or DEFAULT_GOAL

        try:
            with client_ctx(self.cfg, machine, password) as c:
                profs = c.profiles()
                want = str(body.get("llm_id") or "")
                prof = next((p for p in profs if str(p.get("id")) == want), None)
                if prof is None:
                    prof = next((p for p in profs if p.get("is_default")), None)
                if prof is None and profs:
                    prof = profs[0]
                if prof is None:
                    return {"ok": False, "error": "该主机没有任何 LLM 配置"}
                payload = {
                    "name": name,
                    "description": desc,
                    "goal": goal_text,
                    "llm_profile_ids": [int(prof["id"])],
                    "timeout_seconds": timeout_min * 60,
                    "plan_heartbeat_seconds": int(d.get("plan_heartbeat_minutes", 10)) * 60,
                    "coverage_enabled": bool(d.get("coverage_enabled", True)),
                    "seed_first_intent": bool(d.get("seed_first_intent", False)),
                }
                if src:
                    payload["source_task_ids"] = [src]
                if not payload["goal"]:
                    return {"ok": False, "error": "目标为空"}
                st, res = c.create_task(payload)
                if st not in (200, 201) or not res.get("id"):
                    return {"ok": False, "error": "HTTP %s %s" % (st, str(res)[:160])}
                return {"ok": True, "task_id": res["id"], "status": res.get("status", ""),
                        "llm": prof.get("name")}
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:150])}


BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def open_app_window(url, width=1040, height=780):
    """用 Chrome/Edge 的 --app 模式开一个固定大小的独立窗口：
    没有地址栏/标签栏，尺寸写死，独立临时 profile（不吃你日常浏览器的内存）。"""
    for exe in BROWSERS:
        if not os.path.exists(exe):
            continue
        prof = os.path.join(tempfile.gettempdir(), "artex_console_profile")
        args = [
            exe, "--app=" + url,
            "--window-size=%d,%d" % (width, height),
            "--window-position=100,60",
            "--user-data-dir=" + prof,
            "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--disable-sync", "--disable-translate",
            "--disable-background-networking", "--disable-default-apps",
            "--disable-component-update",
            "--disable-features=Translate,BackForwardCache",
            "--disk-cache-size=1048576",
        ]
        try:
            subprocess.Popen(args, close_fds=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return exe
        except Exception:
            break
    webbrowser.open(url)
    return None


def main():
    ap = argparse.ArgumentParser(description="ARTEX 本地总控制台")
    ap.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    ap.add_argument("--port", type=int)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--window-size", default="1040x780", help="窗口尺寸，如 1040x780")
    ap.add_argument("--minimize-console", action="store_true", help="启动后最小化控制台窗口（Windows）")
    args = ap.parse_args()

    if args.minimize_console and os.name == "nt":
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 6)   # SW_MINIMIZE
        except Exception:
            pass

    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    global _CONFIG_PATH
    _CONFIG_PATH = os.path.abspath(args.config)
    cfg = load_config(args.config)
    apply_export_dir(cfg)
    Handler.cfg = cfg
    port = args.port or int(cfg["console"].get("port", 8900))

    print("ARTEX Controller：%d 台主机（%d 台已配置密码）"
          % (len(cfg["machines"]), sum(1 for m in cfg["machines"] if m.get("ssh_password"))))
    print("页面地址： http://127.0.0.1:%d" % port)
    print("（每台点右上角开关建立常连接，连上后每 8 秒自动刷新；断开即释放）")

    Handler.port = port
    Handler.allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    srv.request_queue_size = 8
    if not args.no_browser:
        try:
            w, h = [int(x) for x in str(args.window_size).lower().split("x")]
        except Exception:
            w, h = 1040, 780
        threading.Timer(1.0, lambda: open_app_window("http://127.0.0.1:%d" % port, w, h)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
