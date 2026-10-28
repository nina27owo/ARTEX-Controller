#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARTEX 本地总控制台（会话 + 任务下发 + 按需刷新）

* 左侧 9 个会话（每台机器一个），右侧是该会话的操作面板
* 「刷新」：**现连现断** —— 建 SSH 隧道 → 拉 /api/tasks → 立刻断开，不做常驻连接
* 「下发」：同一套路，建连 → 建任务 → 断开，成功后自动刷新一次
* 只监听 127.0.0.1，数据全部走 SSH 转发到各机 127.0.0.1:8787

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
import re
import select
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
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
DEFAULT_GOAL = "获取权限"
EXPORT_ROOT = os.path.join(HERE, "machine")
KNOWN_HOSTS_FILE = os.path.join(HERE, "ssh_host_keys.json")


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
    # 只展示 ID 最大的 5 个任务（即最新创建的 5 个）
    rows.sort(key=_task_num, reverse=True)
    all_tasks = [{"id": r["id"], "name": r["name"], "status": r["status"]} for r in rows[:80]]
    return {
        "tasks_total": len(tasks), "counts": counts, "findings": findings,
        "in_flight": inflight, "last_activity": last,
        "active": rows[:5], "active_total": len(tasks),
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


def export_task(client, ip, task_id, task_name):
    """导出到 <程序目录>/machine/<ip>/<任务名>/：
       总报告.md + 严重/*.md + 高危/*.md + 导出信息.txt
    """
    tid = str(task_id).strip()
    base = os.path.join(EXPORT_ROOT,
                        _safe_dirname(ip, "unknown-ip"),
                        _safe_dirname(task_name, "task_" + tid))
    os.makedirs(base, exist_ok=True)
    res = {"critical": 0, "high": 0, "errors": []}

    # 1) 总报告（任务级 Markdown）
    st, data, _ = client.raw("/api/report?task=" + tid)
    if st == 200 and data:
        with open(os.path.join(base, "总报告.md"), "wb") as f:
            f.write(data)
    else:
        res["errors"].append("总报告 HTTP %s" % st)

    # 2) 严重 / 高危：每个漏洞一个 md（服务端打包 zip，这里解压）
    for sev, label, key in (("critical", "严重", "critical"), ("high", "高危", "high")):
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

    with open(os.path.join(base, "导出信息.txt"), "w", encoding="utf-8") as f:
        f.write("任务 #%s  %s\n" % (tid, task_name))
        f.write("导出时间：%s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
        f.write("严重报告：%d 个\n高危报告：%d 个\n" % (res["critical"], res["high"]))
        if res["errors"]:
            f.write("异常：%s\n" % "；".join(res["errors"]))
    res["dir"] = os.path.relpath(base, HERE).replace("\\", "/")
    return res


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
  .side-foot{display:flex;gap:6px;padding:8px 14px 10px;border-top:1px solid var(--line)}
  .foot-btn{flex:1;height:30px;display:flex;align-items:center;justify-content:center;padding:0}
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
  .item.on{background:#fffdf8;border-left-color:var(--accent);box-shadow:0 1px 0 rgba(150,104,63,.06)}
  .item .ip{font-size:13px;font-weight:500;letter-spacing:.2px;color:var(--ink)}
  .item .lb{font-size:11px;color:var(--ink-3);letter-spacing:.2px}
  .dot{width:7px;height:7px;border-radius:50%;flex:none;margin-top:6px;box-shadow:0 0 0 2px rgba(255,255,255,.7)}
  .d0{background:#cfc3b1}.d1{background:#6fa07c}.d2{background:#c1705c}

  main{flex:1;min-width:0;overflow-y:auto;overflow-x:hidden;padding:18px 24px 28px}
  #tasks{overflow-x:auto}

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
  .auto{font-size:13px;color:var(--ink-2);padding:7px 0;letter-spacing:.2px}

  .chips{display:flex;gap:10px;flex-wrap:wrap;margin:2px 0 16px}
  .chip{
    background:var(--panel);border:1px solid var(--line);border-radius:9px;
    padding:7px 14px 8px;min-width:82px;box-shadow:0 1px 2px rgba(120,95,60,.05);
  }
  .chip .k{font-size:10.5px;letter-spacing:.4px;color:var(--ink-3)}
  .chip .v{font-size:18px;font-weight:600;line-height:1.25;font-variant-numeric:tabular-nums}

  table{width:100%;border-collapse:collapse}
  th,td{padding:7px 10px;text-align:left;white-space:nowrap}
  th{
    font-size:11px;font-weight:500;letter-spacing:.5px;color:var(--ink-3);
    border-bottom:1px solid var(--line);background:transparent;
  }
  td{font-size:12.5px;color:var(--ink);border-bottom:1px solid var(--line-soft)}
  tbody tr:last-child td{border-bottom:none}
  tbody tr:hover td{background:rgba(255,255,255,.55)}
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
    display:flex;align-items:center;gap:8px;margin:0 0 12px;
    font-size:11.5px;font-weight:600;letter-spacing:.8px;color:var(--ink-2);
  }
  .sec h3 .sp{flex:1}
  button.mini{width:auto;padding:3px 11px;font-size:11.5px;letter-spacing:.2px}
  #tasks tbody tr{cursor:pointer}
  #tasks td.ops,#tasks th.ops{text-align:right;white-space:nowrap}
  #tasks td.ops button{margin-left:5px}
  #tasks tbody tr.sel td{background:#f7efdf}
  #tasks tbody tr.sel td:first-child{box-shadow:inset 3px 0 0 var(--accent)}
  .sec h3 .muted{font-weight:400;letter-spacing:0}

  .tag{
    display:inline-block;padding:1px 8px;border-radius:9px;font-size:11px;
    background:var(--line-soft);color:var(--ink-2);letter-spacing:.2px;
  }
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
  <main>
    <div id="empty" class="empty"><div class="slogan"><div class="wordmark">ARTEX</div><div class="wordmark-sub">CONTROLLER</div><div class="rule"></div><div class="tagline">Easy to wire, built to control.</div></div></div>
    <div id="panel" hidden>
      <div class="hdr">
        <h1 id="p-ip"></h1><span class="muted" id="p-label"></span>
        <span style="flex:1"></span>
        <span class="muted" id="p-time" style="font-size:11.5px"></span>
        <input id="p-pw" type="password" placeholder="SSH 密码" data-i18n-ph="ssh_pw_ph" style="width:150px" hidden>
        <label class="switch" title="连接后自动刷新" data-i18n-title="auto_refresh_title">
          <input type="checkbox" id="p-conn">
          <span class="slider"></span>
        </label>
        <span id="conn-label" class="muted" style="font-size:11.5px;min-width:92px">未连接</span>
      </div>
      <div id="p-err" class="err" hidden></div>
      <div id="p-placeholder" class="placeholder" hidden><div class="slogan"><div class="wordmark">ARTEX</div><div class="wordmark-sub">CONTROLLER</div><div class="rule"></div><div class="tagline">Easy to wire, built to control.</div></div></div>
      <div id="p-body" hidden>
        <div class="chips" id="chips"></div>
        <div class="sec">
          <h3><span data-i18n="recent_tasks">最近任务</span> <span class="muted" id="t-note"></span><span class="sp"></span>
            <button id="btn-export" class="ghost mini" disabled data-i18n="export">导出报告</button></h3>
          <div id="tasks"></div>
          <div id="exp-msg" class="muted" style="margin-top:8px;font-size:12px"></div>
        </div>

        <div class="sec" id="ask-sec" hidden>
          <h3><span data-i18n="ask_main">提问主 Agent</span> · <span id="ask-title" style="color:var(--ink)"></span>
            <span class="sp"></span>
            <span id="ask-status" class="muted"></span>
          </h3>
          <textarea id="ask-msg" rows="3" placeholder="输入要给主 Agent 的指令或问题，Ctrl+Enter 发送" data-i18n-ph="ask_ph"></textarea>
          <div class="row" style="margin-top:10px;margin-bottom:0">
            <button id="btn-ask" data-i18n="send">发送</button>
            <span class="muted" style="font-size:11.5px" data-i18n="ask_hint">点任务行右侧「提问」切换目标任务</span>
          </div>
          <div id="ask-reply" class="reply" hidden></div>
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
            <label data-i18n="desc_auto">描述（自动生成）</label>
            <div class="auto-row">
              <div class="auto" id="f-desc-auto"></div>
              <a class="lnk" id="lnk-desc" title="临时修改本次任务的描述" data-i18n="edit_short" data-i18n-title="edit_desc_title">编辑</a>
            </div>
            <textarea id="f-desc-tmp" rows="2" hidden placeholder="临时修改本次任务的描述" data-i18n-ph="edit_desc_title"></textarea>
          </div>
          <div class="field" style="margin-top:8px">
            <div class="auto-row">
              <details><summary><span data-i18n="goal_fixed">目标（默认）</span></summary><pre id="f-goal-fixed"></pre></details>
              <a class="lnk" id="lnk-goal" title="临时修改本次任务的目标" data-i18n="edit_short" data-i18n-title="edit_goal_title">编辑</a>
            </div>
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

<script>
let MACHINES = [], CUR = null, CFG = {}, PWD = {}, REFRESHED = {}, SEL = null, ASK = null;
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
    tasks_note: '（按 ID 倒序，最新 {1} 个 / 共 {2} 个）',
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
    desc_auto: '描述（自动生成）', edit_short: '编辑',
    edit_desc_title: '临时修改本次任务的描述', edit_goal_title: '临时修改本次任务的目标',
    goal_fixed: '目标（默认）',
    desc_req: '描述（继承任务时必填）', goal_req: '目标（继承任务时必填）',
    desc_ph: '例如：在 xxx 基础上做二次利用验证', goal_ph: '例如：拿到该后台的管理权限',
    llm: 'LLM', llm_note: '（使用服务器中设定配置）', llm_ph: '（刷新后可选）',
    send_task: '下发', dispatching: '下发中…', confirm_send: '确认下发', cancel: '取消',
    desc_template: '渗透{1}源站及其子站', name_ph: '<名称>',
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
    op_failed: '操作失败', active_mark: '（激活）'
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
    tasks_note: ' (newest {1} of {2}, by ID)',
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
    desc_auto: 'Description (auto)', edit_short: 'Edit',
    edit_desc_title: 'Temporarily override the description for this task',
    edit_goal_title: 'Temporarily override the goal for this task',
    goal_fixed: 'Goal (default)',
    desc_req: 'Description (required when inheriting)', goal_req: 'Goal (required when inheriting)',
    desc_ph: 'e.g. post-exploitation based on xxx', goal_ph: 'e.g. gain admin access to the panel',
    llm: 'LLM', llm_note: '(configured on the server)', llm_ph: '(available after refresh)',
    send_task: 'Dispatch', dispatching: 'Dispatching…', confirm_send: 'Confirm dispatch', cancel: 'Cancel',
    desc_template: 'Pentest {1} origin and subdomains', name_ph: '<name>',
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
    op_failed: 'Operation failed', active_mark: ' (active)'
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

async function boot(){
  await loadMachines();
  // 页面刷新后，把服务端还活着的连接同步回来
  try {
    const c = await api('/api/connected', {});
    (c.ips || []).forEach(ip => { CONNECTED[ip] = true; setDot(ip, 'd1'); });
    if (Object.keys(CONNECTED).length){ startPoll(); pollOnce(); }
  } catch(e){}
}

function renderMachines(){
  $('list').innerHTML = MACHINES.map(m =>
    '<div class="item" data-ip="' + esc(m.ip) + '">' +
      '<span class="dot d0" id="dot-' + esc(m.ip) + '"></span>' +
      '<span><div class="ip">' + esc(m.ip) + '</div><div class="lb">' + esc(m.label || '') +
        ((m.has_password || m.has_key) ? '' : esc(T('no_creds'))) + '</div></span>' +
      '<span class="ops">' +
        '<button class="icon btn-medit" data-ip="' + esc(m.ip) + '" title="' + esc(T('edit')) + '">✎</button>' +
        '<button class="icon btn-mdel" data-ip="' + esc(m.ip) + '" title="' + esc(T('del')) + '">✕</button>' +
      '</span></div>').join('');
  $('list').querySelectorAll('.item').forEach(el => {
    el.onclick = (ev) => {
      if (!ev.target.classList || !ev.target.classList.contains('icon')) select(el.dataset.ip);
    };
  });
  $('list').querySelectorAll('.btn-medit').forEach(b =>
    b.onclick = (e) => { e.stopPropagation(); openMachineForm(b.dataset.ip); });
  $('list').querySelectorAll('.btn-mdel').forEach(b =>
    b.onclick = (e) => { e.stopPropagation(); delMachine(b.dataset.ip); });
}

async function loadMachines(){
  const d = await api('/api/machines');
  MACHINES = d.machines; CFG = d;
  LANG = d.lang === 'en' ? 'en' : 'zh';
  applyLang();
  $('f-goal-fixed').textContent = d.goal || '';
  $('f-goal-fixed').dataset.raw = d.goal || '';
  $('f-timeout').value = d.timeout_minutes || 600;
  renderMachines();
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
  $('m-modal').hidden = false;
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
      $('m-modal').hidden = true;
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
      delete CONNECTED[ip];
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
$('m-cancel').onclick = () => { $('m-modal').hidden = true; };

function select(ip){
  CUR = ip;
  document.querySelectorAll('.item').forEach(el => el.classList.toggle('on', el.dataset.ip === ip));
  const m = MACHINES.find(x => x.ip === ip);
  $('empty').hidden = true; $('panel').hidden = false;
  $('p-ip').textContent = ip;
  $('p-label').textContent = m.label || '';
  $('p-pw').hidden = !!m.has_password;
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
  updateDesc();
  const conn = !!CONNECTED[ip];
  $('p-placeholder').hidden = conn;
  if (conn){
    const cached = REFRESHED[ip];
    if (cached && cached.ok) render(cached);
    else $('p-body').hidden = true;
    pollOnce();
  } else {
    $('p-body').hidden = true;
  }
}
function updateDesc(){
  const v = $('f-name').value.trim();
  $('f-desc-auto').textContent = T('desc_template', v || T('name_ph'));
}

/* 继承任务：切换后描述/目标改为手填 */
async function onSrcChange(){
  const src = $('f-src').value;
  $('f-auto').hidden = !!src;
  $('f-manual').hidden = !src;
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

$('lnk-desc').onclick = (e) => {
  e.preventDefault();
  const t = $('f-desc-tmp');
  if (t.hidden){ t.value = $('f-desc-auto').textContent || ''; t.hidden = false; t.focus(); }
  else { t.hidden = true; }
};
$('lnk-goal').onclick = (e) => {
  e.preventDefault();
  const t = $('f-goal-tmp');
  if (t.hidden){ t.value = $('f-goal-fixed').dataset.raw || CFG.goal || ''; t.hidden = false; t.focus(); }
  else { t.hidden = true; }
};

function setDot(ip, cls){ const d = $('dot-' + ip); if (d) d.className = 'dot ' + cls; }

let CONNECTED = {};
let pollTimer = null;

function setConnUI(on){
  $('p-conn').checked = !!on;
  if (on){ $('conn-label').textContent = T('connected'); $('conn-label').style.color = 'var(--ok)'; }
  else { $('conn-label').textContent = T('disconnected'); $('conn-label').style.color = 'var(--ink-3)'; }
  $('dispatch-sec').hidden = !on;      // 没连接不显示下发区（拿不到 LLM 配置）
  if ($('p-placeholder')) $('p-placeholder').hidden = !!on;
}

async function doConnect(){
  if (!CUR) return;
  const ip = CUR, m = MACHINES.find(x => x.ip === ip);
  const pw = m.has_password ? '' : $('p-pw').value;
  if (!m.has_password && !pw){ showErr(T('no_pw_top')); setConnUI(false); return; }
  if (pw) PWD[ip] = pw;
  $('p-err').hidden = true;
  $('conn-label').textContent = T('connecting');
  try {
    const d = await api('/api/connect', {ip, password: pw});
    if (!d.ok){
      showErr(d.error || T('conn_failed'));
      setDot(ip, 'd2'); setConnUI(false); return;
    }
    CONNECTED[ip] = true;
    setDot(ip, 'd1');
    REFRESHED[ip] = d;
    render(d);
    setConnUI(true);
    startPoll();
  } catch(e){
    showErr(T('conn_failed_e') + e);
    setConnUI(false);
  }
}

async function doDisconnect(){
  if (!CUR) return;
  const ip = CUR;
  setConnUI(false);
  delete CONNECTED[ip];
  $('p-body').hidden = true;
  try { await api('/api/disconnect', {ip}); } catch(e){}
  if (!Object.keys(CONNECTED).length) stopPoll();
}

function startPoll(){
  if (pollTimer) return;
  pollTimer = setInterval(pollOnce, 8000);
}
function stopPoll(){
  if (pollTimer){ clearInterval(pollTimer); pollTimer = null; }
}

async function pollOnce(){
  // 只刷当前会话（其它连着的机器保持连接、切过去时再刷）
  const ips = (CUR && CONNECTED[CUR]) ? [CUR] : [];
  if (!Object.keys(CONNECTED).length){ stopPoll(); return; }
  if (!ips.length) return;
  let d;
  try { d = await api('/api/poll', {ips}); } catch(e){ return; }
  (d.results || []).forEach(r => {
    if (r.ok){
      REFRESHED[r.ip] = Object.assign({}, REFRESHED[r.ip] || {}, r);
      setDot(r.ip, 'd1');
      if (r.ip === CUR && CONNECTED[r.ip]) render(r);
    } else {
      delete CONNECTED[r.ip];
      setDot(r.ip, 'd2');
      if (r.ip === CUR){ setConnUI(false); showErr(T('disconnected_e') + (r.error || '')); }
    }
  });
  if (!Object.keys(CONNECTED).length) stopPoll();
}

$('p-conn').addEventListener('change', () => {
  if ($('p-conn').checked) doConnect(); else doDisconnect();
});

function showErr(msg){ const e = $('p-err'); e.textContent = msg; e.hidden = false; }

function render(d){
  $('p-body').hidden = false;
  $('p-time').textContent = d.fetched_at ? (T('refreshed_at') + new Date(d.fetched_at*1000).toLocaleTimeString()) : '';
  const f = d.findings, c = d.counts || {};
  $('chips').innerHTML =
    chip(T('tasks_total'), d.tasks_total, '#96683f') +
    chip(T('running'), c.running || 0, '#4b7357') +
    chip(T('paused'), c.paused || 0, '#9c8636') +
    chip(T('critical'), f.critical, '#a8452f') +
    chip(T('high'), f.high, '#bf7132') +
    chip(T('medium'), f.medium, '#9c8636') +
    chip(T('low'), f.low, '#5d7f93') +
    chip(T('intent'), d.in_flight, '#786c5d');
  $('t-note').textContent = d.active.length
      ? T('tasks_note', d.active.length, d.active_total) : '';
  $('tasks').innerHTML = d.active.length ? ('<table><tr><th>#</th><th>' + T('th_task') + '</th><th>' + T('th_status') + '</th>' +
      '<th class="num">' + T('intent') + '</th><th class="num">' + T('critical') + '</th><th class="num">' + T('high') + '</th><th class="num">' + T('medium') + '</th><th class="num">' + T('low') + '</th><th class="ops"></th></tr>' +
      d.active.map(t => '<tr data-id="' + esc(t.id) + '" data-name="' + esc(t.name) + '"><td class="muted">' + esc(t.id) + '</td><td>' + esc(t.name) + '</td>' +
        '<td><span class="tag s-' + esc(t.status) + '">' + esc(stName(t.status)) + '</span></td>' +
        '<td class="num">' + t.in_flight + '</td>' + num(t.findings.critical, t.findings.critical?'c-critical':'') +
        num(t.findings.high, t.findings.high?'c-high':'') + num(t.findings.medium, t.findings.medium?'c-medium':'') +
        num(t.findings.low, t.findings.low?'c-low':'') + '<td class="ops">' + ctrlBtn(t) +
        '<button class="mini ghost btn-ask" data-id="' + esc(t.id) + '" data-name="' + esc(t.name) + '">' + T('ask') + '</button></td></tr>').join('') + '</table>')
    : '<div class="muted">' + T('no_tasks') + '</div>';
  SEL = null;
  $('btn-export').disabled = true;
  $('exp-msg').textContent = '';
  // 继承任务下拉（保留当前选择）
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
      $('btn-export').disabled = false;
      $('exp-msg').textContent = '';
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
function chip(k, v, color){
  return '<div class="chip"><div class="k">' + k + '</div><div class="v" style="color:' + color + '">' + (v||0) + '</div></div>';
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
                   : (tmpDesc || T('desc_template', name));
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
      $('f-desc-tmp').hidden = true; $('f-desc-tmp').value = '';
      $('f-goal-tmp').hidden = true; $('f-goal-tmp').value = '';
      $('f-src').value = '';
      onSrcChange();
      updateDesc();
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
  ASK = {id: id, name: name};
  $('ask-sec').hidden = false;
  $('ask-title').textContent = '#' + id + ' ' + name;
  $('ask-reply').hidden = true;
  $('ask-reply').textContent = '';
  $('ask-status').textContent = '';
  $('ask-msg').value = '';
  $('ask-msg').focus();
  $('ask-sec').scrollIntoView({block: 'nearest'});
}

async function doAsk(){
  if (!ASK || !CUR) return;
  const msg = $('ask-msg').value.trim();
  if (!msg){ $('ask-status').textContent = T('ask_empty'); return; }
  const m = MACHINES.find(x => x.ip === CUR);
  const pw = m.has_password ? '' : $('p-pw').value;
  $('btn-ask').disabled = true;
  $('btn-ask').textContent = T('sending');
  $('ask-reply').hidden = true;
  const t0 = Date.now();
  const timer = setInterval(() => {
    $('ask-status').textContent = T('waiting') + Math.round((Date.now() - t0) / 1000) + 's';
  }, 1000);
  try {
    const d = await api('/api/ask', {ip: CUR, password: pw, task_id: ASK.id, message: msg});
    $('ask-reply').hidden = false;
    if (d.ok){
      $('ask-status').textContent = '';
      $('ask-reply').textContent = d.reply || T('empty_reply');
    } else {
      $('ask-status').textContent = '';
      $('ask-reply').innerHTML = '<span style="color:#a8452f">✗ ' + esc(d.error || T('op_failed')) + '</span>';
    }
  } catch(e){
    $('ask-status').textContent = '';
    $('ask-reply').hidden = false;
    $('ask-reply').textContent = T('req_failed') + e;
  } finally {
    clearInterval(timer);
    $('btn-ask').disabled = false;
    $('btn-ask').textContent = T('send');
  }
}

$('btn-ask').onclick = doAsk;
$('ask-msg').addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)){ e.preventDefault(); doAsk(); }
});

async function doExport(){
  if (!CUR || !SEL) return;
  const m = MACHINES.find(x => x.ip === CUR);
  const pw = m.has_password ? '' : $('p-pw').value;
  $('btn-export').disabled = true;
  $('btn-export').textContent = T('exporting');
  $('exp-msg').textContent = '';
  try {
    const d = await api('/api/export', {ip: CUR, password: pw,
      task_id: SEL.id, task_name: SEL.name});
    if (d.ok){
      $('exp-msg').innerHTML = '<span class="ok">' + esc(T('exported_to', d.dir, d.critical || 0, d.high || 0)) + '</span> ' +
        '<a href="#" id="lnk-open" style="color:var(--accent)">' + esc(T('open_dir')) + '</a>';
      $('lnk-open').onclick = (e) => { e.preventDefault(); api('/api/open-dir', {dir: d.dir}); };
    } else {
      $('exp-msg').innerHTML = '<span style="color:#a8452f">✗ ' + esc(d.error || T('op_failed')) + '</span>';
    }
  } catch(e){
    $('exp-msg').innerHTML = '<span style="color:#a8452f">✗ ' + esc(T('req_failed')) + esc(e) + '</span>';
  } finally {
    $('btn-export').disabled = !SEL;
    $('btn-export').textContent = T('export');
  }
}
$('btn-export').onclick = doExport;
$('btn-send').onclick = askSend;
$('btn-confirm-send').onclick = () => { $('f-confirm').hidden = true; $('btn-send').disabled = false; send(); };
$('btn-cancel-send').onclick = cancelSend;
$('f-name').addEventListener('keydown', e => { if (e.key === 'Enter'){ e.preventDefault(); askSend(); } });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('f-confirm').hidden) cancelSend(); });

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
  :root{
    --bg:#f6f1e7;--panel:#fdfaf4;--line:#e6dccb;--line-soft:#efe7d9;
    --ink:#4a4136;--ink-2:#786c5d;--ink-3:#a59a8b;
    --accent:#96683f;--accent-d:#7d5533;--ok:#4b7357;--crit:#a8452f;
  }
  *{box-sizing:border-box}
  body.dark{
    --bg:#1f1a15;--panel:#272119;--line:#3b332a;--line-soft:#332c24;
    --ink:#e6dccc;--ink-2:#bdb09e;--ink-3:#8a7d6c;
    --accent:#d0a271;--accent-d:#b98a55;--ok:#83b18e;--crit:#d97f68;
  }
  html,body{margin:0;min-height:100%}
  body{
    background:var(--bg);color:var(--ink);
    font:13.5px/1.65 "Segoe UI","Microsoft YaHei","PingFang SC",system-ui,sans-serif;
    display:flex;justify-content:center;padding:48px 20px;
    -webkit-font-smoothing:antialiased;
  }
  .wrap{width:min(620px,100%)}
  .head{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:18px}
  .brand{font-size:16px;font-weight:600;letter-spacing:.4px;color:var(--accent)}
  .sub{font-size:12px;color:var(--ink-3);letter-spacing:1px;margin-top:2px}
  .back{color:var(--accent);font-size:12px;text-decoration:none}
  .back:hover{text-decoration:underline}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
        padding:20px 22px;box-shadow:0 1px 3px rgba(120,95,60,.06)}
  .row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px}
  .field{display:flex;flex-direction:column;gap:5px}
  .field label{font-size:11px;letter-spacing:.4px;color:var(--ink-3)}
  input,select{
    font:inherit;font-size:13px;color:var(--ink);background:#fffdf9;
    border:1px solid var(--line);border-radius:6px;padding:6px 10px;
  }
  body.dark input,body.dark select{background:#231e18}
  input:focus,select:focus{outline:none;border-color:#c8a986;box-shadow:0 0 0 3px rgba(150,104,63,.10)}
  button{
    font:inherit;font-size:13px;padding:6px 18px;border-radius:6px;cursor:pointer;
    background:var(--accent);border:1px solid var(--accent-d);color:#fdfaf4;letter-spacing:.3px;
  }
  button:hover{background:var(--accent-d)}
  button:disabled{opacity:.5;cursor:not-allowed}
  .muted{color:var(--ink-3);font-size:12px;margin-left:10px}
  .ok{color:var(--ok)}
</style>
</head>
<body>
<script>try{if(localStorage.getItem('artex_theme')==='1')document.body.classList.add('dark')}catch(e){}</script>
<div class="wrap">
  <div class="head">
    <div><div class="brand">ARTEX Controller</div><div class="sub" data-i18n="sub">全局设置</div></div>
    <a class="back" href="/" data-i18n="back">← 返回控制台</a>
  </div>
  <div class="card">
    <div class="row" style="margin-bottom:0">
      <div class="field" style="flex:1">
        <label data-i18n="lang">语言</label>
        <select id="lang">
          <option value="zh">简体中文</option>
          <option value="en">English</option>
        </select>
      </div>
    </div>
    <div class="row" style="margin:18px 0 0;align-items:center">
      <button id="save" data-i18n="save">保存</button>
      <span id="msg" class="muted"></span>
    </div>
  </div>
</div>
<script>
let LANG = 'zh';
const D = {
  zh: {
    sub: '设置', back: '← 返回控制台', lang: '语言',
    save: '保存', saving: '保存中…', saved: '已保存', fail: '保存失败', req_fail: '请求失败：'
  },
  en: {
    sub: 'Settings', back: '← Back to console', lang: 'Language',
    save: 'Save', saving: 'Saving…', saved: 'Saved', fail: 'Save failed', req_fail: 'Request failed: '
  }
};
const $ = id => document.getElementById(id);
function T(k){ return (D[LANG] || D.zh)[k] || D.zh[k] || k; }
function applyLang(){
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = T(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = T(el.dataset.i18nPh); });
  document.documentElement.lang = LANG === 'en' ? 'en' : 'zh-CN';
  document.title = LANG === 'en' ? 'ARTEX · Settings' : 'ARTEX · 设置';
}
async function load(){
  const d = await (await fetch('/api/settings')).json();
  LANG = d.lang === 'en' ? 'en' : 'zh';
  $('lang').value = LANG;
  applyLang();
}
$('lang').onchange = (e) => { LANG = e.target.value; applyLang(); };
$('save').onclick = async () => {
  $('save').disabled = true;
  $('msg').textContent = T('saving'); $('msg').className = 'muted';
  try {
    const r = await fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'},
                                            body: JSON.stringify({lang: $('lang').value})});
    const d = await r.json();
    if (d.ok){ $('msg').textContent = T('saved'); $('msg').className = 'muted ok'; }
    else { $('msg').textContent = d.error || T('fail'); $('msg').className = 'muted'; }
  } catch(e){ $('msg').textContent = T('req_fail') + e; $('msg').className = 'muted'; }
  finally { $('save').disabled = false; }
};
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
            self._json({
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
                "goal": DEFAULT_GOAL,
                "timeout_minutes": int(d.get("timeout_minutes", 600)),
                "llm_key": d.get("llm", ""),
                "login_user": d.get("login_user", ""),
                "login_password": d.get("login_password", ""),
                "default_artex_port": int(d.get("artex_port", 8787)),
                "lang": (self.cfg.get("console") or {}).get("lang", "zh"),
            })
            return
        if self.path.startswith("/api/settings"):
            c = self.cfg.get("console") or {}
            self._json({"lang": c.get("lang", "zh")})
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
        name = (body.get("task_name") or "").strip() or ("task_" + tid)
        try:
            with client_ctx(self.cfg, machine, password) as c:
                res = export_task(c, machine["ip"], tid, name)
            res["ok"] = True
            return res
        except paramiko.AuthenticationException:
            return {"ok": False, "error": "SSH 认证失败：密码不对"}
        except Exception as e:
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:160])}

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

    def _save_settings(self, body):
        lang = body.get("lang")
        if lang not in ("zh", "en"):
            return {"ok": False, "error": "语言不合法"}
        self.cfg.setdefault("console", {})["lang"] = lang
        save_config(self.cfg)
        return {"ok": True}

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
        save_config(self.cfg)
        return {"ok": True, "ip": ip}

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
                return ask_main_agent(c, tid, msg,
                                      timeout=int(body.get("timeout") or 240))
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
                desc = "渗透%s源站及其子站" % name
            if not goal_text:
                goal_text = DEFAULT_GOAL

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
