from __future__ import annotations

import json
import os
import queue
import socket
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

from tkinter import ttk
import uvicorn

import app as webapp


# --------------------
# Paths for config/log
# --------------------
APPDATA = Path(os.environ.get("APPDATA", str(Path.home())))
CFG_DIR = APPDATA / "WebFS"
CFG_DIR.mkdir(parents=True, exist_ok=True)
CFG_FILE = CFG_DIR / "config.json"
LOG_FILE = CFG_DIR / "access.log"


def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def check_port_free(host: str, port: int) -> tuple[bool, str]:
    """
    预检查端口是否可绑定：避免 uvicorn 异步报错难捕获
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_host = "" if host in ("0.0.0.0", "::") else host
    try:
        sock.bind((bind_host, port))
        sock.listen(1)
        return True, ""
    except OSError as e:
        return False, str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass


# --------------------
# Server controller
# --------------------
class ServerController:
    def __init__(self):
        self.server: uvicorn.Server | None = None
        self.thread: threading.Thread | None = None
        self.error_queue: "queue.Queue[str]" = queue.Queue()

    def start(self, root_dir: str, host: str, port: int, log_file: str):
        if self.running():
            return

        # FastAPI runtime options
        webapp.set_runtime(root_dir=root_dir, log_file=log_file)

        config = uvicorn.Config(
            webapp.app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(config)

        def run():
            try:
                self.server.run()
            except Exception as e:
                try:
                    self.error_queue.put_nowait(str(e))
                except Exception:
                    pass

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.should_exit = True
        self.server = None
        self.thread = None

    def running(self) -> bool:
        return self.server is not None and not self.server.should_exit


# --------------------
# GUI
# --------------------
class AppUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Web 文件服务器（局域网共享）")
        self.geometry("980x620")
        self.minsize(980, 620)

        self.ctrl = ServerController()
        self.lan_ip = get_lan_ip()

        # settings vars
        self.root_var = tk.StringVar()
        self.host_var = tk.StringVar(value="0.0.0.0")
        self.port_var = tk.StringVar(value="8000")
        self.allow_ipv4 = tk.BooleanVar(value=True)
        self.allow_ipv6 = tk.BooleanVar(value=False)
        self.guest_mode_var = tk.StringVar(value="browse_only")
        self.admin_accounts: list[dict] = []
        self.user_accounts: list[dict] = []

        # status vars
        self.status_var = tk.StringVar(value="已停止")
        self.url_var = tk.StringVar(value="")
        self.local_url_var = tk.StringVar(value="")

        # log filter vars
        self.filter_action = tk.StringVar(value="ALL")  # ALL / VIEW / DOWNLOAD / UPLOAD / ERROR / LIST
        self.filter_text = tk.StringVar(value="")
        self.autoscroll = tk.BooleanVar(value=True)

        # internal log cache
        self.log_rows: list[dict] = []
        self._next_iid = 1

        self._build_ui()
        self._load_config()
        self._load_history_log()
        self._refresh_status_ui()
        self._poll_queues()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # -------- UI Build --------
    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=6)
        style.configure("TLabelframe", padding=8)

        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=10)

        # status indicator
        self.canvas = tk.Canvas(top, width=14, height=14, highlightthickness=0)
        self.dot = self.canvas.create_oval(2, 2, 12, 12, fill="#888", outline="")
        self.canvas.pack(side="left", padx=(0, 8))
        ttk.Label(top, textvariable=self.status_var, font=("Segoe UI", 11, "bold")).pack(side="left")

        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=10)

        ttk.Label(top, text="访问：").pack(side="left")
        self.url_entry = ttk.Entry(top, textvariable=self.url_var, width=38)
        self.url_entry.pack(side="left", padx=6)
        ttk.Button(top, text="复制", command=self.copy_url).pack(side="left")

        ttk.Label(top, text="本机：").pack(side="left", padx=(16, 0))
        self.local_entry = ttk.Entry(top, textvariable=self.local_url_var, width=28)
        self.local_entry.pack(side="left", padx=6)
        ttk.Button(top, text="打开浏览器", command=self.open_browser).pack(side="left")

        # notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.tab_ctrl = ttk.Frame(nb)
        self.tab_logs = ttk.Frame(nb)
        nb.add(self.tab_ctrl, text="控制台")
        nb.add(self.tab_logs, text="访问日志")

        self._build_ctrl_tab()
        self._build_logs_tab()

    def _build_ctrl_tab(self):
        frm = ttk.Frame(self.tab_ctrl)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        lf = ttk.Labelframe(frm, text="服务器设置")
        lf.pack(fill="x")

        row1 = ttk.Frame(lf)
        row1.pack(fill="x", pady=6)
        ttk.Label(row1, text="共享文件夹：").pack(side="left")
        self.root_entry = ttk.Entry(row1, textvariable=self.root_var, width=80)
        self.root_entry.pack(side="left", padx=8, fill="x", expand=True)
        ttk.Button(row1, text="浏览…", command=self.pick_dir).pack(side="left")
        ttk.Button(row1, text="打开文件夹", command=self.open_folder).pack(side="left", padx=(8, 0))

        row2 = ttk.Frame(lf)
        row2.pack(fill="x", pady=6)
        ttk.Label(row2, text="端口：").pack(side="left")
        ttk.Entry(row2, textvariable=self.port_var, width=10).pack(side="left", padx=8)
        ttk.Label(row2, text="（IPv4/IPv6 开关在下方“账户与权限管理”中设置）", foreground="#666").pack(side="left", padx=8)

        row3 = ttk.Frame(lf)
        row3.pack(fill="x", pady=(8, 6))
        self.btn_start = ttk.Button(row3, text="启动服务器", command=self.start_server)
        self.btn_stop = ttk.Button(row3, text="停止服务器", command=self.stop_server)
        self.btn_start.pack(side="left")
        self.btn_stop.pack(side="left", padx=10)

        sec = ttk.Labelframe(frm, text="账户与权限管理")
        sec.pack(fill="x", pady=(12, 0))
        net = ttk.Frame(sec)
        net.pack(fill="x", pady=4)
        ttk.Label(net, text="网络访问：").pack(side="left")
        ttk.Checkbutton(net, text="允许 IPv4", variable=self.allow_ipv4).pack(side="left", padx=6)
        ttk.Checkbutton(net, text="允许 IPv6", variable=self.allow_ipv6).pack(side="left", padx=6)

        acc = ttk.Frame(sec)
        acc.pack(fill="x", pady=4)
        ttk.Button(acc, text="管理员账户…", command=self.manage_admins).pack(side="left")
        ttk.Button(acc, text="普通账户…", command=self.manage_users).pack(side="left", padx=8)
        ttk.Label(acc, text="游客模式：").pack(side="left", padx=(20,6))
        ttk.Combobox(acc, textvariable=self.guest_mode_var, state="readonly", width=16,
                     values=["debug", "browse_only", "disabled"]).pack(side="left")

        tips = ttk.Labelframe(frm, text="提示")
        tips.pack(fill="x", pady=(12, 0))
        ttk.Label(
            tips,
            text="• 手机无法访问时：检查 Windows 防火墙入站规则是否允许端口。\n"
                 "• 默认仅用于局域网共享；如需公网使用请自行增加鉴权。",
            justify="left",
        ).pack(anchor="w")

        # live log tail (compact)
        tail = ttk.Labelframe(frm, text="最近事件（实时）")
        tail.pack(fill="both", expand=True, pady=(12, 0))

        self.tail_text = tk.Text(tail, height=12, wrap="none")
        self.tail_text.pack(fill="both", expand=True)
        self.tail_text.configure(state="disabled")

    def _build_logs_tab(self):
        frm = ttk.Frame(self.tab_logs)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        # filters
        fbar = ttk.Frame(frm)
        fbar.pack(fill="x")

        ttk.Label(fbar, text="快速筛选：").pack(side="left")
        for name, val in [("全部", "ALL"), ("查看", "VIEW"), ("下载", "DOWNLOAD"), ("上传", "UPLOAD"), ("错误", "ERROR"), ("列表", "LIST")]:
            ttk.Button(fbar, text=name, command=lambda v=val: self.set_action_filter(v)).pack(side="left", padx=4)

        ttk.Separator(fbar, orient="vertical").pack(side="left", fill="y", padx=10)

        ttk.Label(fbar, text="关键字(IP/路径)：").pack(side="left")
        ent = ttk.Entry(fbar, textvariable=self.filter_text, width=34)
        ent.pack(side="left", padx=6)
        ent.bind("<KeyRelease>", lambda e: self.rebuild_tree())

        ttk.Checkbutton(fbar, text="自动滚动", variable=self.autoscroll).pack(side="left", padx=10)
        ttk.Button(fbar, text="清空视图", command=self.clear_view).pack(side="right")
        ttk.Button(fbar, text="导出日志…", command=self.export_log).pack(side="right", padx=8)

        # stats
        self.stats_var = tk.StringVar(value="统计：0 条")
        ttk.Label(frm, textvariable=self.stats_var).pack(anchor="w", pady=(8, 6))

        # tree
        columns = ("time", "ip", "action", "path", "status", "detail")
        self.tree = ttk.Treeview(frm, columns=columns, show="headings", height=18)
        for c, w in [("time", 150), ("ip", 130), ("action", 90), ("path", 360), ("status", 70), ("detail", 280)]:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, anchor="w")

        vsb = ttk.Scrollbar(frm, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    # -------- Persistence --------
    def _load_config(self):
        if CFG_FILE.exists():
            try:
                data = json.loads(CFG_FILE.read_text(encoding="utf-8"))
                self.root_var.set(data.get("root_dir", str(Path.home())))
                self.host_var.set(data.get("host", "0.0.0.0"))
                self.port_var.set(str(data.get("port", 8000)))
                self.allow_ipv4.set(data.get("allow_ipv4", True))
                self.allow_ipv6.set(data.get("allow_ipv6", False))
                self.guest_mode_var.set(data.get("guest_mode", "browse_only"))
                self.admin_accounts = data.get("admins", [{"username":"admin","password":"admin"}])
                self.user_accounts = data.get("users", [])
                return
            except Exception:
                pass
        self.root_var.set(str(Path.home()))
        self.admin_accounts = [{"username":"admin","password":"admin"}]
        self.user_accounts = []

    def _save_config(self):
        data = {
            "root_dir": self.root_var.get().strip(),
            "host": self.host_var.get().strip() or "0.0.0.0",
            "port": int(self.port_var.get().strip() or "8000"),
            "allow_ipv4": self.allow_ipv4.get(),
            "allow_ipv6": self.allow_ipv6.get(),
            "guest_mode": self.guest_mode_var.get(),
            "admins": self.admin_accounts,
            "users": self.user_accounts,
        }
        try:
            CFG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _load_history_log(self, max_lines: int = 3000):
        if not LOG_FILE.exists():
            self._update_stats()
            return
        try:
            lines = LOG_FILE.read_text(encoding="utf-8").splitlines()[-max_lines:]
            for ln in lines:
                try:
                    row = json.loads(ln)
                    self.log_rows.append(row)
                except Exception:
                    continue
            self.rebuild_tree()
        except Exception:
            pass

    # -------- Actions --------
    def pick_dir(self):
        d = filedialog.askdirectory(initialdir=self.root_var.get() or str(Path.home()))
        if d:
            self.root_var.set(d)

    def open_folder(self):
        p = self.root_var.get().strip()
        if not p:
            return
        try:
            Path(p).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        try:
            os.startfile(p)  # Windows
        except Exception:
            pass

    def start_server(self):
        root_dir = self.root_var.get().strip()
        if not self.allow_ipv4.get() and not self.allow_ipv6.get():
            messagebox.showerror("启动失败", "IPv4 和 IPv6 不能同时禁用。")
            return
        host = "::" if self.allow_ipv6.get() and not self.allow_ipv4.get() else "0.0.0.0"
        if self.allow_ipv4.get() and self.allow_ipv6.get():
            host = "::"
        try:
            port = int(self.port_var.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("启动失败", "端口必须是 1~65535 的整数。")
            return

        if not root_dir or not Path(root_dir).exists():
            messagebox.showerror("启动失败", "请选择有效的共享文件夹。")
            return

        ok, err = check_port_free(host, port)
        if not ok:
            messagebox.showerror("启动失败", f"端口无法绑定（可能被占用或权限不足）：\n{err}")
            return

        # 先保存设置
        self._save_config()

        webapp.set_auth_config({
            "admins": self.admin_accounts,
            "users": self.user_accounts,
            "guest_mode": self.guest_mode_var.get(),
        })
        # 启动
        self.ctrl.start(root_dir=root_dir, host=host, port=port, log_file=str(LOG_FILE))

        # 立即更新 UI（停止按钮可用）
        self._refresh_status_ui()

        # 显示访问地址
        show_host = self.lan_ip if host == "0.0.0.0" else host
        self.url_var.set(f"http://{show_host}:{port}")
        self.local_url_var.set(f"http://127.0.0.1:{port}")

    def stop_server(self):
        self.ctrl.stop()
        self._refresh_status_ui()

    def copy_url(self):
        url = self.url_var.get().strip()
        if not url:
            return
        self.clipboard_clear()
        self.clipboard_append(url)

    def open_browser(self):
        import webbrowser
        url = self.local_url_var.get().strip() or self.url_var.get().strip()
        if url:
            webbrowser.open(url, new=2)

    # -------- Logs --------
    def set_action_filter(self, v: str):
        self.filter_action.set(v)
        self.rebuild_tree()

    def _match_filter(self, row: dict) -> bool:
        act = self.filter_action.get()
        row_act = (row.get("action") or "").upper()

        # “查看”包含 VIEW；也包含 raw 不下载的 VIEW
        if act != "ALL":
            if act == "VIEW" and row_act != "VIEW":
                return False
            if act == "DOWNLOAD" and row_act != "DOWNLOAD":
                return False
            if act == "UPLOAD" and row_act != "UPLOAD":
                return False
            if act == "ERROR" and row_act != "ERROR":
                return False
            if act == "LIST" and row_act != "LIST":
                return False

        kw = self.filter_text.get().strip().lower()
        if kw:
            ip = (row.get("ip") or "").lower()
            path = (row.get("path") or "").lower()
            detail = (row.get("detail") or "").lower()
            if kw not in ip and kw not in path and kw not in detail:
                return False

        return True

    def rebuild_tree(self):
        # 清空并按过滤条件重建
        for iid in self.tree.get_children():
            self.tree.delete(iid)

        self._next_iid = 1
        for row in self.log_rows:
            if self._match_filter(row):
                self._insert_tree_row(row)

        self._update_stats(scroll_to_end=True)

    def _insert_tree_row(self, row: dict):
        ts = row.get("ts") or time.time()
        tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        values = (
            tstr,
            row.get("ip", "-"),
            row.get("action", "-"),
            row.get("path", "-"),
            str(row.get("status", "")),
            row.get("detail", ""),
        )
        self.tree.insert("", "end", iid=str(self._next_iid), values=values)
        self._next_iid += 1

    def _append_tail(self, row: dict):
        ts = row.get("ts") or time.time()
        tstr = time.strftime("%H:%M:%S", time.localtime(ts))
        line = f"[{tstr}] {row.get('ip','-')} {row.get('action','-')} {row.get('path','-')} {row.get('status','')}\n"

        self.tail_text.configure(state="normal")
        self.tail_text.insert("end", line)
        # 控制最近显示
        if int(self.tail_text.index("end-1c").split(".")[0]) > 300:
            self.tail_text.delete("1.0", "50.0")
        self.tail_text.see("end")
        self.tail_text.configure(state="disabled")

    def clear_view(self):
        # 只清空 GUI 视图，不删除磁盘日志（你也可以扩展成“清空日志文件”）
        self.log_rows.clear()
        self.rebuild_tree()
        self._update_stats()

    def export_log(self):
        fp = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("JSON lines", "*.jsonl"), ("All files", "*.*")],
            initialdir=str(CFG_DIR),
            initialfile="access_export.log",
        )
        if not fp:
            return
        try:
            with open(fp, "w", encoding="utf-8") as f:
                for row in self.log_rows:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
            messagebox.showinfo("导出成功", f"已导出到：\n{fp}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def _update_stats(self, scroll_to_end: bool = False):
        # 统计全量（不随过滤变化也可以；这里给你“随过滤变化”的统计）
        filtered = [r for r in self.log_rows if self._match_filter(r)]
        ips = {r.get("ip") for r in filtered if r.get("ip")}
        counts = {"LIST": 0, "VIEW": 0, "DOWNLOAD": 0, "UPLOAD": 0, "ERROR": 0}
        for r in filtered:
            a = (r.get("action") or "").upper()
            if a in counts:
                counts[a] += 1
        self.stats_var.set(
            f"统计（当前筛选）：{len(filtered)} 条 · 唯一IP {len(ips)} · "
            f"LIST {counts['LIST']} / VIEW {counts['VIEW']} / DOWNLOAD {counts['DOWNLOAD']} / "
            f"UPLOAD {counts['UPLOAD']} / ERROR {counts['ERROR']}"
        )

        if scroll_to_end and self.autoscroll.get():
            children = self.tree.get_children()
            if children:
                self.tree.see(children[-1])

    # -------- Status UI --------
    def _refresh_status_ui(self):
        running = self.ctrl.running()
        if running:
            self.status_var.set("运行中")
            self.canvas.itemconfig(self.dot, fill="#32d074")  # green
            self.btn_start.state(["disabled"])
            self.btn_stop.state(["!disabled"])
        else:
            self.status_var.set("已停止")
            self.canvas.itemconfig(self.dot, fill="#999999")
            self.btn_start.state(["!disabled"])
            self.btn_stop.state(["disabled"])

    # -------- Poll queues --------
    def _poll_queues(self):
        # 1) server start errors
        try:
            err = self.ctrl.error_queue.get_nowait()
            messagebox.showerror("服务器异常退出", err)
            self.ctrl.stop()
            self._refresh_status_ui()
        except queue.Empty:
            pass

        # 2) access logs from app.state.log_queue
        #    注意：未启动服务器前 app.state.log_queue 也存在，但可能为空
        try:
            q = getattr(webapp.app.state, "log_queue", None)
            if q:
                while True:
                    row = q.get_nowait()
                    self.log_rows.append(row)

                    # tail panel
                    self._append_tail(row)

                    # tree insert (incremental)
                    if self._match_filter(row):
                        self._insert_tree_row(row)
                        if self.autoscroll.get():
                            children = self.tree.get_children()
                            if children:
                                self.tree.see(children[-1])
        except queue.Empty:
            pass
        except Exception:
            pass

        self._update_stats()
        self._refresh_status_ui()

        self.after(500, self._poll_queues)

    def on_close(self):
        self._save_config()
        try:
            self.ctrl.stop()
        except Exception:
            pass
        self.destroy()


    def _default_user_permissions(self):
        return {"browse": True, "view": True, "download": False, "upload": False, "delete": False}

    def manage_admins(self):
        name = simpledialog.askstring("管理员", "用户名：")
        if not name:
            return
        pwd = simpledialog.askstring("管理员", "密码：", show="*")
        if not pwd:
            return
        self.admin_accounts = [a for a in self.admin_accounts if a.get("username") != name]
        self.admin_accounts.append({"username": name, "password": pwd})
        messagebox.showinfo("完成", "管理员账户已添加/更新。")

    def manage_users(self):
        name = simpledialog.askstring("普通账户", "用户名：")
        if not name:
            return
        pwd = simpledialog.askstring("普通账户", "密码：", show="*")
        if not pwd:
            return
        perms = self._default_user_permissions()
        for k, label in [("download", "允许下载"), ("upload", "允许上传"), ("delete", "允许删除")]:
            perms[k] = messagebox.askyesno("普通账户权限", f"{label}？")
        self.user_accounts = [u for u in self.user_accounts if u.get("username") != name]
        self.user_accounts.append({"username": name, "password": pwd, "permissions": perms})
        messagebox.showinfo("完成", "普通账户已添加/更新。")

if __name__ == "__main__":
    AppUI().mainloop()