from __future__ import annotations

import json
import os
import queue
import socket
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from tkinter import filedialog, messagebox, simpledialog

from tkinter import ttk

import uvicorn

import app as webapp

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


class ServerController:
    def __init__(self):
        self.server: uvicorn.Server | None = None
        self.thread: threading.Thread | None = None
        self.error_queue: "queue.Queue[str]" = queue.Queue()

    def start(self, root_dir: str, host: str, port: int, log_file: str):
        if self.running():
            return

        webapp.set_runtime(root_dir=root_dir, log_file=log_file)
        config = uvicorn.Config(webapp.app, host=host, port=port, log_level="warning", access_log=False)
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


class AppUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Web 文件服务器（局域网共享）")
        self.geometry("1180x740")
        self.minsize(1080, 680)

        self.ctrl = ServerController()
        self.lan_ip = get_lan_ip()

        self.root_var = tk.StringVar()
        self.port_var = tk.StringVar(value="8000")
        self.allow_ipv4 = tk.BooleanVar(value=True)
        self.allow_ipv6 = tk.BooleanVar(value=False)
        self.guest_mode_var = tk.StringVar(value="browse_only")
        self.admin_accounts: list[dict] = []
        self.user_accounts: list[dict] = []

        self.allow_ipv4 = tk.BooleanVar(value=True)
        self.allow_ipv6 = tk.BooleanVar(value=False)
        self.guest_mode_var = tk.StringVar(value="browse_only")
        self.admin_accounts: list[dict] = []
        self.user_accounts: list[dict] = []

        self.allow_ipv4 = tk.BooleanVar(value=True)
        self.allow_ipv6 = tk.BooleanVar(value=False)
        self.guest_mode_var = tk.StringVar(value="browse_only")
        self.admin_accounts: list[dict] = []
        self.user_accounts: list[dict] = []

        self.status_var = tk.StringVar(value="已停止")
        self.url_var = tk.StringVar(value="")
        self.local_url_var = tk.StringVar(value="")

        self.filter_action = tk.StringVar(value="ALL")
        self.filter_text = tk.StringVar(value="")
        self.autoscroll = tk.BooleanVar(value=True)
        self.log_rows: list[dict] = []
        self._next_iid = 1

        self.account_search = tk.StringVar(value="")
        self.selected_account_key: tuple[str, str] | None = None
        self.acc_role_var = tk.StringVar(value="")
        self.acc_name_var = tk.StringVar(value="")
        self.acc_pass_var = tk.StringVar(value="")
        self.acc_perm_browse = tk.BooleanVar(value=True)
        self.acc_perm_view = tk.BooleanVar(value=True)
        self.acc_perm_download = tk.BooleanVar(value=False)
        self.acc_perm_upload = tk.BooleanVar(value=False)
        self.acc_perm_delete = tk.BooleanVar(value=False)

        self._build_ui()
        self._load_config()
        self._load_history_log()
        self.refresh_account_list()
        self._refresh_status_ui()
        self._poll_queues()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=6)
        style.configure("TLabelframe", padding=8)

        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=10)
        self.canvas = tk.Canvas(top, width=14, height=14, highlightthickness=0)
        self.dot = self.canvas.create_oval(2, 2, 12, 12, fill="#888", outline="")
        self.canvas.pack(side="left", padx=(0, 8))
        ttk.Label(top, textvariable=self.status_var, font=("Segoe UI", 11, "bold")).pack(side="left")

        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Label(top, text="访问：").pack(side="left")
        self.url_entry = ttk.Entry(top, textvariable=self.url_var, width=40)
        self.url_entry.pack(side="left", padx=6)
        ttk.Button(top, text="复制", command=self.copy_url).pack(side="left")
        ttk.Label(top, text="本机：").pack(side="left", padx=(16, 0))
        self.local_entry = ttk.Entry(top, textvariable=self.local_url_var, width=30)
        self.local_entry.pack(side="left", padx=6)
        ttk.Button(top, text="打开浏览器", command=self.open_browser).pack(side="left")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.tab_ctrl = ttk.Frame(self.nb)
        self.tab_accounts = ttk.Frame(self.nb)
        self.tab_logs = ttk.Frame(self.nb)
        self.nb.add(self.tab_ctrl, text="控制台")
        self.nb.add(self.tab_accounts, text="账户与权限")
        self.nb.add(self.tab_logs, text="访问日志")

        self._build_ctrl_tab()
        self._build_accounts_tab()
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
        ttk.Label(row2, text="账户/网络权限请在“账户与权限”页配置", foreground="#666").pack(side="left", padx=8)
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
            text="• 启动前请在“账户与权限”页面完成账号和游客策略配置。\n"
            "• 手机无法访问时请检查防火墙和端口放行。",
            justify="left",
        ).pack(anchor="w")

        tail = ttk.Labelframe(frm, text="最近事件（实时）")
        tail.pack(fill="both", expand=True, pady=(12, 0))
        self.tail_text = tk.Text(tail, height=12, wrap="none")
        self.tail_text.pack(fill="both", expand=True)
        self.tail_text.configure(state="disabled")

    def _build_accounts_tab(self):
        frm = ttk.Frame(self.tab_accounts)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        global_box = ttk.Labelframe(frm, text="全局访问策略")
        global_box.pack(fill="x")
        g1 = ttk.Frame(global_box)
        g1.pack(fill="x", pady=4)
        ttk.Label(g1, text="网络访问：").pack(side="left")
        ttk.Checkbutton(g1, text="允许 IPv4", variable=self.allow_ipv4).pack(side="left", padx=8)
        ttk.Checkbutton(g1, text="允许 IPv6", variable=self.allow_ipv6).pack(side="left", padx=8)

        g2 = ttk.Frame(global_box)
        g2.pack(fill="x", pady=4)
        ttk.Label(g2, text="游客模式：").pack(side="left")
        ttk.Combobox(
            g2,
            textvariable=self.guest_mode_var,
            state="readonly",
            width=14,
            values=["debug", "browse_only", "disabled"],
        ).pack(side="left", padx=8)
        ttk.Label(g2, text="debug=高风险全权限，browse_only=仅浏览，disabled=禁止游客", foreground="#666").pack(side="left")

        body = ttk.Panedwindow(frm, orient="horizontal")
        body.pack(fill="both", expand=True, pady=(10, 0))

        left = ttk.Labelframe(body, text="账户列表")
        right = ttk.Labelframe(body, text="账户详情")
        body.add(left, weight=3)
        body.add(right, weight=5)

        topbar = ttk.Frame(left)
        topbar.pack(fill="x", pady=(2, 6))
        ttk.Label(topbar, text="搜索：").pack(side="left")
        ent = ttk.Entry(topbar, textvariable=self.account_search)
        ent.pack(side="left", fill="x", expand=True, padx=6)
        ent.bind("<KeyRelease>", lambda e: self.refresh_account_list())

        btnbar = ttk.Frame(left)
        btnbar.pack(fill="x", pady=(0, 6))
        ttk.Button(btnbar, text="新增管理员", command=lambda: self.create_account("admin")).pack(side="left")
        ttk.Button(btnbar, text="新增普通账户", command=lambda: self.create_account("user")).pack(side="left", padx=6)
        ttk.Button(btnbar, text="删除账户", command=self.delete_selected_account).pack(side="right")

        cols = ("role", "username", "perm")
        self.acc_tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        for c, text, w in [("role", "角色", 90), ("username", "用户名", 160), ("perm", "权限摘要", 260)]:
            self.acc_tree.heading(c, text=text)
            self.acc_tree.column(c, width=w, anchor="w")
        self.acc_tree.pack(fill="both", expand=True)
        self.acc_tree.bind("<<TreeviewSelect>>", self.on_select_account)

        form = ttk.Frame(right)
        form.pack(fill="x")
        ttk.Label(form, text="角色：").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Label(form, textvariable=self.acc_role_var).grid(row=0, column=1, sticky="w")
        ttk.Label(form, text="用户名：").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.acc_name_var, width=28).grid(row=1, column=1, sticky="w")
        ttk.Label(form, text="密码：").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.acc_pass_var, width=28, show="*").grid(row=2, column=1, sticky="w")

        perm_box = ttk.Labelframe(right, text="权限")
        perm_box.pack(fill="x", pady=(8, 4))
        self.perm_widgets = [
            ttk.Checkbutton(perm_box, text="浏览目录", variable=self.acc_perm_browse),
            ttk.Checkbutton(perm_box, text="查看文件", variable=self.acc_perm_view),
            ttk.Checkbutton(perm_box, text="下载文件", variable=self.acc_perm_download),
            ttk.Checkbutton(perm_box, text="上传文件", variable=self.acc_perm_upload),
            ttk.Checkbutton(perm_box, text="删除文件", variable=self.acc_perm_delete),
        ]
        for i, w in enumerate(self.perm_widgets):
            w.grid(row=0, column=i, padx=6, pady=6, sticky="w")

        actbar = ttk.Frame(right)
        actbar.pack(fill="x", pady=(2, 8))
        ttk.Button(actbar, text="保存修改", command=self.save_account_detail).pack(side="left")
        ttk.Button(actbar, text="重置", command=self.clear_account_detail).pack(side="left", padx=6)
        ttk.Button(actbar, text="删除该账户", command=self.delete_selected_account).pack(side="right")

        recbox = ttk.Labelframe(right, text="该账户访问记录")
        recbox.pack(fill="both", expand=True)
        self.acc_log_tree = ttk.Treeview(recbox, columns=("time", "ip", "action", "path", "status"), show="headings", height=12)
        for c, text, w in [("time", "时间", 150), ("ip", "IP", 120), ("action", "动作", 90), ("path", "路径", 250), ("status", "状态", 70)]:
            self.acc_log_tree.heading(c, text=text)
            self.acc_log_tree.column(c, width=w, anchor="w")
        self.acc_log_tree.pack(fill="both", expand=True)

    def _build_logs_tab(self):
        frm = ttk.Frame(self.tab_logs)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        fbar = ttk.Frame(frm)
        fbar.pack(fill="x")
        ttk.Label(fbar, text="快速筛选：").pack(side="left")
        for name, val in [("全部", "ALL"), ("查看", "VIEW"), ("下载", "DOWNLOAD"), ("上传", "UPLOAD"), ("删除", "DELETE"), ("错误", "ERROR"), ("列表", "LIST")]:
            ttk.Button(fbar, text=name, command=lambda v=val: self.set_action_filter(v)).pack(side="left", padx=4)

        ttk.Separator(fbar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Label(fbar, text="关键字(IP/用户/路径)：").pack(side="left")
        ent = ttk.Entry(fbar, textvariable=self.filter_text, width=40)
        ent.pack(side="left", padx=6)
        ent.bind("<KeyRelease>", lambda e: self.rebuild_tree())
        ttk.Checkbutton(fbar, text="自动滚动", variable=self.autoscroll).pack(side="left", padx=10)
        ttk.Button(fbar, text="清空所有日志", command=self.clear_all_logs).pack(side="right")
        ttk.Button(fbar, text="备份日志到目录…", command=self.backup_logs).pack(side="right", padx=8)
        ttk.Button(fbar, text="导出日志…", command=self.export_log).pack(side="right", padx=8)
        ttk.Button(fbar, text="清空视图", command=self.clear_view).pack(side="right", padx=8)

        self.stats_var = tk.StringVar(value="统计：0 条")
        ttk.Label(frm, textvariable=self.stats_var).pack(anchor="w", pady=(8, 6))

        columns = ("time", "ip", "user", "action", "path", "status", "detail")
        self.tree = ttk.Treeview(frm, columns=columns, show="headings", height=18)
        for c, w, title in [
            ("time", 140, "TIME"), ("ip", 120, "IP"), ("user", 160, "USER"),
            ("action", 90, "ACTION"), ("path", 280, "PATH"), ("status", 70, "STATUS"), ("detail", 220, "DETAIL")
        ]:
            self.tree.heading(c, text=title)
            self.tree.column(c, width=w, anchor="w")

        vsb = ttk.Scrollbar(frm, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def _load_config(self):
        if CFG_FILE.exists():
            try:
                data = json.loads(CFG_FILE.read_text(encoding="utf-8"))
                self.root_var.set(data.get("root_dir", str(Path.home())))
                self.port_var.set(str(data.get("port", 8000)))
                self.allow_ipv4.set(data.get("allow_ipv4", True))
                self.allow_ipv6.set(data.get("allow_ipv6", False))
                self.guest_mode_var.set(data.get("guest_mode", "browse_only"))
                self.admin_accounts = data.get("admins", [{"username": "admin", "password": "admin"}])
                self.user_accounts = data.get("users", [])
                if not self.admin_accounts:
                    self.admin_accounts = [{"username": "admin", "password": "admin"}]
                self.admin_accounts = data.get("admins", [{"username":"admin","password":"admin"}])
                self.user_accounts = data.get("users", [])
                return
            except Exception:
                pass
        self.root_var.set(str(Path.home()))
        self.admin_accounts = [{"username": "admin", "password": "admin"}]
        self.admin_accounts = [{"username":"admin","password":"admin"}]
        self.user_accounts = []

    def _save_config(self):
        data = {
            "root_dir": self.root_var.get().strip(),
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
                    if "user" not in row:
                        row["user"] = "-"
                    self.log_rows.append(row)
                except Exception:
                    continue
            self.rebuild_tree()
        except Exception:
            pass

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
            os.startfile(p)
        except Exception:
            pass

    def _build_host(self) -> str:
        if not self.allow_ipv4.get() and not self.allow_ipv6.get():
            raise ValueError("IPv4 和 IPv6 不能同时禁用。")
        if self.allow_ipv6.get():
            return "::"
        return "0.0.0.0"

    def start_server(self):
        root_dir = self.root_var.get().strip()
        if not self.allow_ipv4.get() and not self.allow_ipv6.get():
            messagebox.showerror("启动失败", "IPv4 和 IPv6 不能同时禁用。")
            return
        host = "::" if self.allow_ipv6.get() and not self.allow_ipv4.get() else "0.0.0.0"
        if self.allow_ipv4.get() and self.allow_ipv6.get():
            host = "::"
        try:
            host = self._build_host()
            port = int(self.port_var.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError("端口必须是 1~65535")
        except ValueError as e:
            messagebox.showerror("启动失败", str(e))
            return

        if not root_dir or not Path(root_dir).exists():
            messagebox.showerror("启动失败", "请选择有效的共享文件夹。")
            return

        ok, err = check_port_free(host, port)
        if not ok:
            messagebox.showerror("启动失败", f"端口无法绑定：\n{err}")
            return

        self._save_config()
        webapp.set_auth_config({"admins": self.admin_accounts, "users": self.user_accounts, "guest_mode": self.guest_mode_var.get()})

        webapp.set_auth_config({
            "admins": self.admin_accounts,
            "users": self.user_accounts,
            "guest_mode": self.guest_mode_var.get(),
        })
        # 启动
        self.ctrl.start(root_dir=root_dir, host=host, port=port, log_file=str(LOG_FILE))

        self._refresh_status_ui()
        show_host = self.lan_ip if host == "0.0.0.0" else "[::1]" if host == "::" else host
        self.url_var.set(f"http://{show_host}:{port}")
        self.local_url_var.set(f"http://127.0.0.1:{port}")

    def stop_server(self):
        self.ctrl.stop()
        self._refresh_status_ui()

    def copy_url(self):
        url = self.url_var.get().strip()
        if url:
            self.clipboard_clear()
            self.clipboard_append(url)

    def open_browser(self):
        import webbrowser
        url = self.local_url_var.get().strip() or self.url_var.get().strip()
        if url:
            webbrowser.open(url, new=2)

    def _perm_summary(self, role: str, perms: dict | None = None) -> str:
        if role == "admin":
            return "全权限"
        if not perms:
            return "-"
        return "/".join([k for k, v in perms.items() if v]) or "无"

    def get_all_accounts(self) -> list[dict]:
        rows: list[dict] = []
        for a in self.admin_accounts:
            rows.append({"role": "admin", "username": a.get("username", ""), "password": a.get("password", ""), "permissions": {"browse": True, "view": True, "download": True, "upload": True, "delete": True}})
        for u in self.user_accounts:
            rows.append({"role": "user", "username": u.get("username", ""), "password": u.get("password", ""), "permissions": u.get("permissions", self.default_user_permissions())})
        return rows

    def refresh_account_list(self):
        for iid in self.acc_tree.get_children():
            self.acc_tree.delete(iid)
        kw = self.account_search.get().strip().lower()
        for row in self.get_all_accounts():
            if kw and kw not in row["username"].lower():
                continue
            rid = f"{row['role']}::{row['username']}"
            self.acc_tree.insert("", "end", iid=rid, values=("管理员" if row["role"] == "admin" else "普通", row["username"], self._perm_summary(row["role"], row.get("permissions"))))

    def on_select_account(self, _event=None):
        sels = self.acc_tree.selection()
        if not sels:
            return
        role, username = sels[0].split("::", 1)
        self.selected_account_key = (role, username)
        if role == "admin":
            src = next((a for a in self.admin_accounts if a.get("username") == username), None)
            perms = {"browse": True, "view": True, "download": True, "upload": True, "delete": True}
        else:
            src = next((u for u in self.user_accounts if u.get("username") == username), None)
            perms = (src or {}).get("permissions", self.default_user_permissions())
        if not src:
            return
        self.acc_role_var.set("管理员" if role == "admin" else "普通账户")
        self.acc_name_var.set(src.get("username", ""))
        self.acc_pass_var.set(src.get("password", ""))
        self.acc_perm_browse.set(perms.get("browse", True))
        self.acc_perm_view.set(perms.get("view", True))
        self.acc_perm_download.set(perms.get("download", False))
        self.acc_perm_upload.set(perms.get("upload", False))
        self.acc_perm_delete.set(perms.get("delete", False))

        state = ["disabled"] if role == "admin" else ["!disabled"]
        for w in self.perm_widgets:
            w.state(state)
        if role == "admin":
            self.acc_name_var.set(username)
        self.refresh_account_logs()

    def default_user_permissions(self):
        return {"browse": True, "view": True, "download": False, "upload": False, "delete": False}

    def create_account(self, role: str):
        self.selected_account_key = None
        self.acc_role_var.set("管理员" if role == "admin" else "普通账户")
        self.acc_name_var.set("")
        self.acc_pass_var.set("")
        perms = {"browse": True, "view": True, "download": role == "admin", "upload": role == "admin", "delete": role == "admin"}
        self.acc_perm_browse.set(perms["browse"])
        self.acc_perm_view.set(perms["view"])
        self.acc_perm_download.set(perms["download"])
        self.acc_perm_upload.set(perms["upload"])
        self.acc_perm_delete.set(perms["delete"])
        for w in self.perm_widgets:
            w.state(["disabled"] if role == "admin" else ["!disabled"])

    def save_account_detail(self):
        role = "admin" if self.acc_role_var.get().startswith("管理员") else "user"
        username = self.acc_name_var.get().strip()
        password = self.acc_pass_var.get().strip()
        if not username or not password:
            messagebox.showerror("保存失败", "用户名和密码不能为空。")
            return

        old_role = self.selected_account_key[0] if self.selected_account_key else role
        old_name = self.selected_account_key[1] if self.selected_account_key else username

        self.admin_accounts = [a for a in self.admin_accounts if not (old_role == "admin" and a.get("username") == old_name)]
        self.user_accounts = [u for u in self.user_accounts if not (old_role == "user" and u.get("username") == old_name)]

        if role == "admin":
            self.admin_accounts.append({"username": username, "password": password})
        else:
            perms = {
                "browse": self.acc_perm_browse.get(),
                "view": self.acc_perm_view.get(),
                "download": self.acc_perm_download.get(),
                "upload": self.acc_perm_upload.get(),
                "delete": self.acc_perm_delete.get(),
            }
            self.user_accounts.append({"username": username, "password": password, "permissions": perms})

        self.selected_account_key = (role, username)
        self.refresh_account_list()
        if role == "admin" and len(self.admin_accounts) == 0:
            self.admin_accounts.append({"username": "admin", "password": "admin"})
        self._save_config()
        messagebox.showinfo("已保存", "账户信息已更新。")

    def clear_account_detail(self):
        self.selected_account_key = None
        self.acc_role_var.set("")
        self.acc_name_var.set("")
        self.acc_pass_var.set("")
        for var, val in [
            (self.acc_perm_browse, True), (self.acc_perm_view, True), (self.acc_perm_download, False),
            (self.acc_perm_upload, False), (self.acc_perm_delete, False)
        ]:
            var.set(val)
        for w in self.perm_widgets:
            w.state(["!disabled"])
        self.refresh_account_logs()

    def delete_selected_account(self):
        if not self.selected_account_key:
            messagebox.showwarning("提示", "请先选择一个账户。")
            return
        role, username = self.selected_account_key
        if role == "admin" and len(self.admin_accounts) <= 1:
            messagebox.showerror("删除失败", "至少保留一个管理员账户。")
            return
        if not messagebox.askyesno("确认", f"确定删除账户 {username} 吗？"):
            return
        if role == "admin":
            self.admin_accounts = [a for a in self.admin_accounts if a.get("username") != username]
        else:
            self.user_accounts = [u for u in self.user_accounts if u.get("username") != username]
        self.clear_account_detail()
        self.refresh_account_list()
        self._save_config()

    def refresh_account_logs(self):
        for iid in self.acc_log_tree.get_children():
            self.acc_log_tree.delete(iid)
        if not self.selected_account_key:
            return
        role, username = self.selected_account_key
        marker = f"{username}({role})"
        rows = [r for r in self.log_rows if (r.get("user") or "") == marker]
        for row in rows[-300:]:
            ts = row.get("ts") or time.time()
            tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            self.acc_log_tree.insert("", "end", values=(tstr, row.get("ip", "-"), row.get("action", "-"), row.get("path", "-"), str(row.get("status", ""))))

    def set_action_filter(self, v: str):
        self.filter_action.set(v)
        self.rebuild_tree()

    def _match_filter(self, row: dict) -> bool:
        act = self.filter_action.get()
        row_act = (row.get("action") or "").upper()
        if act != "ALL" and row_act != act:
            return False

        kw = self.filter_text.get().strip().lower()
        if kw:
            ip = (row.get("ip") or "").lower()
            user = (row.get("user") or "").lower()
            path = (row.get("path") or "").lower()
            detail = (row.get("detail") or "").lower()
            if kw not in ip and kw not in user and kw not in path and kw not in detail:
                return False
        return True

    def rebuild_tree(self):
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
            row.get("user", "-"),
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
        line = f"[{tstr}] {row.get('ip','-')} {row.get('user','-')} {row.get('action','-')} {row.get('path','-')} {row.get('status','')}\n"
        self.tail_text.configure(state="normal")
        self.tail_text.insert("end", line)
        if int(self.tail_text.index("end-1c").split(".")[0]) > 300:
            self.tail_text.delete("1.0", "50.0")
        self.tail_text.see("end")
        self.tail_text.configure(state="disabled")

    def clear_view(self):
        self.log_rows.clear()
        self.rebuild_tree()
        self.refresh_account_logs()
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

    def backup_logs(self):
        target_dir = filedialog.askdirectory(initialdir=str(CFG_DIR), title="选择日志备份目录")
        if not target_dir:
            return

        target = Path(target_dir)
        target.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        out = target / f"webfs_access_backup_{stamp}.log"

        try:
            if LOG_FILE.exists():
                out.write_text(LOG_FILE.read_text(encoding="utf-8"), encoding="utf-8")
            else:
                with out.open("w", encoding="utf-8") as f:
                    for row in self.log_rows:
                        f.write(json.dumps(row, ensure_ascii=False) + "\n")
            messagebox.showinfo("备份成功", f"日志已备份到：\n{out}")
        except Exception as e:
            messagebox.showerror("备份失败", str(e))

    def clear_all_logs(self):
        if not messagebox.askyesno("确认清空", "将清空内存与磁盘中的全部访问日志，是否继续？"):
            return

        self.log_rows.clear()
        self.rebuild_tree()
        self.refresh_account_logs()

        self.tail_text.configure(state="normal")
        self.tail_text.delete("1.0", "end")
        self.tail_text.configure(state="disabled")

        try:
            LOG_FILE.write_text("", encoding="utf-8")
        except Exception:
            pass

        try:
            logs = getattr(webapp.app.state, "logs", None)
            if logs is not None:
                logs.clear()
        except Exception:
            pass

        try:
            q = getattr(webapp.app.state, "log_queue", None)
            if q:
                while True:
                    q.get_nowait()
        except queue.Empty:
            pass
        except Exception:
            pass

        self._update_stats()
        messagebox.showinfo("完成", "已清空全部日志记录。")

    def _update_stats(self, scroll_to_end: bool = False):
        filtered = [r for r in self.log_rows if self._match_filter(r)]
        ips = {r.get("ip") for r in filtered if r.get("ip")}
        users = {r.get("user") for r in filtered if r.get("user") and r.get("user") != "-"}
        counts = {"LIST": 0, "VIEW": 0, "DOWNLOAD": 0, "UPLOAD": 0, "DELETE": 0, "ERROR": 0}
        for r in filtered:
            a = (r.get("action") or "").upper()
            if a in counts:
                counts[a] += 1
        self.stats_var.set(
            f"统计（当前筛选）：{len(filtered)} 条 · 唯一IP {len(ips)} · 账号 {len(users)} · "
            f"LIST {counts['LIST']} / VIEW {counts['VIEW']} / DOWNLOAD {counts['DOWNLOAD']} / "
            f"UPLOAD {counts['UPLOAD']} / DELETE {counts['DELETE']} / ERROR {counts['ERROR']}"
        )
        if scroll_to_end and self.autoscroll.get():
            children = self.tree.get_children()
            if children:
                self.tree.see(children[-1])

    def _refresh_status_ui(self):
        running = self.ctrl.running()
        if running:
            self.status_var.set("运行中")
            self.canvas.itemconfig(self.dot, fill="#32d074")
            self.btn_start.state(["disabled"])
            self.btn_stop.state(["!disabled"])
        else:
            self.status_var.set("已停止")
            self.canvas.itemconfig(self.dot, fill="#999999")
            self.btn_start.state(["!disabled"])
            self.btn_stop.state(["disabled"])

    def _poll_queues(self):
        try:
            err = self.ctrl.error_queue.get_nowait()
            messagebox.showerror("服务器异常退出", err)
            self.ctrl.stop()
            self._refresh_status_ui()
        except queue.Empty:
            pass

        try:
            q = getattr(webapp.app.state, "log_queue", None)
            if q:
                while True:
                    row = q.get_nowait()
                    if "user" not in row:
                        row["user"] = "-"
                    self.log_rows.append(row)
                    self._append_tail(row)
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
        self.refresh_account_logs()
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
