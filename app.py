from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    FileResponse,
    StreamingResponse,
    JSONResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from urllib.parse import quote
from uuid import uuid4

from utils import (
    list_dir,
    safe_resolve,
    is_image,
    is_video,
    guess_mime,
    image_list_in_folder,
    thumb_path,
)

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Web File Server (Windows)")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ------------------------
# Runtime options + Logging
# ------------------------

@dataclass
class AccessLog:
    ts: float
    ip: str
    user: str
    action: str          # LIST / VIEW / DOWNLOAD / UPLOAD / DELETE / ERROR / THUMB
    path: str            # rel path or url path
    status: int
    detail: str = ""

    @property
    def time_str(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))


def _ensure_log_store():
    if not hasattr(app.state, "logs"):
        app.state.logs = deque(maxlen=20000)  # in-memory
    if not hasattr(app.state, "log_lock"):
        app.state.log_lock = threading.Lock()
    if not hasattr(app.state, "log_queue"):
        # GUI 轮询用
        import queue
        app.state.log_queue = queue.Queue()
    if not hasattr(app.state, "log_file"):
        app.state.log_file = None  # Path or None


def log_access(ip: str, action: str, path: str, status: int = 200, detail: str = "", user: str = "-"):
    _ensure_log_store()
    entry = AccessLog(ts=time.time(), ip=ip, user=user, action=action, path=path, status=status, detail=detail)

    with app.state.log_lock:
        app.state.logs.append(entry)

    # 推给 GUI
    try:
        app.state.log_queue.put_nowait(asdict(entry))
    except Exception:
        pass

    # 落盘（JSONL）
    lf: Optional[Path] = app.state.log_file
    if lf:
        try:
            lf.parent.mkdir(parents=True, exist_ok=True)
            with lf.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        except Exception:
            pass


def set_runtime(root_dir: str, log_file: Optional[str] = None) -> None:
    app.state.root_dir = Path(root_dir).resolve()
    _ensure_log_store()
    app.state.log_file = Path(log_file).resolve() if log_file else None
    if not hasattr(app.state, "auth_config"):
        set_auth_config(default_auth_config())


def default_auth_config() -> dict:
    return {
        "admins": [{"username": "admin", "password": "admin"}],
        "users": [],
        "guest_mode": "browse_only",  # debug / browse_only / disabled
    }


def set_auth_config(auth_config: Optional[dict] = None) -> None:
    app.state.auth_config = auth_config or default_auth_config()
    if not hasattr(app.state, "sessions"):
        app.state.sessions = {}


def get_auth_config() -> dict:
    cfg = getattr(app.state, "auth_config", None)
    if not cfg:
        cfg = default_auth_config()
        app.state.auth_config = cfg
    return cfg


def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get("webfs_token")
    if not token:
        return None
    sessions = getattr(app.state, "sessions", {})
    user = sessions.get(token)
    return user


def get_request_user_label(request: Request) -> str:
    user = get_current_user(request)
    if not user:
        return "-"
    return f"{user.get('username', '-') }({user.get('role', '-')})"


def build_permissions(role: str, user: Optional[dict] = None, cfg: Optional[dict] = None) -> dict:
    if role == "admin":
        return {"browse": True, "view": True, "download": True, "upload": True, "delete": True}
    if role == "user" and user:
        return user.get("permissions") or {"browse": True, "view": True, "download": False, "upload": False, "delete": False}
    cfg = cfg or get_auth_config()
    gm = cfg.get("guest_mode", "browse_only")
    if gm == "debug":
        return {"browse": True, "view": True, "download": True, "upload": True, "delete": True}
    if gm == "browse_only":
        return {"browse": True, "view": True, "download": False, "upload": False, "delete": False}
    return {"browse": False, "view": False, "download": False, "upload": False, "delete": False}


def require_permission(request: Request, perm: str):
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Please login")
    if not user.get("permissions", {}).get(perm, False):
        raise HTTPException(403, "Permission denied")


def page_ctx(request: Request) -> dict:
    return {
        "request": request,
        "user": get_current_user(request),
        "auth": get_auth_config(),
    }


def get_root_dir() -> Path:
    root = getattr(app.state, "root_dir", None)
    if not root:
        root = BASE_DIR
        app.state.root_dir = root
    return root


# -------------- Jinja helpers --------------

def url_path(p: str) -> str:
    parts = [quote(x) for x in p.split("/") if x != ""]
    return "/".join(parts)

templates.env.filters["url_path"] = url_path


# -------------------- Error handlers (log errors) --------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    ip = request.client.host if request.client else "-"
    log_access(ip, "ERROR", request.url.path, status=exc.status_code, detail=str(exc.detail), user=get_request_user_label(request))
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    ip = request.client.host if request.client else "-"
    log_access(ip, "ERROR", request.url.path, status=422, detail="ValidationError", user=get_request_user_label(request))
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})


# -------------------- Routes --------------------

@app.get("/", response_class=HTMLResponse)
def home():
    return RedirectResponse(url="/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/browse/")
    cfg = get_auth_config()
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "allow_guest": cfg.get("guest_mode", "browse_only") != "disabled",
            "guest_mode": cfg.get("guest_mode", "browse_only"),
            "error": request.query_params.get("error", ""),
        },
    )


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    cfg = get_auth_config()
    account = None
    role = ""
    for a in cfg.get("admins", []):
        if a.get("username") == username and a.get("password") == password:
            account = a
            role = "admin"
            break
    if not account:
        for u in cfg.get("users", []):
            if u.get("username") == username and u.get("password") == password:
                account = u
                role = "user"
                break
    if not account:
        return RedirectResponse(url="/login?error=账号或密码错误", status_code=303)

    token = uuid4().hex
    if not hasattr(app.state, "sessions"):
        app.state.sessions = {}
    if not hasattr(app.state, "sessions"):
        app.state.sessions = {}
    app.state.sessions[token] = {
        "username": account.get("username", username),
        "role": role,
        "permissions": build_permissions(role, account, cfg),
    }
    resp = RedirectResponse(url="/browse/", status_code=303)
    resp.set_cookie("webfs_token", token, httponly=True, samesite="lax")
    return resp


@app.get("/guest-enter")
def guest_enter():
    cfg = get_auth_config()
    if cfg.get("guest_mode", "browse_only") == "disabled":
        return RedirectResponse(url="/login?error=游客访问已禁用", status_code=303)
    token = uuid4().hex
    app.state.sessions[token] = {
        "username": "guest",
        "role": "guest",
        "permissions": build_permissions("guest", None, cfg),
    }
    resp = RedirectResponse(url="/browse/", status_code=303)
    resp.set_cookie("webfs_token", token, httponly=True, samesite="lax")
    return resp


@app.get("/logout")
def logout(request: Request):
    token = request.cookies.get("webfs_token")
    if token:
        app.state.sessions.pop(token, None)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("webfs_token")
    return resp


@app.get("/browse/", response_class=HTMLResponse)
@app.get("/browse/{rel_path:path}", response_class=HTMLResponse)
def browse(request: Request, rel_path: str = ""):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if not user.get("permissions", {}).get("browse", False):
        raise HTTPException(403, "Permission denied")
    root = get_root_dir()
    rel_path = rel_path.strip("/")

    # 文件则跳转到 open
    try:
        abs_path = safe_resolve(root, rel_path)
    except ValueError:
        raise HTTPException(400, "Invalid path")

    if abs_path.exists() and abs_path.is_file():
        return RedirectResponse(url=f"/open/{url_path(rel_path)}")

    # 目录
    try:
        entries, stats = list_dir(root, rel_path)
    except FileNotFoundError:
        raise HTTPException(404, "Not found")

    # 记录：LIST
    ip = request.client.host if request.client else "-"
    log_access(ip, "LIST", "/" + rel_path if rel_path else "/", user=get_request_user_label(request))

    image_mode = (stats["image_files"] >= 6) and (stats["image_ratio"] >= 0.6)

    crumbs = []
    if rel_path:
        parts = rel_path.split("/")
        for i in range(len(parts)):
            sub = "/".join(parts[: i + 1])
            crumbs.append({"name": parts[i], "rel": sub})

    return templates.TemplateResponse(
        "browse.html",
        {
            **page_ctx(request),
            "rel_path": rel_path,
            "entries": entries,
            "stats": stats,
            "image_mode": image_mode,
            "crumbs": crumbs,
            "root_name": str(root),
            "can_upload": user.get("permissions", {}).get("upload", False),
            "can_download": user.get("permissions", {}).get("download", False),
            "can_delete": user.get("permissions", {}).get("delete", False),
        },
    )


@app.get("/open/{rel_path:path}", response_class=HTMLResponse)
def open_file(request: Request, rel_path: str):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if not user.get("permissions", {}).get("view", False):
        raise HTTPException(403, "Permission denied")
    root = get_root_dir()
    rel_path = rel_path.strip("/")

    try:
        p = safe_resolve(root, rel_path)
    except ValueError:
        raise HTTPException(400, "Invalid path")

    if not p.exists() or not p.is_file():
        raise HTTPException(404, "Not found")

    ip = request.client.host if request.client else "-"
    log_access(ip, "VIEW", "/" + rel_path, user=get_request_user_label(request))

    if is_image(p):
        folder_rel, imgs, idx = image_list_in_folder(root, rel_path)
        return templates.TemplateResponse(
            "image_view.html",
            {
                **page_ctx(request),
                "rel_path": rel_path,
                "folder_rel": folder_rel,
                "images": imgs,
                "index": idx,
                "filename": p.name,
                "can_download": user.get("permissions", {}).get("download", False),
            },
        )

    if is_video(p):
        return templates.TemplateResponse(
            "video_view.html",
            {
                **page_ctx(request),
                "rel_path": rel_path,
                "filename": p.name,
                "mime": guess_mime(p),
                "can_download": user.get("permissions", {}).get("download", False),
            },
        )

    return templates.TemplateResponse(
        "file_view.html",
        {
            **page_ctx(request),
            "rel_path": rel_path,
            "filename": p.name,
            "mime": guess_mime(p),
            "size": p.stat().st_size,
            "can_download": user.get("permissions", {}).get("download", False),
        },
    )


def parse_range(range_header: str, file_size: int) -> Optional[tuple[int, int]]:
    if not range_header or not range_header.startswith("bytes="):
        return None
    spec = range_header.replace("bytes=", "").strip()
    if "," in spec:
        spec = spec.split(",")[0].strip()
    if "-" not in spec:
        return None

    a, b = spec.split("-", 1)
    a = a.strip()
    b = b.strip()

    if a == "" and b == "":
        return None

    if a == "":
        suffix = int(b)
        if suffix <= 0:
            return None
        start = max(0, file_size - suffix)
        end = file_size - 1
        return start, end

    start = int(a)
    if start >= file_size:
        return None

    end = file_size - 1 if b == "" else min(int(b), file_size - 1)
    if end < start:
        return None
    return start, end


@app.get("/raw/{rel_path:path}")
def raw(request: Request, rel_path: str, download: int = 0):
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Please login")
    need_perm = "download" if download else "view"
    if not user.get("permissions", {}).get(need_perm, False):
        raise HTTPException(403, "Permission denied")
    root = get_root_dir()
    rel_path = rel_path.strip("/")

    try:
        p = safe_resolve(root, rel_path)
    except ValueError:
        raise HTTPException(400, "Invalid path")

    if not p.exists() or not p.is_file():
        raise HTTPException(404, "Not found")

    ip = request.client.host if request.client else "-"
    action = "DOWNLOAD" if download else "VIEW"
    log_access(ip, action, "/" + rel_path, user=get_request_user_label(request))

    file_size = p.stat().st_size
    range_header = request.headers.get("range")
    mime = guess_mime(p)

    headers = {"Accept-Ranges": "bytes"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{p.name}"'

    r = parse_range(range_header, file_size) if range_header else None
    if not r:
        return FileResponse(path=str(p), media_type=mime, headers=headers, filename=p.name if download else None)

    start, end = r
    length = end - start + 1

    def iterfile():
        with open(p, "rb") as f:
            f.seek(start)
            remaining = length
            chunk = 1024 * 256
            while remaining > 0:
                data = f.read(min(chunk, remaining))
                if not data:
                    break
                remaining -= len(data)
                yield data

    headers.update(
        {
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Content-Length": str(length),
        }
    )
    return StreamingResponse(iterfile(), status_code=206, media_type=mime, headers=headers)


@app.get("/thumb/{rel_path:path}")
def thumb(request: Request, rel_path: str, w: int = 360, h: int = 360):
    root = get_root_dir()
    rel_path = rel_path.strip("/")

    try:
        p = safe_resolve(root, rel_path)
    except ValueError:
        raise HTTPException(400, "Invalid path")

    if not p.exists() or not p.is_file() or not is_image(p):
        raise HTTPException(404, "Not found")

    # 缩略图一般不记入你关心的“查看/下载/上传”，但你要的话也可记 THUMB
    # ip = request.client.host if request.client else "-"
    # log_access(ip, "THUMB", "/" + rel_path)

    try:
        from PIL import Image
    except Exception:
        return FileResponse(str(p), media_type=guess_mime(p))

    w = max(64, min(int(w), 1024))
    h = max(64, min(int(h), 1024))

    out = thumb_path(root, rel_path, w, h)
    if out.exists():
        return FileResponse(str(out), media_type="image/jpeg")

    try:
        with Image.open(p) as im:
            im = im.convert("RGB")
            im.thumbnail((w, h))
            im.save(out, "JPEG", quality=85, optimize=True)
    except Exception:
        return FileResponse(str(p), media_type=guess_mime(p))

    return FileResponse(str(out), media_type="image/jpeg")


@app.post("/upload/{rel_dir:path}")
async def upload(request: Request, rel_dir: str, file: UploadFile = File(...)):
    """
    上传文件到指定目录（rel_dir），安全限制：只能写入共享根目录以内
    """
    require_permission(request, "upload")
    root = get_root_dir()
    rel_dir = rel_dir.strip("/")

    try:
        target_dir = safe_resolve(root, rel_dir)
    except ValueError:
        raise HTTPException(400, "Invalid path")

    if not target_dir.exists() or not target_dir.is_dir():
        raise HTTPException(404, "Target directory not found")

    filename = Path(file.filename).name  # 防止带路径
    if not filename:
        raise HTTPException(400, "Invalid filename")

    # 冲突处理：同名则追加 (1)(2)...
    out = target_dir / filename
    if out.exists():
        stem = out.stem
        suf = out.suffix
        i = 1
        while True:
            cand = target_dir / f"{stem}({i}){suf}"
            if not cand.exists():
                out = cand
                break
            i += 1

    # 写入
    data = await file.read()
    out.write_bytes(data)

    ip = request.client.host if request.client else "-"
    log_access(ip, "UPLOAD", f"/{rel_dir}/{out.name}".replace("//", "/"), status=200, detail=f"{len(data)} bytes", user=get_request_user_label(request))

    return {"ok": True, "saved_as": out.name, "bytes": len(data)}

    return {"ok": True, "saved_as": out.name, "bytes": len(data)}


@app.post("/delete/{rel_path:path}")
def delete_file(request: Request, rel_path: str):
    require_permission(request, "delete")
    root = get_root_dir()
    rel_path = rel_path.strip("/")
    try:
        p = safe_resolve(root, rel_path)
    except ValueError:
        raise HTTPException(400, "Invalid path")
    if not p.exists() or not p.is_file():
        raise HTTPException(404, "Not found")
    p.unlink()
    ip = request.client.host if request.client else "-"
    log_access(ip, "DELETE", "/" + rel_path, status=200, user=get_request_user_label(request))
    log_access(ip, "DELETE", "/" + rel_path, status=200)
    parent = rel_path.rsplit("/", 1)[0] if "/" in rel_path else ""
    return RedirectResponse(url=f"/browse/{url_path(parent)}", status_code=303)
