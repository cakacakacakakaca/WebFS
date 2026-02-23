from __future__ import annotations

import hashlib
import mimetypes
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional, Tuple

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".avif"}
VIDEO_EXTS = {".mp4", ".webm", ".ogv", ".mov", ".m4v"}

CACHE_DIR_NAME = ".webfs_cache"
THUMBS_DIR_NAME = "thumbs"


@dataclass(frozen=True)
class DirEntryView:
    name: str
    rel_path: str
    is_dir: bool
    size: int
    mtime: float
    kind: str  # "dir" | "image" | "video" | "file"

    @property
    def mtime_str(self) -> str:
        return datetime.fromtimestamp(self.mtime).strftime("%Y-%m-%d %H:%M")

    @property
    def size_str(self) -> str:
        return human_size(self.size)


def human_size(n: int) -> str:
    # 1024-based
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for u in units:
        if x < 1024.0 or u == units[-1]:
            return f"{x:.0f}{u}" if u == "B" else f"{x:.1f}{u}"
        x /= 1024.0
    return f"{n}B"


def is_image(p: Path) -> bool:
    return p.suffix.lower() in IMAGE_EXTS


def is_video(p: Path) -> bool:
    return p.suffix.lower() in VIDEO_EXTS


def guess_mime(p: Path) -> str:
    mt, _ = mimetypes.guess_type(str(p))
    return mt or "application/octet-stream"


def safe_resolve(root: Path, rel: str) -> Path:
    """
    防止 .. 路径穿越：最终必须落在 root 目录内
    """
    root = root.resolve()
    target = (root / rel).resolve()
    if root == target or root in target.parents:
        return target
    raise ValueError("Invalid path")


def list_dir(root: Path, rel_dir: str) -> Tuple[list[DirEntryView], dict]:
    """
    返回目录条目 + 统计信息（用于判断图片模式）
    """
    d = safe_resolve(root, rel_dir)
    if not d.exists() or not d.is_dir():
        raise FileNotFoundError(rel_dir)

    entries: list[DirEntryView] = []
    total_files = 0
    image_files = 0

    for p in sorted(d.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        # 不展示缓存目录
        if p.name == CACHE_DIR_NAME:
            continue

        st = p.stat()
        isdir = p.is_dir()
        kind = "dir" if isdir else ("image" if is_image(p) else ("video" if is_video(p) else "file"))
        size = 0 if isdir else st.st_size

        if not isdir:
            total_files += 1
            if kind == "image":
                image_files += 1

        rel_path = str(Path(rel_dir) / p.name).replace("\\", "/")
        entries.append(
            DirEntryView(
                name=p.name,
                rel_path=rel_path,
                is_dir=isdir,
                size=size,
                mtime=st.st_mtime,
                kind=kind,
            )
        )

    stats = {
        "total_files": total_files,
        "image_files": image_files,
        "image_ratio": (image_files / total_files) if total_files else 0.0,
    }
    return entries, stats


def image_list_in_folder(root: Path, rel_file: str) -> Tuple[str, list[str], int]:
    """
    给定某个图片文件路径，返回：
    - folder_rel
    - 该文件夹内图片相对路径列表（按文件名排序）
    - 当前文件 index
    """
    fp = safe_resolve(root, rel_file)
    if not fp.exists() or not fp.is_file() or not is_image(fp):
        raise FileNotFoundError(rel_file)

    folder = fp.parent
    folder_rel = str(Path(rel_file).parent).replace("\\", "/")
    imgs = []
    for p in sorted(folder.iterdir(), key=lambda x: x.name.lower()):
        if p.is_file() and is_image(p):
            imgs.append(str(Path(folder_rel) / p.name).replace("\\", "/"))

    cur = str(Path(rel_file)).replace("\\", "/")
    idx = imgs.index(cur) if cur in imgs else 0
    return folder_rel, imgs, idx


def thumb_path(root: Path, rel_img: str, w: int, h: int) -> Path:
    """
    缩略图缓存位置：root/.webfs_cache/thumbs/<hash>_<w>x<h>.jpg
    用 mtime + size 做 hash 以便图片更新后自动失效
    """
    p = safe_resolve(root, rel_img)
    st = p.stat()
    key = f"{rel_img}|{st.st_mtime_ns}|{st.st_size}|{w}x{h}"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()
    cache_root = root / CACHE_DIR_NAME / THUMBS_DIR_NAME
    cache_root.mkdir(parents=True, exist_ok=True)
    return cache_root / f"{digest}_{w}x{h}.jpg"