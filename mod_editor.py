"""Manage directory-based Mods for the game without inventing a game manifest."""

from __future__ import annotations

import csv
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tkinter as tk
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from tkinter import filedialog, messagebox, simpledialog, ttk

from gjd_editor import decode_file, parse_csv


GAME_ROOT = Path(__file__).resolve().parent
MODS_DIR = GAME_ROOT / "Mods"
DATA_DIR = GAME_ROOT / "data"
CONFIG_PATH = GAME_ROOT / "config.ini"
GJD_EDITOR = GAME_ROOT / "gjd_editor.py"
TABLE_DOC = GAME_ROOT / "数据表作用说明.md"


def safe_mod_name(value: str) -> str:
    name = value.strip()
    if (not name or name in {".", ".."} or name[-1:] in {".", " "}
            or re.search(r'[<>:"/\\|?*\x00-\x1f]', name)
            or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", name)):
        raise ValueError("名称不能为空，也不能包含 Windows 路径保留字符。")
    return name


def selected_mod(config_path: Path = CONFIG_PATH) -> str:
    if not config_path.exists():
        return ""
    raw = config_path.read_bytes()
    text = raw.decode("utf-8-sig", errors="replace")
    in_section = False
    for line in text.splitlines():
        section = re.match(r"\s*\[([^]]+)\]", line)
        if section:
            in_section = section.group(1).strip().casefold() == "modconfig"
            continue
        if in_section:
            value = re.match(r"\s*SelMod\s*=\s*(.*?)\s*(?:[;#].*)?$", line, re.IGNORECASE)
            if value:
                return value.group(1).strip()
    return ""


def set_selected_mod(value: str, config_path: Path = CONFIG_PATH) -> Path:
    text = config_path.read_text(encoding="utf-8-sig") if config_path.exists() else ""
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    in_section = False
    section_found = False
    key_found = False
    for index, line in enumerate(lines):
        section = re.match(r"\s*\[([^]]+)\]", line)
        if section:
            if in_section and not key_found:
                lines.insert(index, f"SelMod={value}{newline}")
                key_found = True
                break
            in_section = section.group(1).strip().casefold() == "modconfig"
            section_found |= in_section
            continue
        if in_section and re.match(r"\s*SelMod\s*=", line, re.IGNORECASE):
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            lines[index] = f"SelMod={value}{ending}"
            key_found = True
            break
    if in_section and not key_found:
        lines.append(f"SelMod={value}{newline}")
        key_found = True
    if not section_found:
        if text and not text.endswith(("\n", "\r")):
            lines.append(newline)
        if text and lines and lines[-1].strip():
            lines.append(newline)
        lines.extend([f"[ModConfig]{newline}", f"SelMod={value}{newline}"])
    output = "".join(lines)
    if config_path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        shutil.copy2(config_path, config_path.with_name(f"{config_path.name}.bak.{stamp}"))
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", delete=False,
                                     dir=config_path.parent, prefix=f".{config_path.name}.", suffix=".tmp") as temp:
        temp.write(output)
        temp_path = Path(temp.name)
    temp_path.replace(config_path)
    return config_path


def mod_directories(path: Path) -> tuple[Path, Path]:
    return path / "Data", path / "Res"


def mod_status(path: Path) -> str:
    data, resources = mod_directories(path)
    if data.is_dir() and resources.is_dir():
        return "可加载"
    missing = [name for name, exists in (("Data", data.is_dir()), ("Res", resources.is_dir())) if not exists]
    return "缺少 " + " / ".join(missing)


def data_summary(path: Path) -> tuple[int, int, str, str]:
    text, key = decode_file(path)
    rows = parse_csv(text)
    if rows and len(rows[0]) > 1 and all(len(row) == len(rows[0]) for row in rows):
        return len(rows) - 1, len(rows[0]), f"XOR 0x{key:02X}", "CSV"
    return max(0, len(text.splitlines()) - 1), 0, f"XOR 0x{key:02X}", "文本配置"


def table_difference(path: Path) -> str:
    original = DATA_DIR / path.name
    if not original.exists():
        return "MOD 新增表"
    if path.name.casefold() == "config.gjd":
        return "配置文本（值与原版不同）"
    try:
        mod_text, _ = decode_file(path)
        original_text, _ = decode_file(original)
        mod_rows = parse_csv(mod_text)
        original_rows = parse_csv(original_text)
    except (UnicodeDecodeError, csv.Error):
        return "格式待检查"
    if not mod_rows or not original_rows:
        return "格式待检查"
    mod_header = mod_rows[0]
    base_header = original_rows[0]
    if mod_header == base_header:
        return "字段与原版一致"
    if len(mod_header) != len(base_header):
        return f"字段数变化 {len(base_header)}→{len(mod_header)}"
    return "字段名称有差异"


def load_table_descriptions(path: Path = TABLE_DOC) -> dict[str, str]:
    descriptions: dict[str, str] = {}
    if not path.exists():
        return descriptions
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\|\s*`([^`]+\.gjd)`\s*\|\s*(.*?)\s*\|\s*$", line)
        if match:
            descriptions[match.group(1).casefold()] = match.group(2)
    return descriptions


def backup_existing(path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = path.with_name(f"{path.name}.bak.{stamp}")
    shutil.copy2(path, backup)
    return backup


def create_mod(name: str, mods_dir: Path = MODS_DIR) -> Path:
    name = safe_mod_name(name)
    mods_dir.mkdir(parents=True, exist_ok=True)
    root = mods_dir / name
    root.mkdir(exist_ok=False)
    (root / "Data").mkdir()
    (root / "Res").mkdir()
    return root


def _zip_member_path(info: zipfile.ZipInfo) -> tuple[str, ...]:
    raw_name = info.filename.replace("\\", "/")
    path = PurePosixPath(raw_name)
    parts = tuple(part for part in path.parts if part not in {"", "."})
    if path.is_absolute() or not parts or any(part == ".." or ":" in part for part in parts):
        raise ValueError(f"压缩包包含不安全路径：{info.filename}")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise ValueError(f"压缩包包含符号链接：{info.filename}")
    return parts


def import_mod_zip(archive: Path, mod_name: str, mods_dir: Path = MODS_DIR) -> Path:
    name = safe_mod_name(mod_name)
    mods_dir.mkdir(parents=True, exist_ok=True)
    destination = mods_dir / name
    if destination.exists():
        raise FileExistsError(f"MOD 目录已存在：{name}")

    with zipfile.ZipFile(archive) as package:
        members = [(info, _zip_member_path(info)) for info in package.infolist()]
        candidates: list[tuple[str, ...]] = [()]
        for _, parts in members:
            candidates.extend(parts[:depth] for depth in range(1, len(parts)))
        prefix = next((candidate for candidate in candidates
                       if {parts[len(candidate)].casefold() for _, parts in members
                           if len(parts) > len(candidate) and parts[:len(candidate)] == candidate}
                       >= {"data", "res"}), None)
        if prefix is None:
            raise ValueError("压缩包中没有找到同一目录下的 Data 和 Res 文件夹。")
        stage = Path(tempfile.mkdtemp(prefix=".mod-import-", dir=mods_dir))
        try:
            found_data = found_res = False
            for info, parts in members:
                if parts[:len(prefix)] != prefix:
                    continue
                relative = parts[len(prefix):]
                if not relative or relative[0] == "__MACOSX":
                    continue
                found_data |= relative[0].casefold() == "data"
                found_res |= relative[0].casefold() == "res"
                target = stage.joinpath(*relative)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
            if not (found_data and found_res and (stage / "Data").is_dir() and (stage / "Res").is_dir()):
                raise ValueError("压缩包的 Data/Res 目录结构不完整。")
            stage.replace(destination)
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
    return destination


class ModEditor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("修仙传 MOD 管理器")
        self.geometry("1320x820")
        self.minsize(1040, 650)
        self.configure(bg="#f2f5f6")
        self.mod_paths: list[Path] = []
        self.selected_path: Path | None = None
        self.active_name = selected_mod()
        self.table_descriptions = load_table_descriptions()
        self.status_var = tk.StringVar(value="就绪")
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f2f5f6")
        style.configure("Panel.TFrame", background="#ffffff")
        style.configure("TLabel", background="#f2f5f6", foreground="#26343a", font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background="#ffffff", foreground="#26343a", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#ffffff", foreground="#18272b", font=("Segoe UI", 16, "bold"))
        style.configure("Muted.TLabel", background="#ffffff", foreground="#718096", font=("Segoe UI", 9))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9), background="#ffffff", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), padding=(6, 8))
        style.map("Treeview", background=[("selected", "#dcecef")], foreground=[("selected", "#16343a")])

        shell = ttk.Frame(self)
        shell.pack(fill="both", expand=True)
        sidebar = ttk.Frame(shell, style="Panel.TFrame", width=285, padding=(15, 16))
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="MOD 库", style="Title.TLabel").pack(anchor="w")
        ttk.Label(sidebar, text="Mods 文件夹", style="Muted.TLabel").pack(anchor="w", pady=(3, 12))
        self.mod_list = tk.Listbox(sidebar, activestyle="none", exportselection=False,
                                   font=("Segoe UI", 10), bg="#ffffff", fg="#26343a",
                                   selectbackground="#dcecef", selectforeground="#16343a",
                                   highlightthickness=0, borderwidth=0)
        self.mod_list.pack(fill="both", expand=True)
        self.mod_list.bind("<<ListboxSelect>>", self._on_mod_select)
        ttk.Button(sidebar, text="＋ 新建 MOD", command=self.create_mod_ui).pack(fill="x", pady=(12, 5))
        ttk.Button(sidebar, text="导入 ZIP…", command=self.import_zip_ui).pack(fill="x", pady=5)
        ttk.Button(sidebar, text="刷新列表", command=self.refresh).pack(fill="x", pady=5)

        main = ttk.Frame(shell, padding=(18, 14, 18, 10))
        main.pack(side="left", fill="both", expand=True)
        head = ttk.Frame(main, style="Panel.TFrame", padding=(14, 12))
        head.pack(fill="x", pady=(0, 12))
        title_row = ttk.Frame(head, style="Panel.TFrame")
        title_row.pack(fill="x")
        self.title_label = ttk.Label(title_row, text="选择一个 MOD", style="Title.TLabel")
        self.title_label.pack(side="left")
        self.status_badge = ttk.Label(title_row, text="", style="Muted.TLabel")
        self.status_badge.pack(side="left", padx=(12, 0))
        ttk.Button(title_row, text="启用所选", command=self.enable_selected).pack(side="right", padx=(8, 0))
        ttk.Button(title_row, text="停用 MOD", command=self.disable_mod).pack(side="right")
        self.summary_label = ttk.Label(head, text="", style="Panel.TLabel")
        self.summary_label.pack(anchor="w", pady=(8, 0))
        self.compat_label = ttk.Label(head, text="", style="Muted.TLabel", wraplength=940, justify="left")
        self.compat_label.pack(anchor="w", pady=(5, 0))

        section = ttk.Frame(main)
        section.pack(fill="x", pady=(0, 8))
        ttk.Label(section, text="MOD 数据表", font=("Segoe UI", 11, "bold")).pack(side="left")
        self.table_count = ttk.Label(section, text="")
        self.table_count.pack(side="left", padx=(8, 0))
        ttk.Button(section, text="从原版复制…", command=self.copy_base_table).pack(side="right", padx=(8, 0))
        ttk.Button(section, text="编辑所选表", command=self.edit_selected_table).pack(side="right")
        ttk.Button(section, text="完整说明", command=self.open_table_doc).pack(side="right", padx=(0, 8))

        table_box = ttk.Frame(main, style="Panel.TFrame", padding=1)
        table_box.pack(fill="both", expand=True)
        cols = ("name", "rows", "fields", "encoding", "difference")
        self.table_tree = ttk.Treeview(table_box, columns=cols, show="headings", selectmode="browse")
        headings = (("name", "文件"), ("rows", "记录"), ("fields", "字段"),
                    ("encoding", "编码"), ("difference", "与原版对比"))
        widths = {"name": 240, "rows": 90, "fields": 90, "encoding": 110, "difference": 240}
        for col, heading in headings:
            self.table_tree.heading(col, text=heading)
            self.table_tree.column(col, width=widths[col], minwidth=70, stretch=(col in {"name", "difference"}),
                                   anchor="w" if col in {"name", "encoding", "difference"} else "center")
        scroll = ttk.Scrollbar(table_box, orient="vertical", command=self.table_tree.yview)
        self.table_tree.configure(yscrollcommand=scroll.set)
        self.table_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.table_tree.bind("<Double-1>", lambda _event: self.edit_selected_table())
        self.table_tree.bind("<<TreeviewSelect>>", self._on_table_select)

        help_row = ttk.Frame(main, padding=(0, 8, 0, 0))
        help_row.pack(fill="x")
        ttk.Label(help_row, text="表作用", font=("Segoe UI", 10, "bold")).pack(side="left", anchor="n", padx=(0, 10))
        self.table_purpose = ttk.Label(help_row, text="选择数据表查看作用说明。", wraplength=920, justify="left")
        self.table_purpose.pack(side="left", fill="x", expand=True)

        resources = ttk.Frame(main, padding=(0, 10, 0, 0))
        resources.pack(fill="x")
        self.resource_label = ttk.Label(resources, text="资源目录：未选择")
        self.resource_label.pack(side="left")
        ttk.Button(resources, text="导入资源文件…", command=self.import_resources).pack(side="right", padx=(8, 0))
        ttk.Button(resources, text="打开 Res 目录", command=lambda: self.open_subfolder("Res")).pack(side="right")
        folders = ttk.Frame(main)
        folders.pack(fill="x", pady=(7, 0))
        ttk.Button(folders, text="打开 MOD 目录", command=self.open_mod_folder).pack(side="left")
        ttk.Button(folders, text="导出 ZIP…", command=self.export_zip).pack(side="left", padx=(8, 0))
        ttk.Label(folders, textvariable=self.status_var, foreground="#718096").pack(side="right")

    def refresh(self, keep_name: str | None = None) -> None:
        self.table_descriptions = load_table_descriptions()
        if keep_name is None and self.selected_path:
            keep_name = self.selected_path.name
        self.active_name = selected_mod()
        MODS_DIR.mkdir(parents=True, exist_ok=True)
        self.mod_paths = sorted((path for path in MODS_DIR.iterdir() if path.is_dir() and not path.is_symlink()),
                                key=lambda path: path.name.casefold())
        self.mod_list.delete(0, "end")
        selected_index = None
        for index, path in enumerate(self.mod_paths):
            mark = "  ✓ 已启用" if path.name == self.active_name else ""
            self.mod_list.insert("end", f"{path.name}{mark}")
            if path.name == keep_name:
                selected_index = index
        if selected_index is None and self.mod_paths:
            selected_index = 0
        if selected_index is not None:
            self.mod_list.selection_set(selected_index)
            self.mod_list.see(selected_index)
            self._show_mod(self.mod_paths[selected_index])
        else:
            self.selected_path = None
            self._show_mod(None)

    def _on_mod_select(self, _event: tk.Event) -> None:
        selection = self.mod_list.curselection()
        if selection and selection[0] < len(self.mod_paths):
            self._show_mod(self.mod_paths[selection[0]])

    def _show_mod(self, path: Path | None) -> None:
        self.selected_path = path
        self.table_tree.delete(*self.table_tree.get_children())
        if not path:
            self.title_label.configure(text="Mods 文件夹中还没有 MOD")
            self.status_badge.configure(text="")
            self.summary_label.configure(text="")
            self.compat_label.configure(text="")
            self.table_count.configure(text="")
            self.resource_label.configure(text="资源目录：未选择")
            self.table_purpose.configure(text="选择数据表查看作用说明。")
            return
        data_dir, res_dir = mod_directories(path)
        data_files = sorted(data_dir.glob("*.gjd"), key=lambda item: item.name.casefold()) if data_dir.is_dir() else []
        resource_files = [item for item in res_dir.rglob("*") if item.is_file()] if res_dir.is_dir() else []
        size = sum(item.stat().st_size for item in resource_files)
        status = mod_status(path)
        self.title_label.configure(text=path.name)
        self.status_badge.configure(text=("当前启用" if path.name == self.active_name else status))
        self.summary_label.configure(text=f"{len(data_files)} 张数据表  ·  {len(resource_files)} 个资源文件  ·  资源 {size / 1024 / 1024:.1f} MB")
        game_version = "1.1.1.11"
        mod_version = ""
        for doc in path.glob("*.txt"):
            try:
                content = doc.read_bytes().decode("gbk", errors="replace")
            except OSError:
                continue
            match = re.search(r"(?im)^\s*v\.?\s*(\d+(?:\.\d+)+)", content)
            if match:
                mod_version = match.group(1)
                break
        if mod_version:
            self.compat_label.configure(text=f"说明文档版本 v{mod_version}；当前游戏程序为 v{game_version}。版本并不一致，启用前请确认此 MOD 支持当前游戏。")
        elif status != "可加载":
            self.compat_label.configure(text="目录缺少游戏要求的 Data 或 Res。补齐两个目录后才能设为当前 MOD。")
        else:
            self.compat_label.configure(text="游戏读取 Mods\\<名称>\\Data 和 Res，并从 config.ini 的 SelMod 选择；未发现游戏要求的 manifest。")
        self.table_count.configure(text=f"{len(data_files)} 张表")
        for file in data_files:
            try:
                rows, fields, encoding, _kind = data_summary(file)
                difference = table_difference(file)
                self.table_tree.insert("", "end", iid=str(file), values=(file.name, rows, fields or "文本", encoding, difference))
            except (OSError, UnicodeDecodeError, csv.Error) as exc:
                self.table_tree.insert("", "end", iid=str(file), values=(file.name, "?", "?", "无法识别", str(exc)[:60]))
        table_ids = self.table_tree.get_children()
        if table_ids:
            self.table_tree.selection_set(table_ids[0])
            self._on_table_select()
        else:
            self.table_purpose.configure(text="此 MOD 暂无 .gjd 数据表。")
        self.resource_label.configure(text=f"Res：{len(resource_files)} 个文件 · {res_dir}")
        self.status_var.set(f"{path.name} · {status}")

    def _require_mod(self) -> Path | None:
        if not self.selected_path:
            messagebox.showinfo("选择 MOD", "请先在左侧选择一个 MOD。", parent=self)
            return None
        return self.selected_path

    def create_mod_ui(self) -> None:
        name = simpledialog.askstring("新建 MOD", "MOD 文件夹名称", parent=self)
        if not name:
            return
        try:
            path = create_mod(name)
        except (ValueError, FileExistsError, OSError) as exc:
            messagebox.showerror("无法新建 MOD", str(exc), parent=self)
            return
        self.refresh(path.name)
        self.status_var.set(f"已创建 {path.name}，Data 和 Res 目录已就绪")

    def import_zip_ui(self) -> None:
        archive = filedialog.askopenfilename(parent=self, title="导入 MOD 压缩包", initialdir=str(MODS_DIR),
                                             filetypes=[("ZIP 压缩包", "*.zip"), ("所有文件", "*.*")])
        if not archive:
            return
        default_name = Path(archive).stem
        name = simpledialog.askstring("导入 MOD", "导入后的 MOD 名称", initialvalue=default_name, parent=self)
        if not name:
            return
        try:
            path = import_mod_zip(Path(archive), name)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            messagebox.showerror("导入失败", str(exc), parent=self)
            return
        self.refresh(path.name)
        self.status_var.set(f"已导入 {path.name}；原压缩包未修改")

    def enable_selected(self) -> None:
        path = self._require_mod()
        if not path:
            return
        status = mod_status(path)
        if status != "可加载":
            messagebox.showerror("目录不完整", f"{path.name} {status}", parent=self)
            return
        if path.name == self.active_name:
            return
        accepted = messagebox.askyesno(
            "启用 MOD",
            f"将把 config.ini 的 SelMod 设为“{path.name}”。\n\n游戏会将使用此 MOD 创建的角色与原版区分；版本不兼容时可能无法进入或造成存档问题。\n\n继续启用？",
            parent=self)
        if not accepted:
            return
        try:
            set_selected_mod(path.name)
        except (OSError, UnicodeError) as exc:
            messagebox.showerror("写入配置失败", str(exc), parent=self)
            return
        self.refresh(path.name)
        self.status_var.set("已启用；请在游戏重新读取 MOD 配置后生效")

    def disable_mod(self) -> None:
        if not self.active_name:
            return
        if not messagebox.askyesno("停用 MOD", "将清空 config.ini 的 SelMod，切回原版。\n\n使用 MOD 创建的角色可能不再兼容原版。继续？", parent=self):
            return
        try:
            set_selected_mod("")
        except (OSError, UnicodeError) as exc:
            messagebox.showerror("写入配置失败", str(exc), parent=self)
            return
        self.refresh(self.selected_path.name if self.selected_path else None)
        self.status_var.set("已切回原版；请在游戏重新读取配置后生效")

    def copy_base_table(self) -> None:
        mod = self._require_mod()
        if not mod:
            return
        data_dir, _ = mod_directories(mod)
        data_dir.mkdir(parents=True, exist_ok=True)
        files = sorted(DATA_DIR.glob("*.gjd"), key=lambda item: item.name.casefold())
        dialog = tk.Toplevel(self)
        dialog.title("从原版复制数据表")
        dialog.geometry("430x530")
        dialog.transient(self)
        dialog.grab_set()
        ttk.Label(dialog, text="选择复制到该 MOD 的原版数据表").pack(anchor="w", padx=14, pady=(14, 8))
        search_var = tk.StringVar()
        search = ttk.Entry(dialog, textvariable=search_var)
        search.pack(fill="x", padx=14, pady=(0, 8))
        listbox = tk.Listbox(dialog, activestyle="none", exportselection=False, font=("Segoe UI", 10))
        listbox.pack(fill="both", expand=True, padx=14)
        ttk.Label(dialog, text="同名表会先生成备份，再以原版文件覆盖。", foreground="#718096").pack(anchor="w", padx=14, pady=8)

        def refill(*_args: object) -> None:
            query = search_var.get().casefold()
            listbox.delete(0, "end")
            for item in files:
                if query in item.name.casefold():
                    listbox.insert("end", item.name)

        def copy_selected(_event: tk.Event | None = None) -> None:
            chosen = listbox.curselection()
            if not chosen:
                return
            source = DATA_DIR / listbox.get(chosen[0])
            target = data_dir / source.name
            if target.exists():
                if not messagebox.askyesno("覆盖数据表", f"{source.name} 已存在。\n\n将备份 MOD 中的文件并用原版覆盖。继续？", parent=dialog):
                    return
                backup_existing(target)
            shutil.copy2(source, target)
            dialog.destroy()
            self._show_mod(mod)
            self.status_var.set(f"已从原版复制 {source.name}；现在可打开编辑")

        search_var.trace_add("write", refill)
        listbox.bind("<Double-1>", copy_selected)
        actions = ttk.Frame(dialog, padding=14)
        actions.pack(fill="x")
        ttk.Button(actions, text="复制所选", command=copy_selected).pack(side="right")
        ttk.Button(actions, text="取消", command=dialog.destroy).pack(side="right", padx=(0, 8))
        refill()

    def _selected_table_path(self) -> Path | None:
        selected = self.table_tree.selection()
        return Path(selected[0]) if selected else None

    def _on_table_select(self, _event: tk.Event | None = None) -> None:
        path = self._selected_table_path()
        if not path:
            self.table_purpose.configure(text="选择数据表查看作用说明。")
            return
        description = self.table_descriptions.get(path.name.casefold())
        if description:
            self.table_purpose.configure(text=description)
        else:
            self.table_purpose.configure(text="暂无这张表的作用说明；可从“完整说明”打开文档补充。")

    def open_table_doc(self) -> None:
        if not TABLE_DOC.exists():
            messagebox.showerror("说明文档不存在", str(TABLE_DOC), parent=self)
            return
        os.startfile(TABLE_DOC)

    def edit_selected_table(self) -> None:
        path = self._selected_table_path()
        if not path:
            messagebox.showinfo("选择数据表", "请先选择一张 MOD 数据表。", parent=self)
            return
        try:
            subprocess.Popen([sys.executable, str(GJD_EDITOR), str(path)], cwd=str(GAME_ROOT))
        except OSError as exc:
            messagebox.showerror("无法启动 GJD 编辑器", str(exc), parent=self)

    def import_resources(self) -> None:
        mod = self._require_mod()
        if not mod:
            return
        files = filedialog.askopenfilenames(parent=self, title="选择要放入 MOD 的资源文件")
        if not files:
            return
        relative_dir = simpledialog.askstring("资源目标目录", "在 Res 下的相对目录（留空表示 Res 根目录）", initialvalue="", parent=self)
        if relative_dir is None:
            return
        relative = PurePosixPath(relative_dir.replace("\\", "/"))
        if relative.is_absolute() or any(part in {"..", "."} or ":" in part for part in relative.parts):
            messagebox.showerror("目录无效", "请输入 Res 下的相对目录。", parent=self)
            return
        res_dir = mod / "Res"
        target_dir = res_dir.joinpath(*relative.parts)
        target_dir.mkdir(parents=True, exist_ok=True)
        for item in files:
            source = Path(item)
            target = target_dir / source.name
            if target.exists():
                if not messagebox.askyesno("覆盖资源", f"{target.relative_to(res_dir)} 已存在。\n\n备份并覆盖？", parent=self):
                    continue
                backup_existing(target)
            shutil.copy2(source, target)
        self._show_mod(mod)
        self.status_var.set("资源文件已复制到 MOD")

    def open_subfolder(self, name: str) -> None:
        mod = self._require_mod()
        if not mod:
            return
        path = mod / name
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(path)

    def open_mod_folder(self) -> None:
        mod = self._require_mod()
        if mod:
            os.startfile(mod)

    def export_zip(self) -> None:
        mod = self._require_mod()
        if not mod:
            return
        if mod_status(mod) != "可加载":
            messagebox.showerror("无法导出", f"{mod.name} {mod_status(mod)}", parent=self)
            return
        target = filedialog.asksaveasfilename(parent=self, title="导出 MOD ZIP", initialdir=str(MODS_DIR),
                                               initialfile=f"{mod.name}.zip", defaultextension=".zip",
                                               filetypes=[("ZIP 压缩包", "*.zip")])
        if not target:
            return
        try:
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("Data/", "")
                archive.writestr("Res/", "")
                for path in sorted(mod.rglob("*")):
                    if path.is_symlink():
                        continue
                    arcname = path.relative_to(mod).as_posix()
                    if path.is_dir():
                        archive.writestr(arcname.rstrip("/") + "/", "")
                    elif ".bak." not in path.name and not path.name.endswith(".tmp"):
                        archive.write(path, arcname)
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc), parent=self)
            return
        self.status_var.set(f"已导出 {Path(target).name}")


if __name__ == "__main__":
    ModEditor().mainloop()
