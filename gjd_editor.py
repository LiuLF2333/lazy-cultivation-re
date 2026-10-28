"""Desktop editor for the game's XOR-obfuscated GBK .gjd data files."""

from __future__ import annotations

import argparse
import csv
import io
import shutil
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


XOR_KEY = 0xC6
APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"


def detect_xor_key(path: Path, raw: bytes) -> int:
    candidates: list[tuple[int, int]] = []
    for key in (0xC6, 0xB8):
        try:
            text = bytes(value ^ key for value in raw).decode("gbk", errors="strict")
            rows = parse_csv(text)
        except (UnicodeDecodeError, csv.Error):
            continue
        if path.name.casefold() == "config.gjd":
            if key == 0xC6:
                return key
            continue
        if len(rows) < 2 or not rows[0]:
            continue
        uniform = len(rows[0]) > 1 and all(len(row) == len(rows[0]) for row in rows)
        header = ",".join(rows[0])
        score = (1000 if uniform else 0) + min(len(rows[0]), 100)
        score += min(sum("\u4e00" <= char <= "\u9fff" for char in header), 100)
        candidates.append((score, key))
    return max(candidates)[1] if candidates else XOR_KEY


def decode_file(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    key = detect_xor_key(path, raw)
    return bytes(value ^ key for value in raw).decode("gbk", errors="strict"), key


def encode_text(text: str) -> bytes:
    raw = text.encode("gbk", errors="strict")
    return bytes(value ^ XOR_KEY for value in raw)


def parse_csv(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text, newline=""), strict=True))


class GjdEditor(tk.Tk):
    def __init__(self, initial_path: Path | None = None):
        super().__init__()
        self.title("GJD 数据编辑器")
        self.geometry("1480x860")
        self.minsize(980, 620)
        self.configure(bg="#f3f5f7")

        self.path: Path | None = None
        self.mode = ""
        self.headers: list[str] = []
        self.rows: list[list[str]] = []
        self.xor_key = XOR_KEY
        self.dirty = False
        self.editor: tk.Entry | None = None
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="选择或打开一个 .gjd 文件")
        self.file_filter_var = tk.StringVar()
        self._build_ui()
        self._load_file_list()
        self.search_var.trace_add("write", lambda *_: self._refresh_grid())
        self.protocol("WM_DELETE_WINDOW", self._close)

        if initial_path:
            self.open_path(initial_path)

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f3f5f7")
        style.configure("Panel.TFrame", background="#ffffff")
        style.configure("TLabel", background="#f3f5f7", foreground="#263238", font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background="#ffffff", foreground="#263238", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#ffffff", foreground="#17252a", font=("Segoe UI", 15, "bold"))
        style.configure("Muted.TLabel", background="#ffffff", foreground="#718096", font=("Segoe UI", 9))
        style.configure("TButton", padding=(10, 6), font=("Segoe UI", 9))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9), background="#ffffff", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), padding=(6, 8))
        style.map("Treeview", background=[("selected", "#d9eef0")], foreground=[("selected", "#142d32")])

        root = ttk.Frame(self, padding=0)
        root.pack(fill="both", expand=True)

        sidebar = ttk.Frame(root, style="Panel.TFrame", padding=(14, 16))
        sidebar.pack(side="left", fill="y")
        sidebar.configure(width=260)
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="GJD 数据编辑器", style="Title.TLabel").pack(anchor="w")
        ttk.Label(sidebar, text="浏览并编辑游戏数据表", style="Muted.TLabel").pack(anchor="w", pady=(3, 14))
        ttk.Entry(sidebar, textvariable=self.file_filter_var).pack(fill="x", pady=(0, 10))
        self.file_filter_var.trace_add("write", lambda *_: self._load_file_list())
        list_frame = ttk.Frame(sidebar, style="Panel.TFrame")
        list_frame.pack(fill="both", expand=True)
        self.file_list = tk.Listbox(list_frame, activestyle="none", exportselection=False,
                                    font=("Segoe UI", 10), bg="#ffffff", fg="#27343a",
                                    selectbackground="#d9eef0", selectforeground="#142d32",
                                    highlightthickness=0, borderwidth=0)
        file_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_list.yview)
        self.file_list.configure(yscrollcommand=file_scroll.set)
        self.file_list.pack(side="left", fill="both", expand=True)
        file_scroll.pack(side="right", fill="y")
        self.file_list.bind("<<ListboxSelect>>", self._on_file_select)
        ttk.Button(sidebar, text="打开其他文件…", command=self._choose_file).pack(fill="x", pady=(12, 0))

        main = ttk.Frame(root, padding=(18, 14, 18, 10))
        main.pack(side="left", fill="both", expand=True)
        toolbar = ttk.Frame(main)
        toolbar.pack(fill="x", pady=(0, 12))
        self.file_title = ttk.Label(toolbar, text="未打开文件", font=("Segoe UI", 14, "bold"))
        self.file_title.pack(side="left")
        self.file_meta = ttk.Label(toolbar, text="", foreground="#718096")
        self.file_meta.pack(side="left", padx=(12, 0))
        ttk.Button(toolbar, text="保存", command=self.save_file).pack(side="right", padx=(8, 0))
        ttk.Button(toolbar, text="重新载入", command=self.reload_file).pack(side="right")

        tools = ttk.Frame(main)
        tools.pack(fill="x", pady=(0, 8))
        ttk.Label(tools, text="筛选记录").pack(side="left")
        search = ttk.Entry(tools, textvariable=self.search_var, width=32)
        search.pack(side="left", padx=(8, 14))
        search.bind("<Escape>", lambda _event: self.search_var.set(""))
        self.count_label = ttk.Label(tools, text="")
        self.count_label.pack(side="left")
        self.add_button = ttk.Button(tools, text="＋ 新增行", command=self.add_row)
        self.add_button.pack(side="right", padx=(8, 0))
        self.delete_button = ttk.Button(tools, text="删除选中行", command=self.delete_row)
        self.delete_button.pack(side="right")
        self.batch_button = ttk.Button(tools, text="批量改列…", command=self.batch_edit_column)
        self.batch_button.pack(side="right", padx=(0, 8))

        self.grid_panel = ttk.Frame(main, style="Panel.TFrame", padding=1)
        self.grid_panel.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(self.grid_panel, show="headings", selectmode="browse")
        ybar = ttk.Scrollbar(self.grid_panel, orient="vertical", command=self.tree.yview)
        xbar = ttk.Scrollbar(self.grid_panel, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        self.grid_panel.rowconfigure(0, weight=1)
        self.grid_panel.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self._begin_cell_edit)
        self.tree.bind("<Button-1>", self._finish_cell_edit, add="+")

        footer = ttk.Frame(main)
        self.footer = footer
        footer.pack(fill="x", pady=(9, 0))
        ttk.Label(footer, textvariable=self.status_var).pack(side="left")
        ttk.Label(footer, text="双击单元格编辑 · Ctrl+S 保存", foreground="#718096").pack(side="right")
        self.bind("<Control-s>", lambda _event: self.save_file())

        self.raw_text = tk.Text(main, wrap="none", undo=True, font=("Consolas", 10),
                                bg="#ffffff", fg="#263238", insertbackground="#263238",
                                relief="flat", padx=12, pady=10)
        self.raw_text.bind("<<Modified>>", self._on_raw_modified)

    def _load_file_list(self) -> None:
        current = self.path
        self.file_list.delete(0, "end")
        self.files = sorted(DATA_DIR.glob("*.gjd"), key=lambda item: item.name.casefold()) if DATA_DIR.exists() else []
        query = self.file_filter_var.get().strip().casefold()
        for path in self.files:
            if query and query not in path.name.casefold():
                continue
            self.file_list.insert("end", path.name)
            if current and path.resolve() == current.resolve():
                self.file_list.selection_set("end")
        if current and current.parent.resolve() == DATA_DIR.resolve():
            selected = self.file_list.curselection()
            if selected:
                self.file_list.see(selected[0])

    def _on_file_select(self, _event: tk.Event) -> None:
        selection = self.file_list.curselection()
        if not selection:
            return
        path = DATA_DIR / self.file_list.get(selection[0])
        if self.path and path.resolve() == self.path.resolve():
            return
        if not self._confirm_discard():
            self._select_current_file()
            return
        self.open_path(path)

    def _select_current_file(self) -> None:
        if not self.path or self.path.parent.resolve() != DATA_DIR.resolve():
            self.file_list.selection_clear(0, "end")
            return
        for index in range(self.file_list.size()):
            if (DATA_DIR / self.file_list.get(index)).resolve() == self.path.resolve():
                self.file_list.selection_clear(0, "end")
                self.file_list.selection_set(index)
                self.file_list.see(index)
                return

    def _confirm_discard(self) -> bool:
        if not self.dirty:
            return True
        answer = messagebox.askyesnocancel("未保存的修改", "当前文件有未保存的修改。\n\n是否先保存？", parent=self)
        if answer is None:
            return False
        if answer:
            return self.save_file()
        return True

    def open_path(self, path: Path) -> None:
        try:
            text, xor_key = decode_file(path)
            parsed = parse_csv(text)
            uniform = bool(parsed) and len(parsed) > 1 and len(parsed[0]) > 1 and all(len(row) == len(parsed[0]) for row in parsed)
        except (UnicodeDecodeError, csv.Error) as exc:
            messagebox.showerror("无法读取文件", f"{path.name}\n\n{exc}", parent=self)
            return
        self.path = path.resolve()
        self.xor_key = xor_key
        self.dirty = False
        self.file_title.configure(text=path.name)
        if uniform:
            self.mode = "csv"
            self.headers = parsed[0]
            self.rows = parsed[1:]
            self.grid_panel.pack(fill="both", expand=True, before=self.footer)
            self.raw_text.pack_forget()
            self.raw_text.pack_forget()
            self.add_button.state(["!disabled"])
            self.delete_button.state(["!disabled"])
            self.batch_button.state(["!disabled"])
            self.search_var.set("")
            self._configure_grid()
            self._refresh_grid()
            self.file_meta.configure(text=f"{len(self.rows)} 行 · {len(self.headers)} 列 · XOR 0x{self.xor_key:02X}")
        else:
            self.mode = "text"
            self.headers = []
            self.rows = []
            self.grid_panel.pack_forget()
            self.add_button.state(["disabled"])
            self.delete_button.state(["disabled"])
            self.batch_button.state(["disabled"])
            self.raw_text.pack(fill="both", expand=True, before=self.footer)
            self.raw_text.delete("1.0", "end")
            self.raw_text.insert("1.0", text)
            self.raw_text.edit_modified(False)
            self.file_meta.configure(text="文本配置")
            self.count_label.configure(text="")
        self.status_var.set(f"已打开 {self.path}")
        self.title(f"{path.name} - GJD 数据编辑器")

    def _configure_grid(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = tuple(str(index) for index in range(len(self.headers)))
        for index, header in enumerate(self.headers):
            column = str(index)
            self.tree.heading(column, text=header)
            self.tree.column(column, width=min(240, max(110, len(header) * 19)), minwidth=80, stretch=False, anchor="w")

    def _refresh_grid(self) -> None:
        if self.mode != "csv":
            return
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().strip().casefold()
        visible = 0
        for row_index, row in enumerate(self.rows):
            if query and query not in "\t".join(row).casefold():
                continue
            self.tree.insert("", "end", iid=str(row_index), values=row)
            visible += 1
        self.count_label.configure(text=f"{visible} / {len(self.rows)} 条记录")

    def _begin_cell_edit(self, event: tk.Event) -> None:
        if self.mode != "csv":
            return
        item = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)
        if not item or not column_id:
            return
        column_index = int(column_id[1:]) - 1
        if not 0 <= column_index < len(self.headers):
            return
        self._finish_cell_edit()
        box = self.tree.bbox(item, column_id)
        if not box:
            return
        x, y, width, height = box
        value = self.rows[int(item)][column_index]
        entry = tk.Entry(self.tree, font=("Segoe UI", 9), relief="solid", borderwidth=1)
        entry.insert(0, value)
        entry.select_range(0, "end")
        entry.place(x=x, y=y, width=width, height=height)
        self.editor = entry

        def commit(_event: tk.Event | None = None) -> str:
            if self.editor is not entry:
                return "break"
            new_value = entry.get()
            row_index = int(item)
            if self.rows[row_index][column_index] != new_value:
                self.rows[row_index][column_index] = new_value
                self.dirty = True
                self.status_var.set("有未保存的修改")
                self.tree.item(item, values=self.rows[row_index])
            entry.destroy()
            self.editor = None
            return "break"

        entry.bind("<Return>", commit)
        entry.bind("<FocusOut>", commit)
        entry.bind("<Escape>", lambda _event: (entry.destroy(), setattr(self, "editor", None), "break")[-1])
        entry.focus_set()

    def _finish_cell_edit(self, _event: tk.Event | None = None) -> None:
        if self.editor:
            self.editor.event_generate("<Return>")

    def add_row(self) -> None:
        if self.mode != "csv":
            return
        row = [""] * len(self.headers)
        self.rows.append(row)
        self.dirty = True
        self.search_var.set("")
        self._refresh_grid()
        item = str(len(self.rows) - 1)
        self.tree.selection_set(item)
        self.tree.see(item)
        self.status_var.set("已新增一行，请填写字段并保存")
        if self.headers:
            box = self.tree.bbox(item, "#1")
            if box:
                self._begin_cell_edit(type("Event", (), {"y": box[1] + 2, "x": box[0] + 2})())

    def delete_row(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        row_index = int(selection[0])
        if not messagebox.askyesno("删除记录", f"删除第 {row_index + 1} 行记录？", parent=self):
            return
        del self.rows[row_index]
        self.dirty = True
        self._refresh_grid()
        self.status_var.set("记录已删除，尚未保存")

    def batch_edit_column(self) -> None:
        if self.mode != "csv" or not self.headers:
            return
        self._finish_cell_edit()

        dialog = tk.Toplevel(self)
        dialog.title("批量修改整列")
        dialog.transient(self)
        dialog.resizable(False, False)
        dialog.configure(padx=18, pady=16)

        ttk.Label(dialog, text="要修改的列").grid(row=0, column=0, sticky="w", pady=(0, 8))
        column_var = tk.StringVar()
        column_box = ttk.Combobox(dialog, textvariable=column_var, values=self.headers, state="readonly", width=34)
        column_box.grid(row=0, column=1, sticky="ew", pady=(0, 8))
        preferred = next((i for i, header in enumerate(self.headers)
                          if "叠加" in header or "堆叠" in header or "stack" in header.casefold()), 0)
        column_box.current(preferred)

        ttk.Label(dialog, text="统一设置为").grid(row=1, column=0, sticky="w", pady=8)
        value_var = tk.StringVar()
        value_entry = ttk.Entry(dialog, textvariable=value_var, width=37)
        value_entry.grid(row=1, column=1, sticky="ew", pady=8)

        filtered_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(dialog, text="仅修改当前筛选结果", variable=filtered_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(4, 8))
        impact_var = tk.StringVar()
        ttk.Label(dialog, textvariable=impact_var).grid(row=3, column=0, columnspan=2, sticky="w")

        def matching_indices() -> list[int]:
            if not filtered_var.get():
                return list(range(len(self.rows)))
            query = self.search_var.get().strip().casefold()
            return [i for i, row in enumerate(self.rows)
                    if not query or query in "\t".join(row).casefold()]

        def update_impact(*_args: object) -> None:
            count = len(matching_indices())
            impact_var.set(f"将检查 {count} 条记录" + ("（仅当前筛选结果）" if filtered_var.get() else "（整张表）"))

        filtered_var.trace_add("write", update_impact)
        update_impact()

        buttons = ttk.Frame(dialog)
        buttons.grid(row=4, column=0, columnspan=2, sticky="e", pady=(16, 0))

        def apply() -> None:
            indices = matching_indices()
            if not indices:
                messagebox.showinfo("没有记录", "当前范围内没有可修改的记录。", parent=dialog)
                return
            column_index = column_box.current()
            header = self.headers[column_index]
            value = value_var.get()
            changed = sum(self.rows[i][column_index] != value for i in indices)
            if changed == 0:
                messagebox.showinfo("无需修改", "所选记录的这一列已经是该值。", parent=dialog)
                return
            scope = "当前筛选结果" if filtered_var.get() else "整张表"
            if not messagebox.askyesno(
                "确认批量修改",
                f"将把{scope}中 {changed} 条记录的「{header}」设为：\n\n{value}\n\n继续吗？",
                parent=dialog,
            ):
                return
            for row_index in indices:
                self.rows[row_index][column_index] = value
            self.dirty = True
            self._refresh_grid()
            self.status_var.set(f"已批量修改「{header}」：{changed} 条记录，尚未保存")
            dialog.destroy()

        ttk.Button(buttons, text="取消", command=dialog.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="应用", command=apply).pack(side="right")
        dialog.bind("<Return>", lambda _event: apply())
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.grab_set()
        value_entry.focus_set()

    def _on_raw_modified(self, _event: tk.Event) -> None:
        if self.mode == "text" and self.raw_text.edit_modified():
            self.dirty = True
            self.status_var.set("有未保存的修改")
            self.raw_text.edit_modified(False)

    def _serialized_text(self) -> str:
        if self.mode == "text":
            return self.raw_text.get("1.0", "end-1c")
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(self.headers)
        for row in self.rows:
            if len(row) != len(self.headers):
                raise ValueError(f"记录字段数不匹配：期望 {len(self.headers)} 项，实际 {len(row)} 项")
            writer.writerow(row)
        return output.getvalue()

    def save_file(self) -> bool:
        if not self.path:
            return False
        self._finish_cell_edit()
        try:
            encoded = bytes(value ^ self.xor_key for value in self._serialized_text().encode("gbk", errors="strict"))
        except (UnicodeEncodeError, ValueError) as exc:
            messagebox.showerror("无法保存", f"{exc}\n\n请检查文本或字段数量。", parent=self)
            return False
        try:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = self.path.with_name(f"{self.path.name}.bak.{stamp}")
            shutil.copy2(self.path, backup)
            temp = self.path.with_name(f".{self.path.name}.{stamp}.tmp")
            temp.write_bytes(encoded)
            temp.replace(self.path)
        except OSError as exc:
            messagebox.showerror("保存失败", str(exc), parent=self)
            return False
        self.dirty = False
        if self.mode == "csv":
            self.file_meta.configure(text=f"{len(self.rows)} 行 · {len(self.headers)} 列 · XOR 0x{self.xor_key:02X}")
        self.status_var.set(f"已保存 · 备份：{backup.name}")
        return True

    def reload_file(self) -> None:
        if not self.path or not self._confirm_discard():
            return
        self.open_path(self.path)

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="打开 GJD 文件", initialdir=str(DATA_DIR),
                                          filetypes=[("GJD 数据文件", "*.gjd"), ("所有文件", "*.*")])
        if path and self._confirm_discard():
            self.open_path(Path(path))
            self._load_file_list()

    def _close(self) -> None:
        if self._confirm_discard():
            self.destroy()


def main() -> None:
    parser = argparse.ArgumentParser(description="编辑游戏的 .gjd 数据表")
    parser.add_argument("file", nargs="?", type=Path, help="启动时打开的 .gjd 文件")
    args = parser.parse_args()
    app = GjdEditor(args.file)
    app.mainloop()


if __name__ == "__main__":
    main()
