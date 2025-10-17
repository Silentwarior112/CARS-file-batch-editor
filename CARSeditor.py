import os
import csv
import struct
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

# ----- Part type mapping -----
PART_TYPE_NAMES = {
    1: "Brake",
    2: "Brake Controller",
    3: "Suspension",
    4: "ASCC",
    5: "TCSC",
    6: "Chassis",
    7: "RacingModify",
    8: "Weight Reduction",
    9: "Steer",
    10: "Drivetrain",
    11: "Gearbox",
    12: "Engine",
    13: "NA Tune",
    14: "Turbo",
    15: "Port Polish",
    16: "Engine Balance",
    17: "Displacement",
    18: "Computer",
    19: "Intercooler",
    20: "Muffler",
    21: "Clutch",
    22: "Flywheel",
    23: "Driveshaft",
    24: "LSD",
    25: "Front Tire",
    26: "Rear Tire",
    27: "Nitrous",
    28: "Supercharger",
    4294967295: "Dummy",
}

ITEM_SIZE = 16
HEADER_SIZE = 8

# --- Hardcoded column widths (characters) ---
TYPE_COL_CHARS = 20       
CATEGORY_COL_CHARS = 8    
ID_COL_CHARS = 6          

# --- Helpers ---
def dec_to_hex_stem(n: int) -> str:
    """670 -> '000000000000029E' (uppercase, 16 hex chars)."""
    return f"{int(n):016X}"

def parse_file(path: str):
    """Parse parts file in little-endian. Ignore header count; only error if body isn't multiple of 16."""
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < HEADER_SIZE:
        raise ValueError("File too small to contain header (need 8 bytes).")

    declared_count = data[0]  # informational
    pad = data[1:8]
    body = data[HEADER_SIZE:]
    remainder = len(body) % ITEM_SIZE
    if remainder != 0:
        raise ValueError(f"Trailing bytes do not form a full item: got {remainder} extra byte(s).")

    items = []
    unpack_fmt = "<III4s"
    for i in range(len(body) // ITEM_SIZE):
        off = i * ITEM_SIZE
        id_val, type_val, cat_val, _ = struct.unpack(unpack_fmt, body[off: off + ITEM_SIZE])
        items.append({"id": id_val, "type": type_val, "category": cat_val})

    warnings = []
    if any(pad):
        warnings.append("Header padding (bytes 1–7) not all 0x00.")
    if declared_count != len(items):
        warnings.append(f"Header count={declared_count}, parsed items={len(items)} (ignored).")

    return {"items": items, "warnings": warnings}

def remove_type_from_file(path: str, type_value: int) -> tuple[int, int, int]:
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < HEADER_SIZE:
        raise ValueError("File too small to contain header (need 8 bytes).")

    header = data[:HEADER_SIZE]
    body = data[HEADER_SIZE:]
    if len(body) % ITEM_SIZE != 0:
        raise ValueError("Body length is not a multiple of 16 bytes; cannot edit safely.")

    unpack_fmt = "<III4s"
    kept_chunks = []
    removed = 0
    total = len(body) // ITEM_SIZE

    for i in range(total):
        off = i * ITEM_SIZE
        chunk = body[off: off + ITEM_SIZE]
        _id_val, type_val, _cat_val, _pad = struct.unpack(unpack_fmt, chunk)
        if type_val == type_value:
            removed += 1
        else:
            kept_chunks.append(chunk)

    new_body = b"".join(kept_chunks)
    new_header = bytes([0xFF]) + header[1:8]  # Max out the part count. No drawback to doing so, allows manual hex editing to be easy not having to think about this

    with open(path, "wb") as f:
        f.write(new_header + new_body)

    return removed, total, len(new_body) // ITEM_SIZE
    
def remove_type_category_from_file(path: str, type_value: int, category_value: int) -> tuple[int, int, int]:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < HEADER_SIZE:
        raise ValueError("File too small to contain header (need 8 bytes).")

    header = data[:HEADER_SIZE]
    body = data[HEADER_SIZE:]
    if len(body) % ITEM_SIZE != 0:
        raise ValueError("Body length is not a multiple of 16 bytes; cannot edit safely.")

    unpack_fmt = "<III4s"
    kept, removed = [], 0
    total = len(body) // ITEM_SIZE

    for i in range(total):
        off = i * ITEM_SIZE
        chunk = body[off: off + ITEM_SIZE]
        _id_val, type_val, cat_val, _pad = struct.unpack(unpack_fmt, chunk)
        if type_val == type_value and cat_val == category_value:
            removed += 1
        else:
            kept.append(chunk)

    new_body = b"".join(kept)
    new_header = bytes([0xFF]) + header[1:8]

    with open(path, "wb") as f:
        f.write(new_header + new_body)

    return removed, total, len(kept)

def replace_type_category_in_file(path: str,
                                  target_type: int,
                                  target_category: int,
                                  new_id,                     # int or None
                                  new_type: int,
                                  new_category: int) -> bool:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < HEADER_SIZE:
        raise ValueError("File too small to contain header (need 8 bytes).")

    header = data[:HEADER_SIZE]
    body = data[HEADER_SIZE:]
    if len(body) % ITEM_SIZE != 0:
        raise ValueError("Body length is not a multiple of 16 bytes; cannot edit safely.")

    unpack_fmt = "<III4s"
    pack_fmt = "<III4s"

    total = len(body) // ITEM_SIZE
    replaced = False
    chunks = []

    for i in range(total):
        off = i * ITEM_SIZE
        chunk = body[off: off + ITEM_SIZE]
        _id_val, type_val, cat_val, _pad = struct.unpack(unpack_fmt, chunk)

        if (not replaced) and (type_val == target_type) and (cat_val == target_category):
            # If new_id is None, keep the existing id
            use_id = _id_val if (new_id is None) else int(new_id)
            chunk = struct.pack(pack_fmt, use_id, int(new_type), int(new_category), b"\x00\x00\x00\x00")
            replaced = True

        chunks.append(chunk)

    if not replaced:
        return False

    new_body = b"".join(chunks)
    new_header = bytes([0xFF]) + header[1:8]   # always set 1st byte to FF per your rule

    with open(path, "wb") as f:
        f.write(new_header + new_body)

    return True
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < HEADER_SIZE:
        raise ValueError("File too small to contain header (need 8 bytes).")

    header = data[:HEADER_SIZE]
    body = data[HEADER_SIZE:]
    if len(body) % ITEM_SIZE != 0:
        raise ValueError("Body length is not a multiple of 16 bytes; cannot edit safely.")

    unpack_fmt = "<III4s"
    pack_fmt = "<III4s"

    total = len(body) // ITEM_SIZE
    replaced = False
    chunks = []

    for i in range(total):
        off = i * ITEM_SIZE
        chunk = body[off: off + ITEM_SIZE]
        _id_val, type_val, cat_val, _pad = struct.unpack(unpack_fmt, chunk)
        if (not replaced) and (type_val == target_type) and (cat_val == target_category):
            chunk = struct.pack(pack_fmt, int(new_id), int(new_type), int(new_category), b"\x00\x00\x00\x00")
            replaced = True
        chunks.append(chunk)

    if not replaced:
        return False

    new_body = b"".join(chunks)
    new_header = bytes([0xFF]) + header[1:8]

    with open(path, "wb") as f:
        f.write(new_header + new_body)

    return True

def add_item_sorted_by_type(path: str, new_id: int, new_type: int, new_category: int) -> int:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < HEADER_SIZE:
        raise ValueError("File too small to contain header (need 8 bytes).")

    header = data[:HEADER_SIZE]
    body = data[HEADER_SIZE:]
    if len(body) % ITEM_SIZE != 0:
        raise ValueError("Body length is not a multiple of 16 bytes; cannot edit safely.")

    unpack_fmt = "<III4s"
    pack_fmt = "<III4s"
    total = len(body) // ITEM_SIZE
    last_leq = -1
    for i in range(total):
        off = i * ITEM_SIZE
        _id_val, type_val, _cat_val, _pad = struct.unpack(unpack_fmt, body[off: off + ITEM_SIZE])
        if type_val <= new_type:
            last_leq = i
    insert_index = last_leq + 1

    new_chunk = struct.pack(pack_fmt, int(new_id), int(new_type), int(new_category), b"\x00\x00\x00\x00")
    prefix = body[: insert_index * ITEM_SIZE]
    suffix = body[insert_index * ITEM_SIZE :]
    new_body = prefix + new_chunk + suffix

    new_header = bytes([0xFF]) + header[1:8]

    with open(path, "wb") as f:
        f.write(new_header + new_body)

    return 1

class ScrollableItems(ttk.Frame):
    """Scrollable table with fixed header and hardcoded column widths."""
    def __init__(self, master):
        super().__init__(master)
        self.fixed_font = tkfont.nametofont("TkFixedFont")

        # Header
        self.header = ttk.Frame(self)
        self.header.grid(row=0, column=0, sticky="w")
        ttk.Label(self.header, text="Type", width=TYPE_COL_CHARS, anchor="w", font=self.fixed_font)\
            .grid(row=0, column=0, padx=4, pady=(0, 4))
        ttk.Label(self.header, text="Category", width=CATEGORY_COL_CHARS, anchor="w", font=self.fixed_font)\
            .grid(row=0, column=1, padx=4, pady=(0, 4))
        ttk.Label(self.header, text=" ID", width=ID_COL_CHARS, anchor="w", font=self.fixed_font)\
            .grid(row=0, column=2, padx=4, pady=(0, 4))

        # Scrollable list
        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.vscroll = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vscroll.set)
        self.canvas.grid(row=1, column=0, sticky="nsew")
        self.vscroll.grid(row=1, column=1, sticky="ns", padx=(2, 0))
        self.rowconfigure(1, weight=1)

        self.inner = ttk.Frame(self.canvas)
        self.inner_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self._row_vars = []
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.inner.bind("<Enter>", self._bind_mousewheel)
        self.inner.bind("<Leave>", self._unbind_mousewheel)
        self.canvas.bind("<Enter>", self._bind_mousewheel)
        self.canvas.bind("<Leave>", self._unbind_mousewheel)

    def _bind_mousewheel(self, _=None):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel, add="+")
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"), add="+")
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"), add="+")

    def _unbind_mousewheel(self, _=None):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_mousewheel(self, event):
        delta = -1 if event.delta > 0 else 1
        self.canvas.yview_scroll(delta, "units")

    def clear(self):
        for c in self.inner.winfo_children():
            c.destroy()
        self._row_vars.clear()

    def populate(self, items):
        self.clear()
        for item in items:
            row = ttk.Frame(self.inner)
            type_num = item["type"]
            type_name = PART_TYPE_NAMES.get(type_num, f"Unknown ({type_num})")
            type_var = tk.StringVar(value=f"{type_num}--{type_name}")
            cat_var = tk.StringVar(value=str(item["category"]))
            id_var = tk.StringVar(value=str(item["id"]))
            ttk.Entry(row, width=TYPE_COL_CHARS, state="readonly", textvariable=type_var, font=self.fixed_font)\
                .grid(row=0, column=0, padx=4, pady=1)
            ttk.Entry(row, width=CATEGORY_COL_CHARS, state="readonly", textvariable=cat_var, font=self.fixed_font)\
                .grid(row=0, column=1, padx=4, pady=1)
            ttk.Entry(row, width=ID_COL_CHARS, state="readonly", textvariable=id_var, font=self.fixed_font)\
                .grid(row=0, column=2, padx=4, pady=1)
            row.pack(anchor="w")
            self._row_vars.append((type_var, cat_var, id_var))

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CARS Batch Editor")
        self.geometry("860x700")

        self.selected_paths = []          # original selection order
        self.display_paths = []           # paths aligned with sorted labels
        self.display_labels = []          # labels shown in combobox
        self.file_cache = {}
        self.names_map = {}

        # Auto-load CSV FIRST
        self._load_names_csv_hardcoded()

        # --- Top bar ---
        top = ttk.Frame(self)
        top.pack(side="top", fill="x", padx=10, pady=8)

        ttk.Button(top, text="Load files", command=self.load_files).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(top, text="Load file list", command=self.load_files_from_list).grid(row=0, column=1, padx=(0, 16))
        ttk.Button(top, text="Batch Remove", command=self.batch_remove_dialog).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(top, text="Batch Replace", command=self.batch_replace_dialog).grid(row=0, column=3, padx=(0, 8))
        ttk.Button(top, text="Batch Add", command=self.batch_add_dialog).grid(row=0, column=4, padx=(0, 16))

        ttk.Label(top, text="Selected file:").grid(row=0, column=5, sticky="w")
        self.file_combo_var = tk.StringVar()  # NEW: track value changes
        self.file_combo = ttk.Combobox(top, state="readonly", width=50, values=[], textvariable=self.file_combo_var)
        self.file_combo.grid(row=0, column=6, padx=(4, 8), sticky="ew")
        self.file_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_view())
        self.file_combo_var.trace_add("write", lambda *_: self.refresh_view())
        top.grid_columnconfigure(6, weight=1)

        # List panel
        self.items_panel = ScrollableItems(self)
        self.items_panel.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        # Status bar
        self.status = ttk.Label(self, anchor="w", relief="sunken")
        self.status.pack(side="bottom", fill="x")
        
    def _confirm_multi_file_action(self, action_name: str) -> bool:
        """Ask for confirmation when performing a batch action on multiple files."""
        if len(self.selected_paths) <= 1:
            return True  # no warning needed
    
        count = len(self.selected_paths)
        return messagebox.askokcancel(
            "Confirm Batch Action",
            f"You are about to {action_name} on {count} files.\n\nThis action will modify them permanently.\n\nContinue?",
            icon="warning"
        )
        
    def _center_window(self, win):
        """
        Center a toplevel `win` over the main window (self). Works cross-platform.
        Call AFTER you've populated the window's widgets.
        """
        win.update_idletasks()  # ensure geometry is calculated
    
        # popup size
        w = win.winfo_width()
        h = win.winfo_height()
        if w <= 1 or h <= 1:  # sometimes 1x1 before mapped; fall back to requested size
            w = win.winfo_reqwidth()
            h = win.winfo_reqheight()
    
        # parent (main window) position & size
        px = self.winfo_rootx()
        py = self.winfo_rooty()
        pw = self.winfo_width()
        ph = self.winfo_height()
    
        # if parent not yet sized (startup), use screen center
        if pw <= 1 or ph <= 1:
            sw = win.winfo_screenwidth()
            sh = win.winfo_screenheight()
            x = (sw - w) // 2
            y = (sh - h) // 2
        else:
            x = px + (pw - w) // 2
            y = py + (ph - h) // 2
    
        # keep on-screen with a small margin
        margin = 10
        x = max(margin, x)
        y = max(margin, y)
    
        win.geometry(f"{w}x{h}+{x}+{y}")

    # --------- Hardcoded CSV loading ---------
    def _load_names_csv_hardcoded(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(base_dir, "database", "GENERIC_CAR.csv")
        if not os.path.exists(csv_path):
            print(f"GENERIC_CAR.csv not found at {csv_path}")
            return
        names_map = {}
        try:
            with open(csv_path, "r", newline="", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) < 2:
                        continue
                    try:
                        dec = int(row[0].strip())
                    except ValueError:
                        continue
                    name = row[1].strip()
                    if name:
                        names_map[dec] = name
        except Exception as e:
            messagebox.showerror("CSV Load Error", f"Failed to read GENERIC_CAR.csv:\n{e}")
            return
        self.names_map = names_map
        print(f"Loaded {len(names_map)} name(s) from GENERIC_CAR.csv")

    # --------- File list & labels (sorted A–Z by label) ---------
    def _refresh_file_combo_labels(self):
        labeled_pairs = []  # (label, path)
        for p in self.selected_paths:
            base = os.path.basename(p)
            stem, _ = os.path.splitext(base)
            label = base
            try:
                dec_value = int(stem, 16)
                if dec_value in self.names_map:
                    name = self.names_map[dec_value]
                    label = f"{name} — {base}"   # prepend name
            except ValueError:
                pass
        # keep order stable by sorting on label lowercased
            labeled_pairs.append((label, p))

        labeled_pairs.sort(key=lambda t: t[0].lower())
        self.display_labels = [lbl for (lbl, _p) in labeled_pairs]
        self.display_paths = [p for (_lbl, p) in labeled_pairs]

        self.file_combo["values"] = self.display_labels
        if self.display_labels:
            current = self.file_combo.get()
            if current in self.display_labels:
                self.file_combo.current(self.display_labels.index(current))
            else:
                self.file_combo.current(0)

    # ---------- Standard "Load Files…" ----------
    def load_files(self):
        paths = filedialog.askopenfilenames(title="Select CARS files", filetypes=[("All files", "*.*")])
        if not paths:
            return
        self.selected_paths = list(paths)
        self.file_cache.clear()
        self._refresh_file_combo_labels()
        self.refresh_view()

    # ---------- Load from list (CSV of decimal IDs) ----------
    def _index_files_by_stem(self, folder: str) -> dict[str, str]:
        """Return {UPPERCASE_STEM: full_path} for all files in folder."""
        idx = {}
        try:
            for name in os.listdir(folder):
                full = os.path.join(folder, name)
                if not os.path.isfile(full):
                    continue
                stem, _ext = os.path.splitext(name)
                idx[stem.upper()] = full
        except Exception as e:
            messagebox.showerror("Folder error", f"Failed to index folder:\n{e}")
        return idx

    def load_files_from_list(self):
        list_csv = filedialog.askopenfilename(
            title="Select CSV list (column 1 = decimal IDs)",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not list_csv:
            return

        folder = filedialog.askdirectory(title="Select folder that contains the files")
        if not folder:
            return

        by_stem = self._index_files_by_stem(folder)
        targets, missing = [], []

        try:
            with open(list_csv, "r", newline="", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row:
                        continue
                    try:
                        dec = int(row[0].strip())
                    except ValueError:
                        continue
                    stem = dec_to_hex_stem(dec)
                    full = by_stem.get(stem)
                    if full:
                        targets.append(full)
                    else:
                        missing.append(f"{dec} -> {stem}")
        except Exception as e:
            messagebox.showerror("CSV Load Error", f"Failed to read list CSV:\n{e}")
            return

        # Dedup preserve order
        seen, ordered_paths = set(), []
        for p in targets:
            if p not in seen:
                ordered_paths.append(p)
                seen.add(p)

        self.selected_paths = ordered_paths
        self.file_cache.clear()
        self._refresh_file_combo_labels()
        self.refresh_view()

        msg = [
            "Load from list complete.",
            f"Folder: {folder}",
            f"CSV: {os.path.basename(list_csv)}",
            f"Files matched/loaded: {len(ordered_paths)}",
        ]
        if missing:
            msg.append(f"Missing (no matching filename stem): {len(missing)}")
            preview = "\n".join(missing[:20])
            if len(missing) > 20:
                preview += f"\n... and {len(missing)-20} more"
            msg.append(preview)
        messagebox.showinfo("Load from list", "\n".join(msg))

    def _current_selected_path(self):
        idx = self.file_combo.current()
        if idx is None or idx < 0 or idx >= len(self.display_paths):
            return None
        return self.display_paths[idx]

    def refresh_view(self):
        if not self.display_paths or self.file_combo.current() == -1:
            self.items_panel.clear()
            self.status.configure(text="No file loaded.")
            return

        path = self._current_selected_path()
        if path is None:
            self.items_panel.clear()
            self.status.configure(text="Invalid selection.")
            return

        if path in self.file_cache:
            parsed = self.file_cache[path]
        else:
            try:
                parsed = parse_file(path)
                self.file_cache[path] = parsed
            except Exception as e:
                self.items_panel.clear()
                messagebox.showerror("Parse Error", f"{os.path.basename(path)}:\n{e}")
                self.status.configure(text=f"Failed to parse: {os.path.basename(path)}")
                return

        self.items_panel.populate(parsed["items"])
        self.status.configure(text=f"{os.path.basename(path)} — parsed {len(parsed['items'])} item(s)")

    # --------- Batch remove (by Type) ---------
    def batch_remove_dialog(self):
        if not self.selected_paths:
            messagebox.showinfo("Batch remove", "Load files first.")
            return
    
        dlg = tk.Toplevel(self)
        dlg.title("Batch remove")
        dlg.transient(self)
        dlg.grab_set()
    
        # Type selection
        ttk.Label(dlg, text="Part Type:").grid(row=0, column=0, padx=10, pady=(12, 4), sticky="w")
        type_pairs = sorted(PART_TYPE_NAMES.items(), key=lambda kv: kv[0])  # numeric order
        choices = [f"{num} — {name}" for num, name in type_pairs]
        type_var = tk.StringVar(value=choices[0])
        ttk.Combobox(dlg, state="readonly", values=choices, textvariable=type_var, width=32)\
            .grid(row=1, column=0, padx=10, pady=(0, 8), sticky="w")
    
        # Category targeting
        ttk.Label(dlg, text="Target Category (uint32; decimal or 0x..):").grid(row=2, column=0, padx=10, pady=(0, 2), sticky="w")
        cat_var = tk.StringVar(value="0")
        cat_entry = ttk.Entry(dlg, textvariable=cat_var, width=20)
        cat_entry.grid(row=3, column=0, padx=10, pady=(0, 8), sticky="w")
    
        # Checkbox: delete all parts of this type
        all_types_var = tk.BooleanVar(value=False)  # unchecked by default => category-sensitive
        def _toggle_cat(*_):
            cat_entry.configure(state=("disabled" if all_types_var.get() else "normal"))
        all_chk = ttk.Checkbutton(dlg, text="Delete ALL parts of this type", variable=all_types_var, command=_toggle_cat)
        all_chk.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="w")
        _toggle_cat()
    
        # Buttons
        btns = ttk.Frame(dlg)
        btns.grid(row=5, column=0, padx=10, pady=(0, 12), sticky="e")
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(
            btns, text="OK",
            command=lambda: self._do_batch_remove(dlg, type_var.get(), cat_var.get(), all_types_var.get())
        ).pack(side="right")
    
        self._center_window(dlg)
        dlg.wait_window(dlg)

    def _do_batch_remove(self, dlg, choice_str: str, cat_str: str, delete_all_of_type: bool):
        dlg.destroy()
        try:
            type_value = int(choice_str.split("—", 1)[0].strip())
            category_value = None if delete_all_of_type else int(cat_str.strip(), 0)  # allow 0x.. too
        except Exception:
            messagebox.showerror("Batch remove", "Invalid inputs.")
            return
    
        # Confirm if acting on multiple files
        if not self._confirm_multi_file_action("remove parts"):
            return
    
        total_files = len(self.selected_paths)
        total_removed, errors = 0, []
    
        for path in self.selected_paths:
            try:
                if delete_all_of_type:
                    removed, _old, _new = remove_type_from_file(path, type_value)
                else:
                    removed, _old, _new = remove_type_category_from_file(path, type_value, category_value)
                total_removed += removed
                if removed and path in self.file_cache:
                    del self.file_cache[path]
            except Exception as e:
                errors.append(f"{os.path.basename(path)}: {e}")
    
        self.refresh_view()
    
        mode = "Type ONLY" if delete_all_of_type else f"Type & Category ({category_value})"
        msg = [
            "Batch remove finished.",
            f"Mode: {mode}",
            f"Type: {type_value} — {PART_TYPE_NAMES.get(type_value, 'Unknown')}",
            f"Files processed: {total_files}",
            f"Items removed: {total_removed}",
        ]
        if errors:
            msg.append("\nErrors:")
            msg.extend(errors)
        messagebox.showinfo("Batch remove", "\n".join(msg))

    # --------- Batch replace (by Type & Category) ---------
    def batch_replace_dialog(self):
        if not self.selected_paths:
            messagebox.showinfo("Batch replace", "Load files first.")
            return
    
        dlg = tk.Toplevel(self)
        dlg.title("Batch replace item (by Type & Category)")
        dlg.transient(self)
        dlg.grab_set()
    
        rowi = 0
        ttk.Label(dlg, text="Target Part Type (to find):").grid(row=rowi, column=0, padx=10, pady=(12, 4), sticky="w")
        type_pairs = sorted(PART_TYPE_NAMES.items(), key=lambda kv: kv[0])
        type_choices = [f"{num} — {name}" for num, name in type_pairs]
        target_type_var = tk.StringVar(value=type_choices[0])
        ttk.Combobox(dlg, state="readonly", values=type_choices, textvariable=target_type_var, width=32)\
            .grid(row=rowi+1, column=0, padx=10, pady=(0, 10), sticky="w")
        rowi += 2
    
        ttk.Label(dlg, text="Target Category (uint32; decimal or 0x..):").grid(row=rowi, column=0, padx=10, pady=(0, 2), sticky="w")
        target_cat_var = tk.StringVar(value="0")
        ttk.Entry(dlg, textvariable=target_cat_var, width=20).grid(row=rowi+1, column=0, padx=10, pady=(0, 10), sticky="w")
        rowi += 2
    
        ttk.Label(dlg, text="New Category (uint32):").grid(row=rowi, column=0, padx=10, pady=(0, 2), sticky="w")
        new_cat_var = tk.StringVar(value="0")
        ttk.Entry(dlg, textvariable=new_cat_var, width=20).grid(row=rowi+1, column=0, padx=10, pady=(0, 8), sticky="w")
        rowi += 2
    
        # Retain ID checkbox + New ID field
        retain_id_var = tk.BooleanVar(value=False)
        def _toggle_new_id():
            id_state = "disabled" if retain_id_var.get() else "normal"
            new_id_entry.configure(state=id_state)
    
        retain_chk = ttk.Checkbutton(dlg, text="Retain part ID", variable=retain_id_var, command=_toggle_new_id)
        retain_chk.grid(row=rowi, column=0, padx=10, pady=(0, 4), sticky="w")
        rowi += 1
    
        ttk.Label(dlg, text="New ID (uint32):").grid(row=rowi, column=0, padx=10, pady=(0, 2), sticky="w")
        new_id_var = tk.StringVar(value="0")
        new_id_entry = ttk.Entry(dlg, textvariable=new_id_var, width=20)
        new_id_entry.grid(row=rowi+1, column=0, padx=10, pady=(0, 12), sticky="w")
        _toggle_new_id()  # initialize state
        rowi += 2
    
        btns = ttk.Frame(dlg)
        btns.grid(row=rowi, column=0, padx=10, pady=(0, 12), sticky="e")
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(
            btns, text="OK",
            command=lambda: self._do_batch_replace_precise(
                dlg,
                target_type_str=target_type_var.get(),
                target_cat_str=target_cat_var.get(),
                new_cat_str=new_cat_var.get(),
                new_id_str=new_id_var.get(),
                retain_id=retain_id_var.get(),
            )
        ).pack(side="right")
    
        self._center_window(dlg)
        dlg.wait_window(dlg)

    def _do_batch_replace_precise(self,
                                dlg,
                                target_type_str: str,
                                target_cat_str: str,
                                new_cat_str: str,
                                new_id_str: str,
                                retain_id: bool):
        dlg.destroy()
        try:
            target_type = int(target_type_str.split("—", 1)[0].strip())
            target_category = int(target_cat_str.strip(), 0)
            new_category = int(new_cat_str.strip(), 0)
            new_id = None if retain_id else int(new_id_str.strip(), 0)
        except Exception:
            messagebox.showerror("Batch replace", "Invalid inputs. Use uint32 numbers (e.g., 123 or 0x7B).")
            return
    
        # Confirm if multiple files
        if not self._confirm_multi_file_action("replace parts"):
            return
    
        total_files = len(self.selected_paths)
        files_modified, errors = 0, []
    
        for path in self.selected_paths:
            try:
                changed = replace_type_category_in_file(
                    path,
                    target_type=target_type,
                    target_category=target_category,
                    new_id=new_id,                  # None => keep existing
                    new_type=target_type,           # keep same type per your rule
                    new_category=new_category,
                )
                if changed:
                    files_modified += 1
                    if path in self.file_cache:
                        del self.file_cache[path]
            except Exception as e:
                errors.append(f"{os.path.basename(path)}: {e}")
    
        self.refresh_view()
    
        msg = [
            "Batch replace finished.",
            f"Target: Type={target_type} — {PART_TYPE_NAMES.get(target_type, 'Unknown')}, Category={target_category}",
            ("Replaced with: Category="
            f"{new_category} and retained ID" if new_id is None else
            f"Replaced with: ID={new_id}, Category={new_category}"),
            f"Files processed: {total_files}",
            f"Files modified: {files_modified}",
        ]
        if errors:
            msg.append("\nErrors:")
            msg.extend(errors)
        messagebox.showinfo("Batch replace", "\n".join(msg))

    # --------- Batch add (insert sorted by Type) ---------
    def batch_add_dialog(self):
        if not self.selected_paths:
            messagebox.showinfo("Batch add", "Load files first.")
            return

        dlg = tk.Toplevel(self)
        dlg.title("Batch add item")
        dlg.transient(self)
        dlg.grab_set()

        rowi = 0
        ttk.Label(dlg, text="New Type:").grid(row=rowi, column=0, padx=10, pady=(12, 4), sticky="w")
        type_pairs = sorted(PART_TYPE_NAMES.items(), key=lambda kv: kv[0])
        type_choices = [f"{num} — {name}" for num, name in type_pairs]
        new_type_var = tk.StringVar(value=type_choices[0])
        ttk.Combobox(dlg, state="readonly", values=type_choices, textvariable=new_type_var, width=32)\
            .grid(row=rowi+1, column=0, padx=10, pady=(0, 10), sticky="w")
        rowi += 2

        ttk.Label(dlg, text="New Category (uint32; decimal or 0x..):").grid(row=rowi, column=0, padx=10, pady=(0, 2), sticky="w")
        new_cat_var = tk.StringVar(value="0")
        ttk.Entry(dlg, textvariable=new_cat_var, width=20).grid(row=rowi+1, column=0, padx=10, pady=(0, 10), sticky="w")
        rowi += 2

        ttk.Label(dlg, text="New ID (uint32; decimal or 0x..):").grid(row=rowi, column=0, padx=10, pady=(0, 2), sticky="w")
        new_id_var = tk.StringVar(value="0")
        ttk.Entry(dlg, textvariable=new_id_var, width=20).grid(row=rowi+1, column=0, padx=10, pady=(0, 12), sticky="w")
        rowi += 2

        btns = ttk.Frame(dlg)
        btns.grid(row=rowi, column=0, padx=10, pady=(0, 12), sticky="e")
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(
            btns, text="OK",
            command=lambda: self._do_batch_add(
                dlg,
                new_type_str=new_type_var.get(),
                new_cat_str=new_cat_var.get(),
                new_id_str=new_id_var.get(),
            )
        ).pack(side="right")
        self._center_window(dlg)
        dlg.wait_window(dlg)

    def _do_batch_add(self, dlg, new_type_str: str, new_cat_str: str, new_id_str: str):
        dlg.destroy()
        try:
            new_type = int(new_type_str.split("—", 1)[0].strip())
            new_category = int(new_cat_str.strip(), 0)  # decimal or 0x..
            new_id = int(new_id_str.strip(), 0)        # decimal or 0x..
        except Exception:
            messagebox.showerror("Batch add", "Invalid inputs. Use uint32 numbers (e.g., 123 or 0x7B).")
            return
            
        if not self._confirm_multi_file_action("add parts"):
            return

        total_files = len(self.selected_paths)
        files_written, errors = 0, []

        for path in self.selected_paths:
            try:
                add_item_sorted_by_type(path, new_id=new_id, new_type=new_type, new_category=new_category)
                files_written += 1
                if path in self.file_cache:
                    del self.file_cache[path]
            except Exception as e:
                errors.append(f"{os.path.basename(path)}: {e}")

        self.refresh_view()

        msg = [
            "Batch add finished.",
            f"Inserted triple: ID={new_id}, Type={new_type} — {PART_TYPE_NAMES.get(new_type, 'Unknown')}, Category={new_category}",
            f"Files processed: {total_files}",
            f"Files modified: {files_written}",
        ]
        if errors:
            msg.append("\nErrors:")
            msg.extend(errors)
        messagebox.showinfo("Batch add", "\n".join(msg))

if __name__ == "__main__":
    App().mainloop()
