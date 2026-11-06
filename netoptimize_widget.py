import ctypes
import sys
import os
import json
import queue
import tempfile
import shutil
import fnmatch
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox, ttk, scrolledtext, filedialog
import psutil
import time
import threading
import subprocess
import socket
import ipaddress
import sqlite3
from datetime import datetime
import csv
import re

# ===================== 字体 =====================
FONT_FAMILY = "Microsoft YaHei UI"


def pick_font(root):
    """优先选用系统里更精致的无衬线字体，找不到再回退。"""
    global FONT_FAMILY
    try:
        fams = set(tkfont.families(root))
    except Exception:
        return
    for name in ("HarmonyOS Sans SC", "MiSans", "Microsoft YaHei UI", "微软雅黑"):
        if name in fams:
            FONT_FAMILY = name
            return

# ===================== 路径与配置 =====================
def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

APP_DIR = app_dir()
DB_PATH = os.path.join(APP_DIR, "net_log.db")
CONFIG_PATH = os.path.join(APP_DIR, "net_config.json")
CREATE_NO_WINDOW = 0x08000000


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ===================== SQLite 日志数据库 =====================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS operate_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        action TEXT,
        result TEXT
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS ping_record (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        target TEXT,
        packet_sent INTEGER,
        packet_lost INTEGER,
        loss_rate REAL,
        avg_delay REAL,
        raw_text TEXT
    )
    ''')
    conn.commit()
    conn.close()


def write_log(action, result):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO operate_log(time, action, result) VALUES (?,?,?)", (t, action, result))
    conn.commit()
    conn.close()


def write_ping_log(target, sent, lost, loss_rate, avg_delay, raw_text):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute('''INSERT INTO ping_record
    (time,target,packet_sent,packet_lost,loss_rate,avg_delay,raw_text)
    VALUES (?,?,?,?,?,?,?)''', (t, target, sent, lost, loss_rate, avg_delay, raw_text))
    conn.commit()
    conn.close()


def get_nic_list():
    nics = []
    for name in psutil.net_if_addrs().keys():
        if "Loopback" not in name and "lo" not in name:
            nics.append(name)
    return nics


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


if not is_admin():
    if getattr(sys, "frozen", False):
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        params = subprocess.list2cmdline(sys.argv)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    sys.exit(0)


def get_all_private_ip():
    res = []
    for nic_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip_str = addr.address
                if ip_str == "127.0.0.1":
                    continue
                try:
                    ip_obj = ipaddress.IPv4Address(ip_str)
                    if ip_obj.is_private:
                        res.append((nic_name, ip_str))
                except Exception:
                    continue
    return res


def get_nic_full_info(nic_name):
    info = {
        "mac": "未知",
        "ip": "未知",
        "netmask": "未知",
        "gateway": "未知"
    }
    addrs = psutil.net_if_addrs().get(nic_name, [])
    for addr in addrs:
        if addr.family == psutil.AF_LINK:
            info["mac"] = addr.address
        if addr.family == socket.AF_INET:
            info["ip"] = addr.address
            info["netmask"] = addr.netmask
    return info


def fmt_speed(n):
    if n < 1024:
        return f"{n} B/s"
    elif n < 1024 * 1024:
        return f"{n/1024:.1f} KB/s"
    else:
        val = n / (1024 * 1024)
        if val > 10:
            return f"{val:.1f} MB/s"
        else:
            return f"{val:.2f} MB/s"


def fmt_speed_short(n):
    """悬浮球用的紧凑格式，避免文字撑出球体。"""
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n/1024:.0f}K"
    val = n / (1024 * 1024)
    return f"{val:.1f}M" if val < 10 else f"{val:.0f}M"


# ===================== 文件缓存清理 =====================
def cache_dir_size(path, pattern=None):
    if not path or not os.path.isdir(path):
        return 0
    total = 0
    if pattern:
        try:
            for name in os.listdir(path):
                if fnmatch.fnmatch(name.lower(), pattern):
                    try:
                        total += os.path.getsize(os.path.join(path, name))
                    except OSError:
                        pass
        except OSError:
            pass
        return total
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def cache_clean_dir(path, pattern=None):
    """删除目录内容或匹配的缓存文件，返回释放的字节数。占用中的文件自动跳过。"""
    if not path or not os.path.isdir(path):
        return 0
    freed = 0
    if pattern:
        try:
            names = os.listdir(path)
        except OSError:
            return 0
        for name in names:
            if not fnmatch.fnmatch(name.lower(), pattern):
                continue
            fp = os.path.join(path, name)
            try:
                size = os.path.getsize(fp)
                os.remove(fp)
                freed += size
            except OSError:
                pass
        return freed

    # 保护当前正在运行的 PyInstaller 单文件解压目录，避免自删
    protected = set()
    mei = getattr(sys, "_MEIPASS", None)
    if mei:
        protected.add(os.path.normcase(os.path.abspath(mei)))

    try:
        entries = os.listdir(path)
    except OSError:
        return 0
    for entry in entries:
        fp = os.path.join(path, entry)
        if entry.upper().startswith("_MEI"):
            continue
        if os.path.normcase(os.path.abspath(fp)) in protected:
            continue
        try:
            if os.path.isdir(fp) and not os.path.islink(fp):
                before = cache_dir_size(fp)
                shutil.rmtree(fp, ignore_errors=True)
                after = cache_dir_size(fp) if os.path.exists(fp) else 0
                freed += max(0, before - after)
            else:
                size = os.path.getsize(fp)
                os.remove(fp)
                freed += size
        except OSError:
            continue
    return freed


class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong),
                ("i64Size", ctypes.c_longlong),
                ("i64NumItems", ctypes.c_longlong)]


def recycle_bin_size():
    try:
        info = SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(info)
        ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
        return int(info.i64Size)
    except Exception:
        return 0


def empty_recycle_bin():
    before = recycle_bin_size()
    try:
        # 0x7 = 无确认框 | 无进度条 | 无声音
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x7)
    except Exception:
        return 0
    return before


class CanvasButton:
    def __init__(self, canvas, x, y, w, h, text, bg_color, hover_color, command,
                 fg_color="#334155", font=None, radius=10,
                 outline="#e3e9f2"):
        if font is None:
            font = (FONT_FAMILY, 9, "bold")
        self.canvas = canvas
        self.base_x = x
        self.base_y = y
        self.w = w
        self.h = h
        self.text = text
        self.base_bg = bg_color
        self.bg = bg_color
        self.hover_bg = hover_color
        self.fg = fg_color
        self.font = font
        self.command = command
        self.scale = 1.0
        self.r = radius
        self.outline = outline
        self.id_rect = None
        self.id_text = None
        self.is_hover = False
        self.draw()

    def draw(self):
        self.canvas.delete(self.id_rect)
        self.canvas.delete(self.id_text)
        s = self.scale
        cx = self.base_x + self.w / 2
        cy = self.base_y + self.h / 2
        x1 = cx - (self.w * s) / 2
        y1 = cy - (self.h * s) / 2
        x2 = cx + (self.w * s) / 2
        y2 = cy + (self.h * s) / 2
        pts = [
            x1 + self.r, y1, x2 - self.r, y1, x2, y1, x2, y1 + self.r,
            x2, y2 - self.r, x2, y2, x2 - self.r, y2, x1 + self.r, y2,
            x1, y2, x1, y2 - self.r, x1, y1 + self.r, x1, y1
        ]
        self.id_rect = self.canvas.create_polygon(pts, smooth=True, fill=self.bg, outline=self.outline)
        self.id_text = self.canvas.create_text(cx, cy, text=self.text, font=self.font, fill=self.fg)

    def check_pos(self, mx, my):
        cx = self.base_x + self.w / 2
        cy = self.base_y + self.h / 2
        x1 = cx - self.w / 2
        y1 = cy - self.h / 2
        x2 = cx + self.w / 2
        y2 = cy + self.h / 2
        return x1 <= mx <= x2 and y1 <= my <= y2

    def on_enter(self):
        self.is_hover = True
        self.scale = 1.03
        self.bg = self.hover_bg
        self.draw()

    def on_leave(self):
        self.is_hover = False
        self.scale = 1.0
        self.bg = self.base_bg
        self.draw()

    def click(self):
        self.command()


class SimpleCheck:
    """自绘复选框，保证在白色卡片上清晰可见。"""
    def __init__(self, parent, var, command=None):
        self.var = var
        self.command = command
        self.hover = False
        self.canvas = tk.Canvas(parent, width=20, height=20, bg="#ffffff",
                                highlightthickness=0, bd=0, cursor="hand2")
        self.canvas.bind("<Button-1>", self._toggle)
        self.canvas.bind("<Enter>", self._enter)
        self.canvas.bind("<Leave>", self._leave)
        self.var.trace_add("write", lambda *a: self.draw())
        self.draw()

    def _pts(self):
        x1, y1, x2, y2, r = 2, 2, 18, 18, 5
        return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
                x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
                x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]

    def draw(self):
        self.canvas.delete("all")
        if self.var.get():
            self.canvas.create_polygon(self._pts(), smooth=True,
                                       fill="#2563eb", outline="#2563eb")
            self.canvas.create_text(10, 10, text="✓", fill="white",
                                    font=(FONT_FAMILY, 8, "bold"))
        else:
            outline = "#93b4f8" if self.hover else "#cbd5e1"
            self.canvas.create_polygon(self._pts(), smooth=True,
                                       fill="#ffffff", outline=outline, width=1)

    def _toggle(self, e=None):
        self.var.set(not self.var.get())
        if self.command:
            self.command()

    def _enter(self, e=None):
        self.hover = True
        self.draw()

    def _leave(self, e=None):
        self.hover = False
        self.draw()


class NetFloatWidget:
    def __init__(self, root):
        init_db()
        self.root = root
        self.cfg = load_config()
        self.root.title("网络调试助手")
        self.root.attributes("-topmost", True)
        self.root.overrideredirect(True)
        self.root.withdraw()

        self.nic_list = get_nic_list()
        self.selected_nic = tk.StringVar()
        saved_nic = self.cfg.get("nic")
        if saved_nic in self.nic_list:
            self.selected_nic.set(saved_nic)
        elif self.nic_list:
            self.selected_nic.set(self.nic_list[0])
        else:
            self.selected_nic.set("以太网")

        self.expand = False
        self.dragging = False
        self.drag_offset_x = 0
        self.drag_offset_y = 0
        self._press_root = (0, 0)
        self._drag_moved = 0

        # ============ 配色 ============
        self.bg_main = "#eef2f8"
        self.card_bg = "#ffffff"
        self.shadow_color = "#dde5f0"
        self.border_color = "#dbe3ef"
        self.text_dark = "#1e293b"
        self.text_muted = "#7b8a9e"
        self.accent = "#2563eb"
        self.accent_dark = "#1d4ed8"
        self.color_down = "#2563eb"
        self.color_up = "#16a34a"
        self.TRANSPARENT_KEY = "#ff00ff"
        self.r_all = 14
        self.font_normal = (FONT_FAMILY, 10)
        self.font_speed = (FONT_FAMILY, 15, "bold")
        self.font_title = (FONT_FAMILY, 15, "bold")
        self.font_card_title = (FONT_FAMILY, 9)

        # 统一 ttk 控件风格
        style = ttk.Style(self.root)
        try:
            if "clam" in style.theme_names():
                style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Nic.TCombobox", fieldbackground="#ffffff", background="#ffffff",
                        bordercolor="#dbe3ef", lightcolor="#dbe3ef", darkcolor="#dbe3ef",
                        arrowcolor="#64748b", padding=5)
        style.map("Nic.TCombobox",
                  fieldbackground=[("readonly", "#ffffff")],
                  selectbackground=[("readonly", "#ffffff")],
                  selectforeground=[("readonly", "#1e293b")])
        style.configure("Vertical.TScrollbar", gripcount=0, background="#c7d2e3",
                        darkcolor="#eef2f8", lightcolor="#eef2f8", troughcolor="#f6f9fd",
                        bordercolor="#f6f9fd", arrowcolor="#94a3b8")
        style.map("Vertical.TScrollbar", background=[("active", "#aebcd2")])

        # ============ 悬浮球 ============
        self.float_win = tk.Toplevel(root)
        self.float_win.overrideredirect(True)
        self.float_win.attributes("-topmost", True)
        pos = self.cfg.get("float_pos") or [300, 300]
        try:
            fx, fy = int(pos[0]), int(pos[1])
        except Exception:
            fx, fy = 300, 300
        self.float_win.geometry(f"64x64+{fx}+{fy}")
        self.float_win.configure(bg=self.TRANSPARENT_KEY)
        self.float_win.attributes("-transparentcolor", self.TRANSPARENT_KEY)

        self.float_canvas = tk.Canvas(self.float_win, width=64, height=64,
                                      bg=self.TRANSPARENT_KEY, highlightthickness=0,
                                      cursor="hand2")
        self.float_canvas.pack()
        self.float_halo = self.float_canvas.create_oval(1, 1, 63, 63, fill="#e6efff", outline="")
        self.float_oval = self.float_canvas.create_oval(4, 4, 60, 60, fill=self.accent, outline="")
        self.float_down_id = self.float_canvas.create_text(
            32, 26, text="0B", fill="white", font=(FONT_FAMILY,10, "bold"))
        self.float_up_id = self.float_canvas.create_text(
            32, 43, text="↑ 0B", fill="#dbeafe", font=(FONT_FAMILY,7))

        self.float_canvas.bind("<ButtonPress-1>", self.on_float_press)
        self.float_canvas.bind("<B1-Motion>", self.on_float_move)
        self.float_canvas.bind("<ButtonRelease-1>", self.on_float_release)
        self.float_canvas.bind("<Button-3>", self.show_float_menu)
        self.float_canvas.bind("<Enter>", lambda e: self.float_canvas.itemconfigure(self.float_halo, fill="#cde0ff"))
        self.float_canvas.bind("<Leave>", lambda e: self.float_canvas.itemconfigure(self.float_halo, fill="#e6efff"))

        self.float_menu = tk.Menu(self.float_win, tearoff=0)
        self.float_menu.add_command(label="显示 / 隐藏面板", command=self.toggle)
        self.float_menu.add_separator()
        self.float_menu.add_command(label="退出", command=self.exit_app)

        # ============ 主窗口固定尺寸 ============
        self.panel_w = 440
        self.panel_h = 700
        self.root.geometry(f"{self.panel_w}x{self.panel_h}")

        self.canvas_panel = tk.Canvas(self.root, width=self.panel_w, height=self.panel_h,
                                      bg=self.bg_main, highlightthickness=0)
        self.canvas_panel.pack()

        # 外层圆角卡片（双层柔光投影）
        self.draw_round_rect(self.canvas_panel, 14, 14, self.panel_w - 7, self.panel_h - 6,
                             r=self.r_all, fill="#e8eef8", outline="")
        self.draw_round_rect(self.canvas_panel, 11, 11, self.panel_w - 9, self.panel_h - 9,
                             r=self.r_all, fill=self.bg_main, outline=self.border_color, width=1)

        # ============ 顶部渐变头图 ============
        self.draw_round_rect(self.canvas_panel, 20, 16, self.panel_w - 16, 98,
                             r=16, fill="#c8d8f2", outline="")
        self.draw_gradient_round_rect(self.canvas_panel, 18, 14, self.panel_w - 18, 96,
                                      r=16, top="#2563eb", bottom="#4f8df7")
        self.draw_round_rect(self.canvas_panel, 32, 30, 60, 58, r=9, fill="white", outline="")
        self.canvas_panel.create_text(46, 44, text="N", font=(FONT_FAMILY, 13, "bold"),
                                      fill=self.accent)
        self.canvas_panel.create_text(72, 38, text="网络调试助手",
                                      font=(FONT_FAMILY, 15, "bold"), fill="white", anchor="w")
        self.canvas_panel.create_text(72, 60, text="网络诊断 · DNS 优选 · 缓存清理",
                                      font=(FONT_FAMILY, 8), fill="#dbeafe", anchor="w")

        # 网卡下拉
        self.canvas_panel.create_text(32, 120, text="网卡", font=(FONT_FAMILY, 9),
                                      fill=self.text_muted, anchor="w")
        nic_combo = ttk.Combobox(self.root, textvariable=self.selected_nic, values=self.nic_list,
                                 state="readonly", font=(FONT_FAMILY, 10), style="Nic.TCombobox")
        nic_combo.place(x=68, y=106, width=340)
        nic_combo.bind("<<ComboboxSelected>>", self.on_nic_change)

        # ============ 网速双卡片 ============
        self.speed_card_x1 = 28
        self.speed_card_y1 = 148
        self.speed_card_x2 = self.panel_w - 28
        self.speed_card_y2 = 262
        self.draw_round_rect(self.canvas_panel, self.speed_card_x1 + 2, self.speed_card_y1 + 3,
                             self.speed_card_x2 + 2, self.speed_card_y2 + 3, r=self.r_all,
                             fill="#dfe7f3", outline="")
        self.draw_gradient_round_rect(self.canvas_panel, self.speed_card_x1, self.speed_card_y1,
                                      self.speed_card_x2, self.speed_card_y2, r=self.r_all,
                                      top="#ffffff", bottom="#f6faff")
        self.draw_round_rect(self.canvas_panel, self.speed_card_x1, self.speed_card_y1,
                             self.speed_card_x2, self.speed_card_y2, r=self.r_all,
                             fill="", outline=self.border_color)
        mid_x = (self.speed_card_x1 + self.speed_card_x2) / 2
        self.canvas_panel.create_line(mid_x, self.speed_card_y1 + 32,
                                      mid_x, self.speed_card_y2 - 32, fill="#e2e8f2")
        self.canvas_panel.create_text(self.speed_card_x1 + 20, self.speed_card_y1 + 28,
                                      text="下载速度", font=self.font_card_title,
                                      fill=self.text_muted, anchor="w")
        self.canvas_panel.create_text(mid_x + 20, self.speed_card_y1 + 28,
                                      text="上传速度", font=self.font_card_title,
                                      fill=self.text_muted, anchor="w")
        # 网速数字按可用宽度自动选字号，避免顶到中间分割线
        self._speed_fonts = {s: tkfont.Font(family=FONT_FAMILY, size=s, weight="bold")
                             for s in (11, 12, 13, 14)}
        self.text_down_id = self.canvas_panel.create_text(
            self.speed_card_x1 + 20, self.speed_card_y1 + 70, text="0 B/s",
            font=self._speed_fonts[14], fill=self.color_down, anchor="w")
        self.text_up_id = self.canvas_panel.create_text(
            mid_x + 20, self.speed_card_y1 + 70, text="0 B/s",
            font=self._speed_fonts[14], fill=self.color_up, anchor="w")

        # ============ 滚动容器 ============
        scroll_frame_outer = tk.Frame(self.root, bg=self.bg_main)
        scroll_frame_outer.place(x=22, y=274, width=396, height=406)

        self.scroll_canvas = tk.Canvas(scroll_frame_outer, bg=self.card_bg, highlightthickness=1,
                                       highlightbackground="#dbe3ef")
        scrollbar = ttk.Scrollbar(scroll_frame_outer, orient="vertical", command=self.scroll_canvas.yview)
        self.scroll_inner_frame = tk.Frame(self.scroll_canvas, bg=self.card_bg)

        self.scroll_canvas.configure(yscrollcommand=scrollbar.set)
        self.scroll_canvas.create_window((0, 0), window=self.scroll_inner_frame, anchor="nw")

        self.scroll_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def _on_mousewheel(event):
            delta = int(-(event.delta / 120))
            self.scroll_canvas.yview_scroll(delta, "units")
        self.scroll_canvas.bind("<MouseWheel>", _on_mousewheel)
        self.scroll_inner_frame.bind("<MouseWheel>", _on_mousewheel)

        self.btn_list = []
        self.build_buttons()

        self.scroll_canvas.bind("<Motion>", self.on_scroll_mouse_move)
        self.scroll_canvas.bind("<Button-1>", self.on_scroll_click)
        self.root.bind("<MouseWheel>", _on_mousewheel)

        # ============ 网速采集（后台线程只写数据，UI 由主线程刷新） ============
        self.run_flag = True
        self.speed_history_down = []
        self.speed_history_up = []
        self.last_down = 0
        self.last_up = 0
        self._latest_speed = (0, 0)
        self.speed_thread = threading.Thread(target=self.speed_loop, daemon=True)
        self.speed_thread.start()
        self.root.after(500, self.poll_speed)
        self.root.after(150, self.clamp_float)

    # ===================== UI 构建 =====================
    def build_buttons(self):
        styles = {
            "blue": ("#eaf2ff", "#d5e6ff", "#1d4ed8"),
            "green": ("#eaf8f1", "#d3f0e0", "#15803d"),
            "red": ("#ffeded", "#ffd9da", "#b91c1c"),
            "amber": ("#fff7e0", "#ffeabb", "#b45309"),
            "gray": ("#f2f5f9", "#e3e8ef", "#475569"),
        }
        groups = [
            ("DNS 设置", [
                ("切换阿里DNS", "blue", self.dns_ali),
                ("切换腾讯DNS", "blue", self.dns_tencent),
                ("切换百度DNS", "blue", self.dns_baidu),
                ("恢复自动DNS", "blue", self.dns_auto),
                ("刷新DNS缓存", "blue", self.flush_dns),
                ("DNS 批量测速", "blue", self.dns_test_all),
                ("自动优选 DNS", "blue", self.auto_best_dns),
            ]),
            ("诊断与信息", [
                ("查看本机 IP", "green", self.show_ip),
                ("网卡详情", "green", self.show_nic_detail),
                ("完整 IPConfig", "green", self.show_ipconfig_all),
                ("查看监听端口", "green", self.show_listen_port),
                ("Ping 测试 DNS", "green", self.ping_test),
                ("长 Ping 丢包测试", "green", self.long_ping_loss_test),
                ("Tracert 路由追踪", "green", self.tracert_test),
                ("MTU 探测设置", "green", self.mtu_tool),
                ("网速图表", "amber", self.show_speed_chart),
                ("清理文件缓存", "amber", self.clean_cache_tool),
                ("查看日志", "green", self.show_log),
                ("导出 CSV 日志", "green", self.export_csv_log),
            ]),
            ("高危操作", [
                ("清除 ARP 缓存", "red", self.flush_arp),
                ("释放 DHCP IP", "red", self.ip_release),
                ("续订 DHCP IP", "red", self.ip_renew),
                ("重置 Winsock", "red", self.reset_winsock),
                ("重置 TCP/IP 栈", "red", self.reset_tcpip),
            ]),
            ("其他", [
                ("收起面板", "gray", self.hide_panel),
                ("退出程序", "gray", self.exit_app),
            ]),
        ]

        start_x = 8
        btn_w = 174
        btn_h = 38
        gap_x = 8
        gap_y = 10
        content_w = 364

        y = 8
        primary = CanvasButton(
            self.scroll_canvas, start_x, y, content_w, 44, "一键网络体检",
            self.accent, self.accent_dark, self.health_check,
            fg_color="white", font=(FONT_FAMILY, 12, "bold"), radius=12, outline="")
        self.btn_list.append(primary)
        y += 44 + 12

        group_colors = {"DNS 设置": "#3b82f6", "诊断与信息": "#22c55e",
                        "高危操作": "#ef4444", "其他": "#94a3b8"}
        for title, items in groups:
            self.scroll_canvas.create_oval(start_x + 2, y + 5, start_x + 10, y + 13,
                                           fill=group_colors.get(title, "#94a3b8"), outline="")
            self.scroll_canvas.create_text(start_x + 16, y, text=title, anchor="nw",
                                           font=(FONT_FAMILY, 9, "bold"), fill="#94a3b8")
            y += 24
            for idx, (txt, style_key, cmd) in enumerate(items):
                col = idx % 2
                row = idx // 2
                bx = start_x + col * (btn_w + gap_x)
                by = y + row * (btn_h + gap_y)
                bg, hover, fg = styles[style_key]
                btn = CanvasButton(self.scroll_canvas, bx, by, btn_w, btn_h, txt,
                                   bg, hover, cmd, fg_color=fg,
                                   font=(FONT_FAMILY, 10))
                self.btn_list.append(btn)
            rows = (len(items) + 1) // 2
            y += rows * (btn_h + gap_y) + 8

        self.scroll_canvas.configure(scrollregion=(0, 0, content_w + 16, y + 8))

    def draw_round_rect(self, canvas, x1, y1, x2, y2, r, **kw):
        pts = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1
        ]
        return canvas.create_polygon(pts, smooth=True, **kw)

    def draw_gradient_round_rect(self, canvas, x1, y1, x2, y2, r, top, bottom):
        """用逐行线段画圆角渐变，比纯色卡片更有层次。"""
        def rgb(c):
            c = c.lstrip("#")
            return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        r1, g1, b1 = rgb(top)
        r2, g2, b2 = rgb(bottom)
        h = int(y2 - y1)
        if h <= 0:
            return
        for i in range(h):
            t = i / (h - 1) if h > 1 else 0
            col = "#%02x%02x%02x" % (
                int(r1 + (r2 - r1) * t),
                int(g1 + (g2 - g1) * t),
                int(b1 + (b2 - b1) * t))
            if i < r:
                dy = r - i
                dx = r - (r * r - dy * dy) ** 0.5
            elif i >= h - r:
                dy = r - (h - 1 - i)
                dx = r - (r * r - dy * dy) ** 0.5
            else:
                dx = 0
            canvas.create_line(x1 + dx, y1 + i + 0.5, x2 - dx, y1 + i + 0.5, fill=col)

    # ===================== 交互 =====================
    def on_scroll_mouse_move(self, event):
        mx = self.scroll_canvas.canvasx(event.x)
        my = self.scroll_canvas.canvasy(event.y)
        hovering = False
        for btn in self.btn_list:
            if btn.check_pos(mx, my):
                hovering = True
                if not btn.is_hover:
                    btn.on_enter()
            else:
                if btn.is_hover:
                    btn.on_leave()
        cursor = "hand2" if hovering else ""
        if self.scroll_canvas.cget("cursor") != cursor:
            self.scroll_canvas.configure(cursor=cursor)

    def on_scroll_click(self, event):
        mx = self.scroll_canvas.canvasx(event.x)
        my = self.scroll_canvas.canvasy(event.y)
        for btn in self.btn_list:
            if btn.check_pos(mx, my):
                btn.click()
                return

    def on_nic_change(self, event=None):
        self.save_pos()

    def on_float_press(self, e):
        self.dragging = True
        self._drag_moved = 0
        self._press_root = (e.x_root, e.y_root)
        self.drag_offset_x = e.x_root - self.float_win.winfo_x()
        self.drag_offset_y = e.y_root - self.float_win.winfo_y()

    def on_float_move(self, e):
        if not self.dragging:
            return
        px, py = self._press_root
        self._drag_moved = max(self._drag_moved, abs(e.x_root - px) + abs(e.y_root - py))
        old_x = self.float_win.winfo_x()
        old_y = self.float_win.winfo_y()
        nx = e.x_root - self.drag_offset_x
        ny = e.y_root - self.drag_offset_y
        self.float_win.geometry(f"+{nx}+{ny}")
        if self.expand:
            dx, dy = nx - old_x, ny - old_y
            self.root.geometry(f"+{self.root.winfo_x() + dx}+{self.root.winfo_y() + dy}")

    def on_float_release(self, e):
        if not self.dragging:
            return
        self.dragging = False
        if self._drag_moved < 6:
            self.toggle()
        else:
            self.clamp_float()
            self.save_pos()

    def show_float_menu(self, e):
        try:
            self.float_menu.tk_popup(e.x_root, e.y_root)
        finally:
            self.float_menu.grab_release()

    def clamp_float(self):
        """把悬浮球约束在虚拟屏幕范围内（支持多显示器）。"""
        try:
            u = ctypes.windll.user32
            left = u.GetSystemMetrics(76)
            top = u.GetSystemMetrics(77)
            width = u.GetSystemMetrics(78)
            height = u.GetSystemMetrics(79)
        except Exception:
            return
        w = self.float_win.winfo_width() or 64
        h = self.float_win.winfo_height() or 64
        x = self.float_win.winfo_x()
        y = self.float_win.winfo_y()
        nx = min(max(x, left), left + width - w)
        ny = min(max(y, top), top + height - h)
        dx, dy = nx - x, ny - y
        if dx or dy:
            self.float_win.geometry(f"+{nx}+{ny}")
            if self.expand:
                self.root.geometry(f"+{self.root.winfo_x() + dx}+{self.root.winfo_y() + dy}")

    def save_pos(self):
        cfg = load_config()
        cfg["float_pos"] = [self.float_win.winfo_x(), self.float_win.winfo_y()]
        cfg["nic"] = self.selected_nic.get()
        save_config(cfg)

    def show_panel(self):
        self.float_win.update_idletasks()
        fx = self.float_win.winfo_x()
        fy = self.float_win.winfo_y()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        if fx + 64 + self.panel_w > sw:
            px = fx - self.panel_w - 12
        else:
            px = fx + 64 + 8
        px = max(0, min(px, sw - self.panel_w))
        py = max(0, min(fy, sh - self.panel_h))
        self.root.geometry(f"{self.panel_w}x{self.panel_h}+{px}+{py}")
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.expand = True

    def hide_panel(self):
        self.root.withdraw()
        self.expand = False

    def toggle(self):
        self.hide_panel() if self.expand else self.show_panel()

    # ===================== 网速 =====================
    def speed_loop(self):
        old = psutil.net_io_counters()
        while self.run_flag:
            time.sleep(0.7)
            if not self.run_flag:
                break
            try:
                new = psutil.net_io_counters()
            except Exception:
                continue
            down_bytes = new.bytes_recv - old.bytes_recv
            up_bytes = new.bytes_sent - old.bytes_sent
            old = new
            self.last_down = down_bytes
            self.last_up = up_bytes
            self.speed_history_down.append(down_bytes)
            self.speed_history_up.append(up_bytes)
            if len(self.speed_history_down) > 60:
                self.speed_history_down.pop(0)
                self.speed_history_up.pop(0)
            self._latest_speed = (down_bytes, up_bytes)

    def poll_speed(self):
        if not self.run_flag:
            return
        d, u = self._latest_speed
        self.update_speed_ui(d, u)
        try:
            self.root.after(400, self.poll_speed)
        except tk.TclError:
            pass

    def fit_speed_font(self, text):
        """按文字宽度选择字号，保证不越过中间分割线。"""
        for size in (14, 13, 12, 11):
            if self._speed_fonts[size].measure(text) <= 158:
                return self._speed_fonts[size]
        return self._speed_fonts[11]

    def update_speed_ui(self, down_bytes, up_bytes):
        text_d = fmt_speed(down_bytes)
        text_u = fmt_speed(up_bytes)
        try:
            self.canvas_panel.itemconfigure(self.text_down_id, text=text_d,
                                            font=self.fit_speed_font(text_d))
            self.canvas_panel.itemconfigure(self.text_up_id, text=text_u,
                                            font=self.fit_speed_font(text_u))
            self.float_canvas.itemconfigure(self.float_down_id, text=fmt_speed_short(down_bytes))
            self.float_canvas.itemconfigure(self.float_up_id, text="↑ " + fmt_speed_short(up_bytes))
        except tk.TclError:
            pass

    # ===================== 一键网络体检 =====================
    def health_check(self):
        win = tk.Toplevel(self.root)
        win.title("一键网络体检")
        win.geometry("580x500")
        win.attributes("-topmost", True)
        win.configure(bg="#f5f8fd")
        win.resizable(False, False)

        current_nic = self.selected_nic.get()  # 主线程取值，线程里不再碰 Tk 变量

        header = tk.Frame(win, bg="#ffffff", highlightbackground="#dbe3ef", highlightthickness=1)
        header.pack(fill="x", padx=14, pady=(14, 8))
        tk.Label(header, text="网络体检报告", font=(FONT_FAMILY,13, "bold"),
                 bg="#ffffff", fg="#1e293b").pack(anchor="w", padx=14, pady=(10, 2))
        tk.Label(header, text=f"网卡：{current_nic}", font=(FONT_FAMILY, 9),
                 bg="#ffffff", fg="#7b8a9e").pack(anchor="w", padx=14, pady=(0, 10))

        body = tk.Frame(win, bg="#ffffff", highlightbackground="#dbe3ef", highlightthickness=1)
        body.pack(fill="both", expand=True, padx=14, pady=4)

        steps = ["本机 IPv4 地址", "默认网关", "网关连通性", "公网连通性", "域名解析", "外网端口连通"]
        rows = []
        for name in steps:
            row = tk.Frame(body, bg="#ffffff")
            row.pack(fill="x", padx=12, pady=3)
            icon = tk.Label(row, text="⏳", font=(FONT_FAMILY,10), bg="#ffffff",
                            fg="#94a3b8", width=2, anchor="w")
            icon.pack(side="left")
            tk.Label(row, text=name, font=(FONT_FAMILY,10), bg="#ffffff",
                     fg="#334155", width=13, anchor="w").pack(side="left")
            detail = tk.Label(row, text="等待检测…", font=(FONT_FAMILY, 9), bg="#ffffff",
                              fg="#94a3b8", anchor="w")
            detail.pack(side="left", fill="x", expand=True)
            rows.append((icon, detail))

        verdict = tk.Label(win, text="正在检测，请稍候…", font=(FONT_FAMILY,11, "bold"),
                           bg="#f5f8fd", fg="#2563eb", wraplength=540, justify="left")
        verdict.pack(fill="x", padx=18, pady=(8, 2))

        btns = tk.Frame(win, bg="#f5f8fd")
        btns.pack(fill="x", padx=14, pady=(2, 12))

        def rerun():
            win.destroy()
            self.health_check()

        tk.Button(btns, text="重新检测", command=rerun, bg="#e8f1ff", fg="#1d4ed8",
                  relief="flat", font=(FONT_FAMILY, 9), padx=14, pady=4).pack(side="left")
        tk.Button(btns, text="关闭", command=win.destroy, bg="#eef2f8", fg="#475569",
                  relief="flat", font=(FONT_FAMILY, 9), padx=14, pady=4).pack(side="right")

        q = queue.Queue()

        def emit(idx, state, detail):
            q.put((idx, state, detail))

        def worker():
            nic = current_nic
            info = get_nic_full_info(nic)
            ip = info.get("ip", "未知")
            ip_ok = bool(ip) and ip != "未知"
            emit(0, "ok" if ip_ok else "bad", f"{nic} → {ip}")

            gw = self.get_gateway()
            if gw:
                emit(1, "ok", gw)
            else:
                emit(1, "bad", "未找到默认网关")

            gw_ok = False
            if gw:
                ok, loss, avg = self.ping_stat(gw)
                if loss is not None and loss < 100:
                    gw_ok = True
                    emit(2, "ok" if loss == 0 else "warn",
                         f"丢包 {loss}%  平均 {self.fmt_ms(avg)}")
                elif ok:
                    emit(2, "bad", "请求超时（丢包 100%）")
                else:
                    emit(2, "bad", "无法执行 ping，请检查网卡状态")
            else:
                emit(2, "skip", "已跳过")

            pub_ok = False
            ok, loss, avg = self.ping_stat("223.5.5.5")
            if loss is not None and loss < 100:
                pub_ok = True
                emit(3, "ok" if loss == 0 else "warn",
                     f"223.5.5.5  丢包 {loss}%  平均 {self.fmt_ms(avg)}")
            else:
                emit(3, "bad", "223.5.5.5 无响应")

            dns_ok = False
            dns_ms = 0.0
            t0 = time.time()
            try:
                dns_ip = socket.gethostbyname("www.baidu.com")
                dns_ms = (time.time() - t0) * 1000
                dns_ok = True
                emit(4, "ok" if dns_ms < 400 else "warn",
                     f"{dns_ip}  ·  {dns_ms:.0f}ms")
            except Exception as e:
                emit(4, "bad", f"解析失败：{e}")

            tcp_ok = False
            t0 = time.time()
            try:
                s = socket.create_connection(("223.5.5.5", 443), timeout=3)
                s.close()
                tcp_ms = (time.time() - t0) * 1000
                tcp_ok = True
                emit(5, "ok", f"223.5.5.5:443  ·  {tcp_ms:.0f}ms")
            except Exception as e:
                emit(5, "bad", f"建连失败：{e}")

            if not ip_ok:
                text = "❌ 当前网卡没有有效的 IPv4 地址：请检查网线 / WiFi，或尝试释放并续订 DHCP。"
                color = "#dc2626"
            elif not gw:
                text = "❌ 未能获取默认网关：路由表异常，建议检查路由器 DHCP 或重置 TCP/IP 栈。"
                color = "#dc2626"
            elif not gw_ok:
                text = f"❌ 无法连通网关 {gw}：问题在本地链路（网线、交换机、路由器 LAN 口或 WiFi 信号）。"
                color = "#dc2626"
            elif not pub_ok and not tcp_ok:
                text = "⚠ 网关正常但访问不了公网：问题在路由器 WAN 侧（宽带拨号 / 上游线路 / 运营商）。"
                color = "#d97706"
            elif not pub_ok and tcp_ok:
                text = "✅ 外网 TCP 可通，但 ICMP 被限制：网络基本正常，部分程序可能误报「无连接」。"
                color = "#16a34a"
            elif not dns_ok:
                text = "⚠ 网络可达，但域名解析失败：DNS 异常，请到「DNS 设置」切换公共 DNS。"
                color = "#d97706"
            elif dns_ms >= 400:
                text = f"⚠ 网络可用，但域名解析偏慢（{dns_ms:.0f}ms）：建议更换更快的 DNS。"
                color = "#d97706"
            elif not tcp_ok:
                text = "⚠ 网络基本可用，但外网端口建连失败：可能存在端口限制或代理配置。"
                color = "#d97706"
            else:
                text = "✅ 网络状态良好：网关、公网、DNS 解析与外网端口均正常。"
                color = "#16a34a"
            q.put(("done", text, color))

        threading.Thread(target=worker, daemon=True).start()

        def poll():
            try:
                while True:
                    item = q.get_nowait()
                    if item[0] == "done":
                        verdict.config(text=item[1], fg=item[2])
                        write_log("一键网络体检", item[1])
                        return
                    idx, state, detail = item
                    icons = {"ok": ("✅", "#16a34a"), "warn": ("⚠", "#d97706"),
                             "bad": ("❌", "#dc2626"), "skip": ("－", "#94a3b8")}
                    sym, color = icons.get(state, ("⏳", "#94a3b8"))
                    icon, det = rows[idx]
                    icon.config(text=sym, fg=color)
                    det.config(text=detail, fg="#475569")
            except queue.Empty:
                pass
            except tk.TclError:
                return
            try:
                if win.winfo_exists():
                    win.after(120, poll)
            except tk.TclError:
                pass

        win.after(120, poll)

    def get_gateway(self):
        """从路由表取默认网关，失败再退回 ipconfig。"""
        ok, out, _ = self.run_cmd("route print -4")
        if ok:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    try:
                        ipaddress.IPv4Address(parts[2])
                        return parts[2]
                    except Exception:
                        continue
        ok, out, _ = self.run_cmd("ipconfig")
        if ok:
            for line in out.splitlines():
                if "网关" in line or "gateway" in line.lower():
                    for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", line):
                        if ip != "0.0.0.0":
                            return ip
        return None

    def ping_stat(self, target, count=4, timeout=800):
        """返回 (进程成功, 丢包率%, 平均延迟ms)，中英文系统都能解析。"""
        ok, out, err = self.run_cmd(f"ping -n {count} -w {timeout} {target}")
        text = out + err
        loss = None
        avg = None
        m = re.search(r"(\d+)%", text)
        if m:
            loss = int(m.group(1))
        m = re.search(r"(?:平均|Average)\s*[^0-9]{0,6}(\d+)ms", text, re.IGNORECASE)
        if m:
            avg = float(m.group(1))
        return ok, loss, avg

    @staticmethod
    def fmt_ms(avg):
        return "—" if avg is None else f"{avg:.0f}ms"

    # ===================== 文件缓存清理 =====================
    @staticmethod
    def human_size(n):
        n = int(n or 0)
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        if n < 1024 ** 3:
            return f"{n / 1024 / 1024:.1f} MB"
        return f"{n / 1024 ** 3:.2f} GB"

    def refresh_cache_total(self, targets, label):
        try:
            total = sum(t["size"] for t in targets if t["var"].get())
            label.config(text=f"当前勾选合计：{self.human_size(total)}")
        except tk.TclError:
            pass

    def clean_cache_tool(self):
        win = tk.Toplevel(self.root)
        win.title("文件缓存清理")
        win.geometry("640x540")
        win.attributes("-topmost", True)
        win.configure(bg="#f5f8fd")
        win.resizable(False, False)

        header = tk.Frame(win, bg="#ffffff", highlightbackground="#dbe3ef", highlightthickness=1)
        header.pack(fill="x", padx=14, pady=(14, 8))
        tk.Label(header, text="文件缓存清理", font=(FONT_FAMILY, 13, "bold"),
                 bg="#ffffff", fg="#1e293b").pack(anchor="w", padx=14, pady=(10, 2))
        tk.Label(header, text="仅清理临时文件与缩略图缓存，不会删除个人文档",
                 font=(FONT_FAMILY, 9), bg="#ffffff", fg="#7b8a9e").pack(anchor="w", padx=14, pady=(0, 10))

        body = tk.Frame(win, bg="#ffffff", highlightbackground="#dbe3ef", highlightthickness=1)
        body.pack(fill="both", expand=True, padx=14, pady=4)

        explorer_dir = os.path.join(
            os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Explorer")
        targets = [
            {"name": "用户临时文件", "path": tempfile.gettempdir(), "pattern": None,
             "desc": "程序运行产生的临时文件",
             "var": tk.BooleanVar(value=True), "size": 0, "label": None},
            {"name": "系统临时文件",
             "path": os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
             "pattern": None, "desc": "Windows 系统临时文件",
             "var": tk.BooleanVar(value=True), "size": 0, "label": None},
            {"name": "缩略图缓存", "path": explorer_dir, "pattern": "thumbcache_*.db",
             "desc": "资源管理器缩略图数据库",
             "var": tk.BooleanVar(value=True), "size": 0, "label": None},
            {"name": "回收站", "path": None, "pattern": None,
             "desc": "清空回收站（默认不勾选）",
             "var": tk.BooleanVar(value=False), "size": 0, "label": None},
        ]

        for t in targets:
            row = tk.Frame(body, bg="#ffffff")
            row.pack(fill="x", padx=12, pady=6)
            chk = SimpleCheck(row, t["var"],
                              lambda: self.refresh_cache_total(targets, total_label))
            chk.canvas.pack(side="left", padx=(0, 12))
            info = tk.Frame(row, bg="#ffffff")
            info.pack(side="left", fill="x", expand=True)
            tk.Label(info, text=t["name"], font=(FONT_FAMILY, 10, "bold"),
                     bg="#ffffff", fg="#334155", anchor="w").pack(anchor="w")
            path_txt = "清空回收站（删除后无法恢复）" if t["path"] is None else t["path"]
            if len(path_txt) > 56:
                path_txt = path_txt[:26] + " … " + path_txt[-26:]
            tk.Label(info, text=path_txt, font=(FONT_FAMILY, 8),
                     bg="#ffffff", fg="#94a3b8", anchor="w").pack(anchor="w")
            size_lbl = tk.Label(row, text="扫描中…", font=(FONT_FAMILY, 10, "bold"),
                                bg="#ffffff", fg="#2563eb", width=10, anchor="e")
            size_lbl.pack(side="right", padx=(10, 4))
            t["label"] = size_lbl

        total_label = tk.Label(win, text="正在统计缓存大小…", font=(FONT_FAMILY, 11, "bold"),
                               bg="#f5f8fd", fg="#1e293b", anchor="w")
        total_label.pack(fill="x", padx=18, pady=(8, 2))

        btns = tk.Frame(win, bg="#f5f8fd")
        btns.pack(fill="x", padx=14, pady=(2, 12))

        def start_clean():
            selected = [t for t in targets if t["var"].get()]
            if not selected:
                messagebox.showinfo("提示", "请至少勾选一项缓存。", parent=win)
                return
            names = "、".join(t["name"] for t in selected)
            if not messagebox.askyesno(
                    "确认清理", f"将清理：{names}\n删除后无法恢复，确定继续？", parent=win):
                return
            clean_btn.config(state="disabled", text="清理中…")
            q2 = queue.Queue()

            def work():
                freed_total = 0
                for t in selected:
                    if t["path"] is None:
                        freed = empty_recycle_bin()
                    else:
                        freed = cache_clean_dir(t["path"], t["pattern"])
                    freed_total += freed
                    q2.put(("item", t, freed))
                q2.put(("done", freed_total))

            def poll_clean():
                try:
                    while True:
                        item = q2.get_nowait()
                        if item[0] == "done":
                            total_freed = item[1]
                            total_label.config(
                                text=f"✅ 清理完成，共释放 {self.human_size(total_freed)}",
                                fg="#16a34a")
                            clean_btn.config(state="normal", text="开始清理")
                            write_log("清理文件缓存", f"释放 {self.human_size(total_freed)}")
                            return
                        t, freed = item[1], item[2]
                        t["size"] = max(0, t["size"] - freed)
                        t["label"].config(text=self.human_size(t["size"]), fg="#16a34a")
                except queue.Empty:
                    pass
                except tk.TclError:
                    return
                try:
                    if win.winfo_exists():
                        win.after(150, poll_clean)
                except tk.TclError:
                    pass

            threading.Thread(target=work, daemon=True).start()
            win.after(150, poll_clean)

        clean_btn = tk.Button(btns, text="开始清理", command=start_clean, bg="#2563eb", fg="white",
                              activebackground="#1d4ed8", activeforeground="white", relief="flat",
                              font=(FONT_FAMILY, 10, "bold"), padx=20, pady=5, cursor="hand2")
        clean_btn.pack(side="left")
        tk.Button(btns, text="关闭", command=win.destroy, bg="#eef2f8", fg="#475569",
                  activebackground="#e3e9f2", relief="flat", font=(FONT_FAMILY, 9),
                  padx=18, pady=5, cursor="hand2").pack(side="right")

        # 后台统计各项大小
        q = queue.Queue()
        remaining = [len(targets)]

        def scan():
            for idx, t in enumerate(targets):
                size = recycle_bin_size() if t["path"] is None else cache_dir_size(t["path"], t["pattern"])
                q.put((idx, size))

        def poll_scan():
            try:
                while True:
                    idx, size = q.get_nowait()
                    targets[idx]["size"] = size
                    targets[idx]["label"].config(text=self.human_size(size))
                    remaining[0] -= 1
            except queue.Empty:
                pass
            except tk.TclError:
                return
            self.refresh_cache_total(targets, total_label)
            if remaining[0] <= 0:
                return
            try:
                if win.winfo_exists():
                    win.after(120, poll_scan)
            except tk.TclError:
                pass

        threading.Thread(target=scan, daemon=True).start()
        win.after(120, poll_scan)

    # ===================== 原有功能 =====================
    def show_speed_chart(self):
        win = tk.Toplevel(self.root)
        win.title("网速历史图表")
        win.geometry("660x360")
        win.attributes("-topmost", True)
        c = tk.Canvas(win, bg="#ffffff", highlightthickness=0)
        c.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        def redraw():
            c.delete("all")
            w = c.winfo_width()
            h = c.winfo_height()
            if w < 120 or h < 100:
                win.after(600, redraw)
                return
            pad_left = 90
            pad_right = 20
            pad_top = 30
            pad_bottom = 40
            draw_left = pad_left
            draw_right = w - pad_right
            draw_top = pad_top
            draw_bottom = h - pad_bottom
            draw_w = draw_right - draw_left
            draw_h = draw_bottom - draw_top
            data_d = self.speed_history_down
            data_u = self.speed_history_up
            if len(data_d) < 2:
                c.create_text(w / 2, h / 2, text="采集数据中...", font=(FONT_FAMILY,11), fill="#666666")
                win.after(600, redraw)
                return
            maxv = max(max(data_d), max(data_u), 1)
            c.create_rectangle(draw_left, draw_top, draw_right, draw_bottom, outline="#bbbbbb", width=1)
            c.create_line(draw_left, draw_top, draw_left, draw_bottom, fill="#888888")
            c.create_line(draw_left, draw_bottom, draw_right, draw_bottom, fill="#888888")
            for i in range(0, 6):
                ratio = (5 - i) / 5
                y_pos = draw_top + draw_h * ratio
                c.create_line(draw_left, y_pos, draw_right, y_pos, fill="#e5e7eb", dash=(2, 2))
                lab_val = maxv * ratio
                lab_text = fmt_speed(lab_val)
                c.create_text(draw_left - 8, y_pos, text=lab_text, anchor="e",
                              font=(FONT_FAMILY,8), fill="#555555")
            c.create_rectangle(w - 160, 12, w - 135, 26, fill=self.color_down, outline="")
            c.create_text(w - 125, 19, text="下载", anchor="w", font=(FONT_FAMILY, 9))
            c.create_rectangle(w - 85, 12, w - 60, 26, fill=self.color_up, outline="")
            c.create_text(w - 50, 19, text="上传", anchor="w", font=(FONT_FAMILY, 9))
            step_x = draw_w / max(len(data_d) - 1, 1)
            pts_d = []
            pts_u = []
            for idx, v in enumerate(data_d):
                x = draw_left + idx * step_x
                y = draw_bottom - (v / maxv) * draw_h
                pts_d.extend([x, y])
            for idx, v in enumerate(data_u):
                x = draw_left + idx * step_x
                y = draw_bottom - (v / maxv) * draw_h
                pts_u.extend([x, y])
            c.create_line(pts_d, fill=self.color_down, width=2, smooth=True)
            c.create_line(pts_u, fill=self.color_up, width=2, smooth=True)
            win.after(600, redraw)
        redraw()

    def run_cmd(self, cmd):
        try:
            p = subprocess.run(cmd, capture_output=True, shell=True, text=False,
                               creationflags=CREATE_NO_WINDOW)
            try:
                out = p.stdout.decode("gbk", errors="replace")
            except Exception:
                out = p.stdout.decode("utf-8", errors="replace")
            try:
                err = p.stderr.decode("gbk", errors="replace")
            except Exception:
                err = p.stderr.decode("utf-8", errors="replace")
            return p.returncode == 0, out, err
        except Exception as e:
            return False, "", str(e)

    def ip_release(self):
        nic = self.selected_nic.get()
        ans = messagebox.askyesno("确认", "⚠释放网卡DHCP IP，网络会断开，确定继续？")
        if not ans:
            return
        ok, out, err = self.run_cmd(f'ipconfig /release "{nic}"')
        msg = "✅IP已释放" if ok else f"失败:{err}"
        messagebox.showinfo("结果", msg)
        write_log("释放DHCP IP", msg)

    def ip_renew(self):
        nic = self.selected_nic.get()
        ok, out, err = self.run_cmd(f'ipconfig /renew "{nic}"')
        msg = "✅DHCP IP续订完成" if ok else f"失败:{err}"
        messagebox.showinfo("结果", msg)
        write_log("续订DHCP IP", msg)

    def show_ipconfig_all(self):
        ok, out, err = self.run_cmd("ipconfig /all")
        win = tk.Toplevel(self.root)
        win.title("ipconfig /all完整信息")
        win.geometry("640x420")
        win.attributes("-topmost", True)
        st = scrolledtext.ScrolledText(win, font=(FONT_FAMILY, 9))
        st.pack(fill="both", expand=True, padx=10, pady=10)
        st.insert(tk.END, out if ok else err)
        st.config(state="disabled")
        write_log("查看ipconfig完整信息", "成功")

    def show_listen_port(self):
        win = tk.Toplevel(self.root)
        win.title("本机监听端口列表")
        win.geometry("620x400")
        win.attributes("-topmost", True)
        frm = ttk.Frame(win, padding=8)
        frm.pack(fill="both", expand=True)
        tree = ttk.Treeview(frm, columns=("proto", "port", "pid", "proc"), show="headings")
        tree.heading("proto", text="协议")
        tree.heading("port", text="端口")
        tree.heading("pid", text="PID")
        tree.heading("proc", text="进程名")
        tree.column("proto", width=60)
        tree.column("port", width=80)
        tree.column("pid", width=80)
        tree.column("proc", width=380)
        vsb = ttk.Scrollbar(frm, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        def load_port():
            for item in tree.get_children():
                tree.delete(item)
            try:
                conns = psutil.net_connections(kind="inet")
                for c in conns:
                    if c.status != psutil.CONN_LISTEN:
                        continue
                    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    port = c.laddr.port
                    pid = c.pid
                    pname = "未知"
                    if pid:
                        try:
                            p = psutil.Process(pid)
                            pname = p.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    tree.insert("", tk.END, values=(proto, port, pid, pname))
            except Exception as e:
                messagebox.showerror("错误", f"读取端口失败:{str(e)}")
        ttk.Button(frm, text="刷新列表", command=load_port).pack(pady=4)
        load_port()
        write_log("查看监听端口", "成功")

    def mtu_tool(self):
        win = tk.Toplevel(self.root)
        win.title("MTU探测与设置")
        win.geometry("460x300")
        win.attributes("-topmost", True)
        frm = ttk.Frame(win, padding=12)
        frm.pack(fill="x")
        ttk.Label(frm, text="探测目标IP:").grid(row=0, column=0, sticky="w")
        var_target = tk.StringVar(value="223.5.5.5")
        ttk.Entry(frm, textvariable=var_target, width=22).grid(row=0, column=1, padx=6)
        ttk.Label(frm, text="设置MTU值:").grid(row=1, column=0, sticky="w", pady=8)
        var_mtu = tk.StringVar(value="1500")
        ttk.Entry(frm, textvariable=var_mtu, width=22).grid(row=1, column=1, padx=6, pady=8)
        st = scrolledtext.ScrolledText(win, font=(FONT_FAMILY, 9), height=8)
        st.pack(fill="both", expand=True, padx=12, pady=4)

        def detect_mtu():
            tgt = var_target.get().strip()
            st.delete(1.0, tk.END)
            st.insert(tk.END, f"开始探测 {tgt} 最佳MTU...\n")
            best = 28
            for size in range(1472, 27, -2):
                ok, out, _ = self.run_cmd(f'ping -f -l {size} -n 1 -w 600 {tgt}')
                if ok:
                    best = size
                    break
            final_mtu = best + 28
            st.insert(tk.END, f"探测完成，最佳MTU:{final_mtu}\n提示：MTU=数据包大小+28字节IP头\n")

        def set_mtu_val():
            nic = self.selected_nic.get()
            try:
                mtu = int(var_mtu.get())
            except ValueError:
                messagebox.showerror("错误", "MTU必须是数字")
                return
            ok, out, err = self.run_cmd(f'netsh interface ipv4 set subinterface "{nic}" mtu={mtu} store=persistent')
            msg = f"✅MTU设置为{mtu}" if ok else f"失败:{err}"
            messagebox.showinfo("结果", msg)
            write_log(f"设置网卡MTU {nic}", msg)
        ttk.Button(frm, text="探测最佳MTU", command=detect_mtu).grid(row=2, column=0, pady=6)
        ttk.Button(frm, text="应用MTU", command=set_mtu_val).grid(row=2, column=1, pady=6)

    def flush_arp(self):
        ans = messagebox.askyesno("高危确认", "⚠清除ARP缓存，用于解决ARP冲突，确定继续？")
        if not ans:
            return
        ok, out, err = self.run_cmd("arp -d *")
        msg = "✅ ARP缓存已清除" if ok else f"失败:{err}"
        messagebox.showinfo("结果", msg)
        write_log("清除ARP缓存", msg)

    def long_ping_loss_test(self):
        win = tk.Toplevel(self.root)
        win.title("长Ping丢包率测试")
        win.geometry("520x320")
        win.attributes("-topmost", True)
        frm = ttk.Frame(win, padding=10)
        frm.pack(fill="x")
        ttk.Label(frm, text="目标地址:").grid(row=0, column=0, sticky="w")
        var_target = tk.StringVar(value="223.5.5.5")
        ttk.Entry(frm, textvariable=var_target, width=24).grid(row=0, column=1, padx=8)
        ttk.Label(frm, text="发包数量:").grid(row=0, column=2)
        var_cnt = tk.StringVar(value="20")
        ttk.Entry(frm, textvariable=var_cnt, width=8).grid(row=0, column=3, padx=4)
        st = scrolledtext.ScrolledText(win, font=(FONT_FAMILY, 9))
        st.pack(fill="both", expand=True, padx=10, pady=5)

        def do_ping():
            tgt = var_target.get().strip()
            try:
                cnt = int(var_cnt.get())
            except ValueError:
                messagebox.showerror("错误", "发包数量必须数字")
                return
            cmd = f'ping -n {cnt} -w 1000 {tgt}'
            ok, out, err = self.run_cmd(cmd)
            full = out + err
            st.delete(1.0, tk.END)
            st.insert(tk.END, full)
            sent = cnt
            lost = 0
            avg_delay = 0.0
            loss_rate = 0.0
            for line in full.splitlines():
                if "丢失" in line and "%" in line:
                    try:
                        loss_rate = float(line.replace("%", "").split()[-1])
                        lost = int(loss_rate / 100 * sent)
                    except Exception:
                        pass
                if "平均" in line:
                    try:
                        avg_delay = float(line.replace("ms", "").split()[-1])
                    except Exception:
                        pass
            write_ping_log(tgt, sent, lost, loss_rate, avg_delay, full[:1200])
            messagebox.showinfo("统计结果",
                                f"发包:{sent} 丢失:{lost}\n丢包率:{loss_rate:.1f}%\n平均延迟:{avg_delay:.1f}ms")
        ttk.Button(frm, text="开始测试", command=do_ping).grid(row=1, column=0, pady=8)
        ttk.Button(frm, text="关闭", command=win.destroy).grid(row=1, column=1, pady=8)

    def auto_best_dns(self):
        dns_list = [
            ("阿里DNS", "223.5.5.5"),
            ("腾讯DNS", "119.29.29.29"),
            ("百度DNS", "180.76.76.76"),
            ("Cloudflare", "1.1.1.1")
        ]
        res = []
        messagebox.showinfo("提示", "正在测速，请稍候...")
        for name, ip in dns_list:
            ok, out, _ = self.run_cmd(f"ping -n 4 -w 800 {ip}")
            avg = 9999.0
            for line in out.splitlines():
                if "平均" in line and "ms" in line:
                    try:
                        avg = float(line.replace("ms", "").split()[-1])
                    except Exception:
                        pass
            res.append((name, ip, avg))
        res.sort(key=lambda x: x[2])
        best_name, best_ip, best_ms = res[0]
        nic = self.selected_nic.get()
        self.run_cmd(f'netsh interface ip set dns "{nic}" static {best_ip}')
        msg = f"✅自动优选完成\n最优：{best_name} {best_ip}，平均延迟 {best_ms:.1f}ms\n已设置为网卡DNS"
        messagebox.showinfo("优选DNS结果", msg)
        write_log("自动优选DNS", msg)

    def export_csv_log(self):
        fp = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV表格", "*.csv")])
        if not fp:
            return
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        with open(fp, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["操作日志"])
            w.writerow(["时间", "动作", "结果"])
            cur.execute("SELECT time,action,result FROM operate_log ORDER BY id DESC")
            for row in cur.fetchall():
                w.writerow(row)
            w.writerow([])
            w.writerow(["Ping记录"])
            w.writerow(["时间", "目标", "发包数", "丢包数", "丢包率%", "平均延迟ms", "原始信息"])
            cur.execute("SELECT time,target,packet_sent,packet_lost,loss_rate,avg_delay,raw_text "
                        "FROM ping_record ORDER BY id DESC")
            for r in cur.fetchall():
                w.writerow(r)
        conn.close()
        messagebox.showinfo("完成", f"CSV已保存：{fp}")
        write_log("导出CSV日志", fp)

    def ping_test(self):
        ok, out, err = self.run_cmd("ping 223.5.5.5 -n 4")
        win = tk.Toplevel(self.root)
        win.title("Ping结果")
        win.geometry("560x340")
        win.attributes("-topmost", True)
        st = scrolledtext.ScrolledText(win, font=(FONT_FAMILY,10))
        st.pack(fill="both", expand=True, padx=12, pady=12)
        content = out if ok else err
        st.insert(tk.END, content)
        st.config(state="disabled")
        write_ping_log("223.5.5.5", 4, 0, 0.0, 0.0, content[:800])
        write_log("Ping测试DNS", "成功" if ok else "失败")

    def tracert_test(self):
        ok, out, err = self.run_cmd("tracert 223.5.5.5")
        win = tk.Toplevel(self.root)
        win.title("Tracert路由追踪")
        win.geometry("600x360")
        win.attributes("-topmost", True)
        st = scrolledtext.ScrolledText(win, font=(FONT_FAMILY,10))
        st.pack(fill="both", expand=True, padx=12, pady=12)
        content = out if ok else err
        st.insert(tk.END, content)
        st.config(state="disabled")
        write_log("Tracert路由追踪", "成功" if ok else err)

    def dns_test_all(self):
        dns_list = [("阿里", "223.5.5.5"), ("腾讯", "119.29.29.29"), ("百度", "180.76.76.76")]
        res_text = "=== DNS批量测速结果 ===\n"
        for name, ip in dns_list:
            ok, out, _ = self.run_cmd(f"ping {ip} -n 3")
            if ok:
                for line in out.splitlines():
                    if "平均" in line:
                        res_text += f"{name}({ip}) | {line.strip()}\n"
                        break
            else:
                res_text += f"{name}({ip}) | 请求超时\n"
        win = tk.Toplevel(self.root)
        win.title("DNS测速")
        win.geometry("420x260")
        win.attributes("-topmost", True)
        st = scrolledtext.ScrolledText(win, font=(FONT_FAMILY,10))
        st.pack(padx=12, pady=12, fill="both", expand=True)
        st.insert(tk.END, res_text)
        st.config(state="disabled")
        write_log("DNS批量测速", res_text)

    def show_log(self):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT * FROM operate_log ORDER BY id DESC LIMIT 30")
        rows = cur.fetchall()
        conn.close()
        win = tk.Toplevel(self.root)
        win.title("操作日志记录")
        win.geometry("520x360")
        win.attributes("-topmost", True)
        st = scrolledtext.ScrolledText(win, font=(FONT_FAMILY,10))
        st.pack(fill="both", expand=True, padx=12, pady=12)
        if not rows:
            st.insert(tk.END, "暂无操作日志")
        else:
            for r in rows:
                st.insert(tk.END, f"[{r[1]}] 动作：{r[2]}  结果：{r[3]}\n")
        st.config(state="disabled")

    def show_ip(self):
        data = get_all_private_ip()
        win = tk.Toplevel(self.root)
        win.title("本机私网IPv4地址")
        win.geometry("420x360")
        win.attributes("-topmost", True)
        f = tk.Frame(win, padx=18, pady=18)
        f.pack(fill="both", expand=True)
        if not data:
            tk.Label(f, text="未检测到私网IP", font=(FONT_FAMILY,10)).pack()
            return
        for idx, (nic, ip) in enumerate(data):
            row_frm = tk.Frame(f)
            row_frm.pack(anchor="w", pady=6, fill="x")
            tk.Label(row_frm, text=f"▌网卡：{nic}", font=(FONT_FAMILY,10, "bold")).grid(row=0, column=0, sticky="w")
            tk.Label(row_frm, text=f"IP：{ip}", font=(FONT_FAMILY,10), fg="#2563eb").grid(row=1, column=0, sticky="w")

            def copy_ip(txt=ip):
                win.clipboard_clear()
                win.clipboard_append(txt)
                messagebox.showinfo("提示", f"已复制IP：{txt}")
            ttk.Button(row_frm, text="复制IP", command=copy_ip).grid(row=0, column=1, rowspan=2, padx=10)
            if idx != len(data) - 1:
                ttk.Separator(f, orient="horizontal").pack(fill="x", pady=8)
        tk.Button(f, text="关闭", command=win.destroy, bg="#e8f1fc", relief="flat").pack(pady=14)
        write_log("查看本机IP", "成功")

    def show_nic_detail(self):
        nic = self.selected_nic.get()
        info = get_nic_full_info(nic)
        gw = self.get_gateway() or "未知"
        txt = f"""【网卡：{nic}】
MAC地址：{info['mac']}
IPv4地址：{info['ip']}
子网掩码：{info['netmask']}
默认网关：{gw}
"""
        messagebox.showinfo("网卡详细信息", txt)
        write_log("查看网卡详情", nic)

    def dns_ali(self):
        nic = self.selected_nic.get()
        ok, _, err = self.run_cmd(f'netsh interface ip set dns "{nic}" static 223.5.5.5')
        res_msg = "✅ 阿里DNS 223.5.5.5" if ok else f"失败：{err}"
        messagebox.showinfo("结果", res_msg)
        write_log(f"切换阿里DNS（网卡:{nic}）", "成功" if ok else err)

    def dns_tencent(self):
        nic = self.selected_nic.get()
        ok, _, err = self.run_cmd(f'netsh interface ip set dns "{nic}" static 119.29.29.29')
        res_msg = "✅ 腾讯DNS 119.29.29.29" if ok else f"失败：{err}"
        messagebox.showinfo("结果", res_msg)
        write_log(f"切换腾讯DNS（网卡:{nic}）", "成功" if ok else err)

    def dns_baidu(self):
        nic = self.selected_nic.get()
        ok, _, err = self.run_cmd(f'netsh interface ip set dns "{nic}" static 180.76.76.76')
        res_msg = "✅ 百度DNS 180.76.76.76" if ok else f"失败：{err}"
        messagebox.showinfo("结果", res_msg)
        write_log(f"切换百度DNS（网卡:{nic}）", "成功" if ok else err)

    def dns_auto(self):
        nic = self.selected_nic.get()
        ok, _, err = self.run_cmd(f'netsh interface ip set dns "{nic}" dhcp')
        res_msg = "✅ DNS恢复自动获取" if ok else f"失败：{err}"
        messagebox.showinfo("结果", res_msg)
        write_log(f"恢复自动DNS（网卡:{nic}）", "成功" if ok else err)

    def flush_dns(self):
        ok, _, err = self.run_cmd("ipconfig /flushdns")
        res_msg = "✅ DNS缓存刷新成功" if ok else f"失败：{err}"
        messagebox.showinfo("结果", res_msg)
        write_log("刷新DNS缓存", "成功" if ok else err)

    def reset_winsock(self):
        ans = messagebox.askyesno("高危确认", "⚠即将重置Winsock套接字，操作完成建议重启电脑。确定继续吗？")
        if not ans:
            return
        ok, _, err = self.run_cmd("netsh winsock reset")
        res_msg = "✅ Winsock重置，建议重启电脑" if ok else f"失败：{err}"
        messagebox.showinfo("提示", res_msg)
        write_log("重置Winsock", "成功" if ok else err)

    def reset_tcpip(self):
        ans = messagebox.askyesno("高危确认", "⚠即将重置TCP/IP协议栈，操作完成建议重启电脑。确定继续吗？")
        if not ans:
            return
        ok, _, err = self.run_cmd("netsh int ip reset")
        res_msg = "✅ TCP/IP栈重置，建议重启电脑" if ok else f"失败：{err}"
        messagebox.showinfo("提示", res_msg)
        write_log("重置TCP/IP栈", "成功" if ok else err)

    def exit_app(self):
        self.run_flag = False
        self.save_pos()
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        try:
            self.float_win.destroy()
        except tk.TclError:
            pass


if __name__ == "__main__":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass
    root = tk.Tk()
    pick_font(root)
    app = NetFloatWidget(root)
    root.mainloop()
