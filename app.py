import os
import re
import sqlite3
import threading
import subprocess
import requests
from datetime import datetime, timedelta
from pathlib import Path
import webbrowser
import customtkinter as ctk

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from config import validate_config
from alerter import start_alert_daemon, check_and_alert, is_telegram_connected
import log_parser
import auditor
import report_generator
import mitre_mapper
import analyzer

DB_PATH = Path(__file__).parent / "raven.db"

# ── Color Palette ──────────────────────────────────────────
BG_DARK      = "#0B0D0F"
BG_SURFACE   = "#12161A"
BG_CARD      = "#181C22"
BG_ELEVATED  = "#1E2329"
SIDEBAR_BG   = "#080A0C"
ACCENT       = "#00E5A0"
ACCENT_DIM   = "#00B87D"
CRITICAL     = "#FF3B5C"
HIGH_CLR     = "#FF9F1C"
MEDIUM_CLR   = "#00C8FF"
LOW_CLR      = "#6E7681"
SAFE_CLR     = "#00F58A"
TEXT_PRIMARY  = "#E6EDF3"
TEXT_SECONDARY= "#8B949E"
TEXT_MUTED    = "#484F58"
BORDER_CLR   = "#21262D"
HOVER_CLR    = "#161B22"

SEVERITY_COLORS = {
    "Critical": CRITICAL,
    "High": HIGH_CLR,
    "Medium": MEDIUM_CLR,
    "Low": LOW_CLR,
}

# ── Main Application ──────────────────────────────────────
class RavenApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RAVEN 2.0 — Autonomous Defense Matrix")
        self.geometry("1150x780")
        self.minsize(900, 600)
        self.configure(fg_color=BG_DARK)

        self.start_time = datetime.now()
        self._last_threat_count = -1
        self._current_tab = "dashboard"
        self._filter_severity = "All"
        self._geo_cache = {}
        self._reputation_cache = {}
        self._score_history = []
        self._prev_stats = {}
        self._scanline_y = 0.0

        # Grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        start_alert_daemon()

        self._build_top_header()
        self._build_sidebar()
        self._build_main_area()
        self._build_status_bar()

        self._show_dashboard()
        self._pulse_dot()
        self._update_clock()
        self._animate_scanline()
        self._tick_refresh()

    # ── Database ───────────────────────────────────────────
    def _db(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def _fetch_stats(self):
        conn = self._db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as n FROM threats")
        total = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM threats WHERE alerted=0 AND severity IN ('High','Critical')")
        alerts = c.fetchone()["n"]
        c.execute("SELECT severity, COUNT(*) as n FROM threats GROUP BY severity")
        sev = {r["severity"]: r["n"] for r in c.fetchall()}
        c.execute("SELECT COUNT(*) as n FROM audit_results WHERE status='FAIL'")
        fails = c.fetchone()["n"]
        score = max(0, 100 - sev.get("Critical",0)*15 - sev.get("High",0)*8 - sev.get("Medium",0)*3 - sev.get("Low",0)*1 - fails*5)
        conn.close()
        return total, alerts, score, sev, fails

    def _fetch_threats(self, severity_filter="All", limit=50):
        conn = self._db()
        c = conn.cursor()
        if severity_filter == "All":
            c.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,))
        else:
            c.execute(
                "SELECT * FROM threats WHERE severity=? ORDER BY timestamp DESC LIMIT ?",
                (severity_filter, limit),
            )
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def _fetch_audits(self):
        conn = self._db()
        c = conn.cursor()
        c.execute("SELECT * FROM audit_results ORDER BY timestamp DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def _fetch_honeypot_events(self, limit=10):
        conn = self._db()
        c = conn.cursor()
        c.execute("SELECT * FROM honeypot_events ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    # ── IP Geolocation ────────────────────────────────────
    _PRIVATE_RE = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")

    def _geolocate_ip(self, ip: str) -> str:
        """Returns a geo string for the IP. Uses cache and detects private ranges."""
        if ip in self._geo_cache:
            return self._geo_cache[ip]

        if self._PRIVATE_RE.match(ip):
            result = "Private Network"
            self._geo_cache[ip] = result
            return result

        # Return placeholder immediately; the real fetch happens in a thread
        self._geo_cache[ip] = "Locating…"
        threading.Thread(target=self._fetch_geo, args=(ip,), daemon=True).start()
        return self._geo_cache[ip]

    def _fetch_geo(self, ip: str) -> None:
        """Background worker that fetches geo data from ip-api.com."""
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=country,city,isp",
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                city = data.get("city", "Unknown")
                country = data.get("country", "Unknown")
                isp = data.get("isp", "Unknown")
                self._geo_cache[ip] = f"{city}, {country} — {isp}"
            else:
                self._geo_cache[ip] = "Lookup failed"
        except Exception:
            self._geo_cache[ip] = "Lookup failed"

    def _get_reputation(self, ip: str, progress_bar, score_label) -> None:
        """Fetches reputation asynchronously and updates UI."""
        if ip in self._reputation_cache:
            self._update_reputation_ui(self._reputation_cache[ip], progress_bar, score_label)
            return

        if self._PRIVATE_RE.match(ip):
            data = {"abuse_score": 0, "total_reports": 0}
            self._reputation_cache[ip] = data
            self._update_reputation_ui(data, progress_bar, score_label)
            return

        def worker():
            data = analyzer.check_ip_reputation(ip)
            self._reputation_cache[ip] = data
            self.after(0, lambda: self._update_reputation_ui(data, progress_bar, score_label))
            
        threading.Thread(target=worker, daemon=True).start()

    def _update_reputation_ui(self, data, progress_bar, score_label):
        try:
            score = data.get("abuse_score", 0)
            reports = data.get("total_reports", 0)
            
            if score > 50:
                color = CRITICAL
            elif score > 20:
                color = HIGH_CLR
            else:
                color = SAFE_CLR
                
            progress_bar.configure(progress_color=color)
            progress_bar.set(score / 100.0)
            score_label.configure(text=f"Reputation Risk: {score}/100 ({reports} reports)", text_color=color)
        except Exception:
            pass

    def _build_top_header(self):
        self.top_header = ctk.CTkFrame(self, height=52, corner_radius=0, fg_color="#080A0C", border_width=0)
        self.top_header.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.top_header.grid_propagate(False)
        self.top_header.grid_columnconfigure(1, weight=1)

        left_frame = ctk.CTkFrame(self.top_header, fg_color="transparent")
        left_frame.grid(row=0, column=0, sticky="w", padx=20, pady=12)
        
        self.pulse_label = ctk.CTkLabel(left_frame, text="●", font=ctk.CTkFont(size=14, weight="bold"), text_color=ACCENT)
        self.pulse_label.pack(side="left", padx=(0, 8))
        
        ctk.CTkLabel(left_frame, text="RAVEN 2.0 LIVE", font=ctk.CTkFont(size=14, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left")

        self.clock_label = ctk.CTkLabel(self.top_header, text="--:--:-- UTC", font=ctk.CTkFont(size=13, family="Courier"), text_color=TEXT_MUTED)
        self.clock_label.grid(row=0, column=1, pady=12)

        self.threat_badge = ctk.CTkLabel(self.top_header, text=" THREAT LEVEL: UNKNOWN ", font=ctk.CTkFont(size=12, weight="bold"), fg_color=TEXT_MUTED, text_color="#000", corner_radius=4)
        self.threat_badge.grid(row=0, column=2, sticky="e", padx=20, pady=12)

    def _pulse_dot(self):
        if not hasattr(self, 'pulse_label'): return
        current = self.pulse_label.cget("text_color")
        next_color = ACCENT_DIM if current == ACCENT else ACCENT
        self.pulse_label.configure(text_color=next_color)
        self.after(1000, self._pulse_dot)

    def _update_clock(self):
        if not hasattr(self, 'clock_label'): return
        utc_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.clock_label.configure(text=utc_now)
        self.after(1000, self._update_clock)
        
    def _animate_scanline(self):
        if hasattr(self, 'scanline') and self.scanline.winfo_exists():
            self._scanline_y += 0.0125
            if self._scanline_y > 1.0:
                self._scanline_y = 0.0
            self.scanline.place(relx=0, rely=self._scanline_y, relwidth=1.0)
        self.after(50, self._animate_scanline)

    # ── Sidebar ────────────────────────────────────────────
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=SIDEBAR_BG, border_width=0)
        sb.grid(row=1, column=0, rowspan=2, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_rowconfigure(9, weight=1)

        # Logo
        ctk.CTkLabel(sb, text="◈ RAVEN", font=ctk.CTkFont(size=28, weight="bold"), text_color=ACCENT).grid(row=0, column=0, padx=24, pady=(30, 0), sticky="w")
        ctk.CTkLabel(sb, text="  v2.0 Autonomous Defense", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).grid(row=1, column=0, padx=24, pady=(0, 30), sticky="w")

        # Separator
        ctk.CTkFrame(sb, height=1, fg_color=BORDER_CLR).grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 15))

        # Navigation buttons
        btn_cfg = dict(font=ctk.CTkFont(size=14), height=42, anchor="w", corner_radius=8)

        self.nav_dashboard = ctk.CTkButton(sb, text="  ◉  Dashboard", fg_color=BG_ELEVATED, text_color=ACCENT, hover_color=BG_CARD, command=self._show_dashboard, **btn_cfg)
        self.nav_dashboard.grid(row=3, column=0, padx=12, pady=3, sticky="ew")

        self.nav_threats = ctk.CTkButton(sb, text="  ⚡  Threat Feed", fg_color="transparent", text_color=TEXT_SECONDARY, hover_color=BG_CARD, command=self._show_threats, **btn_cfg)
        self.nav_threats.grid(row=4, column=0, padx=12, pady=3, sticky="ew")

        self.threat_badge_lbl = ctk.CTkLabel(self.nav_threats, text="", width=24, height=18, font=ctk.CTkFont(size=10, weight="bold"), fg_color=CRITICAL, text_color="#000", corner_radius=8)
        self.threat_badge_lbl.place(relx=0.85, rely=0.5, anchor="center")
        self.threat_badge_lbl.place_forget()
        self.threat_badge_lbl.bind("<Button-1>", lambda e: self._show_threats())

        self.nav_audit = ctk.CTkButton(sb, text="  ☰  Audit Results", fg_color="transparent", text_color=TEXT_SECONDARY, hover_color=BG_CARD, command=self._show_audit, **btn_cfg)
        self.nav_audit.grid(row=5, column=0, padx=12, pady=3, sticky="ew")

        self.nav_analytics = ctk.CTkButton(sb, text="  📊  Analytics", fg_color="transparent", text_color=TEXT_SECONDARY, hover_color=BG_CARD, command=self._show_analytics, **btn_cfg)
        self.nav_analytics.grid(row=6, column=0, padx=12, pady=3, sticky="ew")

        # Separator
        ctk.CTkFrame(sb, height=1, fg_color=BORDER_CLR).grid(row=7, column=0, sticky="ew", padx=16, pady=15)

        # Action buttons
        self.btn_scan = ctk.CTkButton(sb, text="  🛡  Run Full Scan", font=ctk.CTkFont(size=13, weight="bold"), height=40, fg_color=ACCENT, text_color="#000", hover_color=ACCENT_DIM, corner_radius=8, command=self._run_scan)
        self.btn_scan.grid(row=8, column=0, padx=16, pady=4, sticky="ew")

        self.btn_report = ctk.CTkButton(sb, text="  📄  Export PDF", font=ctk.CTkFont(size=13), height=38, fg_color="transparent", border_width=1, border_color=BORDER_CLR, text_color=TEXT_PRIMARY, hover_color=BG_CARD, corner_radius=8, command=self._generate_report)
        self.btn_report.grid(row=9, column=0, padx=16, pady=4, sticky="new")

        # Bottom section
        self.btn_inject = ctk.CTkButton(sb, text="  ⚠  Inject Test Threat", font=ctk.CTkFont(size=12), height=36, fg_color="transparent", border_width=1, border_color=CRITICAL, text_color=CRITICAL, hover_color="#1A0A10", corner_radius=8, command=self._test_alert)
        self.btn_inject.grid(row=10, column=0, padx=16, pady=(10, 6), sticky="sew")

        self.btn_clear = ctk.CTkButton(sb, text="  ✕  Clear Database", font=ctk.CTkFont(size=12), height=36, fg_color="transparent", border_width=1, border_color=TEXT_MUTED, text_color=TEXT_MUTED, hover_color="#1A0A10", corner_radius=8, command=self._clear_db)
        self.btn_clear.grid(row=11, column=0, padx=16, pady=(0, 20), sticky="sew")

        self._nav_buttons = {
            "dashboard": self.nav_dashboard,
            "threats": self.nav_threats,
            "audit": self.nav_audit,
            "analytics": self.nav_analytics,
        }

    def _set_active_nav(self, name):
        for key, btn in self._nav_buttons.items():
            if key == name:
                btn.configure(fg_color=BG_ELEVATED, text_color=ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_SECONDARY)
        self._current_tab = name

    # ── Main Content Area ──────────────────────────────────
    def _build_main_area(self):
        self.content = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        self.content.grid(row=1, column=1, sticky="nsew", padx=0, pady=0)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)
        
        self.scanline = ctk.CTkFrame(self.content, height=1, fg_color="#004d36")
        self.scanline.place(relx=0, rely=0, relwidth=1.0)

    def _clear_content(self):
        for w in self.content.winfo_children():
            if w != getattr(self, 'scanline', None):
                w.destroy()

    # ── Status Bar ─────────────────────────────────────────
    def _build_status_bar(self):
        self.statusbar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color=BG_SURFACE, border_width=0)
        self.statusbar.grid(row=2, column=1, sticky="ew")
        self.statusbar.grid_columnconfigure(1, weight=1)

        self.status_left = ctk.CTkLabel(self.statusbar, text="● System Online", font=ctk.CTkFont(size=11), text_color=SAFE_CLR)
        self.status_left.grid(row=0, column=0, padx=12, pady=3, sticky="w")

        self.status_right = ctk.CTkLabel(self.statusbar, text="Last refresh: --", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED)
        self.status_right.grid(row=0, column=2, padx=12, pady=3, sticky="e")

        self.status_tg = ctk.CTkLabel(self.statusbar, text="", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED)
        self.status_tg.grid(row=0, column=1, padx=12, pady=3)

    def _update_status_bar(self):
        now = datetime.now().strftime("%H:%M:%S")
        self.status_right.configure(text=f"Last refresh: {now}")
        uptime = datetime.now() - self.start_time
        mins = int(uptime.total_seconds() // 60)
        secs = int(uptime.total_seconds() % 60)
        self.status_left.configure(text=f"● Online — Uptime {mins}m {secs}s")
        tg = "Telegram: Connected" if is_telegram_connected() else "Telegram: Offline"
        tg_clr = SAFE_CLR if is_telegram_connected() else TEXT_MUTED
        self.status_tg.configure(text=tg, text_color=tg_clr)

    # ── Dashboard Tab ──────────────────────────────────────
    def _show_dashboard(self):
        self._set_active_nav("dashboard")
        self._clear_content()

        # Header
        header = ctk.CTkFrame(self.content, fg_color=BG_DARK, height=50)
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="System Overview", font=ctk.CTkFont(size=22, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(header, text=datetime.now().strftime("%A, %B %d %Y"), font=ctk.CTkFont(size=13), text_color=TEXT_MUTED).pack(side="right")

        body = ctk.CTkFrame(self.content, fg_color=BG_DARK)
        body.grid(row=1, column=0, sticky="nsew", padx=20, pady=0)
        body.grid_columnconfigure((0, 1, 2, 3), weight=1)
        body.grid_rowconfigure(1, weight=1)

        total, alerts, score, sev, fails = self._fetch_stats()

        # Stat cards
        self._stat_score = self._make_stat_card(body, "SECURITY SCORE", str(score), self._score_color(score), "/ 100", 0, 0, "score")
        self._stat_threats = self._make_stat_card(body, "TOTAL THREATS", str(total), MEDIUM_CLR, "detected", 0, 1, "total")
        self._stat_alerts = self._make_stat_card(body, "ACTIVE ALERTS", str(alerts), CRITICAL if alerts > 0 else TEXT_MUTED, "unresolved", 0, 2, "alerts")
        self._stat_audits = self._make_stat_card(body, "AUDIT FAILURES", str(fails), HIGH_CLR if fails > 0 else TEXT_MUTED, "issues", 0, 3, "fails")

        # Recent threats preview
        preview_frame = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CLR)
        preview_frame.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(15, 5))
        preview_frame.grid_rowconfigure(1, weight=1)
        preview_frame.grid_columnconfigure(0, weight=6)
        preview_frame.grid_columnconfigure(1, weight=4)

        # Left Column: Threat Feed
        left_col = ctk.CTkFrame(preview_frame, fg_color="transparent")
        left_col.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=(0, 10))
        
        pf_header = ctk.CTkFrame(left_col, fg_color="transparent")
        pf_header.pack(fill="x", padx=10, pady=(15, 5))
        ctk.CTkLabel(pf_header, text="Recent Threats", font=ctk.CTkFont(size=16, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkButton(pf_header, text="View All →", font=ctk.CTkFont(size=12), width=80, height=28, fg_color="transparent", text_color=ACCENT, hover_color=BG_ELEVATED, command=self._show_threats).pack(side="right")

        self._dash_feed = ctk.CTkScrollableFrame(left_col, fg_color="transparent", scrollbar_button_color=BG_ELEVATED)
        self._dash_feed.pack(fill="both", expand=True, padx=0, pady=0)

        threats = self._fetch_threats(limit=10)
        if not threats:
            ctk.CTkLabel(self._dash_feed, text="No threats detected yet. System is clean.", font=ctk.CTkFont(size=14), text_color=TEXT_MUTED).pack(pady=40)
        else:
            for t in threats:
                self._make_threat_row(self._dash_feed, t)

        # Right Column: Honeypot Events
        right_col = ctk.CTkFrame(preview_frame, fg_color="transparent")
        right_col.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=(0, 10))
        
        hp_header = ctk.CTkFrame(right_col, fg_color="transparent")
        hp_header.pack(fill="x", padx=10, pady=(15, 5))
        ctk.CTkLabel(hp_header, text="Honeypot Events", font=ctk.CTkFont(size=16, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left")

        hp_feed = ctk.CTkScrollableFrame(right_col, fg_color="transparent", scrollbar_button_color=BG_ELEVATED)
        hp_feed.pack(fill="both", expand=True, padx=0, pady=0)

        hp_events = self._fetch_honeypot_events(limit=10)
        if not hp_events:
            ctk.CTkLabel(hp_feed, text="No honeypot events.", font=ctk.CTkFont(size=14), text_color=TEXT_MUTED).pack(pady=40)
        else:
            for e in hp_events:
                self._make_hp_row(hp_feed, e)

    def _make_stat_card(self, parent, title, value, color, subtitle, row, col, stat_key=""):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CLR)
        card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)

        strip = ctk.CTkFrame(card, fg_color=color, height=3, corner_radius=0)
        strip.grid(row=0, column=0, sticky="ew")

        prev = self._prev_stats.get(stat_key, 0)
        curr = float(value) if str(value).isdigit() else 0
        trend_str = ""
        if curr > prev:
            trend_str = " ▲"
        elif curr < prev:
            trend_str = " ▼"

        ctk.CTkLabel(card, text=title + trend_str, font=ctk.CTkFont(size=11, weight="bold"), text_color=TEXT_MUTED).grid(row=1, column=0, pady=(15, 0))
        lbl = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=38, weight="bold"), text_color=color)
        lbl.grid(row=2, column=0, pady=(2, 2))
        ctk.CTkLabel(card, text=subtitle, font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).grid(row=3, column=0, pady=(0, 18))
        return lbl

    def _score_color(self, score):
        if score > 80: return SAFE_CLR
        if score > 50: return HIGH_CLR
        return CRITICAL

    # ── Threat Feed Tab ────────────────────────────────────
    def _show_threats(self):
        self._set_active_nav("threats")
        self._clear_content()

        header = ctk.CTkFrame(self.content, fg_color=BG_DARK, height=50)
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text="Threat Feed", font=ctk.CTkFont(size=22, weight="bold"), text_color=TEXT_PRIMARY).grid(row=0, column=0, sticky="w")

        # Filter buttons
        filter_frame = ctk.CTkFrame(header, fg_color="transparent")
        filter_frame.grid(row=0, column=1, sticky="e")
        for sev in ["All", "Critical", "High", "Medium", "Low"]:
            clr = SEVERITY_COLORS.get(sev, TEXT_SECONDARY)
            is_active = self._filter_severity == sev
            ctk.CTkButton(
                filter_frame, text=sev, width=70, height=28,
                font=ctk.CTkFont(size=12, weight="bold" if is_active else "normal"),
                fg_color=BG_ELEVATED if is_active else "transparent",
                text_color=clr if sev != "All" else (ACCENT if is_active else TEXT_SECONDARY),
                border_width=1, border_color=BORDER_CLR, corner_radius=6,
                hover_color=BG_CARD,
                command=lambda s=sev: self._apply_filter(s)
            ).pack(side="left", padx=3)

        self._threat_feed = ctk.CTkScrollableFrame(self.content, fg_color=BG_DARK, scrollbar_button_color=BG_ELEVATED)
        self._threat_feed.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 5))

        threats = self._fetch_threats(self._filter_severity)
        if not threats:
            ctk.CTkLabel(self._threat_feed, text="No matching threats found.", font=ctk.CTkFont(size=14), text_color=TEXT_MUTED).pack(pady=50)
        else:
            for t in threats:
                self._make_threat_card(self._threat_feed, t)

    def _apply_filter(self, severity):
        self._filter_severity = severity
        self._show_threats()

    def _make_threat_row(self, parent, t):
        """Compact threat row for dashboard preview."""
        row = ctk.CTkFrame(parent, fg_color=BG_ELEVATED, corner_radius=6, height=36)
        row.pack(fill="x", padx=4, pady=3)

        sev_clr = SEVERITY_COLORS.get(t["severity"], TEXT_MUTED)

        # Severity dot
        ctk.CTkLabel(row, text="●", font=ctk.CTkFont(size=10), text_color=sev_clr, width=20).pack(side="left", padx=(12, 4))
        ctk.CTkLabel(row, text=t["event_type"], font=ctk.CTkFont(size=13, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, text=t["source_ip"], font=ctk.CTkFont(size=12), text_color=TEXT_SECONDARY).pack(side="left")
        ctk.CTkLabel(row, text=t["severity"], font=ctk.CTkFont(size=11, weight="bold"), text_color=sev_clr).pack(side="right", padx=12)
        ts = t["timestamp"]
        if len(ts) > 16:
            ts = ts[11:19]
        ctk.CTkLabel(row, text=ts, font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).pack(side="right", padx=(0, 8))

    def _make_hp_row(self, parent, e):
        row = ctk.CTkFrame(parent, fg_color=BG_ELEVATED, corner_radius=6, height=36)
        row.pack(fill="x", padx=4, pady=3)
        
        try:
            event_time = datetime.fromisoformat(e["timestamp"])
            delta = datetime.now() - event_time
            mins = int(delta.total_seconds() // 60)
            if mins == 0:
                rel_time = "Just now"
            elif mins < 60:
                rel_time = f"{mins} min ago"
            elif mins < 1440:
                rel_time = f"{mins // 60} hrs ago"
            else:
                rel_time = f"{mins // 1440} days ago"
        except Exception:
            rel_time = "Unknown"

        ctk.CTkLabel(row, text="●", font=ctk.CTkFont(size=10), text_color=HIGH_CLR, width=20).pack(side="left", padx=(12, 4))
        ctk.CTkLabel(row, text=e["attacker_ip"], font=ctk.CTkFont(size=13, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, text=f"Port {e['port']}", font=ctk.CTkFont(size=12), text_color=TEXT_SECONDARY).pack(side="left")
        ctk.CTkLabel(row, text=rel_time, font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).pack(side="right", padx=(0, 12))

    def _make_threat_card(self, parent, t):
        """Full threat card for threat feed."""
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CLR)
        card.pack(fill="x", padx=4, pady=5)

        sev = t["severity"]
        sev_clr = SEVERITY_COLORS.get(sev, TEXT_MUTED)

        # Header
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(14, 6))

        ctk.CTkLabel(hdr, text=f"  {sev.upper()}  ", font=ctk.CTkFont(size=11, weight="bold"), fg_color=sev_clr, text_color="#000", corner_radius=4).pack(side="left")
        ctk.CTkLabel(hdr, text=t["event_type"], font=ctk.CTkFont(size=15, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left", padx=12)
        ctk.CTkLabel(hdr, text=t["timestamp"], font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).pack(side="right")

        # Source IP
        ctk.CTkLabel(card, text=f"Source IP: {t['source_ip']}", font=ctk.CTkFont(size=13), text_color=TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 1))

        # Reputation Bar
        rep_frame = ctk.CTkFrame(card, fg_color="transparent")
        rep_frame.pack(fill="x", padx=16, pady=(2, 4))
        rep_label = ctk.CTkLabel(rep_frame, text="Reputation Risk: Locating...", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED)
        rep_label.pack(side="left", padx=(0, 10))
        rep_pb = ctk.CTkProgressBar(rep_frame, width=150, height=8, corner_radius=4)
        rep_pb.set(0)
        rep_pb.pack(side="left")
        
        self._get_reputation(t["source_ip"], rep_pb, rep_label)

        # Geo location
        geo_text = self._geolocate_ip(t["source_ip"])
        ctk.CTkLabel(card, text=f"📍 {geo_text}", font=ctk.CTkFont(size=12), text_color=TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 4))

        # AI Analysis
        if t.get("ai_analysis"):
            ai_frame = ctk.CTkFrame(card, fg_color=BG_ELEVATED, corner_radius=6)
            ai_frame.pack(fill="x", padx=16, pady=(4, 4))
            ctk.CTkLabel(ai_frame, text=f"🤖  {t['ai_analysis']}", font=ctk.CTkFont(size=12), text_color=TEXT_SECONDARY, wraplength=700, justify="left").pack(padx=14, pady=10, anchor="w")
        else:
            # Add bottom padding if no AI analysis
            ctk.CTkFrame(card, fg_color="transparent", height=4).pack()

        # MITRE ATT&CK (Below AI Analysis)
        mitre = mitre_mapper.get_mitre(t["event_type"])
        if mitre["tactic_id"] != "Unknown":
            mitre_frame = ctk.CTkFrame(card, fg_color="transparent")
            mitre_frame.pack(fill="x", padx=16, pady=(0, 14))
            
            m_text = f"🛡 MITRE: {mitre['tactic_name']} ({mitre['tactic_id']}) ➔ {mitre['technique_name']} "
            ctk.CTkLabel(mitre_frame, text=m_text, font=ctk.CTkFont(size=11, weight="bold"), text_color="#7C3AED").pack(side="left")
            
            link_lbl = ctk.CTkLabel(mitre_frame, text=f"({mitre['technique_id']})", font=ctk.CTkFont(size=11, weight="bold", underline=True), text_color="#7C3AED", cursor="hand2")
            link_lbl.pack(side="left")
            
            # Use default argument binding to capture the correct technique_id in the lambda
            link_lbl.bind("<Button-1>", lambda e, tid=mitre['technique_id']: webbrowser.open(f"https://attack.mitre.org/techniques/{tid}"))
        else:
            ctk.CTkFrame(card, fg_color="transparent", height=10).pack()

    # ── Audit Tab ──────────────────────────────────────────
    def _show_audit(self):
        self._set_active_nav("audit")
        self._clear_content()

        header = ctk.CTkFrame(self.content, fg_color=BG_DARK, height=50)
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Compliance Audit Results", font=ctk.CTkFont(size=22, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left")

        feed = ctk.CTkScrollableFrame(self.content, fg_color=BG_DARK, scrollbar_button_color=BG_ELEVATED)
        feed.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 5))

        audits = self._fetch_audits()
        if not audits:
            ctk.CTkLabel(feed, text="No audit results yet. Click 'Run Full Scan' to start.", font=ctk.CTkFont(size=14), text_color=TEXT_MUTED).pack(pady=50)
        else:
            for a in audits:
                self._make_audit_card(feed, a)

    def _make_audit_card(self, parent, a):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=BORDER_CLR)
        card.pack(fill="x", padx=4, pady=4)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        status = a["status"]
        status_clr = SAFE_CLR if status == "PASS" else CRITICAL
        status_text = "✓ PASS" if status == "PASS" else "✕ FAIL"

        ctk.CTkLabel(hdr, text=status_text, font=ctk.CTkFont(size=12, weight="bold"), text_color=status_clr).pack(side="left")
        ctk.CTkLabel(hdr, text=a["check_name"], font=ctk.CTkFont(size=14, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left", padx=12)
        ctk.CTkLabel(hdr, text=a.get("timestamp", ""), font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).pack(side="right")

        ctk.CTkLabel(card, text=a.get("detail", ""), font=ctk.CTkFont(size=12), text_color=TEXT_SECONDARY, wraplength=700, justify="left").pack(anchor="w", padx=16, pady=(0, 12))

    # ── Analytics Tab ──────────────────────────────────────
    def _fetch_hourly_threats(self):
        """Returns threat counts and worst severity per hour for the last 24h."""
        conn = self._db()
        c = conn.cursor()
        c.execute("SELECT timestamp, severity FROM threats")
        rows = c.fetchall()
        conn.close()

        now = datetime.now()
        severity_rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        # Initialize 24 hour buckets
        counts = [0] * 24
        worst = ["Low"] * 24

        for row in rows:
            try:
                ts = datetime.fromisoformat(row["timestamp"])
            except (ValueError, TypeError):
                continue
            delta = now - ts
            if delta.total_seconds() < 0 or delta.total_seconds() >= 86400:
                continue
            hour_idx = 23 - int(delta.total_seconds() // 3600)
            counts[hour_idx] += 1
            sev = row["severity"] or "Low"
            if severity_rank.get(sev, 0) > severity_rank.get(worst[hour_idx], 0):
                worst[hour_idx] = sev

        labels = []
        for i in range(24):
            h = (now - timedelta(hours=23 - i)).strftime("%H")
            labels.append(h)
        return labels, counts, worst

    def _show_analytics(self):
        self._set_active_nav("analytics")
        self._clear_content()

        header = ctk.CTkFrame(self.content, fg_color=BG_DARK, height=50)
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Analytics", font=ctk.CTkFont(size=22, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left")

        canvas_frame = ctk.CTkScrollableFrame(self.content, fg_color=BG_DARK, scrollbar_button_color=BG_ELEVATED)
        canvas_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 5))

        # Shared matplotlib style
        bg = BG_DARK
        card_bg = BG_CARD
        text_clr = TEXT_PRIMARY
        muted_clr = TEXT_MUTED
        accent = ACCENT
        sev_mpl = {
            "Critical": CRITICAL,
            "High": HIGH_CLR,
            "Medium": MEDIUM_CLR,
            "Low": LOW_CLR,
        }

        # ── Chart 1: Threats per hour (bar) ───────────────
        hour_labels, hour_counts, hour_worst = self._fetch_hourly_threats()
        bar_colors = [sev_mpl.get(w, LOW_CLR) for w in hour_worst]

        fig1, ax1 = plt.subplots(figsize=(8, 2.6), dpi=100)
        fig1.patch.set_facecolor(bg)
        ax1.set_facecolor(card_bg)
        ax1.bar(hour_labels, hour_counts, color=bar_colors, width=0.7, edgecolor="none")
        ax1.set_title("Threats Per Hour (Last 24h)", color=text_clr, fontsize=12, fontweight="bold", pad=10)
        ax1.set_xlabel("Hour", color=muted_clr, fontsize=9)
        ax1.set_ylabel("Count", color=muted_clr, fontsize=9)
        ax1.tick_params(colors=muted_clr, labelsize=7)
        for spine in ax1.spines.values():
            spine.set_color(muted_clr)
        fig1.tight_layout(pad=1.5)

        canvas1 = FigureCanvasTkAgg(fig1, master=canvas_frame)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill="x", padx=10, pady=(10, 5))

        # ── Chart 2: Severity donut ───────────────────────
        _, _, _, sev_counts, _ = self._fetch_stats()
        labels_pie = []
        sizes_pie = []
        colors_pie = []
        for sev_name in ["Critical", "High", "Medium", "Low"]:
            count = sev_counts.get(sev_name, 0)
            if count > 0:
                labels_pie.append(sev_name)
                sizes_pie.append(count)
                colors_pie.append(sev_mpl[sev_name])

        fig2, ax2 = plt.subplots(figsize=(4, 3.2), dpi=100)
        fig2.patch.set_facecolor(bg)
        ax2.set_facecolor(bg)

        if sizes_pie:
            wedges, texts, autotexts = ax2.pie(
                sizes_pie,
                labels=labels_pie,
                colors=colors_pie,
                autopct="%1.0f%%",
                startangle=140,
                pctdistance=0.78,
                wedgeprops=dict(width=0.45, edgecolor=bg),
            )
            for t in texts:
                t.set_color(text_clr)
                t.set_fontsize(9)
            for t in autotexts:
                t.set_color("#000")
                t.set_fontsize(8)
                t.set_fontweight("bold")
        else:
            ax2.text(0.5, 0.5, "No threats", ha="center", va="center", color=muted_clr, fontsize=12, transform=ax2.transAxes)

        ax2.set_title("Severity Breakdown", color=text_clr, fontsize=12, fontweight="bold", pad=10)
        fig2.tight_layout(pad=1.5)

        canvas2 = FigureCanvasTkAgg(fig2, master=canvas_frame)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill="x", padx=10, pady=5)

        # ── Chart 3: Score trend (line) ───────────────────
        fig3, ax3 = plt.subplots(figsize=(8, 2.6), dpi=100)
        fig3.patch.set_facecolor(bg)
        ax3.set_facecolor(card_bg)

        if self._score_history:
            x_vals = list(range(1, len(self._score_history) + 1))
            ax3.plot(x_vals, self._score_history, color=accent, linewidth=2, marker="o", markersize=5, markerfacecolor=accent)
            ax3.fill_between(x_vals, self._score_history, alpha=0.15, color=accent)
            ax3.set_ylim(0, 105)
        else:
            ax3.text(0.5, 0.5, "Collecting data\u2026", ha="center", va="center", color=muted_clr, fontsize=12, transform=ax3.transAxes)

        ax3.set_title("Security Score Trend (Last 10 Refreshes)", color=text_clr, fontsize=12, fontweight="bold", pad=10)
        ax3.set_xlabel("Refresh Cycle", color=muted_clr, fontsize=9)
        ax3.set_ylabel("Score", color=muted_clr, fontsize=9)
        ax3.tick_params(colors=muted_clr, labelsize=7)
        for spine in ax3.spines.values():
            spine.set_color(muted_clr)
        fig3.tight_layout(pad=1.5)

        canvas3 = FigureCanvasTkAgg(fig3, master=canvas_frame)
        canvas3.draw()
        canvas3.get_tk_widget().pack(fill="x", padx=10, pady=(5, 15))

        # Close figures to free memory
        plt.close(fig1)
        plt.close(fig2)
        plt.close(fig3)

    # ── Actions ────────────────────────────────────────────
    def _run_scan(self):
        def worker():
            self.btn_scan.configure(state="disabled", text="  ⏳  Scanning...")
            try:
                log_parser.parse_logs()
                auditor.run_audit()
            except Exception:
                pass
            finally:
                self.btn_scan.configure(state="normal", text="  🛡  Run Full Scan")
                self.after(100, self._refresh_current_tab)
        threading.Thread(target=worker, daemon=True).start()

    def _generate_report(self):
        def worker():
            self.btn_report.configure(state="disabled", text="  ⏳  Generating...")
            try:
                out_dir = Path(__file__).parent / "reports"
                out_dir.mkdir(exist_ok=True)
                report_path = report_generator.generate_report(out_dir)
                # Open the report file
                if os.name == "nt":
                    os.startfile(report_path)
                else:
                    subprocess.Popen(["xdg-open", str(report_path)])
            except Exception as e:
                print(f"Report error: {e}")
            finally:
                self.btn_report.configure(state="normal", text="  📄  Export PDF")
        threading.Thread(target=worker, daemon=True).start()

    def _test_alert(self):
        try:
            conn = self._db()
            c = conn.cursor()
            t = datetime.now().isoformat()
            c.execute("""
                INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (t, "127.0.0.1", "SIMULATED_BREACH", "Manual injection from dashboard UI.", "Critical",
                  "Automated system test — validating render pipeline and alert routing.", "Verify alert receipt on Telegram.", 0))
            conn.commit()
            conn.close()
            check_and_alert()
            self.after(100, self._refresh_current_tab)
            
            # Toast notification
            toast = ctk.CTkToplevel(self)
            toast.overrideredirect(True)
            toast.configure(fg_color="#1E3A2F")
            toast.attributes('-topmost', True)
            
            # Position at bottom-right
            toast_w, toast_h = 220, 50
            x = self.winfo_screenwidth() - toast_w - 40
            y = self.winfo_screenheight() - toast_h - 60
            toast.geometry(f"{toast_w}x{toast_h}+{x}+{y}")
            
            ctk.CTkLabel(toast, text="✓ Test threat injected", font=ctk.CTkFont(size=14, weight="bold"), text_color="#00F58A").pack(expand=True, fill="both", padx=10, pady=5)
            
            self.after(2000, toast.destroy)
        except Exception:
            pass

    def _clear_db(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Confirm Clear Database")
        dialog.geometry("420x220")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        # Center dialog
        x = self.winfo_rootx() + (self.winfo_width() // 2) - 210
        y = self.winfo_rooty() + (self.winfo_height() // 2) - 110
        dialog.geometry(f"+{x}+{y}")

        ctk.CTkLabel(
            dialog, 
            text="This will permanently delete ALL threats, audit results, and honeypot events. This cannot be undone.", 
            font=ctk.CTkFont(size=14), 
            text_color=TEXT_PRIMARY, 
            wraplength=380, 
            justify="center"
        ).pack(pady=(35, 25), padx=20)

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20)

        def on_confirm():
            dialog.destroy()
            try:
                conn = self._db()
                c = conn.cursor()
                c.execute("DELETE FROM threats")
                c.execute("DELETE FROM audit_results")
                c.execute("DELETE FROM honeypot_events")
                conn.commit()
                conn.close()
                self.after(100, self._refresh_current_tab)
            except Exception:
                pass

        def on_cancel():
            dialog.destroy()

        ctk.CTkButton(
            btn_frame, text="Cancel", width=120, height=36,
            fg_color="transparent", border_width=1, border_color=TEXT_MUTED, text_color=TEXT_MUTED, hover_color=BG_CARD,
            command=on_cancel
        ).pack(side="left", padx=10, expand=True)

        ctk.CTkButton(
            btn_frame, text="Clear Everything", width=150, height=36,
            fg_color=CRITICAL, text_color="#000", hover_color="#D12B47",
            command=on_confirm
        ).pack(side="right", padx=10, expand=True)

    # ── Refresh Logic ──────────────────────────────────────
    def _refresh_current_tab(self):
        if self._current_tab == "dashboard":
            self._show_dashboard()
        elif self._current_tab == "threats":
            self._show_threats()
        elif self._current_tab == "audit":
            self._show_audit()
        elif self._current_tab == "analytics":
            self._show_analytics()

    def _tick_refresh(self):
        """Lightweight periodic check — only rebuilds UI if data changed."""
        try:
            total, alerts, score, sev, fails = self._fetch_stats()
            
            # Update Top Header Badge
            if hasattr(self, 'threat_badge'):
                if score > 80:
                    self.threat_badge.configure(text=" THREAT LEVEL: LOW ", fg_color=SAFE_CLR, text_color="#000")
                elif score > 50:
                    self.threat_badge.configure(text=" THREAT LEVEL: MODERATE ", fg_color=HIGH_CLR, text_color="#000")
                else:
                    self.threat_badge.configure(text=" THREAT LEVEL: CRITICAL ", fg_color=CRITICAL, text_color="#000")
                
            # Update Sidebar Badge
            if hasattr(self, 'threat_badge_lbl'):
                if alerts > 0:
                    self.threat_badge_lbl.configure(text=str(alerts))
                    self.threat_badge_lbl.place(relx=0.85, rely=0.5, anchor="center")
                else:
                    self.threat_badge_lbl.place_forget()

            if not self._score_history or self._score_history[-1] != score or total != self._last_threat_count:
                self._score_history.append(score)
                if len(self._score_history) > 10:
                    self._score_history = self._score_history[-10:]
            if total != self._last_threat_count:
                self._last_threat_count = total
                self._refresh_current_tab()
                self._prev_stats = {"score": score, "total": total, "alerts": alerts, "fails": fails}
            self._update_status_bar()
        except Exception:
            pass
        self.after(3000, self._tick_refresh)


# ── Entry Point ────────────────────────────────────────────
def run_app():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    app = RavenApp()
    app.mainloop()

if __name__ == "__main__":
    run_app()
