import os
import sqlite3
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import customtkinter as ctk

from config import validate_config
from alerter import start_alert_daemon, check_and_alert, is_telegram_connected
import log_parser
import auditor
import report_generator

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

        # Grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        start_alert_daemon()

        self._build_sidebar()
        self._build_main_area()
        self._build_status_bar()

        self._show_dashboard()
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
            c.execute("SELECT * FROM threats ORDER BY timestamp DESC")
            # Filter in Python for simplicity
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        if severity_filter != "All":
            rows = [r for r in rows if r["severity"] == severity_filter][:limit]
        return rows

    def _fetch_audits(self):
        conn = self._db()
        c = conn.cursor()
        c.execute("SELECT * FROM audit_results ORDER BY timestamp DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    # ── Sidebar ────────────────────────────────────────────
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=SIDEBAR_BG, border_width=0)
        sb.grid(row=0, column=0, rowspan=2, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_rowconfigure(8, weight=1)

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

        self.nav_audit = ctk.CTkButton(sb, text="  ☰  Audit Results", fg_color="transparent", text_color=TEXT_SECONDARY, hover_color=BG_CARD, command=self._show_audit, **btn_cfg)
        self.nav_audit.grid(row=5, column=0, padx=12, pady=3, sticky="ew")

        # Separator
        ctk.CTkFrame(sb, height=1, fg_color=BORDER_CLR).grid(row=6, column=0, sticky="ew", padx=16, pady=15)

        # Action buttons
        self.btn_scan = ctk.CTkButton(sb, text="  🛡  Run Full Scan", font=ctk.CTkFont(size=13, weight="bold"), height=40, fg_color=ACCENT, text_color="#000", hover_color=ACCENT_DIM, corner_radius=8, command=self._run_scan)
        self.btn_scan.grid(row=7, column=0, padx=16, pady=4, sticky="ew")

        self.btn_report = ctk.CTkButton(sb, text="  📄  Export PDF", font=ctk.CTkFont(size=13), height=38, fg_color="transparent", border_width=1, border_color=BORDER_CLR, text_color=TEXT_PRIMARY, hover_color=BG_CARD, corner_radius=8, command=self._generate_report)
        self.btn_report.grid(row=8, column=0, padx=16, pady=4, sticky="new")

        # Bottom section
        self.btn_inject = ctk.CTkButton(sb, text="  ⚠  Inject Test Threat", font=ctk.CTkFont(size=12), height=36, fg_color="transparent", border_width=1, border_color=CRITICAL, text_color=CRITICAL, hover_color="#1A0A10", corner_radius=8, command=self._test_alert)
        self.btn_inject.grid(row=9, column=0, padx=16, pady=(10, 6), sticky="sew")

        self.btn_clear = ctk.CTkButton(sb, text="  ✕  Clear Database", font=ctk.CTkFont(size=12), height=36, fg_color="transparent", border_width=1, border_color=TEXT_MUTED, text_color=TEXT_MUTED, hover_color="#1A0A10", corner_radius=8, command=self._clear_db)
        self.btn_clear.grid(row=10, column=0, padx=16, pady=(0, 20), sticky="sew")

        self._nav_buttons = {
            "dashboard": self.nav_dashboard,
            "threats": self.nav_threats,
            "audit": self.nav_audit,
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
        self.content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

    def _clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    # ── Status Bar ─────────────────────────────────────────
    def _build_status_bar(self):
        self.statusbar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color=BG_SURFACE, border_width=0)
        self.statusbar.grid(row=1, column=1, sticky="ew")
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
        self._stat_score = self._make_stat_card(body, "SECURITY SCORE", str(score), self._score_color(score), "/ 100", 0, 0)
        self._stat_threats = self._make_stat_card(body, "TOTAL THREATS", str(total), MEDIUM_CLR, "detected", 0, 1)
        self._stat_alerts = self._make_stat_card(body, "ACTIVE ALERTS", str(alerts), CRITICAL if alerts > 0 else TEXT_MUTED, "unresolved", 0, 2)
        self._stat_audits = self._make_stat_card(body, "AUDIT FAILURES", str(fails), HIGH_CLR if fails > 0 else TEXT_MUTED, "issues", 0, 3)

        # Recent threats preview
        preview_frame = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CLR)
        preview_frame.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(15, 5))
        preview_frame.grid_columnconfigure(0, weight=1)
        preview_frame.grid_rowconfigure(1, weight=1)

        pf_header = ctk.CTkFrame(preview_frame, fg_color="transparent")
        pf_header.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 5))
        ctk.CTkLabel(pf_header, text="Recent Activity", font=ctk.CTkFont(size=16, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkButton(pf_header, text="View All →", font=ctk.CTkFont(size=12), width=80, height=28, fg_color="transparent", text_color=ACCENT, hover_color=BG_ELEVATED, command=self._show_threats).pack(side="right")

        self._dash_feed = ctk.CTkScrollableFrame(preview_frame, fg_color="transparent", scrollbar_button_color=BG_ELEVATED)
        self._dash_feed.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        threats = self._fetch_threats(limit=10)
        if not threats:
            ctk.CTkLabel(self._dash_feed, text="No threats detected yet. System is clean.", font=ctk.CTkFont(size=14), text_color=TEXT_MUTED).pack(pady=40)
        else:
            for t in threats:
                self._make_threat_row(self._dash_feed, t)

    def _make_stat_card(self, parent, title, value, color, subtitle, row, col):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_CLR)
        card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11, weight="bold"), text_color=TEXT_MUTED).grid(row=0, column=0, pady=(18, 0))
        lbl = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=38, weight="bold"), text_color=color)
        lbl.grid(row=1, column=0, pady=(2, 2))
        ctk.CTkLabel(card, text=subtitle, font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).grid(row=2, column=0, pady=(0, 18))
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
        ctk.CTkLabel(card, text=f"Source IP: {t['source_ip']}", font=ctk.CTkFont(size=13), text_color=TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 4))

        # AI Analysis
        if t.get("ai_analysis"):
            ai_frame = ctk.CTkFrame(card, fg_color=BG_ELEVATED, corner_radius=6)
            ai_frame.pack(fill="x", padx=16, pady=(4, 14))
            ctk.CTkLabel(ai_frame, text=f"🤖  {t['ai_analysis']}", font=ctk.CTkFont(size=12), text_color=TEXT_SECONDARY, wraplength=700, justify="left").pack(padx=14, pady=10, anchor="w")
        else:
            # Add bottom padding if no AI analysis
            ctk.CTkFrame(card, fg_color="transparent", height=8).pack()

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
        except Exception:
            pass

    def _clear_db(self):
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

    # ── Refresh Logic ──────────────────────────────────────
    def _refresh_current_tab(self):
        if self._current_tab == "dashboard":
            self._show_dashboard()
        elif self._current_tab == "threats":
            self._show_threats()
        elif self._current_tab == "audit":
            self._show_audit()

    def _tick_refresh(self):
        """Lightweight periodic check — only rebuilds UI if data changed."""
        try:
            total, alerts, score, sev, fails = self._fetch_stats()
            if total != self._last_threat_count:
                self._last_threat_count = total
                self._refresh_current_tab()
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
