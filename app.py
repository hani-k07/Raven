import os
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
import customtkinter as ctk

from config import validate_config
from alerter import start_alert_daemon, check_and_alert
import log_parser
import auditor
import report_generator

DB_PATH = Path(__file__).parent / "raven.db"

# Color Palette
BG_COLOR = "#0A0A0A"
SURFACE_COLOR = "#141414"
SIDEBAR_COLOR = "#050505"
ACCENT_COLOR = "#00FFCC"
CRITICAL_COLOR = "#FF2A55"
HIGH_COLOR = "#FF9F1C"
SAFE_COLOR = "#00F58A"
TEXT_COLOR = "#FFFFFF"
MUTED_TEXT = "#8E8E8E"

class RavenApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RAVEN 2.0 - Autonomous Security Matrix")
        self.geometry("1100x750")
        self.configure(fg_color=BG_COLOR)
        
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Start background alerter
        start_alert_daemon()
        
        self.create_sidebar()
        self.create_main_frame()
        
        # Periodically refresh
        self.refresh_data()
        
    def get_db_connection(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
        
    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=SIDEBAR_COLOR)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="RAVEN 2.0", font=ctk.CTkFont(size=26, weight="bold"), text_color=ACCENT_COLOR)
        self.logo_label.grid(row=0, column=0, padx=20, pady=(35, 2))
        self.subtitle = ctk.CTkLabel(self.sidebar_frame, text="Autonomous Defense", font=ctk.CTkFont(size=12), text_color=MUTED_TEXT)
        self.subtitle.grid(row=1, column=0, padx=20, pady=(0, 40))
        
        btn_font = ctk.CTkFont(size=14, weight="bold")
        
        self.btn_refresh = ctk.CTkButton(self.sidebar_frame, text="🔄 Refresh Feed", font=btn_font, fg_color="transparent", border_width=1, border_color="#333333", text_color=TEXT_COLOR, hover_color=SURFACE_COLOR, command=self.refresh_data)
        self.btn_refresh.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_scan = ctk.CTkButton(self.sidebar_frame, text="🛡️ Run Audit & Scan", font=btn_font, fg_color=ACCENT_COLOR, text_color="#000000", hover_color="#00CCAA", command=self.run_scan)
        self.btn_scan.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_report = ctk.CTkButton(self.sidebar_frame, text="📄 Generate PDF", font=btn_font, fg_color="transparent", border_width=1, border_color="#333333", text_color=TEXT_COLOR, hover_color=SURFACE_COLOR, command=self.generate_report)
        self.btn_report.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_test = ctk.CTkButton(self.sidebar_frame, text="⚠️ Inject Test Threat", font=btn_font, fg_color="transparent", border_width=1, text_color=CRITICAL_COLOR, border_color=CRITICAL_COLOR, hover_color="#330A14", command=self.test_alert)
        self.btn_test.grid(row=5, column=0, padx=20, pady=30, sticky="sew")
        
    def create_main_frame(self):
        self.main_frame = ctk.CTkFrame(self, fg_color=BG_COLOR)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.main_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)
        
        # --- Stats Row ---
        self.stat_threats = self.create_stat_card(self.main_frame, "TOTAL THREATS", "0", ACCENT_COLOR, 0, 0)
        self.stat_score = self.create_stat_card(self.main_frame, "SYSTEM SCORE", "100", SAFE_COLOR, 0, 1)
        self.stat_alerts = self.create_stat_card(self.main_frame, "ACTIVE ALERTS", "0", CRITICAL_COLOR, 0, 2)
        
        # --- Threats Feed ---
        self.feed_header = ctk.CTkLabel(self.main_frame, text="LIVE EVENT MATRIX", font=ctk.CTkFont(size=16, weight="bold"), text_color=TEXT_COLOR)
        self.feed_header.grid(row=1, column=0, columnspan=3, padx=15, pady=(20, 5), sticky="w")
        
        self.feed_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color=BG_COLOR, scrollbar_button_color=SURFACE_COLOR, corner_radius=0)
        self.feed_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")

    def create_stat_card(self, parent, title, value, color, row, col):
        card = ctk.CTkFrame(parent, fg_color=SURFACE_COLOR, corner_radius=12)
        card.grid(row=row, column=col, padx=10, pady=(10, 10), sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        
        lbl_title = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12, weight="bold"), text_color=MUTED_TEXT)
        lbl_title.grid(row=0, column=0, pady=(20, 0))
        
        lbl_value = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=42, weight="bold"), text_color=color)
        lbl_value.grid(row=1, column=0, pady=(5, 20))
        
        return lbl_value
        
    def add_threat_card(self, threat):
        card = ctk.CTkFrame(self.feed_frame, fg_color=SURFACE_COLOR, corner_radius=8)
        card.pack(fill="x", padx=5, pady=6)
        
        severity = threat['severity']
        if severity == 'Critical':
            color = CRITICAL_COLOR
            fg = "#000"
        elif severity == 'High':
            color = HIGH_COLOR
            fg = "#000"
        elif severity == 'Medium':
            color = ACCENT_COLOR
            fg = "#000"
        else:
            color = SAFE_COLOR
            fg = "#000"
        
        # Header Row
        header_frame = ctk.CTkFrame(card, fg_color="transparent")
        header_frame.pack(fill="x", padx=15, pady=(15, 5))
        
        lbl_sev = ctk.CTkLabel(header_frame, text=f" {severity.upper()} ", font=ctk.CTkFont(size=12, weight="bold"), fg_color=color, text_color=fg, corner_radius=4)
        lbl_sev.pack(side="left")
        
        lbl_type = ctk.CTkLabel(header_frame, text=f" {threat['event_type']} ", font=ctk.CTkFont(size=15, weight="bold"), text_color=TEXT_COLOR)
        lbl_type.pack(side="left", padx=15)
        
        lbl_time = ctk.CTkLabel(header_frame, text=threat['timestamp'], font=ctk.CTkFont(size=12), text_color=MUTED_TEXT)
        lbl_time.pack(side="right")
        
        # Body
        lbl_ip = ctk.CTkLabel(card, text=f"Source: {threat['source_ip']}", font=ctk.CTkFont(size=13), text_color=MUTED_TEXT)
        lbl_ip.pack(anchor="w", padx=15)
        
        if threat['ai_analysis']:
            analysis_frame = ctk.CTkFrame(card, fg_color="#1E1E1E", corner_radius=6)
            analysis_frame.pack(fill="x", padx=15, pady=(10, 15))
            lbl_ai = ctk.CTkLabel(analysis_frame, text=f"🤖 AI Insight: {threat['ai_analysis']}", font=ctk.CTkFont(size=13), text_color="#D0D0D0", wraplength=750, justify="left")
            lbl_ai.pack(padx=15, pady=12, anchor="w")

    def refresh_data(self):
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) as count FROM threats")
            total_threats = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM threats WHERE alerted=0 AND severity IN ('High', 'Critical')")
            active_alerts = cursor.fetchone()['count']
            
            cursor.execute("SELECT severity, COUNT(*) as count FROM threats GROUP BY severity")
            severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            cursor.execute("SELECT COUNT(*) as count FROM audit_results WHERE status='FAIL'")
            failed_audits = cursor.fetchone()['count']
            
            score = 100
            score -= severity_counts.get('Critical', 0) * 15
            score -= severity_counts.get('High', 0) * 8
            score -= severity_counts.get('Medium', 0) * 3
            score -= severity_counts.get('Low', 0) * 1
            score -= failed_audits * 5
            security_score = max(0, score)
            
            self.stat_threats.configure(text=str(total_threats))
            self.stat_score.configure(text=str(security_score), text_color=SAFE_COLOR if security_score > 80 else HIGH_COLOR if security_score > 50 else CRITICAL_COLOR)
            self.stat_alerts.configure(text=str(active_alerts))
            
            # Refresh Feed
            for widget in self.feed_frame.winfo_children():
                widget.destroy()
                
            cursor.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT 30")
            threats = cursor.fetchall()
            
            if not threats:
                lbl_empty = ctk.CTkLabel(self.feed_frame, text="Matrix is quiet. No threats detected.", font=ctk.CTkFont(size=14), text_color=MUTED_TEXT)
                lbl_empty.pack(pady=60)
            else:
                for t in threats:
                    self.add_threat_card(dict(t))
                    
            conn.close()
        except Exception as e:
            print(f"Error refreshing data: {e}")
            
        self.after(5000, self.refresh_data)
        
    def run_scan(self):
        def scan_thread():
            self.btn_scan.configure(state="disabled", text="🛡️ Scanning Matrix...")
            try:
                log_parser.parse_logs()
                auditor.run_audit()
            except Exception as e:
                print(f"Scan error: {e}")
            finally:
                self.btn_scan.configure(state="normal", text="🛡️ Run Audit & Scan")
                self.after(0, self.refresh_data)
        threading.Thread(target=scan_thread, daemon=True).start()

    def generate_report(self):
        try:
            out_dir = Path(__file__).parent / "reports"
            out_dir.mkdir(exist_ok=True)
            report_path = report_generator.generate_report(out_dir)
            print(f"Report generated at {report_path}")
        except Exception as e:
            print(f"Report error: {e}")

    def test_alert(self):
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, "127.0.0.1", "SIMULATED_BREACH", "Manual test injection from UI.", "Critical", "Automated system test. Validating render pipeline and alert routing.", "Verify alert receipt.", 0))
            conn.commit()
            conn.close()
            check_and_alert()
            self.refresh_data()
        except Exception as e:
            print(f"Test alert error: {e}")

def run_app():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    app = RavenApp()
    app.mainloop()

if __name__ == "__main__":
    run_app()
