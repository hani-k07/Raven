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

class RavenApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RAVEN 2.0 - Cybersecurity Dashboard")
        self.geometry("1000x700")
        
        # Start background alerter if needed
        start_alert_daemon()
        
        # Setup UI
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.create_sidebar()
        self.create_main_frame()
        
        # Periodic refresh
        self.refresh_data()
        
    def get_db_connection(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
        
    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="RAVEN 2.0", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.btn_refresh = ctk.CTkButton(self.sidebar_frame, text="Refresh Data", command=self.refresh_data)
        self.btn_refresh.grid(row=1, column=0, padx=20, pady=10)
        
        self.btn_scan = ctk.CTkButton(self.sidebar_frame, text="Run Audit & Scan", command=self.run_scan)
        self.btn_scan.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_report = ctk.CTkButton(self.sidebar_frame, text="Generate PDF", command=self.generate_report)
        self.btn_report.grid(row=3, column=0, padx=20, pady=10)
        
        self.btn_test = ctk.CTkButton(self.sidebar_frame, text="Test Alert", command=self.test_alert)
        self.btn_test.grid(row=4, column=0, padx=20, pady=10, sticky="s")
        
    def create_main_frame(self):
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Stats row
        self.stat_threats_lbl = ctk.CTkLabel(self.main_frame, text="Total Threats: 0", font=ctk.CTkFont(size=16, weight="bold"))
        self.stat_threats_lbl.grid(row=0, column=0, padx=20, pady=20)
        
        self.stat_score_lbl = ctk.CTkLabel(self.main_frame, text="Security Score: 100", font=ctk.CTkFont(size=16, weight="bold"))
        self.stat_score_lbl.grid(row=0, column=1, padx=20, pady=20)
        
        self.stat_alerts_lbl = ctk.CTkLabel(self.main_frame, text="Active Alerts: 0", font=ctk.CTkFont(size=16, weight="bold"), text_color="#FF4C4C")
        self.stat_alerts_lbl.grid(row=0, column=2, padx=20, pady=20)
        
        # Threats Listbox area
        self.threats_lbl = ctk.CTkLabel(self.main_frame, text="Recent Threats & Events", font=ctk.CTkFont(size=14, weight="bold"))
        self.threats_lbl.grid(row=1, column=0, columnspan=3, padx=20, pady=(10, 0), sticky="w")
        
        self.threats_textbox = ctk.CTkTextbox(self.main_frame, height=400, font=ctk.CTkFont(family="Consolas", size=12))
        self.threats_textbox.grid(row=2, column=0, columnspan=3, padx=20, pady=10, sticky="nsew")
        self.main_frame.grid_rowconfigure(2, weight=1)

    def refresh_data(self):
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Fetch stats
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
            
            self.stat_threats_lbl.configure(text=f"Total Threats: {total_threats}")
            self.stat_score_lbl.configure(text=f"Security Score: {security_score}")
            self.stat_alerts_lbl.configure(text=f"Active Alerts: {active_alerts}")
            
            # Fetch recent threats
            cursor.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT 20")
            threats = cursor.fetchall()
            
            self.threats_textbox.configure(state="normal")
            self.threats_textbox.delete("0.0", "end")
            
            if not threats:
                self.threats_textbox.insert("end", "No recent threats recorded.\n")
            else:
                for t in threats:
                    log_line = f"[{t['timestamp']}] {t['severity']} - {t['event_type']} from {t['source_ip']}\n"
                    self.threats_textbox.insert("end", log_line)
                    if t['ai_analysis']:
                        self.threats_textbox.insert("end", f"  -> Analysis: {t['ai_analysis']}\n")
                    self.threats_textbox.insert("end", "-"*80 + "\n")
            
            self.threats_textbox.configure(state="disabled")
            
            conn.close()
            
        except Exception as e:
            print(f"Error refreshing data: {e}")
            
        # Schedule next refresh
        self.after(5000, self.refresh_data)
        
    def run_scan(self):
        def scan_thread():
            self.btn_scan.configure(state="disabled", text="Scanning...")
            try:
                log_parser.parse_logs()
                auditor.run_audit()
            except Exception as e:
                print(f"Scan error: {e}")
            finally:
                self.btn_scan.configure(state="normal", text="Run Audit & Scan")
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
            ''', (timestamp, "127.0.0.1", "TEST_EVENT", "This is a test event for UI.", "Critical", "Test analysis.", "No action.", 0))
            conn.commit()
            conn.close()
            check_and_alert()
            self.refresh_data()
        except Exception as e:
            print(f"Test alert error: {e}")

def run_app():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = RavenApp()
    app.mainloop()

if __name__ == "__main__":
    run_app()
