import sqlite3
import db_init
from logger import log

def escalate_severity(severity, count):
    """Escalates severity based on the number of occurrences."""
    if count < 5:
        return severity

    levels = {"Low": "Medium", "Medium": "High", "High": "Critical", "Critical": "Critical"}
    return levels.get(severity, severity)

def correlate():
    """
    Identifies repeated activity from the same source IP and
    escalates severity if a threshold is met.
    """
    with db_init.get_connection() as conn:
        cursor = conn.cursor()

        # Find IPs with multiple unalerted threats
        cursor.execute("""
            SELECT source_ip, COUNT(*) as count, MAX(severity) as base_severity
            FROM threats
            WHERE alerted = 0
            GROUP BY source_ip
            HAVING count >= 3
        """)

        results = []
        for row in cursor.fetchall():
            ip = row["source_ip"]
            count = row["count"]
            severity = row["base_severity"]

            new_severity = escalate_severity(severity, count)

            results.append({
                "source_ip": ip,
                "count": count,
                "original_severity": severity,
                "escalated_severity": new_severity
            })

    return results

if __name__ == "__main__":
    # Simple self-test
    log.info(f"Escalation test: Low(5) -> {escalate_severity('Low', 5)}")
    log.info(f"Correlation test: {correlate()}")
