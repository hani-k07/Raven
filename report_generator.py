import sqlite3
from datetime import datetime
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch
import mitre_mapper

DB_PATH = Path(__file__).parent / "raven.db"

def _header_footer(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setFont('Helvetica-Bold', 10)
    canvas_obj.setStrokeColor(colors.HexColor('#E94560'))
    canvas_obj.setFillColor(colors.HexColor('#1A1A2E'))
    canvas_obj.drawString(inch, 10.5 * inch, "RAVEN 2.0 Security Assessment Report")
    canvas_obj.drawString(7 * inch, 10.5 * inch, f"Page {doc.page}")
    canvas_obj.line(inch, 10.4 * inch, 7.5 * inch, 10.4 * inch)
    canvas_obj.restoreState()

def _fetch_data():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM threats ORDER BY timestamp DESC")
    threats = [dict(r) for r in cursor.fetchall()]
    
    cursor.execute("SELECT * FROM audit_results ORDER BY timestamp DESC")
    audits = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    return threats, audits

def _get_security_score(threats, audits):
    score = 100
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in threats:
        counts[t.get('severity', 'Medium')] += 1
        
    score -= counts["Critical"] * 15
    score -= counts["High"] * 8
    score -= counts["Medium"] * 3
    score -= counts["Low"] * 1
    
    failed_audits = sum(1 for a in audits if a.get('status') == 'FAIL')
    score -= failed_audits * 5
    
    return max(0, score), counts, failed_audits

def generate_report(output_dir: Path) -> Path:
    """Generates a multi-page PDF security report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = output_dir / f"RAVEN_Report_{timestamp}.pdf"
    
    threats, audits = _fetch_data()
    score, threat_counts, failed_audits = _get_security_score(threats, audits)
    passed_audits = sum(1 for a in audits if a.get('status') == 'PASS')
    
    doc = SimpleDocTemplate(
        str(file_path),
        pagesize=letter,
        rightMargin=inch,
        leftMargin=inch,
        topMargin=inch,
        bottomMargin=inch
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor('#E94560'),
        alignment=1, 
        spaceAfter=30
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        textColor=colors.white,
        alignment=1,
        spaceAfter=20
    )
    
    heading_style = ParagraphStyle(
        'HeadingStyle',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=colors.HexColor('#1A1A2E'),
        spaceAfter=15
    )
    
    normal_style = styles['Normal']
    
    story = []
    
    cover_data = [
        [Paragraph("RAVEN 2.0 Security Assessment Report", title_style)],
        [Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style)],
        [Paragraph("Classification: CONFIDENTIAL", subtitle_style)]
    ]
    
    cover_table = Table(cover_data, colWidths=[6.5 * inch], rowHeights=[2 * inch, 1 * inch, 1 * inch])
    cover_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#1A1A2E')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 20),
    ]))
    
    story.append(Spacer(1, 2 * inch))
    story.append(cover_table)
    story.append(PageBreak())
    
    story.append(Paragraph("Executive Summary", heading_style))
    
    score_color = colors.green if score >= 75 else (colors.orange if score >= 50 else colors.red)
    score_style = ParagraphStyle(
        'ScoreStyle',
        parent=styles['Heading1'],
        fontSize=32,
        textColor=score_color,
        spaceAfter=20
    )
    story.append(Paragraph(f"Overall Security Score: {score}/100", score_style))
    
    total_threats = len(threats)
    story.append(Paragraph(f"<b>Total Threats:</b> {total_threats}", normal_style))
    story.append(Paragraph(f"<b>Breakdown:</b> Critical: {threat_counts['Critical']} | High: {threat_counts['High']} | Medium: {threat_counts['Medium']} | Low: {threat_counts['Low']}", normal_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Compliance Audit:</b> {passed_audits} passed, {failed_audits} failed.", normal_style))
    story.append(Spacer(1, 20))
    
    summary_text = (
        "The current security posture reflects the state of active threats and compliance failures detected across the environment. "
        "Critical and high-severity incidents require immediate mitigation. Continuous monitoring and enforcement of compliance standards "
        "are recommended to improve the overall security score and maintain defensive readiness."
    )
    story.append(Paragraph(summary_text, normal_style))
    story.append(PageBreak())
    
    story.append(Paragraph("Threat Activity Log", heading_style))
    
    if not threats:
        story.append(Paragraph("No threats detected.", normal_style))
    else:
        threat_table_data = [["Time", "Severity", "Source IP", "Type", "Analysis"]]
        
        for t in threats:
            analysis = t.get('ai_analysis', '')
            if len(analysis) > 80:
                analysis = analysis[:77] + "..."
                
            time_short = t.get('timestamp', '')[:19].replace("T", " ")
            event_type = t.get('event_type', '')
            mitre = mitre_mapper.get_mitre(event_type)
            if mitre["tactic_id"] != "Unknown":
                event_type = f"{event_type}\n({mitre['technique_id']})"
            
            threat_table_data.append([
                time_short,
                t.get('severity', 'Unknown'),
                t.get('source_ip', ''),
                event_type,
                Paragraph(analysis, styles['Normal'])
            ])
            
        t_style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1A1A2E')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ])
        
        for i, row in enumerate(threats, start=1):
            sev = row.get('severity', '')
            bg_color = colors.white
            if sev == 'Critical':
                bg_color = colors.HexColor('#ffcccc')
            elif sev == 'High':
                bg_color = colors.HexColor('#ffebcc')
            elif sev == 'Medium':
                bg_color = colors.HexColor('#cce0ff')
            elif sev == 'Low':
                bg_color = colors.HexColor('#e6e6e6')
                
            t_style.add('BACKGROUND', (0, i), (-1, i), bg_color)
            
        col_widths = [1.2 * inch, 0.8 * inch, 1.2 * inch, 1.0 * inch, 2.8 * inch]
        threat_table = Table(threat_table_data, colWidths=col_widths, repeatRows=1)
        threat_table.setStyle(t_style)
        story.append(threat_table)
        
    story.append(PageBreak())
    
    story.append(Paragraph("Compliance Findings", heading_style))
    
    if not audits:
        story.append(Paragraph("No audit results available.", normal_style))
    else:
        audit_table_data = [["Status", "Check Name", "Detail"]]
        
        for a in audits:
            status = a.get('status', 'WARN')
            mark = status
            
            audit_table_data.append([
                mark,
                a.get('check_name', ''),
                Paragraph(a.get('detail', ''), styles['Normal'])
            ])
            
        a_style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1A1A2E')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ])
        
        for i, row in enumerate(audits, start=1):
            status = row.get('status', 'WARN')
            if status == 'PASS':
                a_style.add('TEXTCOLOR', (0, i), (0, i), colors.green)
            elif status == 'FAIL':
                a_style.add('TEXTCOLOR', (0, i), (0, i), colors.red)
            elif status == 'WARN':
                a_style.add('TEXTCOLOR', (0, i), (0, i), colors.orange)
        
        audit_table = Table(audit_table_data, colWidths=[1.0 * inch, 1.8 * inch, 4.2 * inch], repeatRows=1)
        audit_table.setStyle(a_style)
        story.append(audit_table)
        
    story.append(PageBreak())
    
    story.append(Paragraph("AI Recommendations", heading_style))
    
    recs = [t.get('recommendation', '') for t in threats if t.get('recommendation')]
    unique_recs = []
    for r in recs:
        if r and r not in unique_recs:
            unique_recs.append(r)
            
    if not unique_recs:
        story.append(Paragraph("No recommendations available.", normal_style))
    else:
        for i, rec in enumerate(unique_recs, 1):
            story.append(Paragraph(f"{i}. {rec}", normal_style))
            story.append(Spacer(1, 10))
            
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    
    return file_path

if __name__ == "__main__":
    out_dir = Path(__file__).parent / "reports"
    out_dir.mkdir(exist_ok=True)
    fpath = generate_report(out_dir)
    print(f"Report generated at {fpath}")
