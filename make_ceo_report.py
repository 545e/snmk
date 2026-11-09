#!/usr/bin/env python3
"""Generate a simple, CEO-readable PDF explaining the SNMK project end to end."""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer,
                                Table, TableStyle, FrameBreak, Flowable)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER

OUT = r"D:\snmk\snmk\SNMK_CEO_Report.pdf"

# ---- palette ----
INK   = colors.HexColor("#0f172a")
SLATE = colors.HexColor("#475569")
MUTE  = colors.HexColor("#64748b")
LINE  = colors.HexColor("#e2e8f0")
INDIGO= colors.HexColor("#6366f1")
BLUE  = colors.HexColor("#3b82f6")
CYAN  = colors.HexColor("#06b6d4")
PURPLE= colors.HexColor("#a855f7")
AMBER = colors.HexColor("#f59e0b")
GREEN = colors.HexColor("#22c55e")
TEAL  = colors.HexColor("#14b8a6")
ROSE  = colors.HexColor("#f43f5e")
BGSOFT= colors.HexColor("#f8fafc")

styles = getSampleStyleSheet()
def S(name, **kw):
    base = kw.pop("parent", styles["Normal"])
    return ParagraphStyle(name, parent=base, **kw)

H1   = S("H1", fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=INK, spaceAfter=2)
SUB  = S("SUB", fontName="Helvetica", fontSize=11, leading=15, textColor=MUTE)
H2   = S("H2", fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=INK, spaceBefore=12, spaceAfter=5)
BODY = S("BODY", fontName="Helvetica", fontSize=10.5, leading=16, textColor=SLATE, spaceAfter=6)
LBL  = S("LBL", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=colors.white)
CELL = S("CELL", fontName="Helvetica", fontSize=9.5, leading=13, textColor=SLATE)
CELLB= S("CELLB", fontName="Helvetica-Bold", fontSize=9.5, leading=13, textColor=INK)
SMALL= S("SMALL", fontName="Helvetica", fontSize=8.5, leading=12, textColor=MUTE)
WHITEB = S("WHITEB", fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=colors.white)

class HR(Flowable):
    def __init__(self, w, color=LINE, thick=0.8):
        super().__init__(); self.w=w; self.color=color; self.thick=thick
    def wrap(self, *a): return (self.w, self.thick+6)
    def draw(self):
        self.canv.setStrokeColor(self.color); self.canv.setLineWidth(self.thick)
        self.canv.line(0,3,self.w,3)

class Pill(Flowable):
    """A colored rounded label used as a section tag."""
    def __init__(self, text, color, w=150*mm):
        super().__init__(); self.text=text; self.color=color; self.w=w
    def wrap(self,*a): return (self.w, 9*mm)
    def draw(self):
        c=self.canv
        c.setFillColor(self.color); c.roundRect(0,0,self.w,7*mm,2*mm,fill=1,stroke=0)
        c.setFillColor(colors.white); c.setFont("Helvetica-Bold",11)
        c.drawString(4*mm,2.1*mm,self.text)

class Arch(Flowable):
    """Simple colorful architecture diagram: user -> browser UI -> API -> engines/db."""
    def __init__(self, w): super().__init__(); self.w=w; self.h=92*mm
    def wrap(self,*a): return (self.w, self.h)
    def _box(self,c,x,y,w,h,fill,title,lines,tcol=colors.white):
        c.setFillColor(fill); c.roundRect(x,y,w,h,2.4*mm,fill=1,stroke=0)
        c.setFillColor(tcol); c.setFont("Helvetica-Bold",9.3); c.drawString(x+3*mm,y+h-5.2*mm,title)
        c.setFont("Helvetica",7.4)
        yy=y+h-9.4*mm
        for ln in lines:
            c.drawString(x+3*mm,yy,ln); yy-=3.3*mm
    def _arrow(self,c,x1,y1,x2,y2):
        c.setStrokeColor(MUTE); c.setLineWidth(1.1); c.line(x1,y1,x2,y2)
        import math
        ang=math.atan2(y2-y1,x2-x1); L=2.2*mm
        c.setFillColor(MUTE)
        c.lines([(x2,y2,x2-L*math.cos(ang-0.4),y2-L*math.sin(ang-0.4)),
                 (x2,y2,x2-L*math.cos(ang+0.4),y2-L*math.sin(ang+0.4))])
    def draw(self):
        c=self.canv; W=self.w; H=self.h
        c.setFillColor(BGSOFT); c.roundRect(0,0,W,H,3*mm,fill=1,stroke=0)
        colw=(W-16*mm)/3.0
        x1=5*mm; x2=x1+colw+3*mm; x3=x2+colw+3*mm
        # row 1: user + browser
        self._box(c,x1,H-28*mm,colw,22*mm,INDIGO,"1. Security Analyst",
                  ["Opens the dashboard","in a web browser","Types a website to check"])
        self._box(c,x2,H-28*mm,colw,22*mm,BLUE,"2. Dashboard (UI)",
                  ["Single-page web app","Shows findings, charts,","reports — no install"])
        self._box(c,x3,H-28*mm,colw,22*mm,CYAN,"3. API Engine",
                  ["Fast Python server","Runs scans in background","Returns live results"])
        # row 2: engines
        self._box(c,x1,H-62*mm,colw,26*mm,PURPLE,"4. Scanning Engines",
                  ["SQL Injection tester","Cross-site scripting (XSS)","Directory fuzzer, Recon","+ optional pro tools"])
        self._box(c,x2,H-62*mm,colw,26*mm,AMBER,"5. OWASP Top 10 + AI",
                  ["Grades every finding","Adds fix / mitigation","Optional AI assistant"])
        self._box(c,x3,H-62*mm,colw,26*mm,GREEN,"6. Database (saved)",
                  ["Every scan stored on disk","Survives restart / reopen","History always available"])
        # row 3: outputs
        self._box(c,x1,H-86*mm,colw*3+6*mm,18*mm,TEAL,"7. Reports & Exports",
                  ["One click: PDF, HTML, Word, CSV, JSON, SARIF.",
                   "Each finding shows severity, OWASP category, CWE and a recommended fix."])
        # arrows
        midy=H-17*mm
        self._arrow(c,x1+colw,midy,x2,midy)
        self._arrow(c,x2+colw,midy,x3,midy)
        self._arrow(c,x3+colw/2,H-28*mm,x3+colw/2,H-36*mm)      # api -> db col
        self._arrow(c,x1+colw/2,H-28*mm,x1+colw/2,H-36*mm)      # ui col down
        self._arrow(c,x2+colw/2,H-28*mm,x2+colw/2,H-36*mm)
        self._arrow(c,x2+colw/2,H-62*mm,x2+colw/2,H-68*mm)      # engines -> reports

def chip_table(rows):
    data=[[Paragraph(f"<b>{a}</b>", CELLB), Paragraph(b, CELL)] for a,b in rows]
    t=Table(data, colWidths=[46*mm, 112*mm])
    t.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("LINEBELOW",(0,0),(-1,-2),0.6,LINE),
        ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("LEFTPADDING",(0,0),(-1,-1),2),
    ]))
    return t

def status_table(rows):
    data=[[Paragraph("<b>Capability</b>",WHITEB), Paragraph("<b>Status</b>",WHITEB)]]
    for a,b in rows:
        data.append([Paragraph(a,CELL), Paragraph(b,CELLB)])
    t=Table(data, colWidths=[112*mm,46*mm])
    sty=[("BACKGROUND",(0,0),(-1,0),INK),
         ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
         ("LEFTPADDING",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
         ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,BGSOFT]),
         ("LINEBELOW",(0,0),(-1,-1),0.5,LINE)]
    t.setStyle(TableStyle(sty)); return t

# ---- document ----
def header_footer(canv, doc):
    canv.saveState()
    canv.setFillColor(INK); canv.rect(0, A4[1]-6*mm, A4[0], 6*mm, fill=1, stroke=0)
    canv.setFillColor(MUTE); canv.setFont("Helvetica",8)
    canv.drawString(18*mm, 10*mm, "SNMK — Executive Overview")
    canv.drawRightString(A4[0]-18*mm, 10*mm, f"Page {doc.page}")
    canv.setStrokeColor(LINE); canv.line(18*mm,13*mm,A4[0]-18*mm,13*mm)
    canv.restoreState()

doc = BaseDocTemplate(OUT, pagesize=A4,
                      leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm)
frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=header_footer)])
W = doc.width

story=[]
# Cover block
story.append(Paragraph("SNMK", S("brand", fontName="Helvetica-Bold", fontSize=30, textColor=INDIGO, leading=32)))
story.append(Paragraph("Autonomous Website Security Scanner", H1))
story.append(Paragraph("A simple executive overview — what it is, how it works, and what it is built with.", SUB))
story.append(Spacer(1,5))
story.append(HR(W))
story.append(Spacer(1,6))

story.append(Paragraph("In one line", H2))
story.append(Paragraph("SNMK is a tool that checks a website for security weaknesses — automatically — "
    "and explains each problem in plain words along with how to fix it. You point it at a website you own, "
    "it scans, and it gives you a clear report.", BODY))

story.append(Paragraph("What it does for the business", H2))
story.append(chip_table([
    ("Finds real problems", "Tests websites for the most common and dangerous flaws (hacking entry points) and shows what it found."),
    ("Speaks plainly", "Every problem gets a severity (High / Medium / Low), the industry category it belongs to, and a recommended fix."),
    ("Remembers everything", "Every scan is saved. Close the tool, reopen it later — your history and past results are still there."),
    ("Delivers reports", "One click turns results into a PDF, Word, HTML or spreadsheet report for clients, auditors or the team."),
    ("Stays safe & legal", "It only scans targets you authorize, refuses risky internal addresses, and never damages the site it checks."),
]))

story.append(Spacer(1,4))
story.append(Pill("HOW IT WORKS  —  SIMPLE ARCHITECTURE", INK, W))
story.append(Spacer(1,4))
story.append(Arch(W))
story.append(Paragraph("Read left to right: a person opens the dashboard, types a website, the engine runs many checks "
    "in the background, grades each result against the OWASP Top 10 industry standard, saves it, and produces a report.", SMALL))

story.append(Paragraph("The technology (plain terms)", H2))
story.append(chip_table([
    ("The screen you see", "A web dashboard built with standard web technology (HTML, CSS, JavaScript). Nothing to install — it opens in any browser."),
    ("The brain", "A fast Python server (FastAPI) that runs the scans and answers the dashboard instantly."),
    ("The scanners", "In-house Python engines for SQL-injection, cross-site scripting, hidden-page discovery and reconnaissance. Can also use industry tools (Nmap, Nuclei) when installed."),
    ("The memory", "A built-in database file (SQLite) that stores every scan safely on the computer."),
    ("Optional AI", "Can connect to AI providers (OpenAI, Claude, Gemini) to help explain results — works fine without it too."),
    ("Runs anywhere", "Windows, Linux, Mac, or in a container (Docker)."),
]))

story.append(Paragraph("Honest status — what is real today", H2))
story.append(Paragraph("We verified this by running the tool live against a test target. The results below are measured, not marketing.", BODY))
story.append(status_table([
    ("Core security scanning (SQLi, XSS, fuzzing, recon)", "Working"),
    ("Every finding graded with OWASP Top 10 + a fix", "Working (verified 7/7)"),
    ("Scan history saved and survives restart", "Working"),
    ("Reports export (PDF, HTML, Word, CSV, JSON)", "Working"),
    ("Admin name fills in from the computer user", "Added"),
    ("Dashboard buttons and sections", "Audited & repaired"),
    ("“85 AI agents” marketing claim", "Overstated — ~20 run"),
]))
story.append(Spacer(1,4))
story.append(Paragraph("Bottom line: the scanner is genuine and functional. The only honesty gap is the "
    "“85 autonomous agents” branding — about twenty actually do work; the rest are placeholders. "
    "That is a wording/marketing fix, not a broken product.", BODY))

story.append(Spacer(1,6))
story.append(HR(W))
story.append(Paragraph("Prepared as a non-technical summary of the SNMK platform. Colours in this document match the "
    "colour-coded sections now used inside the dashboard.", SMALL))

doc.build(story)
print("WROTE", OUT)
