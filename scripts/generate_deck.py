import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# ─── COLOR PALETTE (Matched to SUDARSHAN Frontend Theme) ───────────────────────
BG_CANVAS        = RGBColor(248, 250, 252)   # #f8fafc Canvas
WHITE            = RGBColor(255, 255, 255)   # #ffffff
NAVY_HEADER      = RGBColor(15, 23, 42)      # #0f172a Dark Navy
SLATE_BODY       = RGBColor(51, 65, 85)      # #334155 Slate
SLATE_MUTED      = RGBColor(100, 116, 139)   # #64748b Muted Slate
BORDER_LIGHT     = RGBColor(226, 232, 240)   # #e2e8f0 Border
BORDER_STRONG    = RGBColor(203, 213, 225)   # #cbd5e1 Strong Border

BRAND_BLUE       = RGBColor(30, 58, 138)     # #1e3a8a BOI Blue Primary
ACCENT_BLUE      = RGBColor(37, 99, 235)     # #2563eb Bright Blue
SKY_BLUE         = RGBColor(2, 132, 199)     # #0284c7 Sky Blue
BG_LIGHT_BLUE    = RGBColor(239, 246, 255)   # #eff6ff Blue Tint

CRITICAL_RED     = RGBColor(220, 38, 38)     # #dc2626 Critical
HIGH_ORANGE      = RGBColor(234, 88, 12)     # #ea580c High
AMBER_WARN       = RGBColor(217, 119, 6)     # #d97706 Warning
SAFE_GREEN       = RGBColor(5, 150, 105)     # #059669 Safe

BG_LIGHT_RED     = RGBColor(254, 242, 242)   # #fef2f2 Red Tint
BG_LIGHT_GREEN   = RGBColor(236, 253, 245)   # #ecfdf5 Green Tint
BG_LIGHT_AMBER   = RGBColor(254, 243, 199)   # #fef3c7 Amber Tint

# Fonts
FONT_HEADING = "Calibri"
FONT_BODY    = "Calibri"
FONT_MONO    = "Consolas"

# Asset Paths
BRAND_LOGO_COLOUR = os.path.abspath("frontend/public/brand/sudarshan-mark-colour.png")
BRAND_LOGO_WHITE  = os.path.abspath("frontend/public/brand/sudarshan-mark-white.png")

SCREENSHOTS_DIR = os.path.abspath("assets/screenshots")
SAMPLE_SCREENSHOTS_DIR = os.path.abspath("backend/sudarshan_artifacts/test_sample_9a5731b2/screenshots")


def create_deck():
    prs = Presentation()
    # 16:9 Widescreen standard: 13.333 x 7.5 inches
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Helper: Set slide background
    def set_background(slide, color=BG_CANVAS):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = color
        bg.line.fill.background()
        return bg

    # Helper: Add standard slide header
    def add_header(slide, title_text, subtitle_text, category_badge="SUDARSHAN PLATFORM"):
        # Header Container
        badge = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.4), Inches(2.2), Inches(0.3))
        badge.fill.solid()
        badge.fill.fore_color.rgb = BG_LIGHT_BLUE
        badge.line.color.rgb = RGBColor(191, 219, 254)
        badge.line.width = Pt(1)
        tf_b = badge.text_frame
        tf_b.word_wrap = True
        p_b = tf_b.paragraphs[0]
        p_b.text = category_badge.upper()
        p_b.font.name = FONT_HEADING
        p_b.font.size = Pt(8.5)
        p_b.font.bold = True
        p_b.font.color.rgb = BRAND_BLUE
        p_b.alignment = PP_ALIGN.CENTER

        # Title
        tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.72), Inches(10.5), Inches(0.55))
        tf_t = tb_title.text_frame
        tf_t.word_wrap = True
        tf_t.margin_left = tf_t.margin_right = tf_t.margin_top = tf_t.margin_bottom = 0
        p_t = tf_t.paragraphs[0]
        p_t.text = title_text
        p_t.font.name = FONT_HEADING
        p_t.font.size = Pt(21)
        p_t.font.bold = True
        p_t.font.color.rgb = NAVY_HEADER

        # Subtitle
        tb_sub = slide.shapes.add_textbox(Inches(0.8), Inches(1.28), Inches(10.5), Inches(0.35))
        tf_s = tb_sub.text_frame
        tf_s.word_wrap = True
        tf_s.margin_left = tf_s.margin_right = tf_s.margin_top = tf_s.margin_bottom = 0
        p_s = tf_s.paragraphs[0]
        p_s.text = subtitle_text
        p_s.font.name = FONT_BODY
        p_s.font.size = Pt(11)
        p_s.font.color.rgb = SLATE_MUTED

        # Logo mark in top right
        if os.path.exists(BRAND_LOGO_COLOUR):
            slide.shapes.add_picture(BRAND_LOGO_COLOUR, Inches(12.0), Inches(0.45), width=Inches(0.65))

        # Thin header accent rule
        rule = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.68), Inches(11.733), Inches(0.015))
        rule.fill.solid()
        rule.fill.fore_color.rgb = BORDER_LIGHT
        rule.line.fill.background()

    # Helper: Add slide footer
    def add_footer(slide, current_slide, total_slides=15):
        # Footer line
        rule = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(7.05), Inches(11.733), Inches(0.015))
        rule.fill.solid()
        rule.fill.fore_color.rgb = BORDER_LIGHT
        rule.line.fill.background()

        # Left label
        tb_l = slide.shapes.add_textbox(Inches(0.8), Inches(7.12), Inches(8.0), Inches(0.28))
        tf_l = tb_l.text_frame
        tf_l.margin_left = tf_l.margin_top = tf_l.margin_bottom = tf_l.margin_right = 0
        p_l = tf_l.paragraphs[0]
        p_l.text = "SUDARSHAN : Enterprise Android Banking Malware Analysis and Fraud Intelligence Platform"
        p_l.font.name = FONT_BODY
        p_l.font.size = Pt(8.5)
        p_l.font.color.rgb = SLATE_MUTED

        # Right page number
        tb_r = slide.shapes.add_textbox(Inches(10.5), Inches(7.12), Inches(2.033), Inches(0.28))
        tf_r = tb_r.text_frame
        tf_r.margin_left = tf_r.margin_top = tf_r.margin_bottom = tf_r.margin_right = 0
        p_r = tf_r.paragraphs[0]
        p_r.text = f"Slide {current_slide} of {total_slides}"
        p_r.font.name = FONT_BODY
        p_r.font.size = Pt(8.5)
        p_r.font.bold = True
        p_r.font.color.rgb = BRAND_BLUE
        p_r.alignment = PP_ALIGN.RIGHT

    # Helper: Add a clean container card
    def add_card(slide, left, top, width, height, bg_color=WHITE, border_color=BORDER_LIGHT, radius=True):
        shape_type = MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE
        card = slide.shapes.add_shape(shape_type, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        card.line.color.rgb = border_color
        card.line.width = Pt(1)
        return card

    # Helper: Add pill badge
    def add_pill(slide, left, top, text, bg_color=BG_LIGHT_BLUE, text_color=BRAND_BLUE, width=Inches(1.2), height=Inches(0.26)):
        pill = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        pill.fill.solid()
        pill.fill.fore_color.rgb = bg_color
        pill.line.fill.background()
        tf = pill.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = text
        p.font.name = FONT_HEADING
        p.font.size = Pt(8)
        p.font.bold = True
        p.font.color.rgb = text_color
        p.alignment = PP_ALIGN.CENTER
        return pill

    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 1: Title & Value Proposition
    # ════════════════════════════════════════════════════════════════════════════
    s1 = prs.slides.add_slide(blank_layout)
    set_background(s1, RGBColor(7, 13, 24)) # Deep dark navy like the login page

    # Decorative background card
    bg_glow = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.6), Inches(0.6), Inches(12.133), Inches(6.3))
    bg_glow.fill.solid()
    bg_glow.fill.fore_color.rgb = RGBColor(15, 23, 42)
    bg_glow.line.color.rgb = RGBColor(30, 58, 138)
    bg_glow.line.width = Pt(1.5)

    # White Chakra Logo
    if os.path.exists(BRAND_LOGO_WHITE):
        s1.shapes.add_picture(BRAND_LOGO_WHITE, Inches(1.2), Inches(1.2), width=Inches(1.1))

    # Hackathon badge
    add_pill(s1, Inches(2.5), Inches(1.25), "SMART INDIA HACKATHON 2026", bg_color=RGBColor(30, 58, 138), text_color=RGBColor(147, 197, 253), width=Inches(2.8), height=Inches(0.32))

    # Main Title
    t_box = s1.shapes.add_textbox(Inches(1.2), Inches(2.2), Inches(10.8), Inches(1.8))
    tf = t_box.text_frame
    tf.word_wrap = True
    p1 = tf.paragraphs[0]
    p1.text = "SUDARSHAN"
    p1.font.name = FONT_HEADING
    p1.font.size = Pt(46)
    p1.font.bold = True
    p1.font.color.rgb = WHITE

    p2 = tf.add_paragraph()
    p2.text = "Enterprise Android Banking Malware Analysis and Fraud Intelligence Platform"
    p2.font.name = FONT_HEADING
    p2.font.size = Pt(19)
    p2.font.bold = True
    p2.font.color.rgb = RGBColor(147, 197, 253)

    p3 = tf.add_paragraph()
    p3.space_before = Pt(14)
    p3.text = "Bridging the intelligence translation gap from raw Android bytecode to court-admissible, deterministic fraud verdicts and explainable SOC intelligence."
    p3.font.name = FONT_BODY
    p3.font.size = Pt(13)
    p3.font.color.rgb = RGBColor(203, 213, 225)

    # 4 Key Value Metric Pillars
    pillars = [
        ("DETERMINISTIC VERDICT", "0 to 100 FRS", "Mathematical risk engine; AI never computes raw score", RGBColor(56, 189, 248)),
        ("AGENTIC EXPLORATION", "5-Level Perception", "Automated bypass of OTP, login, and anti-analysis traps", RGBColor(147, 197, 253)),
        ("VIDE BRAND DEFENSE", "4-Axis Detection", "Identifies cloned Indian bank apps prior to credential theft", RGBColor(52, 211, 153)),
        ("ENTERPRISE READY", "2,841 Tests Passing", "Tested across 165 test suites with 100% pass rate", RGBColor(251, 191, 36)),
    ]

    card_w = Inches(2.65)
    card_h = Inches(1.5)
    start_x = Inches(1.2)
    start_y = Inches(4.5)
    spacing = Inches(0.28)

    for i, (title, stat, desc, col) in enumerate(pillars):
        c = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, start_x + i * (card_w + spacing), start_y, card_w, card_h)
        c.fill.solid()
        c.fill.fore_color.rgb = RGBColor(15, 23, 42)
        c.line.color.rgb = RGBColor(51, 65, 85)
        c.line.width = Pt(1)

        tbox = s1.shapes.add_textbox(start_x + i * (card_w + spacing) + Inches(0.15), start_y + Inches(0.12), card_w - Inches(0.3), card_h - Inches(0.24))
        ctf = tbox.text_frame
        ctf.word_wrap = True
        ctf.margin_top = ctf.margin_bottom = ctf.margin_left = ctf.margin_right = 0
        
        cp1 = ctf.paragraphs[0]
        cp1.text = title
        cp1.font.size = Pt(8.5)
        cp1.font.bold = True
        cp1.font.color.rgb = RGBColor(148, 163, 184)

        cp2 = ctf.add_paragraph()
        cp2.text = stat
        cp2.font.size = Pt(14)
        cp2.font.bold = True
        cp2.font.color.rgb = col

        cp3 = ctf.add_paragraph()
        cp3.space_before = Pt(4)
        cp3.text = desc
        cp3.font.size = Pt(9)
        cp3.font.color.rgb = RGBColor(203, 213, 225)

    # Footer banner on Slide 1
    ft = s1.shapes.add_textbox(Inches(1.2), Inches(6.3), Inches(10.8), Inches(0.3))
    ft_tf = ft.text_frame
    p_ft = ft_tf.paragraphs[0]
    p_ft.text = "Target Focus: Protecting Indian Banking Infrastructure (Bank of India, SBI, PNB, ICICI, HDFC) from Android Trojans"
    p_ft.font.size = Pt(9.5)
    p_ft.font.color.rgb = RGBColor(100, 116, 139)


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 2: The Problem - Intelligence Translation Gap
    # ════════════════════════════════════════════════════════════════════════════
    s2 = prs.slides.add_slide(blank_layout)
    set_background(s2)
    add_header(s2, "The Problem: The Mobile Threat Intelligence Translation Gap", 
               "Why conventional malware tools fail against modern Android banking trojans and leave SOC teams blind",
               "PROBLEM DEFINITION")
    add_footer(s2, 2)

    # 3 Core Failure Pain Points
    pain_points = [
        ("1. Deceptive Payloads & Evasion", 
         "Banking trojans (Drinik, Xenomorph, Hydra, Anubis) use dynamic DEX loading, reflection, and encrypted strings. Static analysis sees only generic packers, missing malicious runtime logic entirely.",
         CRITICAL_RED, BG_LIGHT_RED),
        ("2. The Intelligence Translation Gap", 
         "Raw tooling emits thousands of disjointed events (SMS permissions, Accessibility flags, socket connections). SOC analysts are overwhelmed and lack the causal link proving fraud intent.",
         HIGH_ORANGE, BG_LIGHT_AMBER),
        ("3. Uncontrolled AI Hallucination", 
         "Generic LLMs used in security tools invent CVEs, fabricate risk scores, and hallucinate behaviors. Financial compliance requires deterministic, court-admissible mathematical proof.",
         BRAND_BLUE, BG_LIGHT_BLUE),
    ]

    for i, (title, body, col, bg_col) in enumerate(pain_points):
        x = Inches(0.8 + i * 3.98)
        y = Inches(1.9)
        w = Inches(3.78)
        h = Inches(1.7)
        c = add_card(s2, x, y, w, h, bg_color=bg_col, border_color=BORDER_LIGHT)
        
        # Color accent strip on left
        strip = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, Inches(0.08), h)
        strip.fill.solid()
        strip.fill.fore_color.rgb = col
        strip.line.fill.background()

        tb = s2.shapes.add_textbox(x + Inches(0.2), y + Inches(0.15), w - Inches(0.35), h - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_top = tf.margin_bottom = tf.margin_left = tf.margin_right = 0
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(12)
        p.font.bold = True
        p.font.color.rgb = col

        p2 = tf.add_paragraph()
        p2.space_before = Pt(6)
        p2.text = body
        p2.font.size = Pt(9.5)
        p2.font.color.rgb = SLATE_BODY

    # Comparison Matrix Card: Traditional Tools vs SUDARSHAN
    matrix_card = add_card(s2, Inches(0.8), Inches(3.8), Inches(11.733), Inches(3.05))

    tb_m = s2.shapes.add_textbox(Inches(1.05), Inches(3.95), Inches(11.2), Inches(0.35))
    tf_m = tb_m.text_frame
    p_m = tf_m.paragraphs[0]
    p_m.text = "EXECUTION COMPARISON : TRADITIONAL TOOLS VS. SUDARSHAN ARCHITECTURE"
    p_m.font.size = Pt(11)
    p_m.font.bold = True
    p_m.font.color.rgb = BRAND_BLUE

    # Table layout
    headers = ["Analysis Dimension", "Conventional Sandbox / AV Tools", "SUDARSHAN Enterprise Platform", "Operational Impact"]
    col_widths = [Inches(2.2), Inches(3.2), Inches(3.6), Inches(2.2)]
    col_x = [Inches(1.05), Inches(3.25), Inches(6.45), Inches(10.05)]
    
    # Header row
    hy = Inches(4.35)
    for j, h_text in enumerate(headers):
        tb_h = s2.shapes.add_textbox(col_x[j], hy, col_widths[j], Inches(0.28))
        tf_h = tb_h.text_frame
        tf_h.margin_top = tf_h.margin_bottom = tf_h.margin_left = tf_h.margin_right = 0
        ph = tf_h.paragraphs[0]
        ph.text = h_text
        ph.font.size = Pt(9)
        ph.font.bold = True
        ph.font.color.rgb = NAVY_HEADER

    rows = [
        ("Static Analysis", "Decompilation dumps and raw permission counts", "VIDE 4-Axis Visual Impersonation and auto-repaired AST", "Catches fake bank lookalikes immediately"),
        ("Dynamic Sandbox", "Blind 30s timeout; fails on OTP/login screens", "5-Level Agentic Explorer with synthetic credential dispatch", "Achieves deep multi-screen state exploration"),
        ("Telemetry Correlation", "Isolated event logs requiring manual grep", "Causal Workflow Reconstruction with MITRE ATT&CK mapping", "Reconstructs complete fraud attack sequences"),
        ("Scoring Authority", "Subjective CVSS or hallucinated AI scores", "Deterministic Fraud Risk Score (FRS 0-100) with 4 Safety Floors", "Court-admissible, fully auditable risk metric"),
        ("SOC Integration", "Unstructured JSON reports; slow triage", "Evidence-grounded RAG Dossiers and STIX 2.1 / MISP feeds", "Accelerates incident triage from hours to minutes"),
    ]

    for i, r in enumerate(rows):
        ry = Inches(4.75 + i * 0.42)
        # alternate row background
        if i % 2 == 1:
            row_bg = s2.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.95), ry - Inches(0.04), Inches(11.433), Inches(0.38))
            row_bg.fill.solid()
            row_bg.fill.fore_color.rgb = RGBColor(248, 250, 252)
            row_bg.line.fill.background()

        for j, val in enumerate(r):
            tb_c = s2.shapes.add_textbox(col_x[j], ry, col_widths[j], Inches(0.35))
            tf_c = tb_c.text_frame
            tf_c.word_wrap = True
            tf_c.margin_top = tf_c.margin_bottom = tf_c.margin_left = tf_c.margin_right = 0
            pc = tf_c.paragraphs[0]
            pc.text = val
            pc.font.size = Pt(8.5)
            if j == 0:
                pc.font.bold = True
                pc.font.color.rgb = NAVY_HEADER
            elif j == 2:
                pc.font.bold = True
                pc.font.color.rgb = BRAND_BLUE
            elif j == 1:
                pc.font.color.rgb = SLATE_MUTED
            else:
                pc.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 3: What is SUDARSHAN? The Four-Pillar Convergence
    # ════════════════════════════════════════════════════════════════════════════
    s3 = prs.slides.add_slide(blank_layout)
    set_background(s3)
    add_header(s3, "What is SUDARSHAN? The Four-Pillar Convergence",
               "A purpose-built fraud intelligence platform translating raw artifacts into court-admissible banking defense",
               "PLATFORM PILLARS")
    add_footer(s3, 3)

    pillars_s3 = [
        ("PILLAR 1", "Multi-Source Evidence Extraction", BRAND_BLUE, [
            "Dual-Engine Static Analysis: MobSF rules + Androguard AST decomposition",
            "APK Structure Repair: Auto-heals corrupted ZIP headers and manifests",
            "VIDE Impersonation Engine: Detects fake Indian banking app lookalikes",
            "IOC Reputation Feeds: 24h cached VT, AlienVault OTX, AbuseIPDB lookup"
        ]),
        ("PILLAR 2", "Deep Dynamic Exploration", ACCENT_BLUE, [
            "PID-Accurate Early Hooking: Injects Frida bundle prior to native library init",
            "5-Level Perception Loop: XML hierarchy, Activity state, Frida, Logcat, Vision",
            "Autonomous Obstacle Dispatcher: Auto-fills OTPs, pins, and login forms",
            "Anti-Analysis Evasion Bypasses: Transparent stubs mask tracerpid and root"
        ]),
        ("PILLAR 3", "Deterministic Risk Authority", SKY_BLUE, [
            "Mathematical FRS Engine: 0-100 score combining STEI, BFCI v2, and Impact",
            "4 Non-Bypassable Safety Floors: Enforces minimum risk for stealth and evasion",
            "CH27 Fraud Triad Escalation: Cloned layout + Cert mismatch + Accessibility",
            "Absolute Zero AI Risk Bias: Code-level rule authority governs final verdict"
        ]),
        ("PILLAR 4", "Evidence-Constrained Intelligence", RGBColor(16, 149, 193), [
            "Google Gemini 2.5 Flash RAG: Natural language explanation strictly on indexed facts",
            "3-State Circuit Breaker: Instant fallback if API limits or errors occur",
            "Automated Investigation Dossier: 7-section structured executive report",
            "Enterprise SOC Export: STIX 2.1 bundles, MISP feeds, and signed evidence JSON"
        ]),
    ]

    c_w = Inches(2.78)
    c_h = Inches(4.9)
    for i, (tag, title, col, points) in enumerate(pillars_s3):
        x = Inches(0.8 + i * 2.98)
        y = Inches(1.9)
        card = add_card(s3, x, y, c_w, c_h, bg_color=WHITE, border_color=BORDER_LIGHT)

        # Header bar on card
        top_bar = s3.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, c_w, Inches(0.55))
        top_bar.fill.solid()
        top_bar.fill.fore_color.rgb = col
        top_bar.line.fill.background()

        tb_tag = s3.shapes.add_textbox(x + Inches(0.15), y + Inches(0.08), c_w - Inches(0.3), Inches(0.2))
        tf_tag = tb_tag.text_frame
        p_tag = tf_tag.paragraphs[0]
        p_tag.text = tag
        p_tag.font.size = Pt(8)
        p_tag.font.bold = True
        p_tag.font.color.rgb = RGBColor(224, 242, 254)

        tb_title = s3.shapes.add_textbox(x + Inches(0.15), y + Inches(0.26), c_w - Inches(0.3), Inches(0.3))
        tf_title = tb_title.text_frame
        p_title = tf_title.paragraphs[0]
        p_title.text = title
        p_title.font.size = Pt(9.5)
        p_title.font.bold = True
        p_title.font.color.rgb = WHITE

        # Content bullets
        tb_body = s3.shapes.add_textbox(x + Inches(0.18), y + Inches(0.7), c_w - Inches(0.36), c_h - Inches(0.8))
        tf_body = tb_body.text_frame
        tf_body.word_wrap = True
        for pt in points:
            p = tf_body.add_paragraph()
            p.space_before = Pt(10)
            p.text = "- " + pt
            p.font.size = Pt(9)
            p.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 4: Complete System Architecture
    # ════════════════════════════════════════════════════════════════════════════
    s4 = prs.slides.add_slide(blank_layout)
    set_background(s4)
    add_header(s4, "Complete System Architecture",
               "Modular, strictly bounded, and tamper-resistant architecture engineered for high-throughput banking SOCs",
               "SYSTEM ARCHITECTURE")
    add_footer(s4, 4)

    # Architectural Layers (Vertical stack with clear boundaries)
    layers = [
        ("1. Presentation & Analyst Experience", 
         [("React 18 / Vite SPA", "Clean White/Blue Theme"), ("Tailwind CSS + Lucide", "Responsive UI System"), ("Role-Based Access", "Admin / SOC Lead / Analyst"), ("Evidence Registry", "Searchable finding tables")]),
        ("2. API Gateway & Orchestration Core", 
         [("FastAPI Gateway (:8000)", "Strict CORS & Rate Limiting"), ("JWT Auth Engine", "Stateless analyst sessions"), ("Durable Queue & Workers", "Resilient async batching"), ("SQLite WAL Store", "Forensic persistence")]),
        ("3. Dual-Engine Analysis Foundation", 
         [("Static Decompilation", "Androguard + MobSF rules"), ("VIDE Engine", "AST, Color & String Matching"), ("Android AVD Sandbox", "Hardened emulator container"), ("Frida Dynamic Bundle", "Early PID hook instrumentation")]),
        ("4. Intelligence & Correlation Engine", 
         [("Runtime Event Bus", "High-speed telemetry broker"), ("Threat Correlator", "VT, OTX, AbuseIPDB (24h TTL)"), ("Workflow Reconstructor", "Causal attack chain builder"), ("MITRE ATT&CK Mapping", "Mobile fraud technique tags")]),
        ("5. Deterministic Scoring & AI Explanation", 
         [("STEI Engine", "5-axis static exposure"), ("BFCI v2 Engine", "7 behavioral fraud axes"), ("4 Safety Floors", "Stealth & evasion bounds"), ("Gemini 2.5 Flash RAG", "Evidence-constrained narrative")]),
    ]

    y_start = Inches(1.9)
    layer_h = Inches(0.92)
    layer_gap = Inches(0.12)

    for i, (layer_title, sub_boxes) in enumerate(layers):
        ly = y_start + i * (layer_h + layer_gap)
        l_card = add_card(s4, Inches(0.8), ly, Inches(11.733), layer_h, bg_color=WHITE, border_color=BORDER_LIGHT)

        # Left label strip
        l_strip = s4.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), ly, Inches(2.6), layer_h)
        l_strip.fill.solid()
        l_strip.fill.fore_color.rgb = BRAND_BLUE if i % 2 == 0 else RGBColor(30, 64, 175)
        l_strip.line.fill.background()

        tb_l = s4.shapes.add_textbox(Inches(0.9), ly + Inches(0.25), Inches(2.4), Inches(0.5))
        tf_l = tb_l.text_frame
        tf_l.word_wrap = True
        tf_l.margin_top = tf_l.margin_bottom = tf_l.margin_left = tf_l.margin_right = 0
        p_l = tf_l.paragraphs[0]
        p_l.text = layer_title
        p_l.font.size = Pt(10)
        p_l.font.bold = True
        p_l.font.color.rgb = WHITE

        # Sub boxes
        b_w = Inches(2.1)
        b_h = Inches(0.68)
        b_x_start = Inches(3.6)
        b_gap = Inches(0.18)

        for k, (b_title, b_desc) in enumerate(sub_boxes):
            bx = b_x_start + k * (b_w + b_gap)
            by = ly + Inches(0.12)
            box = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, bx, by, b_w, b_h)
            box.fill.solid()
            box.fill.fore_color.rgb = BG_LIGHT_BLUE
            box.line.color.rgb = RGBColor(191, 219, 254)
            box.line.width = Pt(1)

            tb_b = s4.shapes.add_textbox(bx + Inches(0.1), by + Inches(0.08), b_w - Inches(0.2), b_h - Inches(0.16))
            tf_b = tb_b.text_frame
            tf_b.word_wrap = True
            tf_b.margin_top = tf_b.margin_bottom = tf_b.margin_left = tf_b.margin_right = 0
            pb1 = tf_b.paragraphs[0]
            pb1.text = b_title
            pb1.font.size = Pt(8.5)
            pb1.font.bold = True
            pb1.font.color.rgb = BRAND_BLUE

            pb2 = tf_b.add_paragraph()
            pb2.text = b_desc
            pb2.font.size = Pt(7.5)
            pb2.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 5: End-to-End Analysis Pipeline
    # ════════════════════════════════════════════════════════════════════════════
    s5 = prs.slides.add_slide(blank_layout)
    set_background(s5)
    add_header(s5, "End-to-End Analysis Pipeline: From APK to Court-Admissible Verdict",
               "Six sequential, strictly bounded analysis stages executing with automated failovers and complete auditability",
               "ANALYSIS PIPELINE")
    add_footer(s5, 5)

    stages = [
        ("STAGE 01", "Intake & Header Repair", 
         "Validates APK structure, hashes SHA-256, extracts signing certificates, and auto-heals corrupted central directories.",
         "zipfile, androguard, apktool", BRAND_BLUE),
        ("STAGE 02", "Static Decompilation & VIDE", 
         "Decompiles DEX bytecode into smali and Java AST. VIDE detects visual brand cloning across 10 protected Indian banks.",
         "Androguard, MobSF, RapidFuzz", ACCENT_BLUE),
        ("STAGE 03", "Dynamic Detonation", 
         "Boots APK in instrumented Android sandbox. Injects Frida banking trojan bundle at spawn time before anti-root loads.",
         "Android AVD, ADB, Frida hook bundle", SKY_BLUE),
        ("STAGE 04", "Deep Agentic Exploration", 
         "5-level perception loop navigates UI barriers, automatically bypassing login screens, OTP prompts, and permission dialogs.",
         "Agentic Explorer, OCR vision", RGBColor(14, 116, 144)),
        ("STAGE 05", "Causal Workflow Reconstruction", 
         "Correlates raw runtime events through causal chain rules into an end-to-end multi-stage fraud attack sequence.",
         "WorkflowReconstructor, MITRE ATT&CK", RGBColor(15, 118, 110)),
        ("STAGE 06", "Deterministic Scoring & RAG", 
         "FRS calculator enforces 4 safety floors. Gemini 2.5 Flash RAG synthesizes an evidence-grounded threat dossier.",
         "RiskEngine, Gemini 2.5 Flash", RGBColor(67, 56, 202)),
    ]

    col_w = Inches(1.8)
    col_h = Inches(4.8)
    gap = Inches(0.18)
    x_offset = Inches(0.8)

    for i, (num, title, desc, tools, col) in enumerate(stages):
        x = x_offset + i * (col_w + gap)
        y = Inches(1.9)
        c = add_card(s5, x, y, col_w, col_h, bg_color=WHITE, border_color=BORDER_LIGHT)

        # Top pill
        pill = s5.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, col_w, Inches(0.42))
        pill.fill.solid()
        pill.fill.fore_color.rgb = col
        pill.line.fill.background()

        tb_num = s5.shapes.add_textbox(x, y + Inches(0.08), col_w, Inches(0.28))
        tf_num = tb_num.text_frame
        p_num = tf_num.paragraphs[0]
        p_num.text = num
        p_num.font.size = Pt(8.5)
        p_num.font.bold = True
        p_num.font.color.rgb = WHITE
        p_num.alignment = PP_ALIGN.CENTER

        # Stage title
        tb_t = s5.shapes.add_textbox(x + Inches(0.1), y + Inches(0.55), col_w - Inches(0.2), Inches(0.75))
        tf_t = tb_t.text_frame
        tf_t.word_wrap = True
        tf_t.margin_top = tf_t.margin_bottom = tf_t.margin_left = tf_t.margin_right = 0
        p_t = tf_t.paragraphs[0]
        p_t.text = title
        p_t.font.size = Pt(10)
        p_t.font.bold = True
        p_t.font.color.rgb = NAVY_HEADER

        # Description
        tb_d = s5.shapes.add_textbox(x + Inches(0.1), y + Inches(1.4), col_w - Inches(0.2), Inches(2.2))
        tf_d = tb_d.text_frame
        tf_d.word_wrap = True
        tf_d.margin_top = tf_d.margin_bottom = tf_d.margin_left = tf_d.margin_right = 0
        p_d = tf_d.paragraphs[0]
        p_d.text = desc
        p_d.font.size = Pt(8.5)
        p_d.font.color.rgb = SLATE_BODY

        # Tools box at bottom
        tb_tool = s5.shapes.add_textbox(x + Inches(0.08), y + Inches(3.75), col_w - Inches(0.16), Inches(0.9))
        tf_tool = tb_tool.text_frame
        tf_tool.word_wrap = True
        tf_tool.margin_top = tf_tool.margin_bottom = tf_tool.margin_left = tf_tool.margin_right = 0
        p_tl1 = tf_tool.paragraphs[0]
        p_tl1.text = "CORE ENGINES:"
        p_tl1.font.size = Pt(7)
        p_tl1.font.bold = True
        p_tl1.font.color.rgb = BRAND_BLUE

        p_tl2 = tf_tool.add_paragraph()
        p_tl2.text = tools
        p_tl2.font.size = Pt(8)
        p_tl2.font.color.rgb = SLATE_MUTED

        # Connecting dash if not last
        if i < len(stages) - 1:
            dash = s5.shapes.add_shape(MSO_SHAPE.RECTANGLE, x + col_w + Inches(0.02), Inches(2.15), Inches(0.14), Inches(0.03))
            dash.fill.solid()
            dash.fill.fore_color.rgb = RGBColor(148, 163, 184)
            dash.line.color.rgb = RGBColor(148, 163, 184)


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 6: Static Threat Intelligence & VIDE
    # ════════════════════════════════════════════════════════════════════════════
    s6 = prs.slides.add_slide(blank_layout)
    set_background(s6)
    add_header(s6, "Static Threat Intelligence & Visual Impersonation (VIDE)",
               "Unmasking fake banking apps, credential stealers, and phishing overlays prior to sandbox execution",
               "STATIC INTELLIGENCE & VIDE")
    add_footer(s6, 6)

    # Left Card: Static Threat Intelligence Pipeline
    c_left = add_card(s6, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.9))
    tb_sl = s6.shapes.add_textbox(Inches(1.05), Inches(2.1), Inches(5.1), Inches(0.4))
    tf_sl = tb_sl.text_frame
    p_sl = tf_sl.paragraphs[0]
    p_sl.text = "STATIC DECOMPILATION & THREAT SCORING"
    p_sl.font.size = Pt(12)
    p_sl.font.bold = True
    p_sl.font.color.rgb = BRAND_BLUE

    static_points = [
        ("Resilient Header Repair", "Auto-repairs manipulated APK ZIP headers, truncated manifests, and obfuscated string pools used to crash standard analysis tools."),
        ("DEX & Smali AST Analysis", "Parses classes, methods, and reflection calls; identifies hidden dynamic DEX loaders, native dropper binaries, and packing signatures."),
        ("Permission & Component Profiling", "Flags 127 high-risk Android permissions (Accessibility, System Alert Window, Read/Send SMS, Query All Packages) and hidden receivers."),
        ("External Threat Feeds (24h Cache)", "Hashes, domains, and IP endpoints are correlated against VirusTotal, AlienVault OTX, and AbuseIPDB with SQLite caching to conserve quota."),
        ("STEI Calculation (0 to 100)", "Combines Credential Theft (60%), Banking Targeting (20%), Permission Risk (10%), Obfuscation (5%), and Infrastructure Risk (5%).")
    ]

    for idx, (head, body) in enumerate(static_points):
        tb_pt = s6.shapes.add_textbox(Inches(1.05), Inches(2.6 + idx * 0.8), Inches(5.1), Inches(0.75))
        tf_pt = tb_pt.text_frame
        tf_pt.word_wrap = True
        tf_pt.margin_top = tf_pt.margin_bottom = tf_pt.margin_left = tf_pt.margin_right = 0
        p1 = tf_pt.paragraphs[0]
        p1.text = "- " + head
        p1.font.size = Pt(9.5)
        p1.font.bold = True
        p1.font.color.rgb = NAVY_HEADER
        p2 = tf_pt.add_paragraph()
        p2.text = body
        p2.font.size = Pt(8.5)
        p2.font.color.rgb = SLATE_BODY

    # Right Card: VIDE (Visual Impersonation Detection Engine)
    c_right = add_card(s6, Inches(6.7), Inches(1.9), Inches(5.833), Inches(4.9))
    tb_sr = s6.shapes.add_textbox(Inches(6.95), Inches(2.1), Inches(5.3), Inches(0.4))
    tf_sr = tb_sr.text_frame
    p_sr = tf_sr.paragraphs[0]
    p_sr.text = "VIDE: VISUAL IMPERSONATION DETECTION ENGINE"
    p_sr.font.size = Pt(12)
    p_sr.font.bold = True
    p_sr.font.color.rgb = BRAND_BLUE

    vide_axes = [
        ("1. Layout View AST Distance (Threshold: 0.20)", 
         "Decompiles layout XML into an Abstract Syntax Tree. Compares view hierarchy structures against official banking templates.", RGBColor(30, 58, 138)),
        ("2. CIEDE2000 Color Vector Distance", 
         "Calculates perceptual color difference Delta-E across dominant palette vectors to detect fake banking theme color clones.", ACCENT_BLUE),
        ("3. RapidFuzz String Similarity (Threshold: 82.0)", 
         "Token-based string matching detects typosquatting and deceptive brand names across app labels and package identifiers.", SKY_BLUE),
        ("4. Protected Signer Registry (10 Indian Banks)", 
         "Maintains cryptographically verified SHA-256 signer certificates for Bank of India, SBI, PNB, ICICI, HDFC, Axis, and others.", RGBColor(5, 150, 105))
    ]

    for idx, (title, desc, col) in enumerate(vide_axes):
        ay = Inches(2.6 + idx * 0.82)
        box = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.95), ay, Inches(5.3), Inches(0.72))
        box.fill.solid()
        box.fill.fore_color.rgb = BG_LIGHT_BLUE
        box.line.color.rgb = RGBColor(191, 219, 254)
        box.line.width = Pt(1)

        tb_a = s6.shapes.add_textbox(Inches(7.1), ay + Inches(0.08), Inches(5.0), Inches(0.56))
        tf_a = tb_a.text_frame
        tf_a.word_wrap = True
        tf_a.margin_top = tf_a.margin_bottom = tf_a.margin_left = tf_a.margin_right = 0
        p_a1 = tf_a.paragraphs[0]
        p_a1.text = title
        p_a1.font.size = Pt(9)
        p_a1.font.bold = True
        p_a1.font.color.rgb = col
        p_a2 = tf_a.add_paragraph()
        p_a2.text = desc
        p_a2.font.size = Pt(8)
        p_a2.font.color.rgb = SLATE_BODY

    # VIDE Outcome Callout Box
    res_box = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.95), Inches(5.95), Inches(5.3), Inches(0.65))
    res_box.fill.solid()
    res_box.fill.fore_color.rgb = BG_LIGHT_RED
    res_box.line.color.rgb = RGBColor(254, 202, 202)
    tb_res = s6.shapes.add_textbox(Inches(7.1), Inches(6.0), Inches(5.0), Inches(0.55))
    tf_res = tb_res.text_frame
    tf_res.word_wrap = True
    p_r1 = tf_res.paragraphs[0]
    p_r1.text = "CRITICAL DETECTION OUTCOME :"
    p_r1.font.size = Pt(8.5)
    p_r1.font.bold = True
    p_r1.font.color.rgb = CRITICAL_RED
    p_r2 = tf_res.add_paragraph()
    p_r2.text = "Visual clone match (>0.85) + Signer Certificate Mismatch activates CH27 Fraud Triad escalation (FRS >= 95)."
    p_r2.font.size = Pt(8)
    p_r2.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 7: Dynamic Analysis & Deep Agentic Exploration
    # ════════════════════════════════════════════════════════════════════════════
    s7 = prs.slides.add_slide(blank_layout)
    set_background(s7)
    add_header(s7, "Dynamic Analysis & Deep Agentic Exploration",
               "Autonomous sandbox execution powered by PID-accurate early hooking and 5-level perception navigation",
               "DYNAMIC DETONATION")
    add_footer(s7, 7)

    # Left Column: Technical Capabilities
    c_dyn = add_card(s7, Inches(0.8), Inches(1.9), Inches(7.4), Inches(4.9))

    tb_dt = s7.shapes.add_textbox(Inches(1.05), Inches(2.1), Inches(6.9), Inches(0.35))
    tf_dt = tb_dt.text_frame
    p_dt = tf_dt.paragraphs[0]
    p_dt.text = "SANDBOX ORCHESTRATION & FRIDA INSTRUMENTATION"
    p_dt.font.size = Pt(11.5)
    p_dt.font.bold = True
    p_dt.font.color.rgb = BRAND_BLUE

    dyn_features = [
        ("Early PID Hook Injection (banking_trojan.bundle.js)", 
         "Frida attaches at process spawn time prior to native library initialization, neutralizing anti-analysis routines that attempt to terminate the app upon detecting ptrace or frida-server."),
        ("ART Runtime Deoptimization & Universal SSL Bypass", 
         "Deoptimizes JIT-compiled methods to ensure all sensitive banking API calls trigger hooks; neutralizes certificate pinning across OkHttp3, TrustManager, and Conscrypt."),
        ("5-Level Perception Hierarchy Loop", 
         "Level 1: Native Accessibility XML hierarchy dump (sub-second UI parsing)\n"
         "Level 2: Activity Manager state and focused window detection\n"
         "Level 3: Frida method invocation hooks and dynamic event interception\n"
         "Level 4: Real-time Android Window Manager and Logcat error telemetry\n"
         "Level 5: Computer Vision / OCR fallback when views are obfuscated or rendered in WebViews"),
        ("Directed Screen Graph Exploration", 
         "Maintains a state transition graph of discovered screens to eliminate infinite loops; dynamically schedules interactions to maximize code coverage within a 130s adaptive budget.")
    ]

    for idx, (title, desc) in enumerate(dyn_features):
        tb_df = s7.shapes.add_textbox(Inches(1.05), Inches(2.55 + idx * 1.05), Inches(6.9), Inches(0.95))
        tf_df = tb_df.text_frame
        tf_df.word_wrap = True
        tf_df.margin_top = tf_df.margin_bottom = tf_df.margin_left = tf_df.margin_right = 0
        p1 = tf_df.paragraphs[0]
        p1.text = "- " + title
        p1.font.size = Pt(9.5)
        p1.font.bold = True
        p1.font.color.rgb = NAVY_HEADER
        p2 = tf_df.add_paragraph()
        p2.space_before = Pt(3)
        p2.text = desc
        p2.font.size = Pt(8.5)
        p2.font.color.rgb = SLATE_BODY

    # Right Column: Real Dynamic Execution Screenshots
    c_pic = add_card(s7, Inches(8.4), Inches(1.9), Inches(4.133), Inches(4.9))

    tb_pt = s7.shapes.add_textbox(Inches(8.6), Inches(2.1), Inches(3.7), Inches(0.3))
    tf_pt = tb_pt.text_frame
    p_pt = tf_pt.paragraphs[0]
    p_pt.text = "REAL SANDBOX RUNTIME CAPTURE"
    p_pt.font.size = Pt(10.5)
    p_pt.font.bold = True
    p_pt.font.color.rgb = BRAND_BLUE

    # Mobile screenshots
    shot1_path = os.path.join(SAMPLE_SCREENSHOTS_DIR, "0002_state_state-001_bank_logi.png")
    shot2_path = os.path.join(SAMPLE_SCREENSHOTS_DIR, "0003_Runtime_permission_dialog.png")

    if os.path.exists(shot1_path):
        s7.shapes.add_picture(shot1_path, Inches(8.65), Inches(2.5), width=Inches(1.75))
        lbl1 = s7.shapes.add_textbox(Inches(8.65), Inches(6.15), Inches(1.75), Inches(0.5))
        tf_lbl1 = lbl1.text_frame
        tf_lbl1.word_wrap = True
        p_l1 = tf_lbl1.paragraphs[0]
        p_l1.text = "Screen 1: Bank Login Form\n(Automated test credentials)"
        p_l1.font.size = Pt(7.5)
        p_l1.font.color.rgb = SLATE_MUTED

    if os.path.exists(shot2_path):
        s7.shapes.add_picture(shot2_path, Inches(10.55), Inches(2.5), width=Inches(1.75))
        lbl2 = s7.shapes.add_textbox(Inches(10.55), Inches(6.15), Inches(1.75), Inches(0.5))
        tf_lbl2 = lbl2.text_frame
        tf_lbl2.word_wrap = True
        p_l2 = tf_lbl2.paragraphs[0]
        p_l2.text = "Screen 2: Permission Trap\n(Accessibility abuse bypass)"
        p_l2.font.size = Pt(7.5)
        p_l2.font.color.rgb = SLATE_MUTED


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 8: Handling Real-World Banking App Obstacles
    # ════════════════════════════════════════════════════════════════════════════
    s8 = prs.slides.add_slide(blank_layout)
    set_background(s8)
    add_header(s8, "Handling Real-World Banking App Obstacles",
               "Automated perception and dispatch mechanisms breaking through complex barriers that stall traditional sandboxes",
               "OBSTACLE NAVIGATION")
    add_footer(s8, 8)

    obstacles = [
        ("Login & Credential Gates", 
         "Challenge: Banking malware pauses execution until user inputs valid credentials.\n"
         "SUDARSHAN Solution: Synthetic Credential Dispatcher detects input fields and injects plausible test identities, triggering subsequent fraud logic.",
         BRAND_BLUE, BG_LIGHT_BLUE),
        ("OTP & SMS 2FA Prompts", 
         "Challenge: App stalls waiting for an incoming carrier SMS verification code.\n"
         "SUDARSHAN Solution: Virtual SMS Gateway simulates incoming OTP messages via ADB, directly firing the malware's SMS interception receivers.",
         ACCENT_BLUE, BG_LIGHT_BLUE),
        ("Custom M-PIN & Number Pads", 
         "Challenge: Scrambled on-screen custom PIN keypads prevent text input injection.\n"
         "SUDARSHAN Solution: OCR coordinate mapper detects numeric keypad bounding boxes and coordinates randomized tap sequences.",
         SKY_BLUE, BG_LIGHT_BLUE),
        ("Runtime Permission Dialogs", 
         "Challenge: System popups block app until user grants Accessibility or SMS access.\n"
         "SUDARSHAN Solution: Auto-Grant Dispatcher monitors system dialog windows and programmatically clicks 'Allow' or activates accessibility services.",
         RGBColor(14, 116, 144), BG_LIGHT_BLUE),
        ("Phishing Overlays & WebViews", 
         "Challenge: Trojan hides malicious payload inside an overlay WebView or sub-domain.\n"
         "SUDARSHAN Solution: Multi-Window Monitor intercepts TYPE_APPLICATION_OVERLAY, extracts rendered HTML, and captures phishing form targets.",
         RGBColor(15, 118, 110), BG_LIGHT_BLUE),
        ("Anti-Analysis & Sandbox Checks", 
         "Challenge: Malware detects emulator files (qemu, build props), root (su), or Frida.\n"
         "SUDARSHAN Solution: Stealth Frida Stubs spoof device fingerprint, hide open ports, and mask tracerpid, ensuring malware executes fully.",
         CRITICAL_RED, BG_LIGHT_RED),
    ]

    card_w8 = Inches(3.78)
    card_h8 = Inches(2.25)
    for i, (title, text, col, bg_col) in enumerate(obstacles):
        row = i // 3
        col_idx = i % 3
        x = Inches(0.8 + col_idx * 3.98)
        y = Inches(1.9 + row * 2.45)

        card = add_card(s8, x, y, card_w8, card_h8, bg_color=bg_col, border_color=BORDER_LIGHT)

        # Top strip
        strip = s8.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, card_w8, Inches(0.38))
        strip.fill.solid()
        strip.fill.fore_color.rgb = col
        strip.line.fill.background()

        tb_t = s8.shapes.add_textbox(x + Inches(0.12), y + Inches(0.06), card_w8 - Inches(0.24), Inches(0.26))
        tf_t = tb_t.text_frame
        p_t = tf_t.paragraphs[0]
        p_t.text = title
        p_t.font.size = Pt(9.5)
        p_t.font.bold = True
        p_t.font.color.rgb = WHITE

        tb_b = s8.shapes.add_textbox(x + Inches(0.15), y + Inches(0.48), card_w8 - Inches(0.3), card_h8 - Inches(0.55))
        tf_b = tb_b.text_frame
        tf_b.word_wrap = True
        tf_b.margin_top = tf_b.margin_bottom = tf_b.margin_left = tf_b.margin_right = 0
        p_b = tf_b.paragraphs[0]
        p_b.text = text
        p_b.font.size = Pt(8.5)
        p_b.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 9: From Runtime Events to Fraud Intelligence
    # ════════════════════════════════════════════════════════════════════════════
    s9 = prs.slides.add_slide(blank_layout)
    set_background(s9)
    add_header(s9, "From Runtime Events to Fraud Intelligence: Causal Workflow Reconstruction",
               "Converting thousands of disjointed hook logs into coherent, causal banking fraud attack sequences",
               "WORKFLOW RECONSTRUCTION")
    add_footer(s9, 9)

    # Top Concept Card: Single Hook vs Causal Chain
    c_top = add_card(s9, Inches(0.8), Inches(1.9), Inches(11.733), Inches(1.4))
    tb_tc = s9.shapes.add_textbox(Inches(1.05), Inches(2.02), Inches(11.2), Inches(1.15))
    tf_tc = tb_tc.text_frame
    tf_tc.word_wrap = True
    p_tc1 = tf_tc.paragraphs[0]
    p_tc1.text = "THE RECONSTRUCTION ADVANTAGE : SINGLE INDICATOR VS. COMPLETE ATTACK CHAIN"
    p_tc1.font.size = Pt(10.5)
    p_tc1.font.bold = True
    p_tc1.font.color.rgb = BRAND_BLUE

    p_tc2 = tf_tc.add_paragraph()
    p_tc2.space_before = Pt(4)
    p_tc2.text = "Conventional sandboxes output disconnected event logs: an SMS read event, an accessibility flag, a socket send. In isolation, any one event could be benign. SUDARSHAN's WorkflowReconstructor engine correlates events across time and causal dependencies, proving malicious attack progression with mathematical confidence."
    p_tc2.font.size = Pt(9)
    p_tc2.font.color.rgb = SLATE_BODY

    # Reconstructed Attack Sequence Flow (Hydra Banking Trojan Real Example)
    flow_steps = [
        ("STAGE 1: SERVICE ACTIVATION", "Accessibility Hijack", "T1417 (Input Capture)", 
         "App tricks user or auto-clicks to enable Accessibility Service; starts monitoring window content.", BRAND_BLUE),
        ("STAGE 2: OVERLAY PHISHING", "Fake Banking Surface", "T1411 (Overlay Phishing)", 
         "Detects launch of genuine banking app; immediately draws full-screen fake login overlay on top.", ACCENT_BLUE),
        ("STAGE 3: 2FA INTERCEPTION", "SMS OTP Theft", "T1412 (SMS Capture)", 
         "Intercepts incoming SMS broadcast, suppresses notification, extracts 6-digit OTP from message text.", SKY_BLUE),
        ("STAGE 4: C2 EXFILTRATION", "Credential Transmission", "T1437 (C2 Protocol)", 
         "Transmits harvested login credentials, OTP, and device identity to malicious C2 server over HTTPS.", RGBColor(220, 38, 38)),
    ]

    sw = Inches(2.78)
    sh = Inches(3.2)
    s_gap = Inches(0.2)
    for idx, (st_name, st_act, mitre, st_desc, col) in enumerate(flow_steps):
        sx = Inches(0.8) + idx * (sw + s_gap)
        sy = Inches(3.55)
        sc = add_card(s9, sx, sy, sw, sh, bg_color=WHITE, border_color=BORDER_LIGHT)

        # Header band
        hb = s9.shapes.add_shape(MSO_SHAPE.RECTANGLE, sx, sy, sw, Inches(0.45))
        hb.fill.solid()
        hb.fill.fore_color.rgb = col
        hb.line.fill.background()

        tb_h = s9.shapes.add_textbox(sx + Inches(0.1), sy + Inches(0.08), sw - Inches(0.2), Inches(0.3))
        tf_h = tb_h.text_frame
        ph = tf_h.paragraphs[0]
        ph.text = st_name
        ph.font.size = Pt(8.5)
        ph.font.bold = True
        ph.font.color.rgb = WHITE

        # Action & MITRE
        tb_a = s9.shapes.add_textbox(sx + Inches(0.12), sy + Inches(0.55), sw - Inches(0.24), Inches(0.7))
        tf_a = tb_a.text_frame
        tf_a.word_wrap = True
        pa1 = tf_a.paragraphs[0]
        pa1.text = st_act
        pa1.font.size = Pt(11)
        pa1.font.bold = True
        pa1.font.color.rgb = NAVY_HEADER
        pa2 = tf_a.add_paragraph()
        pa2.text = "MITRE ATT&CK: " + mitre
        pa2.font.size = Pt(8)
        pa2.font.bold = True
        pa2.font.color.rgb = BRAND_BLUE

        # Description
        tb_sd = s9.shapes.add_textbox(sx + Inches(0.12), sy + Inches(1.35), sw - Inches(0.24), Inches(1.6))
        tf_sd = tb_sd.text_frame
        tf_sd.word_wrap = True
        psd = tf_sd.paragraphs[0]
        psd.text = st_desc
        psd.font.size = Pt(8.5)
        psd.font.color.rgb = SLATE_BODY



    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 10: Deterministic Risk Engine
    # ════════════════════════════════════════════════════════════════════════════
    s10 = prs.slides.add_slide(blank_layout)
    set_background(s10)
    add_header(s10, "Deterministic Risk Engine: Mathematical Authority",
               "Guaranteed, auditable, and court-admissible risk scoring where AI is prohibited from computing verdicts",
               "RISK ENGINE")
    add_footer(s10, 10)

    # Left Card: FRS Master Formula & Components
    c_form = add_card(s10, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.9))

    tb_fh = s10.shapes.add_textbox(Inches(1.05), Inches(2.1), Inches(5.1), Inches(0.4))
    tf_fh = tb_fh.text_frame
    p_fh = tf_fh.paragraphs[0]
    p_fh.text = "FRAUD RISK SCORE (FRS) FORMULA"
    p_fh.font.size = Pt(11.5)
    p_fh.font.bold = True
    p_fh.font.color.rgb = BRAND_BLUE

    # Formula Box
    fbox = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.05), Inches(2.5), Inches(5.1), Inches(0.7))
    fbox.fill.solid()
    fbox.fill.fore_color.rgb = BG_LIGHT_BLUE
    fbox.line.color.rgb = RGBColor(191, 219, 254)
    tb_f = s10.shapes.add_textbox(Inches(1.15), Inches(2.55), Inches(4.9), Inches(0.55))
    tf_f = tb_f.text_frame
    tf_f.word_wrap = True
    pf = tf_f.paragraphs[0]
    pf.text = "FRS = 0.25*STEI + 0.35*BFCI + 0.20*Correlation + 0.20*BankingImpact"
    pf.font.name = FONT_MONO
    pf.font.size = Pt(9.5)
    pf.font.bold = True
    pf.font.color.rgb = BRAND_BLUE

    frs_details = [
        ("STEI (Static Threat Exposure Index)", "0.60*CT + 0.20*BT + 0.10*PR + 0.05*OB + 0.05*IR\nWeights credential theft and targeting over generic permissions."),
        ("BFCI v2 (Behavioral Confidence Index)", "7 behavioral axes: Accessibility (0.315), SMS Intercept (0.225), Overlay Phishing (0.180), Bank Target (0.090), Code Exec (0.100), Network (0.045), Persistence (0.045)."),
        ("Threat Correlation Score", "External IP/Domain/Hash matches from VT, AlienVault OTX, AbuseIPDB."),
        ("Targeted Banking Impact Score", "Direct targeting of Indian financial entities (BOI, SBI, UPI protocols).")
    ]

    for idx, (head, desc) in enumerate(frs_details):
        tb_fd = s10.shapes.add_textbox(Inches(1.05), Inches(3.35 + idx * 0.8), Inches(5.1), Inches(0.75))
        tf_fd = tb_fd.text_frame
        tf_fd.word_wrap = True
        tf_fd.margin_top = tf_fd.margin_bottom = tf_fd.margin_left = tf_fd.margin_right = 0
        p1 = tf_fd.paragraphs[0]
        p1.text = "- " + head
        p1.font.size = Pt(9)
        p1.font.bold = True
        p1.font.color.rgb = NAVY_HEADER
        p2 = tf_fd.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(8)
        p2.font.color.rgb = SLATE_BODY

    # Right Card: Safety Floors & CH27 Triad
    c_floors = add_card(s10, Inches(6.7), Inches(1.9), Inches(5.833), Inches(4.9))

    tb_flh = s10.shapes.add_textbox(Inches(6.95), Inches(2.1), Inches(5.3), Inches(0.4))
    tf_flh = tb_flh.text_frame
    p_flh = tf_flh.paragraphs[0]
    p_flh.text = "NON-BYPASSABLE SAFETY FLOORS & FRAUD TRIAD"
    p_flh.font.size = Pt(11.5)
    p_flh.font.bold = True
    p_flh.font.color.rgb = BRAND_BLUE

    floors = [
        ("1. Visibility Safety Floor (Min FRS: 60)", "If app hides launcher icon or operates stealthily without user visibility, score cannot drop below 60.", AMBER_WARN),
        ("2. Static Evidence Floor (Min FRS: 70)", "Verified banking trojan signatures or hardcoded phishing overlays guarantee High/Critical risk floor.", HIGH_ORANGE),
        ("3. Evasion Safety Floor (Min FRS: 65)", "Active anti-analysis, ptrace detection, or environment tampering enforces minimum suspicious floor.", RGBColor(14, 116, 144)),
        ("4. Execution Assertions Floor (Min FRS: 85)", "Observed credential scraping or overlay injection forces score to minimum 85 regardless of other weights.", CRITICAL_RED)
    ]

    for idx, (title, desc, col) in enumerate(floors):
        fy = Inches(2.55 + idx * 0.72)
        fb = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.95), fy, Inches(5.3), Inches(0.64))
        fb.fill.solid()
        fb.fill.fore_color.rgb = BG_LIGHT_BLUE
        fb.line.color.rgb = RGBColor(191, 219, 254)
        fb.line.width = Pt(1)

        tb_f = s10.shapes.add_textbox(Inches(7.1), fy + Inches(0.06), Inches(5.0), Inches(0.52))
        tf_f = tb_f.text_frame
        tf_f.word_wrap = True
        tf_f.margin_top = tf_f.margin_bottom = tf_f.margin_left = tf_f.margin_right = 0
        pf1 = tf_f.paragraphs[0]
        pf1.text = title
        pf1.font.size = Pt(8.5)
        pf1.font.bold = True
        pf1.font.color.rgb = col
        pf2 = tf_f.add_paragraph()
        pf2.text = desc
        pf2.font.size = Pt(7.5)
        pf2.font.color.rgb = SLATE_BODY

    # CH27 Fraud Triad Callout Card
    triad_card = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.95), Inches(5.55), Inches(5.3), Inches(1.05))
    triad_card.fill.solid()
    triad_card.fill.fore_color.rgb = BG_LIGHT_RED
    triad_card.line.color.rgb = RGBColor(254, 202, 202)
    triad_card.line.width = Pt(1)

    tb_tr = s10.shapes.add_textbox(Inches(7.1), Inches(5.62), Inches(5.0), Inches(0.9))
    tf_tr = tb_tr.text_frame
    tf_tr.word_wrap = True
    ptr1 = tf_tr.paragraphs[0]
    ptr1.text = "THE CH27 ON-DEVICE FRAUD TRIAD ESCALATION :"
    ptr1.font.size = Pt(8.5)
    ptr1.font.bold = True
    ptr1.font.color.rgb = CRITICAL_RED

    ptr2 = tf_tr.add_paragraph()
    ptr2.text = "High Visual Clone (>0.85) + Signer Cert Mismatch + Accessibility Abuse (BIND_ACCESSIBILITY_SERVICE)\n==> Immediate Hard Escalation to FRS >= 95 (CRITICAL RISK)"
    ptr2.font.size = Pt(8)
    ptr2.font.bold = True
    ptr2.font.color.rgb = NAVY_HEADER


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 11: AI + RAG + Evidence-Constrained Analysis
    # ════════════════════════════════════════════════════════════════════════════
    s11 = prs.slides.add_slide(blank_layout)
    set_background(s11)
    add_header(s11, "AI + RAG + Evidence-Constrained Analysis",
               "Leveraging Google Gemini 2.5 Flash for rapid incident investigation without ever touching deterministic risk scoring",
               "AI INVESTIGATION BOUNDARY")
    add_footer(s11, 11)

    # Left Column: AI Boundary Principles
    c_ai_left = add_card(s11, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.9))

    tb_ail = s11.shapes.add_textbox(Inches(1.05), Inches(2.1), Inches(5.1), Inches(0.4))
    tf_ail = tb_ail.text_frame
    p_ail = tf_ail.paragraphs[0]
    p_ail.text = "STRICT ARCHITECTURAL AI BOUNDARY"
    p_ail.font.size = Pt(11.5)
    p_ail.font.bold = True
    p_ail.font.color.rgb = BRAND_BLUE

    ai_rules = [
        ("AI is an Explainability Engine, NEVER a Calculator", 
         "Gemini 2.5 Flash synthesizes technical findings into natural language explanations. It has zero authority to calculate, modify, or override the deterministic FRS score or risk band."),
        ("Evidence-Constrained RAG Pipeline", 
         "The LLM context window is populated exclusively with structured, verified evidence records from SQLite EvidenceStore. It answers only from indexed facts, citing exact Record IDs."),
        ("3-State Circuit Breaker Resilience", 
         "State 1: Normal (Live Gemini Flash streaming)\n"
         "State 2: Degraded (Rate limit or timeout detected)\n"
         "State 3: Tripped (Instant failover to deterministic rule narrative template; zero downtime)"),
        ("Prompt Injection Defense", 
         "Sanitizes all untrusted strings extracted from APK manifests, activity labels, and certificate metadata to prevent indirect prompt injection attacks.")
    ]

    for idx, (title, desc) in enumerate(ai_rules):
        tb_ar = s11.shapes.add_textbox(Inches(1.05), Inches(2.6 + idx * 1.02), Inches(5.1), Inches(0.92))
        tf_ar = tb_ar.text_frame
        tf_ar.word_wrap = True
        tf_ar.margin_top = tf_ar.margin_bottom = tf_ar.margin_left = tf_ar.margin_right = 0
        p1 = tf_ar.paragraphs[0]
        p1.text = "- " + title
        p1.font.size = Pt(9.5)
        p1.font.bold = True
        p1.font.color.rgb = NAVY_HEADER
        p2 = tf_ar.add_paragraph()
        p2.space_before = Pt(3)
        p2.text = desc
        p2.font.size = Pt(8.5)
        p2.font.color.rgb = SLATE_BODY

    # Right Column: 7-Section Investigation Dossier
    c_ai_right = add_card(s11, Inches(6.7), Inches(1.9), Inches(5.833), Inches(4.9))

    tb_air = s11.shapes.add_textbox(Inches(6.95), Inches(2.1), Inches(5.3), Inches(0.4))
    tf_air = tb_air.text_frame
    p_air = tf_air.paragraphs[0]
    p_air.text = "7-SECTION STRUCTURED INVESTIGATION DOSSIER"
    p_air.font.size = Pt(11.5)
    p_air.font.bold = True
    p_air.font.color.rgb = BRAND_BLUE

    dossier_sections = [
        ("Section 1: Executive Fraud Summary", "Plain-English verdict narrative summarizing malware intent, impact, and confidence level."),
        ("Section 2: Malware Family Attribution", "Correlates behavioral signatures with known banking families (Hydra, Anubis, Xenomorph)."),
        ("Section 3: Behavioral Attack Timeline", "Step-by-step chronological progression of actions executed in the sandbox."),
        ("Section 4: Targeted Financial Entities", "Explicit list of Indian banks, UPI packages, and payment apps targeted for credential theft."),
        ("Section 5: Compromised Permissions & Data", "Inventory of stolen SMS tokens, Accessibility screen scrapes, and contact dumps."),
        ("Section 6: Actionable SOC Recommendations", "Clear guidance: Quarantine app, revoke user sessions, block C2 IPs, push MDM blacklist."),
        ("Section 7: Verifiable Evidence Citations", "Every single statement links directly to an immutable forensic EvidenceRecord hash.")
    ]

    for idx, (stitle, sdesc) in enumerate(dossier_sections):
        sy = Inches(2.55 + idx * 0.58)
        sbox = s11.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.95), sy, Inches(5.3), Inches(0.52))
        sbox.fill.solid()
        sbox.fill.fore_color.rgb = BG_LIGHT_BLUE
        sbox.line.color.rgb = RGBColor(191, 219, 254)
        sbox.line.width = Pt(1)

        tb_s = s11.shapes.add_textbox(Inches(7.1), sy + Inches(0.04), Inches(5.0), Inches(0.44))
        tf_s = tb_s.text_frame
        tf_s.word_wrap = True
        tf_s.margin_top = tf_s.margin_bottom = tf_s.margin_left = tf_s.margin_right = 0
        ps1 = tf_s.paragraphs[0]
        ps1.text = stitle
        ps1.font.size = Pt(8.5)
        ps1.font.bold = True
        ps1.font.color.rgb = BRAND_BLUE
        ps2 = tf_s.add_paragraph()
        ps2.text = sdesc
        ps2.font.size = Pt(7.5)
        ps2.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 12: Real Frontend & Analyst Experience
    # ════════════════════════════════════════════════════════════════════════════
    s12 = prs.slides.add_slide(blank_layout)
    set_background(s12)
    add_header(s12, "Real Frontend & Analyst Experience",
               "Live production UI from the SUDARSHAN console: high-speed triage, auditable evidence, and grounded AI chat",
               "ANALYST INTERFACE")
    add_footer(s12, 12)

    # Embed Real Captured Screenshots
    shot_hist = os.path.join(SCREENSHOTS_DIR, "03_case_history.png")
    shot_evid = os.path.join(SCREENSHOTS_DIR, "05_technical_evidence_hydra.png")
    shot_chat = os.path.join(SCREENSHOTS_DIR, "07_investigation_chat.png")

    # Image 1: Case History (Top Left)
    c1 = add_card(s12, Inches(0.8), Inches(1.9), Inches(5.7), Inches(2.45))
    if os.path.exists(shot_hist):
        s12.shapes.add_picture(shot_hist, Inches(0.95), Inches(2.0), height=Inches(2.25))
    
    # Overlay label 1
    add_pill(s12, Inches(1.0), Inches(2.05), "CASE REGISTRY & RISK BANDS", bg_color=BRAND_BLUE, text_color=WHITE, width=Inches(2.5), height=Inches(0.24))

    # Image 2: Technical Evidence (Top Right)
    c2 = add_card(s12, Inches(6.833), Inches(1.9), Inches(5.7), Inches(2.45))
    if os.path.exists(shot_evid):
        s12.shapes.add_picture(shot_evid, Inches(6.983), Inches(2.0), height=Inches(2.25))
    
    # Overlay label 2
    add_pill(s12, Inches(7.033), Inches(2.05), "TRACEABLE EVIDENCE REGISTRY", bg_color=BRAND_BLUE, text_color=WHITE, width=Inches(2.6), height=Inches(0.24))

    # Image 3: Ask SUDARSHAN RAG Chat (Bottom Center)
    c3 = add_card(s12, Inches(0.8), Inches(4.5), Inches(11.733), Inches(2.35))
    if os.path.exists(shot_chat):
        # Place chat screenshot scaled cleanly inside card
        s12.shapes.add_picture(shot_chat, Inches(0.95), Inches(4.6), height=Inches(2.15))

    # Callout description box on right half of bottom card
    tb_c3 = s12.shapes.add_textbox(Inches(8.0), Inches(4.65), Inches(4.3), Inches(2.0))
    tf_c3 = tb_c3.text_frame
    tf_c3.word_wrap = True
    p_c3_1 = tf_c3.paragraphs[0]
    p_c3_1.text = "GROUNDED ANALYST INVESTIGATION ASSISTANT"
    p_c3_1.font.size = Pt(10.5)
    p_c3_1.font.bold = True
    p_c3_1.font.color.rgb = BRAND_BLUE

    p_c3_2 = tf_c3.add_paragraph()
    p_c3_2.space_before = Pt(4)
    p_c3_2.text = "SUDARSHAN's interactive chat allows tier-1 analysts to query complex technical findings in plain English.\n\n" \
                 "- Grounded strictly in the 17 verified evidence records for this case.\n" \
                 "- Quick prompt chips: Explain score calculation, identify banking targets, reveal concealed payloads, and recommend SOC actions.\n" \
                 "- Transparent verification: Every answer cites the underlying evidence ID."
    p_c3_2.font.size = Pt(8.5)
    p_c3_2.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 13: Enterprise SOC, Security and Scalability
    # ════════════════════════════════════════════════════════════════════════════
    s13 = prs.slides.add_slide(blank_layout)
    set_background(s13)
    add_header(s13, "Enterprise SOC, Security and Scalability",
               "Built for high-volume banking operations: hardened container isolation, granular RBAC, and high throughput",
               "ENTERPRISE OPERATIONS")
    add_footer(s13, 13)

    ent_pillars = [
        ("1. Sandbox & Container Containment", 
         [
             "Isolated Docker network boundaries preventing external network contamination.",
             "Read-only root filesystem with ephemeral tmpfs storage for malware detonation.",
             "Dedicated ADB bridge daemon ensuring zero cross-container process leakage.",
             "Automated environment teardown restoring clean baseline AVD images after each run."
         ], BRAND_BLUE),
        ("2. Granular 3-Tier RBAC Control", 
         [
             "Administrator: System configuration, worker queue monitoring, user provisioning.",
             "SOC Lead: Verdict override authority, analyst case assignment, threat export.",
             "Security Analyst: Case investigation, artifact inspection, grounded AI chat.",
             "Stateless JWT tokens with strict revocation lists and audit trail logging."
         ], ACCENT_BLUE),
        ("3. Durable Queue & Batch Intake", 
         [
             "Enterprise batch scan worker capable of processing 500+ APK portfolios.",
             "Persistent SQLite WAL database surviving unexpected worker restarts.",
             "Automatic job deduplication preventing redundant analysis of duplicate hashes.",
             "Configurable analysis worker pools (5 parallel durable workers standard)."
         ], SKY_BLUE),
        ("4. SOC Interoperability & Export Standards", 
         [
             "STIX 2.1 Threat Intelligence Bundles for SIEM/SOAR automated ingestion.",
             "MISP Event Sharing JSON formats for cross-institutional fraud intelligence.",
             "Court-Admissible Threat Dossiers in standalone signed HTML / PDF formats.",
             "Persistent IOC cache with 24h TTL reducing external API consumption by 85%."
         ], RGBColor(15, 118, 110)),
    ]

    ew = Inches(2.78)
    eh = Inches(4.9)
    e_gap = Inches(0.2)
    for idx, (title, points, col) in enumerate(ent_pillars):
        x = Inches(0.8) + idx * (ew + e_gap)
        y = Inches(1.9)
        c = add_card(s13, x, y, ew, eh, bg_color=WHITE, border_color=BORDER_LIGHT)

        # Header bar
        hb = s13.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, ew, Inches(0.55))
        hb.fill.solid()
        hb.fill.fore_color.rgb = col
        hb.line.fill.background()

        tb_h = s13.shapes.add_textbox(x + Inches(0.12), y + Inches(0.1), ew - Inches(0.24), Inches(0.4))
        tf_h = tb_h.text_frame
        tf_h.word_wrap = True
        ph = tf_h.paragraphs[0]
        ph.text = title
        ph.font.size = Pt(9.5)
        ph.font.bold = True
        ph.font.color.rgb = WHITE

        tb_b = s13.shapes.add_textbox(x + Inches(0.15), y + Inches(0.65), ew - Inches(0.3), eh - Inches(0.75))
        tf_b = tb_b.text_frame
        tf_b.word_wrap = True
        for pt in points:
            p = tf_b.add_paragraph()
            p.space_before = Pt(8)
            p.text = "- " + pt
            p.font.size = Pt(8.5)
            p.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 14: Current Status vs Future Roadmap
    # ════════════════════════════════════════════════════════════════════════════
    s14 = prs.slides.add_slide(blank_layout)
    set_background(s14)
    add_header(s14, "Current Implementation Status vs. Future Roadmap",
               "Disciplined engineering: verified working capabilities today versus strategic expansion milestones",
               "STATUS & ROADMAP")
    add_footer(s14, 14)

    # Left Card: Verified Working Implementation (Today)
    c_today = add_card(s14, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.9))

    tb_th = s14.shapes.add_textbox(Inches(1.05), Inches(2.1), Inches(5.1), Inches(0.4))
    tf_th = tb_th.text_frame
    p_th = tf_th.paragraphs[0]
    p_th.text = "VERIFIED IMPLEMENTED CAPABILITIES (TODAY)"
    p_th.font.size = Pt(11.5)
    p_th.font.bold = True
    p_th.font.color.rgb = BRAND_BLUE

    today_items = [
        ("2,841 Automated Tests Passing (100%)", "Verified across 165 test suites covering static, dynamic, risk, and API modules."),
        ("Dual-Engine Static Analysis & Header Repair", "Auto-repairs corrupted APKs; decomposes DEX smali and parses 127 Android permissions."),
        ("VIDE Visual Impersonation Engine", "Tested and active across 10 protected Indian institutions (BOI, SBI, ICICI, HDFC, etc.)."),
        ("Dynamic Sandbox with Frida Early Hooking", "PID-accurate injection, SSL pinning bypass, and transparent anti-analysis evasion."),
        ("5-Level Perception Loop & Obstacle Dispatcher", "Automated bypass of OTP prompts, permission dialogs, and simulated login forms."),
        ("Deterministic Risk Authority (FRS & 4 Floors)", "Pure code-level scoring authority; AI strictly prohibited from computing verdicts."),
        ("Full React 18 / Vite Analyst Dashboard", "Interactive Case Registry, Evidence Tables, Threat Intel, and Grounded Gemini RAG.")
    ]

    for idx, (title, desc) in enumerate(today_items):
        tb_ti = s14.shapes.add_textbox(Inches(1.05), Inches(2.55 + idx * 0.58), Inches(5.1), Inches(0.55))
        tf_ti = tb_ti.text_frame
        tf_ti.word_wrap = True
        tf_ti.margin_top = tf_ti.margin_bottom = tf_ti.margin_left = tf_ti.margin_right = 0
        p1 = tf_ti.paragraphs[0]
        p1.text = "- " + title
        p1.font.size = Pt(8.5)
        p1.font.bold = True
        p1.font.color.rgb = SAFE_GREEN
        p2 = tf_ti.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(7.5)
        p2.font.color.rgb = SLATE_BODY

    # Right Card: Strategic Future Scope
    c_future = add_card(s14, Inches(6.7), Inches(1.9), Inches(5.833), Inches(4.9))

    tb_fut = s14.shapes.add_textbox(Inches(6.95), Inches(2.1), Inches(5.3), Inches(0.4))
    tf_fut = tb_fut.text_frame
    p_fut = tf_fut.paragraphs[0]
    p_fut.text = "STRATEGIC FUTURE EXPANSION (ROADMAP)"
    p_fut.font.size = Pt(11.5)
    p_fut.font.bold = True
    p_fut.font.color.rgb = ACCENT_BLUE

    future_items = [
        ("Distributed Kubernetes Cluster Orchestration", "Dynamic on-demand pod scaling across enterprise cloud infrastructures for 10,000+ daily APK scans."),
        ("Bare-Metal Physical Device Farm Integration", "Hardware-in-the-loop testing on real Android phones to counter advanced ARM-specific hardware rootkits."),
        ("Multi-Bank Inter-Institutional Threat Mesh", "Decentralized zero-day threat sharing network linking public and private Indian financial institutions."),
        ("Automated SIEM & MDM Policy Generation", "Auto-compilation of YARA rules, SIEM Sigma detection signatures, and real-time MDM push policies."),
        ("Advanced OCR Vision Transformer Upgrades", "Integration of lightweight on-device vision models for sub-second recognition of scrambled numeric keypads.")
    ]

    for idx, (title, desc) in enumerate(future_items):
        tb_fi = s14.shapes.add_textbox(Inches(6.95), Inches(2.65 + idx * 0.8), Inches(5.3), Inches(0.75))
        tf_fi = tb_fi.text_frame
        tf_fi.word_wrap = True
        tf_fi.margin_top = tf_fi.margin_bottom = tf_fi.margin_left = tf_fi.margin_right = 0
        p1 = tf_fi.paragraphs[0]
        p1.text = "- " + title
        p1.font.size = Pt(9)
        p1.font.bold = True
        p1.font.color.rgb = BRAND_BLUE
        p2 = tf_fi.add_paragraph()
        p2.space_before = Pt(2)
        p2.text = desc
        p2.font.size = Pt(8)
        p2.font.color.rgb = SLATE_BODY


    # ════════════════════════════════════════════════════════════════════════════
    # SLIDE 15: Complete Solution & Final Takeaway
    # ════════════════════════════════════════════════════════════════════════════
    s15 = prs.slides.add_slide(blank_layout)
    set_background(s15, RGBColor(7, 13, 24)) # Deep dark navy like Slide 1

    # Decorative background card
    bg_glow15 = s15.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.6), Inches(0.6), Inches(12.133), Inches(6.3))
    bg_glow15.fill.solid()
    bg_glow15.fill.fore_color.rgb = RGBColor(15, 23, 42)
    bg_glow15.line.color.rgb = RGBColor(30, 58, 138)
    bg_glow15.line.width = Pt(1.5)

    # Header on dark background
    if os.path.exists(BRAND_LOGO_WHITE):
        s15.shapes.add_picture(BRAND_LOGO_WHITE, Inches(1.2), Inches(1.1), width=Inches(0.8))

    add_pill(s15, Inches(2.2), Inches(1.15), "CONCLUSION & STRATEGIC VALUE", bg_color=RGBColor(30, 58, 138), text_color=RGBColor(147, 197, 253), width=Inches(2.8), height=Inches(0.3))

    tb_t15 = s15.shapes.add_textbox(Inches(1.2), Inches(1.7), Inches(10.8), Inches(0.9))
    tf_t15 = tb_t15.text_frame
    tf_t15.word_wrap = True
    p15 = tf_t15.paragraphs[0]
    p15.text = "SUDARSHAN : The Definitive Banking Threat Shield"
    p15.font.name = FONT_HEADING
    p15.font.size = Pt(26)
    p15.font.bold = True
    p15.font.color.rgb = WHITE

    p15_sub = tf_t15.add_paragraph()
    p15_sub.text = "Transforming mobile banking defense from disjointed bytecode alerts into court-admissible, deterministic fraud protection."
    p15_sub.font.size = Pt(12)
    p15_sub.font.color.rgb = RGBColor(147, 197, 253)

    # 4 Core Value Pillars
    takeaways = [
        ("Zero AI Hallucination in Scoring", 
         "Deterministic mathematical scoring (FRS 0-100) and 4 non-bypassable safety floors guarantee 100% predictable, auditable, and court-admissible verdicts."),
        ("Deep Autonomous Exploration", 
         "5-level perception hierarchy and synthetic dispatchers break through complex OTP, login, and anti-analysis barriers without human intervention."),
        ("Proactive VIDE Brand Defense", 
         "Unmasks fake Indian banking app lookalikes before user credentials ever leave the device by analyzing layout AST, color vectors, and certificate keys."),
        ("Production Tested & SOC Ready", 
         "2,841 passing automated tests, hardened container containment, granular RBAC, and standard STIX 2.1 feeds ready for enterprise deployment.")
    ]

    card_w15 = Inches(5.25)
    card_h15 = Inches(1.4)
    for idx, (title, desc) in enumerate(takeaways):
        row = idx // 2
        col = idx % 2
        x = Inches(1.2 + col * 5.6)
        y = Inches(2.8 + row * 1.6)

        c = s15.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, card_w15, card_h15)
        c.fill.solid()
        c.fill.fore_color.rgb = RGBColor(15, 23, 42)
        c.line.color.rgb = RGBColor(51, 65, 85)
        c.line.width = Pt(1)

        # Left indicator
        ind = s15.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, Inches(0.08), card_h15)
        ind.fill.solid()
        ind.fill.fore_color.rgb = RGBColor(56, 189, 248) if idx % 2 == 0 else RGBColor(52, 211, 153)
        ind.line.fill.background()

        tb = s15.shapes.add_textbox(x + Inches(0.25), y + Inches(0.15), card_w15 - Inches(0.4), card_h15 - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_top = tf.margin_bottom = tf.margin_left = tf.margin_right = 0
        p1 = tf.paragraphs[0]
        p1.text = title
        p1.font.size = Pt(11)
        p1.font.bold = True
        p1.font.color.rgb = RGBColor(224, 242, 254)

        p2 = tf.add_paragraph()
        p2.space_before = Pt(4)
        p2.text = desc
        p2.font.size = Pt(8.5)
        p2.font.color.rgb = RGBColor(203, 213, 225)

    # Closing Banner at bottom of Slide 15
    close_tb = s15.shapes.add_textbox(Inches(1.2), Inches(6.15), Inches(10.8), Inches(0.4))
    tf_c = close_tb.text_frame
    p_c = tf_c.paragraphs[0]
    p_c.text = "SUDARSHAN : Defending India's Digital Financial Ecosystem | Smart India Hackathon 2026"
    p_c.font.size = Pt(10)
    p_c.font.bold = True
    p_c.font.color.rgb = RGBColor(148, 163, 184)
    p_c.alignment = PP_ALIGN.CENTER

    # Save presentation
    output_path = os.path.abspath("SUDARSHAN_15_SLIDE_COMPLETE_SIH_PRESENTATION.pptx")
    prs.save(output_path)
    print(f"Presentation saved successfully to: {output_path}")

    # Verify slide count
    print(f"Total slide count: {len(prs.slides)}")
    assert len(prs.slides) == 15, f"Expected 15 slides, got {len(prs.slides)}"


if __name__ == "__main__":
    create_deck()
