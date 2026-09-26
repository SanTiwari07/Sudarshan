import os
import sys
import time
import subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE_DIR = Path(r"c:\Projects\Sudarshan")
VIDEO_REC_DIR = BASE_DIR / "video_recording"
RAW_DIR = VIDEO_REC_DIR / "raw"
AUDIO_MASTER = VIDEO_REC_DIR / "audio" / "00_SUDARSHAN_MASTER_VOICEOVER.mp3"
FINAL_VIDEO = VIDEO_REC_DIR / "SUDARSHAN_PREMIUM_DEMO.mp4"
FFMPEG_EXE = BASE_DIR / ".venv" / "Lib" / "site-packages" / "imageio_ffmpeg" / "binaries" / "ffmpeg-win-x86_64-v7.1.exe"

os.makedirs(RAW_DIR, exist_ok=True)

# Helper CSS and JS for studio-quality recording effects
CURSOR_INJECT_SCRIPT = """
(() => {
    if (document.getElementById('studio-cursor')) return;
    
    // Inject custom glowing pointer
    const cursor = document.createElement('div');
    cursor.id = 'studio-cursor';
    cursor.style.cssText = `
        position: fixed;
        width: 22px;
        height: 22px;
        border-radius: 50%;
        background: rgba(30, 144, 255, 0.9);
        border: 2px solid #ffffff;
        box-shadow: 0 0 14px rgba(30, 144, 255, 1.0), 0 0 28px rgba(0, 102, 255, 0.75);
        pointer-events: none;
        z-index: 999999;
        transform: translate(-50%, -50%);
        transition: transform 0.08s ease-out, background 0.15s ease;
        display: block;
    `;
    document.body.appendChild(cursor);

    // Track mouse
    window.addEventListener('mousemove', (e) => {
        cursor.style.left = e.clientX + 'px';
        cursor.style.top = e.clientY + 'px';
    });

    // Ripple effect on click
    window.addEventListener('click', (e) => {
        const ripple = document.createElement('div');
        ripple.style.cssText = `
            position: fixed;
            left: ${e.clientX}px;
            top: ${e.clientY}px;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: transparent;
            border: 2px solid #00f0ff;
            box-shadow: 0 0 20px #00f0ff;
            pointer-events: none;
            z-index: 999998;
            transform: translate(-50%, -50%) scale(1);
            animation: ripple-anim 0.5s ease-out forwards;
        `;
        document.body.appendChild(ripple);
        setTimeout(() => ripple.remove(), 500);
    });

    const style = document.createElement('style');
    style.innerHTML = `
        @keyframes ripple-anim {
            0% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
            100% { transform: translate(-50%, -50%) scale(5.5); opacity: 0; }
        }
        .studio-lower-third {
            position: fixed;
            bottom: 36px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(10, 16, 30, 0.94);
            border: 1px solid rgba(0, 200, 255, 0.45);
            border-radius: 12px;
            padding: 14px 28px;
            display: flex;
            align-items: center;
            gap: 16px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.75), 0 0 25px rgba(0, 150, 255, 0.3);
            backdrop-filter: blur(12px);
            z-index: 999990;
            color: #fff;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            opacity: 0;
            transition: opacity 0.5s ease, transform 0.5s ease;
        }
        .studio-lower-third.visible {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }
    `;
    document.head.appendChild(style);
})();
"""

def show_lower_third(page, tag: str, title: str, subtitle: str):
    try:
        clean_tag = tag.replace('"', '\\"')
        clean_title = title.replace('"', '\\"')
        clean_sub = subtitle.replace('"', '\\"')
        js = f"""
        (() => {{
            let el = document.getElementById('studio-banner');
            if (!el) {{
                el = document.createElement('div');
                el.id = 'studio-banner';
                el.className = 'studio-lower-third';
                document.body.appendChild(el);
            }}
            el.innerHTML = `
                <div style="background: linear-gradient(135deg, #1e90ff, #0052cc); padding: 6px 14px; border-radius: 6px; font-weight: 700; font-size: 13px; letter-spacing: 0.5px; text-transform: uppercase;">{clean_tag}</div>
                <div style="display: flex; flex-direction: column;">
                    <div style="font-weight: 700; font-size: 17px; color: #ffffff; letter-spacing: -0.2px;">{clean_title}</div>
                    <div style="font-size: 13px; color: #94a3b8; margin-top: 2px;">{clean_sub}</div>
                </div>
            `;
            el.classList.add('visible');
        }})();
        """
        page.evaluate(js)
    except Exception:
        pass

def smooth_scroll(page, y: int, duration_ms: int = 1500):
    try:
        page.evaluate(f"""
            (() => {{
                window.scrollTo({{
                    top: {y},
                    behavior: 'smooth'
                }});
            }})();
        """)
        time.sleep(duration_ms / 1000.0)
    except Exception:
        pass

def main():
    print("=== STARTING SUDARSHAN STUDIO DEMO RECORDING ===", flush=True)
    print(f"Target raw directory: {RAW_DIR}", flush=True)
    print(f"Master audio: {AUDIO_MASTER}", flush=True)
    
    # Exact start times for each Act (seconds from 0)
    T_ACT1 = 0.0
    T_ACT2 = 65.9
    T_ACT3_P1 = 122.6
    T_ACT3_P2 = 155.9
    T_ACT3_P3 = 216.1
    T_ACT3_P4 = 262.3
    T_ACT3_P5 = 289.3
    T_ACT4 = 331.0
    T_ACT5 = 379.1
    T_TOTAL = 445.0

    browser = None
    context = None
    try:
        p = sync_playwright().start()
        browser = p.chromium.launch(
            channel="chrome",
            headless=True,
            args=[
                "--start-maximized",
                "--enable-font-antialiasing",
                "--force-device-scale-factor=1",
                "--disable-blink-features=AutomationControlled"
            ]
        )
        context = browser.new_context(
            record_video_dir=str(RAW_DIR),
            record_video_size={"width": 1920, "height": 1080},
            viewport={"width": 1920, "height": 1080}
        )
        page = context.new_page()

        start_time = time.time()
        def elapsed():
            return time.time() - start_time

        def wait_until(target_seconds):
            rem = target_seconds - elapsed()
            if rem > 0:
                time.sleep(rem)

        def move_to(x, y, steps=15, wait_after=0.5):
            try:
                page.mouse.move(x, y, steps=steps)
                time.sleep(wait_after)
            except Exception:
                pass

        def safe_find_box(selector, timeout=1200):
            try:
                loc = page.locator(selector).first
                return loc.bounding_box(timeout=timeout)
            except Exception:
                return None

        def safe_hover(selector, x_offset=0, y_offset=0, steps=12, wait_after=1.0):
            try:
                box = safe_find_box(selector)
                if box:
                    cx = box['x'] + box['width']/2 + x_offset
                    cy = box['y'] + box['height']/2 + y_offset
                    page.mouse.move(cx, cy, steps=steps)
                    time.sleep(wait_after)
                    return True
            except Exception:
                pass
            return False

        def safe_click(selector, steps=10, wait_after=1.5):
            try:
                box = safe_find_box(selector)
                if box:
                    cx = box['x'] + box['width']/2
                    cy = box['y'] + box['height']/2
                    page.mouse.move(cx, cy, steps=steps)
                    time.sleep(0.2)
                    page.mouse.click(cx, cy)
                else:
                    page.locator(selector).first.click(timeout=1000)
                time.sleep(wait_after)
                return True
            except Exception:
                pass
            return False

        # -------------------------------------------------------------
        # SCENE 1: ACT 1 - THE THREAT (0.0s -> 65.9s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 1: Act 1 - The Threat...", flush=True)
        page.goto("http://localhost:5173/login")
        page.wait_for_load_state("networkidle")
        page.evaluate(CURSOR_INJECT_SCRIPT)
        move_to(960, 540, steps=10, wait_after=1.0)
        
        show_lower_third(page, "ACT 1", "The National Threat Horizon", "Sideloaded Banking Malware & WhatsApp Sanchar-Saathi Smishing Campaigns")
        
        time.sleep(3.0)
        safe_click('input[type="text"]')
        try:
            page.fill('input[type="text"]', "admin")
        except Exception:
            pass
        time.sleep(1.5)
        
        safe_click('input[type="password"]')
        try:
            page.fill('input[type="password"]', "Admin123!")
        except Exception:
            pass
        time.sleep(2.0)
        
        # Click Sign In
        safe_click('button[type="submit"]')
        page.wait_for_load_state("networkidle")
        time.sleep(2.5)
        
        # On Dashboard
        page.evaluate(CURSOR_INJECT_SCRIPT)
        show_lower_third(page, "ACT 1", "SUDARSHAN Intelligence Operations", "Zero-Trust APK Inspection for Law Enforcement & Financial SOCs")
        move_to(400, 250, steps=15, wait_after=3.0)
        move_to(800, 320, steps=15, wait_after=3.0)
        smooth_scroll(page, 280, duration_ms=2000)
        time.sleep(4.0)
        smooth_scroll(page, 0, duration_ms=1500)
        
        wait_until(T_ACT2)

        # -------------------------------------------------------------
        # SCENE 2: ACT 2 - THE VIDE BREAKTHROUGH (65.9s -> 122.6s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 2: Act 2 - The VIDE Breakthrough...", flush=True)
        show_lower_third(page, "ACT 2", "VIDE Architecture Breakthrough", "Visual Impersonation Detection Engine - Layout AST & Color Space Token Analysis")
        move_to(200, 180, steps=12, wait_after=3.0)
        move_to(600, 240, steps=15, wait_after=4.0)
        smooth_scroll(page, 200, duration_ms=2000)
        time.sleep(6.0)
        smooth_scroll(page, 0, duration_ms=1500)
        move_to(450, 350, steps=12, wait_after=4.0)
        
        wait_until(T_ACT3_P1)

        # -------------------------------------------------------------
        # SCENE 3: ACT 3 PART 1 - FAST STATIC & MANIFEST ANALYSIS (122.6s -> 155.9s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 3: Act 3 Part 1 - APK Ingestion & AXML Repair...", flush=True)
        show_lower_third(page, "ACT 3 • PART 1", "Fast Static Decoding & AXML Repair", "Header Deserialization, String Table Restoration & Permission Auditing")
        
        # Click on the SBI case
        case_url = "http://localhost:5173/case/72d737368128ca28e3a70d9aaea07b0fd561a670bbc6f93ebd4ee5c3777c178e"
        page.goto(case_url)
        page.wait_for_load_state("networkidle")
        page.evaluate(CURSOR_INJECT_SCRIPT)
        time.sleep(2.0)
        
        # Hover over Case header info
        move_to(300, 180, steps=12, wait_after=2.0) # com.baseline.sbi
        move_to(350, 475, steps=12, wait_after=3.0) # SHA-256
        move_to(480, 540, steps=12, wait_after=3.0) # Permissions
        
        wait_until(T_ACT3_P2)

        # -------------------------------------------------------------
        # SCENE 4: ACT 3 PART 2 - FRAUD CARD & SBI ATTRIBUTION (155.9s -> 216.1s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 4: Act 3 Part 2 - SBI YONO Brand Attribution...", flush=True)
        show_lower_third(page, "ACT 3 • PART 2", "High-Fidelity Brand Attribution", "Definitive Attribution: Targets YONO SBI | Risk Score 74.7/100")
        
        # Highlight Targets YONO SBI badge
        safe_hover('text="Targets YONO SBI"', wait_after=3.0)
        
        # Highlight Risk Score gauge
        safe_hover('text="74.7"', wait_after=3.0)
        
        # Hover executive narrative area
        move_to(400, 320, steps=12, wait_after=4.0)
            
        # Scroll to Score Drivers
        smooth_scroll(page, 450, duration_ms=2000)
        move_to(350, 720, steps=12, wait_after=3.0) # Static Threat +16.1
        move_to(350, 780, steps=12, wait_after=3.0) # Dynamic +1.3
        move_to(350, 840, steps=12, wait_after=3.0) # Threat Intel +10.0
        move_to(350, 900, steps=12, wait_after=3.0) # Banking Impact +20.0
        
        wait_until(T_ACT3_P3)

        # -------------------------------------------------------------
        # SCENE 5: ACT 3 PART 3 - RUNTIME FRIDA SANDBOX (216.1s -> 262.3s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 5: Act 3 Part 3 - Runtime Frida Instrumentation...", flush=True)
        smooth_scroll(page, 0, duration_ms=1500)
        show_lower_third(page, "ACT 3 • PART 3", "Runtime Frida Sandbox Telemetry", "Deep Android Emulation: SMS Interception, Overlay Attacks & Accessibility Abuse")
        
        # Navigate to Evidence tab
        safe_click('text="Evidence"')
        page.wait_for_load_state("networkidle")
        page.evaluate(CURSOR_INJECT_SCRIPT)
        time.sleep(2.0)
        
        # Click Runtime sub-tab
        safe_click('button:has-text("Runtime")')
        time.sleep(2.0)
        
        smooth_scroll(page, 280, duration_ms=1800)
        time.sleep(4.0)
        smooth_scroll(page, 520, duration_ms=1800)
        time.sleep(4.0)
        smooth_scroll(page, 0, duration_ms=1500)
        
        wait_until(T_ACT3_P4)

        # -------------------------------------------------------------
        # SCENE 6: ACT 3 PART 4 - VISUAL EVIDENCE & COLOR AST (262.3s -> 289.3s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 6: Act 3 Part 4 - Visual Impersonation Evidence...", flush=True)
        show_lower_third(page, "ACT 3 • PART 4", "Visual AST & Brand Artifacts", "16 Captured Sandbox Viewports Exposing Fake YONO SBI Phishing Screens")
        
        # Click Visual 16 tab
        safe_click('button:has-text("Visual")')
        time.sleep(2.0)
        
        # Scroll down to view the YONO SBI screenshots
        smooth_scroll(page, 450, duration_ms=1800)
        move_to(560, 720, steps=12, wait_after=2.5) # Hover Frame 03 YONO SBI Login
        move_to(710, 720, steps=12, wait_after=2.5) # Hover Frame 04
        move_to(860, 720, steps=12, wait_after=2.5) # Hover Frame 05
        
        wait_until(T_ACT3_P5)

        # -------------------------------------------------------------
        # SCENE 7: ACT 3 PART 5 - GROUNDED AI COPILOT (289.3s -> 331.0s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 7: Act 3 Part 5 - Ask SUDARSHAN Grounded Copilot...", flush=True)
        smooth_scroll(page, 0, duration_ms=1500)
        show_lower_third(page, "ACT 3 • PART 5", "Grounded AI Security Copilot", "Zero-Hallucination Intelligence Bound Directly to Verified Forensic Evidence")
        
        # Click Ask Sudarshan tab
        safe_click('text="Ask Sudarshan"')
        page.wait_for_load_state("networkidle")
        page.evaluate(CURSOR_INJECT_SCRIPT)
        time.sleep(2.0)
        
        # Hover over prompt cards
        move_to(350, 760, steps=12, wait_after=2.0) # Score calculation
        move_to(460, 760, steps=12, wait_after=2.0) # Banking targets
        move_to(580, 760, steps=12, wait_after=2.0) # Concealed payload
        move_to(780, 760, steps=12, wait_after=2.0) # SOC response
        
        # Click Banking targets card
        safe_click('text="BANKING TARGETS"')
        time.sleep(3.0)
            
        wait_until(T_ACT4)

        # -------------------------------------------------------------
        # SCENE 8: ACT 4 - MATHEMATICAL DETERMINISM (331.0s -> 379.1s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 8: Act 4 - Mathematical Determinism Formula...", flush=True)
        show_lower_third(page, "ACT 4", "Mathematical Determinism & Auditability", "Strict Rule-Engine Score Formulation: +51 Obfuscation, +9 Intel, +9 Target, +6 Runtime")
        
        # Click "How the score was calculated" button
        safe_click('text="How the score was calculated"')
        time.sleep(2.0)
            
        # Modal is open on the right
        move_to(1500, 105, steps=12, wait_after=2.0) # Score 75/100
        move_to(1500, 260, steps=12, wait_after=3.0) # Why suspicious
        move_to(1500, 500, steps=12, wait_after=3.0) # +51 Code Obfuscation
        move_to(1500, 650, steps=12, wait_after=3.0) # +9 Threat Intel
        move_to(1500, 800, steps=12, wait_after=3.0) # +9 Banking Targeting
        move_to(1500, 930, steps=12, wait_after=3.0) # +6 Runtime
        
        wait_until(T_ACT5)

        # -------------------------------------------------------------
        # SCENE 9: ACT 5 - NATIONAL ECOSYSTEM VISION (379.1s -> 445.0s)
        # -------------------------------------------------------------
        print(f"[{elapsed():.1f}s] Scene 9: Act 5 - National Ecosystem Vision & Closing...", flush=True)
        try:
            page.keyboard.press("Escape")
        except Exception:
            pass
        time.sleep(1.5)
        
        # Navigate to Cases
        safe_click('text="Cases"')
        page.wait_for_load_state("networkidle")
        page.evaluate(CURSOR_INJECT_SCRIPT)
        time.sleep(2.0)
        
        show_lower_third(page, "ACT 5", "National Defense Scale", "Unifying CERT-In, RBI & Financial SOCs into an Automated Anti-Trojan Shield")
        
        move_to(960, 300, steps=15, wait_after=4.0)
        smooth_scroll(page, 200, duration_ms=2500)
        time.sleep(5.0)
        smooth_scroll(page, 0, duration_ms=2000)
        time.sleep(5.0)
        
        # Final Fullscreen Branding Overlay
        final_overlay_js = """
        (() => {
            const overlay = document.createElement('div');
            overlay.id = 'final-brand-overlay';
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                background: radial-gradient(circle at center, #0b132b 0%, #020617 100%);
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                z-index: 1000000;
                opacity: 0;
                transition: opacity 1.2s ease-in-out;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                color: #ffffff;
                text-align: center;
            `;
            overlay.innerHTML = `
                <div style="font-size: 68px; font-weight: 800; letter-spacing: -1.5px; background: linear-gradient(135deg, #60a5fa, #38bdf8, #2563eb); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 16px;">
                    SUDARSHAN
                </div>
                <div style="font-size: 24px; font-weight: 500; color: #cbd5e1; max-width: 850px; line-height: 1.5; margin-bottom: 36px;">
                    Autonomous Android Banking Malware & Fraud Intelligence Platform
                </div>
                <div style="display: flex; gap: 20px; margin-top: 12px;">
                    <div style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.15); padding: 14px 28px; border-radius: 10px; font-size: 15px; color: #38bdf8; font-weight: 600;">
                        100% Deterministic Risk Engine
                    </div>
                    <div style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.15); padding: 14px 28px; border-radius: 10px; font-size: 15px; color: #38bdf8; font-weight: 600;">
                        Patent-Pending VIDE Brand Attribution
                    </div>
                    <div style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.15); padding: 14px 28px; border-radius: 10px; font-size: 15px; color: #38bdf8; font-weight: 600;">
                        Grounded AI Forensic Copilot
                    </div>
                </div>
                <div style="font-size: 15px; color: #64748b; margin-top: 50px; letter-spacing: 1px; font-weight: 600;">
                    PROTECTING INDIA'S FINANCIAL ECOSYSTEM • CERT-In • RBI • I4C
                </div>
            `;
            document.body.appendChild(overlay);
            setTimeout(() => { overlay.style.opacity = '1'; }, 100);
        })();
        """
        page.evaluate(final_overlay_js)
        
        wait_until(T_TOTAL)
        print(f"[{elapsed():.1f}s] Browser recording completed successfully!", flush=True)

    except Exception as e:
        print(f"Exception during recording: {e}", flush=True)
    finally:
        if context:
            context.close()
        if browser:
            browser.close()

    # Find the recorded WebM file
    webm_files = [os.path.join(RAW_DIR, f) for f in os.listdir(RAW_DIR) if f.endswith(".webm")]
    if not webm_files:
        raise RuntimeError(f"No WebM files found in {RAW_DIR}")
    
    latest_webm = max(webm_files, key=os.path.getctime)
    print(f"Captured WebM file: {latest_webm} ({os.path.getsize(latest_webm)} bytes)", flush=True)

    # -------------------------------------------------------------
    # MUXING WITH FFMPEG INTO FINAL MP4
    # -------------------------------------------------------------
    print(">>> Muxing 1080p video with pristine Master Voiceover...", flush=True)
    ffmpeg_cmd = [
        str(FFMPEG_EXE),
        "-y",
        "-i", latest_webm,
        "-i", str(AUDIO_MASTER),
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "256k",
        "-shortest",
        str(FINAL_VIDEO)
    ]
    
    print(f"Running ffmpeg: {' '.join(ffmpeg_cmd)}", flush=True)
    result = subprocess.run(ffmpeg_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print("FFmpeg stderr:\n", result.stderr, flush=True)
        raise RuntimeError("FFmpeg muxing failed!")

    print(f"=== FINAL PREMIUM DEMO VIDEO CREATED SUCCESSFULLY ===", flush=True)
    print(f"Output File: {FINAL_VIDEO}", flush=True)
    print(f"Size: {os.path.getsize(FINAL_VIDEO)} bytes", flush=True)

if __name__ == "__main__":
    main()
