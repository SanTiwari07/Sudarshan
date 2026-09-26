import base64
import requests
from pathlib import Path
from playwright.sync_api import sync_playwright

WALLPAPER_PATH = Path(r"C:\Users\SHAMBHAVI PATIL\AppData\Local\Programs\Recordly\resources\assets\wallpapers\sequoia-blue.jpg")
with open(WALLPAPER_PATH, "rb") as f:
    wallpaper_b64 = base64.b64encode(f.read()).decode("utf-8")

r = requests.post("http://localhost:8000/api/v1/auth/login", json={"username": "admin", "password": "Admin123!"})
token = r.json().get("access_token")

HTML_WRAPPER = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    width: 1920px;
    height: 1080px;
    overflow: hidden;
    background-image: url('data:image/jpeg;base64,{wallpaper_b64}');
    background-size: cover;
    background-position: center;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  #viewport-stage {{
    width: 1920px;
    height: 1080px;
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    transform-origin: center center;
    transition: transform 1.1s cubic-bezier(0.16, 1, 0.3, 1);
  }}
  #app-window {{
    width: 1640px;
    height: 940px;
    background: #090d16;
    border-radius: 14px;
    box-shadow: 0 35px 100px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.15);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }}
  #window-titlebar {{
    height: 38px;
    background: #0b1120;
    display: flex;
    align-items: center;
    padding: 0 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    user-select: none;
  }}
  .traffic-lights {{
    display: flex;
    gap: 8px;
  }}
  .traffic-light {{
    width: 12px;
    height: 12px;
    border-radius: 50%;
  }}
  .tl-red {{ background: #ff5f56; }}
  .tl-yellow {{ background: #ffbd2e; }}
  .tl-green {{ background: #27c93f; }}
  #window-title {{
    margin-left: 20px;
    font-size: 13px;
    color: #94a3b8;
    font-weight: 600;
  }}
  #app-frame {{
    flex: 1;
    width: 100%;
    height: calc(100% - 38px);
    border: none;
    background: #ffffff;
  }}
</style>
</head>
<body>
  <div id="viewport-stage">
    <div id="app-window">
      <div id="window-titlebar">
        <div class="traffic-lights">
          <div class="traffic-light tl-red"></div>
          <div class="traffic-light tl-yellow"></div>
          <div class="traffic-light tl-green"></div>
        </div>
        <div id="window-title">
          <span>🛡️ Sudarshan Fraud Intelligence — Case #72d737368 (com.baseline.sbi)</span>
        </div>
      </div>
      <iframe id="app-frame" src="http://localhost:5173/login"></iframe>
    </div>
  </div>
</body>
</html>
"""

test_html_path = r"c:\Projects\Sudarshan\video_recording\recordly_studio.html"
with open(test_html_path, "w", encoding="utf-8") as f:
    f.write(HTML_WRAPPER)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    page.goto(f"file:///{test_html_path.replace(chr(92), '/')}")
    page.wait_for_timeout(2000)
    
    frame = page.frame(name="app-frame") or page.frames[1]
    
    # 1. Set token & go to Case
    frame.evaluate(f"""(tok) => {{
        localStorage.setItem('sudarshan_token', tok);
        window.location.href = 'http://localhost:5173/case/72d737368128ca28e3a70d9aaea07b0fd561a670bbc6f93ebd4ee5c3777c178e';
    }}""", token)
    page.wait_for_timeout(3500)
    
    # 2. Click Evidence tab
    frame.locator('button:has-text("Evidence"), a:has-text("Evidence")').first.click()
    page.wait_for_timeout(1500)
    
    # 3. Click Visual tab
    frame.locator('button:has-text("Visual"), a:has-text("Visual")').first.click()
    page.wait_for_timeout(2000)
    
    # Zoom in on Visual Phishing Screenshots
    page.evaluate("""() => {
        const stage = document.getElementById('viewport-stage');
        stage.style.transform = 'scale(1.48) translate(-60px, -100px)';
    }""")
    page.wait_for_timeout(1500)
    page.screenshot(path=r"c:\Projects\Sudarshan\video_recording\recordly_visual_zoom.png")
    
    # 4. Zoom back out
    page.evaluate("""() => {
        const stage = document.getElementById('viewport-stage');
        stage.style.transform = 'scale(1.0) translate(0px, 0px)';
    }""")
    page.wait_for_timeout(1500)
    
    # 5. Click Case tab again
    frame.locator('button:has-text("Case"), a:has-text("Case")').first.click()
    page.wait_for_timeout(1500)
    
    # 6. Click formula modal
    frame.locator('button:has-text("Why this APK scored"), button:has-text("score was calculated")').first.click()
    page.wait_for_timeout(1500)
    
    # Zoom in on formula breakdown modal
    page.evaluate("""() => {
        const stage = document.getElementById('viewport-stage');
        stage.style.transform = 'scale(1.38) translate(80px, -20px)';
    }""")
    page.wait_for_timeout(1500)
    page.screenshot(path=r"c:\Projects\Sudarshan\video_recording\recordly_formula_zoom.png")
    
    browser.close()
    print("All interaction & auto-zoom screenshots verified!")
