import os
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

WALLPAPER_PATH = Path(r"C:\Users\SHAMBHAVI PATIL\AppData\Local\Programs\Recordly\resources\assets\wallpapers\sequoia-blue.jpg")

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
    background: url('file:///{str(WALLPAPER_PATH).replace(chr(92), "/")}') no-repeat center center;
    background-size: cover;
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
    transition: transform 1.2s cubic-bezier(0.16, 1, 0.3, 1);
  }}
  #app-window {{
    width: 1640px;
    height: 940px;
    background: #0f172a;
    border-radius: 14px;
    box-shadow: 0 30px 90px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.12);
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
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
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
          <span>🛡️ Sudarshan Fraud Intelligence — com.baseline.sbi</span>
        </div>
      </div>
      <iframe id="app-frame" src="http://localhost:5173/case/72d737368128ca28e3a70d9aaea07b0fd561a670bbc6f93ebd4ee5c3777c178e"></iframe>
    </div>
  </div>
</body>
</html>
"""

test_html_path = r"c:\Projects\Sudarshan\video_recording\test_recordly_frame.html"
with open(test_html_path, "w", encoding="utf-8") as f:
    f.write(HTML_WRAPPER)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    
    # First login in cookie session
    login_page = browser.new_page()
    login_page.goto("http://localhost:5173/login")
    login_page.fill('input[type="text"]', "admin")
    login_page.fill('input[type="password"]', "Admin123!")
    login_page.click('button[type="submit"]')
    login_page.wait_for_timeout(2000)
    cookies = login_page.context.cookies()
    page.context.add_cookies(cookies)
    login_page.close()
    
    page.goto(f"file:///{test_html_path.replace(chr(92), '/')}")
    page.wait_for_timeout(3000)
    page.screenshot(path=r"c:\Projects\Sudarshan\video_recording\recordly_frame_test.png")
    
    # Test Zoom into YONO card
    page.evaluate("""
        const stage = document.getElementById('viewport-stage');
        stage.style.transform = 'scale(1.45) translate(-140px, -60px)';
    """)
    page.wait_for_timeout(1500)
    page.screenshot(path=r"c:\Projects\Sudarshan\video_recording\recordly_zoom_test.png")
    
    browser.close()
    print("Recordly frame and zoom screenshots captured!")
