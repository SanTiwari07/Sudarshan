import base64
from pathlib import Path
from playwright.sync_api import sync_playwright

WALLPAPER_PATH = Path(r"C:\Users\SHAMBHAVI PATIL\AppData\Local\Programs\Recordly\resources\assets\wallpapers\sequoia-blue.jpg")
with open(WALLPAPER_PATH, "rb") as f:
    wallpaper_b64 = base64.b64encode(f.read()).decode("utf-8")

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    
    # 1. Login
    page.goto("http://localhost:5173/login")
    page.wait_for_selector('input[type="text"]')
    page.fill('input[type="text"]', "admin")
    page.fill('input[type="password"]', "Admin123!")
    page.click('button[type="submit"]')
    page.wait_for_url("http://localhost:5173/")
    
    # 2. Go to case
    page.goto("http://localhost:5173/case/72d737368128ca28e3a70d9aaea07b0fd561a670bbc6f93ebd4ee5c3777c178e")
    page.wait_for_selector("text=com.baseline.sbi")
    
    # 3. Inject Recordly Window Wrapper with authentic Wallpaper
    page.evaluate(f"""(wallpaper) => {{
        document.body.style.margin = '0';
        document.body.style.padding = '0';
        document.body.style.width = '1920px';
        document.body.style.height = '1080px';
        document.body.style.overflow = 'hidden';
        document.body.style.backgroundImage = 'url(data:image/jpeg;base64,' + wallpaper + ')';
        document.body.style.backgroundSize = 'cover';
        document.body.style.backgroundPosition = 'center';
        
        const root = document.getElementById('root');
        
        const stage = document.createElement('div');
        stage.id = 'recordly-stage';
        stage.style.width = '1920px';
        stage.style.height = '1080px';
        stage.style.display = 'flex';
        stage.style.alignItems = 'center';
        stage.style.justifyContent = 'center';
        stage.style.transition = 'transform 1.0s cubic-bezier(0.16, 1, 0.3, 1)';
        stage.style.transformOrigin = 'center center';
        
        const win = document.createElement('div');
        win.id = 'recordly-window';
        win.style.width = '1640px';
        win.style.height = '940px';
        win.style.borderRadius = '14px';
        win.style.boxShadow = '0 32px 95px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.15)';
        win.style.overflow = 'hidden';
        win.style.display = 'flex';
        win.style.flexDirection = 'column';
        win.style.background = '#090d16';
        
        const titlebar = document.createElement('div');
        titlebar.style.height = '38px';
        titlebar.style.background = '#0f172a';
        titlebar.style.display = 'flex';
        titlebar.style.alignItems = 'center';
        titlebar.style.padding = '0 16px';
        titlebar.style.borderBottom = '1px solid rgba(255,255,255,0.08)';
        titlebar.innerHTML = `
            <div style="display:flex; gap:8px;">
                <div style="width:12px; height:12px; border-radius:50%; background:#ff5f56;"></div>
                <div style="width:12px; height:12px; border-radius:50%; background:#ffbd2e;"></div>
                <div style="width:12px; height:12px; border-radius:50%; background:#27c93f;"></div>
            </div>
            <div style="margin-left:18px; font-size:13px; font-weight:600; color:#94a3b8; font-family:-apple-system,BlinkMacSystemFont,sans-serif;">
                🛡️ Sudarshan Fraud Intelligence — Case #72d737368 (com.baseline.sbi)
            </div>
        `;
        
        const contentContainer = document.createElement('div');
        contentContainer.id = 'recordly-content';
        contentContainer.style.flex = '1';
        contentContainer.style.overflowY = 'auto';
        contentContainer.style.background = '#090d16';
        
        // Move root into container
        document.body.appendChild(stage);
        stage.appendChild(win);
        win.appendChild(titlebar);
        win.appendChild(contentContainer);
        contentContainer.appendChild(root);
    }}""", wallpaper_b64)
    
    page.wait_for_timeout(1000)
    page.screenshot(path=r"c:\Projects\Sudarshan\video_recording\recordly_injected_test.png")
    
    # Zoom into YONO card
    page.evaluate("""() => {
        const stage = document.getElementById('recordly-stage');
        stage.style.transform = 'scale(1.4) translate(-100px, -40px)';
    }""")
    page.wait_for_timeout(1200)
    page.screenshot(path=r"c:\Projects\Sudarshan\video_recording\recordly_injected_zoom_test.png")
    
    browser.close()
    print("DOM-wrapped screenshots captured successfully!")
