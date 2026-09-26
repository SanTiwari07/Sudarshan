from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(channel='chrome', headless=True)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    # 1. Login
    page.goto('http://localhost:5173/login')
    page.wait_for_timeout(1000)
    page.fill('input[type="text"]', 'admin')
    page.fill('input[type="password"]', 'Admin123!')
    page.click('button[type="submit"]')
    page.wait_for_timeout(2000)
    
    # 2. Case page
    page.goto('http://localhost:5173/case/72d737368128ca28e3a70d9aaea07b0fd561a670bbc6f93ebd4ee5c3777c178e')
    page.wait_for_timeout(2000)
    
    # 3. Click "Targets YONO SBI" badge if clickable, or drawer
    badge = page.query_selector('text="Targets YONO SBI"')
    if badge:
        badge.click()
        page.wait_for_timeout(1500)
        page.screenshot(path='c:/Projects/Sudarshan/video_recording/drawer_test.png')
    
    # 4. Click "Evidence" tab
    page.click('text="Evidence"')
    page.wait_for_timeout(2000)
    page.screenshot(path='c:/Projects/Sudarshan/video_recording/evidence_test.png')
    
    # 5. Click "Ask Sudarshan" tab
    page.click('text="Ask Sudarshan"')
    page.wait_for_timeout(2000)
    page.screenshot(path='c:/Projects/Sudarshan/video_recording/copilot_test.png')
    
    browser.close()
    print('All test screenshots captured successfully!')
