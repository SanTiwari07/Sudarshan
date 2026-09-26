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
    
    # 2. Navigate to case
    case_url = 'http://localhost:5173/case/72d737368128ca28e3a70d9aaea07b0fd561a670bbc6f93ebd4ee5c3777c178e'
    page.goto(case_url)
    page.wait_for_timeout(3000)
    print('Navigated to case URL:', page.url)
    page.screenshot(path='c:/Projects/Sudarshan/video_recording/case_view_test.png')
    browser.close()
    print('Saved case_view_test.png successfully!')
