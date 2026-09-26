from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(channel='chrome', headless=True)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    page.goto('http://localhost:5173/login')
    page.wait_for_timeout(1000)
    page.fill('input[type="text"]', 'admin')
    page.fill('input[type="password"]', 'Admin123!')
    page.click('button[type="submit"]')
    page.wait_for_timeout(2000)
    
    page.goto('http://localhost:5173/case/72d737368128ca28e3a70d9aaea07b0fd561a670bbc6f93ebd4ee5c3777c178e')
    page.wait_for_timeout(2000)
    
    page.click('text="Evidence"')
    page.wait_for_timeout(1500)
    
    # Click visual tab
    page.locator('button:has-text("Visual")').first.click()
    page.wait_for_timeout(2000)
    page.screenshot(path='c:/Projects/Sudarshan/video_recording/visual_tab_test.png')
    
    # Click Ask Sudarshan tab
    page.click('text="Ask Sudarshan"')
    page.wait_for_timeout(1500)
    calc_btn = page.query_selector('text="How the score was calculated"')
    if calc_btn:
        calc_btn.click()
        page.wait_for_timeout(2000)
        page.screenshot(path='c:/Projects/Sudarshan/video_recording/formula_modal_test.png')
    
    browser.close()
    print('Visual and formula captured successfully!')
