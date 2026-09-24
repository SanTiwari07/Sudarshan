from playwright.sync_api import sync_playwright
import time
import os

OUT_DIR = "c:\\Projects\\Sudarshan\\sudarshan_artifacts\\screenshots"
os.makedirs(OUT_DIR, exist_ok=True)

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_viewport_size({"width": 1440, "height": 900})
        
        # 1. Login Page
        try:
            page.goto("http://localhost:5173/login", wait_until="networkidle")
            page.screenshot(path=f"{OUT_DIR}/01_login.png")
        except: pass
        
        # Login
        try:
            page.fill("input[name='email']", "admin@sudarshan.local")
            page.fill("input[name='password']", "admin123")
            page.click("button[type='submit']")
            time.sleep(2)
        except: pass

        # Dashboard / Cases
        try:
            page.goto("http://localhost:5173/cases", wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{OUT_DIR}/02_cases_list.png")
        except: pass

        # Upload
        try:
            page.goto("http://localhost:5173/upload", wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{OUT_DIR}/03_upload_page.png")
        except: pass

        # Batch
        try:
            page.goto("http://localhost:5173/batch", wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{OUT_DIR}/04_batch_scan.png")
        except: pass

        # Case Investigation (Assuming case 'demo' exists or empty state)
        try:
            page.goto("http://localhost:5173/case/dummy-sha256", wait_until="networkidle")
            time.sleep(2)
            page.screenshot(path=f"{OUT_DIR}/05_case_detail_dummy.png")
        except: pass

        # Any others
        try:
            page.goto("http://localhost:5173/discovery", wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{OUT_DIR}/06_discovery.png")
        except: pass

        try:
            page.goto("http://localhost:5173/resilience", wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{OUT_DIR}/07_resilience.png")
        except: pass

        browser.close()

if __name__ == '__main__':
    run()
