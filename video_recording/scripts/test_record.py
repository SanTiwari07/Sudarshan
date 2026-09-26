import os
import time
from playwright.sync_api import sync_playwright

output_dir = r"c:\Projects\Sudarshan\video_recording\test_rec"
os.makedirs(output_dir, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    context = browser.new_context(
        record_video_dir=output_dir,
        record_video_size={"width": 1920, "height": 1080},
        viewport={"width": 1920, "height": 1080}
    )
    page = context.new_page()
    page.goto("http://localhost:5173/login")
    page.wait_for_timeout(2000)
    page.fill('input[type="text"]', 'admin')
    page.fill('input[type="password"]', 'Admin123!')
    page.click('button[type="submit"]')
    page.wait_for_timeout(3000)
    context.close()
    browser.close()

recorded_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".webm")]
print("Recorded video file:", recorded_files)
