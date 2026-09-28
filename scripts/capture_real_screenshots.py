import os
import time
from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.common.by import By

os.makedirs('assets/screenshots', exist_ok=True)
opts = Options()
opts.add_argument('--headless')
opts.add_argument('--window-size=1920,1080')
opts.add_argument('--force-device-scale-factor=1')

driver = webdriver.Edge(options=opts)

try:
    print('Navigating to login...')
    driver.get('http://localhost:5173/login')
    time.sleep(2)
    driver.save_screenshot('assets/screenshots/01_login_page.png')
    print('Login page captured')

    # Log in
    driver.find_element(By.ID, 'username').send_keys('soclead')
    driver.find_element(By.ID, 'password').send_keys('Sudarshan@SOC2026')
    driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
    time.sleep(3)
    driver.save_screenshot('assets/screenshots/02_home_upload.png')
    print('Home upload captured, URL:', driver.current_url)

    # 1. Case History Registry
    driver.get('http://localhost:5173/history')
    time.sleep(3)
    driver.save_screenshot('assets/screenshots/03_case_history.png')
    print('Case history captured')

    # 2. Case detail: Hydra Banking Trojan (71c78101f7792fe879a082e323fed89c5e4a43132d01d3f79ed02afd8db45497)
    sha = '71c78101f7792fe879a082e323fed89c5e4a43132d01d3f79ed02afd8db45497'
    driver.get(f'http://localhost:5173/case/{sha}')
    time.sleep(4)
    driver.save_screenshot('assets/screenshots/04_fraud_card_hydra.png')
    print('Fraud card hydra captured')

    # 3. Evidence / Technical view
    driver.get(f'http://localhost:5173/case/{sha}/evidence')
    time.sleep(4)
    driver.save_screenshot('assets/screenshots/05_technical_evidence_hydra.png')
    print('Technical evidence captured')

    # 4. Intelligence view
    driver.get(f'http://localhost:5173/case/{sha}/intel')
    time.sleep(4)
    driver.save_screenshot('assets/screenshots/06_threat_intel_hydra.png')
    print('Threat intel captured')

    # 5. AI Investigation Chat
    driver.get(f'http://localhost:5173/case/{sha}/ask')
    time.sleep(4)
    driver.save_screenshot('assets/screenshots/07_investigation_chat.png')
    print('Investigation chat captured')

    # 6. Anubis Banking Trojan case (dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8)
    sha_anubis = 'dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8'
    driver.get(f'http://localhost:5173/case/{sha_anubis}')
    time.sleep(4)
    driver.save_screenshot('assets/screenshots/08_fraud_card_anubis.png')
    print('Fraud card anubis captured')

    # 7. Batch scan
    driver.get('http://localhost:5173/batch')
    time.sleep(3)
    driver.save_screenshot('assets/screenshots/09_batch_scan.png')
    print('Batch scan captured')

    # 8. Threat Discovery
    driver.get('http://localhost:5173/discovery')
    time.sleep(3)
    driver.save_screenshot('assets/screenshots/10_discovery_page.png')
    print('Discovery page captured')

except Exception as e:
    print('Error occurred:', e)
finally:
    driver.quit()
    print('Selenium driver closed.')
