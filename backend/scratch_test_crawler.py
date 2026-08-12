import asyncio
import logging
from app.services.discovery.crawler import crawl_for_apks

logging.basicConfig(level=logging.INFO)

class MockSession:
    pages_scanned = 0
    def add_log(self, msg):
        print('[LOG]', msg)

async def main():
    print("Testing crawler on https://newpipe.net/")
    apks = await crawl_for_apks('https://newpipe.net/', MockSession(), max_depth=1)
    print("Found APKs:", apks)

if __name__ == '__main__':
    asyncio.run(main())
