# crawler.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time

def crawl_for_sqli(start_url, max_pages=30):
    visited = set()
    queue = [start_url]
    sqli_candidates = set()
    page_count = 0

    while queue and page_count < max_pages:
        current_url = queue.pop(0)
        if current_url in visited:
            continue

        print(f"[{page_count+1}] Ziyaret ediliyor: {current_url}")
        try:
            response = requests.get(current_url, timeout=5)
            if response.status_code != 200:
                print(f"❌ Hata: {current_url}")
                continue
        except Exception as e:
            print(f"⚠ İstek hatası: {e}")
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        if "?" in current_url and "=" in current_url:
            sqli_candidates.add(current_url)
            print(f"🔍 SQLi adayı bulundu: {current_url}")

        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full_url = urljoin(current_url, href)
                if full_url.startswith(start_url) and full_url not in visited:
                    queue.append(full_url)

        visited.add(current_url)
        page_count += 1
        time.sleep(1)

    return list(sqli_candidates)  # Burada URL listesini return ediyoruz

