# 🔍 Port Scanner (Network Port Tarayıcı)

Bu proje, belirlenen bir hedef IP adresi veya alan adı üzerindeki açık portları tespit etmek amacıyla geliştirilmiş hızlı ve hafif bir ağ tarama aracıdır.

Siber güvenlik analizleri, ağ yönetimi ve soket programlama pratikleri için tasarlanmıştır.

## 🚀 Özellikler

* **Hızlı Tarama:** Hedef üzerindeki portları hızlıca tarar.
* **IP ve Hostname Desteği:** Hem IP adresi (örn: 192.168.1.1) hem de alan adı (örn: google.com) ile çalışır.
* **Açık Port Tespiti:** Yalnızca aktif ve bağlantı kabul eden (Open) portları listeler.
* **Kullanıcı Dostu Çıktı:** Tarama sonuçlarını temiz ve okunabilir bir formatta sunar.
* *(Opsiyonel)* **Multi-threading:** Tarama işlemini hızlandırmak için çoklu iş parçacığı (threading) kullanır.

## 🛠️ Kullanılan Teknolojiler

* **Python 3**
* **Socket** (Ağ bağlantıları için)
* **Threading** (Eş zamanlı tarama için)
* **Colorama** (Renkli terminal çıktıları için - *Eğer kullandıysan*)

## 📦 Kurulum

Projeyi yerel makinenize klonlayın:

```bash
git clone [https://github.com/ZelihaBaysan/port-scanner.git](https://github.com/ZelihaBaysan/port-scanner.git)
cd port-scanner

```

Gerekli kütüphaneleri yükleyin (Eğer harici bir kütüphane kullandıysanız, örn: colorama):

```bash
pip install -r requirements.txt
# Veya manuel olarak: pip install colorama

```

## 💻 Kullanım

Tarayıcıyı başlatmak için terminalde aşağıdaki komutu çalıştırın:

```bash
python port_scanner.py

```

Program çalıştığında sizden bir hedef IP veya alan adı isteyecektir. Örnek çalışma senaryosu:

```text
Hedef IP'yi girin: 192.168.1.10
Tarama başlıyor...

[+] Port 22 açık (SSH)
[+] Port 80 açık (HTTP)
[+] Port 443 açık (HTTPS)

Tarama tamamlandı.

```

## ⚠️ Yasal Uyarı (Disclaimer)

Bu araç **yalnızca eğitim ve meşru güvenlik testleri** amacıyla geliştirilmiştir. İzni olmayan ağlarda veya sistemlerde tarama yapmak yasa dışıdır ve etik değildir. Geliştirici, bu aracın kötüye kullanımından sorumlu tutulamaz.
