# 0x94 Scanner v1.0a 
#Python 2x sürümlerde çalışır.
#mysql brute için mysql eklentisi gerekli onuda https://pypi.python.org/pypi/MySQL-python adresinden kurun
#Multi Thread  POST|GET (BLIND/TIME BASED/HEADER/SQL) INJECTION - LFI -XSS SCANNER"
#Sunucu IP adresi ve kullanilan http bilgisini alir
#Sunucu Allow header listesini alir
#Sitedeki tum linkleri 2 farkli yontemle alir (ayni linkleri tarayip zaman kaybi yapmaz)
#seo ile yada 302 yonlendirmeli linklerin location urllerini otomatik alir (otomatik yonlendirme aktiftir)
#tum linklerde get ve post sql injection dener
#tum linklerde blind get ve post sql injection dener
#tum linklerde time based get ve post sql injection dener
#tum linklerde header injection dener
#tum linklerde get ve post basit capli command injection dener
#sayfada herhangi bir degisme oldugunda degisme satirini ekrana yazar
#tum linklerde xss dener / bulunan xss satirinda code / noscript var ise belirtir
#tum linklerde php ve asp lfi dener
#tum linklerde header crlf injection dener
#tum linklerde login sayfalarini otomatik bulup basit capli brute gerceklestirir.
#linklerde olan wordpressleri bulup basit capli brute force yapar.
#linklerde olan joomlalari bulup joomla token acigini otomatik tarar
#son zamanlarda cikan plesk 0day aciginida otomatik test eder
#tomcat olan siteyi tespit edip default passlari authentication brute eder.
#cookie ve proxy destegide vardir.
#ajax ile veri gonderimi olan dosyalari tespit eder
#sitede gecen emailleri otomatik toplar
#calismayan php ve asp kodlarini bulur
#open redirect url leri tespit eder
#index off dizinleri tespit eder
#birden fazla request istegini engelleyen siteleri icin request limit ozelligi vardir.
#bulunan sql aciklarinin yollanan verilerin true ve false deger ciktilarini /debug klasorune kaydeder.
#butun sonuclari rapor.txt ye kaydeder
#sadece guvenlik testleri icin kullanin
#Turk sitelerinde tarama yapmaz.
#https://github.com/antichown/0x94scanner /
#https://twitter.com/0x94
