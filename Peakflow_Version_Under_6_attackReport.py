#Autor: Rildo Souza - rildo.souza@rnp.br, rildo.ras@gmail.com
#Funcao: Este script acessa a interface web do peakflow e busca pelos alertas High gerados recentemente 
# O Script permite que o usuario especifique os filtros dos alertas Highs que deseja buscar.
# Primeiramente o script acessa o peakflow, posteriormente acessa o alerta HIGH e gera os flows referentes a aquele ataque.
# Apos a geracao dos raw flows, cada alerta HIGH gera um arquivo que sera processado por outro script

#Dependencias:
#Instalar os seguintes pacotes
# pip install BeautifulSoup4(bs4)
# Instalar Selenium
# pip install selenium
# Instalar no Ubuntu 
# xvfb
# Instalar o Firefox


import os
import requests
import time
import urllib
from bs4 import BeautifulSoup 
from subprocess import call
from datetime import datetime, timedelta
from selenium import webdriver
from requests import session

#requests.packages.urllib3.disable_warnings()

class AttackMonitor:

	def __init__ ( self , conf ):
		self.conf = conf

	#Pega todos os alarmes do tipo Misuse do Peakflow
	def getAlarms(self , filter):
	
		print "Pegando os alarmes do Peakflow " + filter
		payload = { 
			'api_key' : self.conf['apiKey'] , 
			'filter' : filter
		}
		response = requests.get( self.conf['address'] + '/arborws/alerts' , verify=False ,  params=payload )
		return response.json()
	
	#Gera os arquivos com base nos alarmes encontrados	
	def generateReport(self , alarm):
	
		print 'Gerando report para os alarmes: ' + alarm['id']

		startDate = datetime.strptime(alarm['start'], "%Y-%m-%dT%H:%M:%S") - timedelta(hours=3)
		start = int( time.mktime( startDate.timetuple())) 
		end = int( time.time() )		
#		url = self.conf['address'] + "/administration/reports/alert_flows?report_id=alert_" + alarm['id'] + "&id=" + alarm['id'] + "&start=" + str(start) + "&end=" + str(end) + "&popup=1"
                url = self.conf['address'] + "page?id=host_alert&alert_id=" + alarm['id'] + "&id=" + alarm['id'] + "&start=" + str(start) + "&end=" + str(end)
		
		self.driver = webdriver.Firefox()
		self.driver.implicitly_wait(30)
		self.driver.get( self.conf['address'] + "/?logout=true")
		#self.driver.find_element_by_name("username").clear()
		#self.driver.find_element_by_name("username").send_keys(self.conf['username'])
		#self.driver.find_element_by_name("password").clear()
		#self.driver.find_element_by_name("password").send_keys(self.conf['password'])
		#self.driver.find_element_by_name("Submit").click()	
		self.driver.get( url )
		self.driver.find_element_by_name("run").click()		
		self.driver.quit()
	
	#Pega os reports gerados 
	def getReport (self , alarm):
 
		print "Pegando os reports dos alarmes " + alarm['id']
		index = 0
		with session() as request:
			credentials = {
				'action': '/index',
				'username': self.conf['username'],
				'password': self.conf['password']
			}
			request.allow_redirects = True
			response = request.post( self.conf['address'], verify=False, data=credentials)
			#response = request.get( self.conf['address'] + "/reports/view?popup=1&completed=1&id=alert_" + alarm['id'])
			response = request.get(self.conf['address'] + '/page?id=profiled_router_alert&alert_id=' + alarm['id'])
                        
                        #print response.text 
                        page = BeautifulSoup(response.text, 'lxml')
                        page2 = BeautifulSoup(response.text, 'lxml')
                        table = page2.find('td', {'class': 'severity-percent'})  
                        b = table.find('div' , {'class': 'addl_info'})
                        b = table.find('span')
                        b.extract()
                        c = table.find('div', {'class': 'addl_info'})
                        c = table.find('div')
                        c.extract()
                        
                        tipo_ataque = c.contents[1]
                        global tipo_ataque2
                        tipo_ataque2 = ' '.join(tipo_ataque.split())

			a = page.find('a',{'class': 'post_link pdf_no_print'})
			requestHeaders = {
				'Connection': 'keep-alive',
				'Content-Length': '146',
				'Cache-Control': 'max-age=0',
				'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
				'Upgrade-Insecure-Requests': '1',
				'Content-Type': 'application/x-www-form-urlencoded',
				'DNT': '1',
				'Referer': self.conf['address'] + '/page?id=host_alert&alert_id=' + alarm['id'] + '&cache_id=' + response.url[-13:],
				'Accept-Encoding': 'gzip, deflate',
				'Accept-Language': 'pt-BR,pt;q=0.8,en-US;q=0.6,en;q=0.4'
			}
			data = {
				'time_start': a.attrs['data-time_start'],
				'time_end': a.attrs['data-time_end'],
				'fcap': a.attrs['data-fcap'],
				'alert_id': a.attrs['data-alert_id']
			}

			response = request.post(self.conf['address'] + "/page?id=query_raw_flows", data=data, headers=requestHeaders)
                       
			#Parseando pagina HTML 
			report = ''
			page = BeautifulSoup(response.text, 'lxml')
			table = page.find('table', {'class': 'chart'})
			if table == None:
				return False
			rows = table.findAll('tr')
			for row in rows:
				if index > 1 :
					cols = row.findAll('td')
					#Checa se e uma linha valida
					if cols[0] :
						for col in cols:
							text = col.findAll(text=True)
							for t in text:
								report = report + t + '\t'
					
						report = report + '\n'

				index = index + 1
			
			#Remove as linhas em branco no final do arquivo 
			report = report[:-3]

			reportFile = open(self.conf['path'] + '/' + alarm['id'] + '.txt' , 'w')
			reportFile.write(report)
			reportFile.close()		
				
		return True
		
	#Verifica se o alarme ja esta no arquivo alarms
	def colectReports (self):
		fileAlarms = open(self.conf['path'] + '/alarms.txt' , "a+")
		alarmsRecognized = fileAlarms.read()
		fileAlarms.close()
		
		fileAlarms = open(self.conf['path'] + '/alarms.txt' , "a+")

		alarms = []
		
		#Pega todos os alarmes que estao de acordo com os filtros 
		for filter in self.conf['filters']:
			alarms = alarms + self.getAlarms(filter)
		
		#Gera todos os reports 
		#for alarm in alarms:
		#	if( alarmsRecognized.find(alarm['id']) < 0 ):
	       #		print 'Type: ' + alarm['type'] + " - ID: " + alarm['id']
		#		self.generateReport(alarm)
		
		#Espera x segundos pela geracao dos reports
		time.sleep(self.conf['waitGenerateReport'])
		
		#Pega todos os alarmes 
		for alarm in alarms:
			if( alarmsRecognized.find(alarm['id']) < 0 ):				
				if (self.getReport(alarm)):
					fileAlarms.write( alarm['id'] + '\n')
					#print self.conf['path'] + '/' + alarm['id'] + '.txt'
					#print self.conf['notify']
                                        #print alarm
                                        #print alarm['id'] + " " + alarm['type'] + " " + alarm['annotations'][0]['content'] +  tipo_ataque2
                                        
                                        call([ self.conf['notify2'], self.conf['path'] + '/' + alarm['id'] + '.txt' , alarm['id'],  alarm['max_impact_bps'],  alarm['max_impact_pps'] ,  tipo_ataque2])

 
					call([ self.conf['notify'], self.conf['path'] + '/' + alarm['id'] + '.txt' , alarm['id'] , alarm['max_impact_bps'],  alarm['max_impact_pps'] ,  tipo_ataque2])
					#call([ self.conf['notify'], self.conf['path'] + '/' + alarm['id'] + '.txt' , alarm['id'] ])
				
		fileAlarms.close()
		
serverConf = {
'address' : 'https://200.143.252.235',
'apiKey' : 'tAgHUCyepdvR0ktl',
'username' : 'caisadm',
'password' : '3k5Y!2wS',
'path' : '/home/rildo/Documentos/peakflow/attackReportNew/reports', 
'waitGenerateReport' : 30,
'notify' : '/home/rildo/Documentos/peakflow/notify.pl',
'notify2' : '/home/rildo/Documentos/peakflow/attackReportNew/notify2.sh',
'filters' :  [
                #'at:"TCP SYN" sts:recent sev:high',
                #'at:"TCP RST" sts:recent sev:high',
                #'at:"ICMP" sts:recent sev:high',
                #'at:"NTP Amplification" sts:recent sev:high'
		#'at:"DoS TCP SYN Misuse" sts:recent sev:high',
                #'at:"TCP NULL" sts:recent sev:high',
		#'at:"UDP" sts:recent sev:high',
	]
}

attackMonitor = AttackMonitor(serverConf)
attackMonitor.colectReports()
