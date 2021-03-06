#!/usr/bin/python
#Autor: Rildo Souza - rildo.ras@gmail.com
#Function: The application allows the user to enter a filter and specify the type of attack you want to monitor, as well as criticality , ie ( Attack Low, Medium and High) , aft#er the filter being applied, the application generates a txt file to the user.

#Dependencies:
# Necessary install these packets
# pip install BeautifulSoup4(bs4)


import os
import requests
import time
import urllib
from bs4 import BeautifulSoup 
from subprocess import call
from datetime import datetime, timedelta
from selenium import webdriver
from requests import session
from os import path


#requests.packages.urllib3.disable_warnings()

class AttackMonitor:

	def __init__ ( self , conf ):
		self.conf = conf

	#Get all alarms of Misuse Type from Peakflow
	def getAlarms(self , filter):
              
	        global filter2
                filter2 = filter
		print "Getting all alarms from Peakflow " + filter
		payload = { 
			'api_key' : self.conf['apiKey'] , 
			'filter' : filter
		}
		response = requests.get( self.conf['address'] + '/arborws/alerts' , verify=False ,  params=payload )
		return response.json()
	
	#Get reports  
	def getReport (self , alarm):
 
		print "Generating report from alarms " + alarm['id']
		index = 0
		with session() as request:
			credentials = {
				'action': '/index',
				'username': self.conf['username'],
				'password': self.conf['password']
			}
			request.allow_redirects = True
			response = request.post( self.conf['address'], verify=False, data=credentials)
			response = request.get(self.conf['address'] + '/page?id=profiled_router_alert&alert_id=' + alarm['id'])
                        
                       
                        page = BeautifulSoup(response.text, 'lxml')
                        page2 = BeautifulSoup(response.text, 'lxml')
                        table = page2.find('td', {'class': 'severity-percent'})  
                        b = table.find('div' , {'class': 'addl_info'})
                        b = table.find('span')
                        b.extract()
                        c = table.find('div', {'class': 'addl_info'})
                        c = table.find('div')
                        c.extract()
                        
                        type_attack = c.contents[1]
                        global type_attack2
                        type_attack2 = ' '.join(type_attack.split())

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
                       
			#Parseaning HTML Page 
			report = ''
			page = BeautifulSoup(response.text, 'lxml')
			table = page.find('table', {'class': 'chart'})
			if table == None:
				return False
			rows = table.findAll('tr')
			for row in rows:
				if index > 1 :
					cols = row.findAll('td')
					#Check if line is valid 
					if cols[0] :
						for col in cols:
							text = col.findAll(text=True)
							for t in text:
								report = report + t + '\t'
					
						report = report + '\n'

				index = index + 1
			
			#Remove empty lines in the final of file  
			report = report[:-3]

			reportFile = open(self.conf['path'] + '/' + alarm['id'] + '.txt' , 'w')
			reportFile.write(report)
			reportFile.close()		
				
		return True
		
	#Verify if alarm is the alarm file 
	def colectReports (self):
		fileAlarms = open(self.conf['path'] + '/alarms.txt' , "a+")
		alarmsRecognized = fileAlarms.read()
		fileAlarms.close()
		
		fileAlarms = open(self.conf['path'] + '/alarms.txt' , "a+")

		alarms = []
		
		#Get all alarm according the filters  
		for filter in self.conf['filters']:
			alarms = alarms + self.getAlarms(filter)
                        
		
		#Waiting for x seconds to generating reports 
		time.sleep(self.conf['waitGenerateReport'])
		
		#Get all alarms  
		for alarm in alarms:
			if( alarmsRecognized.find(alarm['id']) < 0 ):				
				if (self.getReport(alarm)):
					fileAlarms.write( alarm['id'] + '\n')

					#print self.conf['path'] + '/' + alarm['id'] + '.txt'
					#print self.conf['notify']
                                        #print self.conf['path'] + '/' + alarm['id'] + '.txt'
					call([ self.conf['path'] + '/' + alarm['id'] + '.txt' , alarm['id'] , alarm['max_impact_bps'],  alarm['max_impact_pps'] ,  type_attack2])
				
		fileAlarms.close()

# Start the information about the Peakflow Web Page 
####################################################		
####################################################
serverConf = {
'address' : 'https://IP Address',
'apiKey' : 'passwd generate in the web page of Peakflow',
'username' : 'user ',
'password' : 'passwd of user',
'path' : '/home/scripts/peakflow/reports', 
'waitGenerateReport' : 30,
'filters' :  [
             'at:"TCP SYN" sts:recent sev:high',
             'at:"TCP RST" sts:recent sev:high',
             'at:"ICMP" sts:recent sev:high',
             'at:"NTP Amplification" sts:recent sev:high',
             'at:"TCP NULL" sts:recent sev:high',
             'at:"DoS UDP Host" sts:recent sev:high',
             'at:"Fragmentation" sts:recent sev:high',
	]
}

attackMonitor = AttackMonitor(serverConf)
attackMonitor.colectReports()
