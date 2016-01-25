#Autor: Rildo Souza - rildo.ras@gmail.com
#Function: The application allows the user to enter a filter and specify the type of attack you want to monitor, as well as criticality , ie ( Attack Low, Medium and High) , aft#er the filter being applied, the application generates a txt file to the user.  

#Dependencies:
# Necessary install these packets
# pip install BeautifulSoup4(bs4)
# pip install selenium
# Install xvfb in Linux  
# Install Firefox


import os
import requests
import time

from bs4 import BeautifulSoup 
from subprocess import call
from datetime import datetime, timedelta
from selenium import webdriver
from requests import session

#requests.packages.urllib3.disable_warnings()

class AttackMonitor:

	def __init__ ( self , conf ):
		self.conf = conf

	#Get all alarms of Misuse Type from Peakflow 
	def getAlarms(self , filter):
	
		print "Getting Alarms of Peakflow " + filter
		payload = { 
			'api_key' : self.conf['apiKey'] , 
			'filter' : filter
		}
		response = requests.get( self.conf['address'] + '/arborws/alerts' , verify=False ,  params=payload )
		return response.json()
	
	#Generating files as alarms finding 	
	def generateReport(self , alarm):
	
		print 'Generating reports from alarms: ' + alarm['id']

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
	
	#Getting the alarms that was generating 
	def getReport (self , alarm):
 
		print "Getting reports from alarms " + alarm['id']
		index = 0
		with session() as request:
			credentials = {
				'action': '/index',
				'username': self.conf['username'],
				'password': self.conf['password']
			}	
			request.post( self.conf['address'], verify=False, data=credentials)
			response = request.get( self.conf['address'] + "/reports/view?popup=1&completed=1&id=alert_" + alarm['id'])
			
			#Parseasing HTML page 
			report = ''
			page = BeautifulSoup(response.text , "html.parser")
			table = page.find('table');
			rows = table.findAll('tr')
						
			for row in rows:
				if index > 1 :
					cols = row.findAll('td')

					#Check if line is valid 
					if cols[0] :
						for col in cols:
							report = report + col.string + '\t'
					
						report = report + '\n'

				index = index + 1
			
			#Remove empty lines in the final of the file  
			report = report[:-3]

			reportFile = open(self.conf['path'] + '/' + alarm['id'] + '.txt' , 'w')
			reportFile.write(report.encode('utf-8'))
			reportFile.close()		
				
		return True
		
	#Verify if alarm is in the alarms files
	def colectReports (self):
		fileAlarms = open(self.conf['path'] + '/alarms.txt' , "a+")
		alarmsRecognized = fileAlarms.read()
		fileAlarms.close()
		
		fileAlarms = open(self.conf['path'] + '/alarms.txt' , "a+")

		alarms = []
		
		#Getting all alarms according the filters  
		for filter in self.conf['filters']:
			alarms = alarms + self.getAlarms(filter)
		
		#Generating all reports  
		for alarm in alarms:
			if( alarmsRecognized.find(alarm['id']) < 0 ):
				#print 'Type: ' + alarm['type'] + " - ID: " + alarm['id']
				self.generateReport(alarm)
		
		#Waiting x seconds for the reports
		time.sleep(self.conf['waitGenerateReport'])
		
		#Getting all alarms now
		for alarm in alarms:
			if( alarmsRecognized.find(alarm['id']) < 0 ):				
				if (self.getReport(alarm)):
					fileAlarms.write( alarm['id'] + '\n')
					call([ self.conf['path'] + '/' + alarm['id'] + '.txt' , alarm['id'] , alarm['type'] ])
				
		fileAlarms.close()
		
serverConf = {
'address' : 'https://address of peakflow appliance',
'apiKey' : 'need to generate in your peakflow appliance',
'username' : 'your username',
'password' : 'password',
'path' : '/home/xxx/script/peakflow/reports', 
'waitGenerateReport' : 30,
'filters' :  [
                'at:"DoS TCP SYN Host" sts:recent sev:high',
		'at:"DoS TCP SYN Misuse" sts:recent sev:high',
		'at:"DoS TCP NULL Misuse" sts:recent sev:high',
		'at:"DoS TCP RCT Misuse" sts:recent sev:high',
		'at:"DoS IP NULL Misuse" sts:recent sev:high',
		'at:"DoS DNS Misuse" sts:recent sev:high',
		'at:"DoS Fragmentation Misuse" sts:recent sev:high',
		'at:"DoS ICMP Misuse" sts:recent sev:high',
		'at:"DoS IP Private Space Misuse" sts:recent sev:high',
		#'at:"DoS Total Traffic Misuse" sts:recent sev:high',
		'at:"DoS TCP NULL Misuse" sts:recent sev:high',
		'at:"DoS UDP Misuse" sts:recent sev:high',
	]
}

attackMonitor = AttackMonitor(serverConf)
attackMonitor.colectReports()
