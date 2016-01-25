#PeakFlow Reports
Copyright (c) 2015 Rildo Souza

What is it?

PeakFlow Reports is an application used to access the web interface PeakflowSP tool and automatically get all the data relating to the identified attacks.

The application allows the user to enter a filter and specify the type of attack you want to monitor, as well as criticality , ie ( Attack Low, Medium and High) , after the filter being applied, the application generates a txt file to the user.

My main goal when I developed this tool was to identify the hosts on our network who were making denial-of-service attack and communicate to them.


License and author

This application is distributed under the GNU license.


Contact the author at rildo.ras@gmail.com



Dependency, Library and Environment:

Peakflow Reports has been tested in the following environment:

Python 2.7.9


Running the Application

There are two versions of the application

First Verson - attackReport_old_en.py ( If you have ArbOS before 6 )

1 - Install Python 2.7.9

2 - Install BeautifulSoup4(bs4)

3 - Install  Selenium

4 - Install xvfb in Linux

5 - Install Firefox

6 - Edit the file (attackReport_old_en.py ) according your Peakflow Appliance

7 - Edit the file ( run.sh ) according your preferences

8 - chmod +x run.sh

9 - ./run.sh


Second Version - attackReport_en.py ( If you have ArbOS 6 or above ) 


1 - Install Python 2.7.9

2 - Install BeautifulSoup4(bs4)

3 - Edit the file (attackReport_en.py ) according your Peakflow Appliance

4 - ./attackReport_en.py
