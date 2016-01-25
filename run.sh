#!/bin/bash



# Check if Peakflow script is running and create virtual environment to execute script 

DIR="/home/peakflow/dir_of_the_script_peakflow"

pgrep "python"

TESTE=`echo $?`



if [ $TESTE -eq 0 ];then

   DATA=`date`
   
   echo "The script is running" - "$DATA" >> $DIR/log.txt

   exit 0;

else
  
#Create virtual display to make clicks and generate reports

   killall Xvfb
   
   
   Xvfb :99 &

   
   export DISPLAY=:99

   
   python attackReport_old_en.py