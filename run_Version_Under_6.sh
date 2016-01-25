#!/bin/bash

DIR="/home/rildo/Documentos/peakflow/attackReport"
pgrep "python"
TESTE=`echo $?`

if [ $TESTE -eq 0 ];then
   DATA=`date`
   echo "Chamada de Script em conjunto" - "$DATA" >> $DIR/log_execucao_duplicada.txt
   exit 0;
else
  #Cria display virtual para cliques
   killall Xvfb
   
   Xvfb :99 &

   export DISPLAY=:99

   python attackReport.py
fi



