#!/bin/bash

echo `date +"%H:%M:%S"` >> output.txt;
echo `virsh list | grep HIH `>>output.txt;
#echo  "Hello" >> output.txt;
echo `vnx -f honeymagic_simple_test.xml -v -M HIH --resume`;
#echo  $'\n' >> output.txt; 
while true
do
  echo `date +"%H:%M:%S"` >> output.txt;
  echo `virsh list | grep HIH `>>output.txt;
  echo `ping -n -c1 10.1.1.2` >> output.txt;
  echo `ping -n -c1 10.1.1.2`;
  sleep 0.1;
  echo  $'\n' >> output.txt; 
done
# ---
